#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Untitled Goose Tool: m365_datadumper!
This module has all the telemetry pulls for M365 (Exchange Online / O365).

Key concepts:
- EXO cmdlets: Exchange Online PowerShell cmdlets executed via the AdminAPI REST endpoint.
  These are used for mailbox info, inbox rules, mobile devices, role groups, etc.
- UAL (Unified Audit Log): The main audit log for M365, queried via Search-UnifiedAuditLog.
  UAL collection uses a complex binary-search bounding algorithm to handle large log volumes
  (see _new_ual_timeframe and _insert_ual_record).
- Save state: Most methods support resuming from a checkpoint file so interrupted runs
  can continue without re-pulling already-collected data.
"""

import asyncio
import csv
import json
import os
import sys
import time
import urllib.parse
import random

from aiohttp.client_exceptions import *
from datetime import datetime, timedelta
from goosey.datadumper import DataDumper
from goosey.progress import get_progress_manager
from goosey.utils import *
from io import StringIO

class M365DataDumper(DataDumper):
    """Collects M365/Exchange Online telemetry: UAL, mailboxes, inbox rules, mobile devices, etc.

    Uses two authentication tokens:
    - app_auth (graph_api): For Microsoft Graph API calls (inbox rules via Graph, users list)
    - o365_app_auth (outlook_office_api): For Exchange Online AdminAPI PowerShell cmdlets
    """

    def __init__(self, output_dir, reports_dir, app_auth, session, config, debug, o365_app_auth, token_manager=None, force_repull=False):
        super().__init__(f'{output_dir}{os.path.sep}m365', reports_dir, app_auth, session, debug, token_manager=token_manager, endpoint_key="graph_api", force_repull=force_repull)
        self.logger = setup_logger(__name__, debug)
        self.gcc = config_get(config, 'config', 'gcc', self.logger).lower() == "true"
        self.gcc_high = config_get(config, 'config', 'gcc_high', self.logger).lower() == "true"
        self.endpoints = get_endpoints(gcc=self.gcc, gcc_high=self.gcc_high)
        self.inboxfailfile = os.path.join(reports_dir, '_user_inbox_503.json')
        self.failurefile = os.path.join(reports_dir, '_no_results.json')

        # UAL bounding state: tracks which time ranges have been searched and their log counts.
        # Used by the binary-search algorithm to avoid re-querying completed ranges.
        self.ual_bounds_state = []
        self.o365_app_auth = o365_app_auth
        # ual_threshold: max logs per time slice before binary-splitting into smaller ranges
        self.threshold = int(config_get(config, 'variables', 'ual_threshold'))
        # max_ual_tasks: concurrency limit for parallel UAL session queries
        self.max_ual_tasks = max(1,int(config_get(config, 'variables', 'max_ual_tasks')))
        self.ual_extra_start = config_get(config, 'variables', 'ual_extra_start')
        self.ual_extra_end = config_get(config, 'variables', 'ual_extra_end')

        # UAL filter parameters (all optional, comma-separated for multi-value)
        self.ual_record_type = config_get(config, 'variables', 'ual_record_type')
        self.ual_operations = config_get(config, 'variables', 'ual_operations')
        self.ual_user_ids = config_get(config, 'variables', 'ual_user_ids')
        self.ual_free_text = config_get(config, 'variables', 'ual_free_text')
        self.ual_ip_addresses = config_get(config, 'variables', 'ual_ip_addresses')
        self.ual_object_ids = config_get(config, 'variables', 'ual_object_ids')
        self.tenantId = config_get(config, 'config', 'tenant')
        self.ual_tasks = []  # Active concurrent UAL sub-tasks
        self.ual_results_cache = []  # Buffers results when API returns data for wrong time range
        self.date_range, self.date_start, self.date_end = get_date_range(config, self.logger)

        self.call_object = [self.endpoints["graph_api"] + "/beta/", self.app_auth, self.logger, self.output_dir, self.get_session()]

    async def run_exo_cmdlet(self, cmdlet, Parameters={}, timeout=120):
        """Execute an Exchange Online PowerShell cmdlet via the AdminAPI REST endpoint.

        This sends a POST to /adminapi/beta/{tenantId}/InvokeCommand with the cmdlet
        name and parameters serialized as JSON. The AdminAPI translates this into a
        remote PowerShell execution on the Exchange Online backend.

        Args:
            cmdlet: PowerShell cmdlet name (e.g. 'Search-UnifiedAuditLog', 'Get-Mailbox').
            Parameters: Dict of cmdlet parameters to pass.
            timeout: Request timeout in seconds (UAL queries may need longer timeouts).

        Returns:
            Tuple of (response_dict, error_string_or_None).
        """
        self.ensure_token("outlook_office_api")
        access_token = self.o365_app_auth["access_token"]
        headers = {
               'Prefer': 'odata.maxpagesize=1000',
               'X-AnchorMailbox': EXO_ANCHOR_MAILBOX,
               'Accept': 'application/json',
               'Content-Type': 'application/json',
               'Authorization': f"Bearer {access_token}",
               'X-ResponseFormat': 'json',
               'X-CmdletName': cmdlet,
               'X-ClientApplication': 'ExoManagementModule'
        }

        raw_payload = {
            'CmdletInput': {
                'CmdletName': cmdlet,
                'Parameters': Parameters
            }
        }
        data=json.dumps(raw_payload)
        result = None
        err = None
        # https://learn.microsoft.com/en-us/powershell/module/exchange
        url = f"{self.endpoints['outlook_office_api']}/adminapi/beta/{self.tenantId}/InvokeCommand"
        self.logger.debug(raw_payload)

        try:
            async with self.ahsession.request("POST", url=url, headers=headers, data=data, timeout=timeout) as r:
                result = await r.text()
                result = json.loads(result)
                result["status"] = r.status
                if r.status == 401:
                    self.logger.error("Detected 401 unauthorized for EXO cmdlet %s." % cmdlet)
                    err = "Unauthorized (401)"
                elif r.status == 429:
                    error = result['error']
                    message = error['message']
                    seconds = message.split(' ')[-2]
                    self.logger.debug("Sleeping for %s seconds" % (seconds))
                    await asyncio.sleep(int(seconds))
                    err = message
                else:
                    if "error" in result:
                        err = result["error"]["message"]
        except TimeoutError:
            err = "TimeoutError"
        except asyncio.exceptions.TimeoutError:
            err = "TimeoutError"
        except Exception as e:
            self.logger.debug("Exception info", exc_info=1)
            err = str(e)

        if err:
            self.logger.debug(err)

        return result, err

    def load_exo_cmdlet(self, load_file):
        """
        Load previous output from an exo cmdlet.
        Return an array of values
        """
        infile = os.path.join(self.output_dir, load_file)
        if not os.path.isfile(infile):
            self.logger.debug(f"File {infile} does not exist")
            return []
        values = []
        infile_handle = open(infile, "r")
        for line in infile_handle:
            values.append(json.loads(line))
        return values


    async def save_exo_cmdlet(self, cmdlet, save_file, Parameters={}, remove_fields=[], append=False, overwrite_existing=False):
        """
        Run an exo powershell cmdlet and save the results to a file
        """
        outfile = os.path.join(self.output_dir, save_file)
        # Check if the output file exists and if we can overwrite it
        if os.path.isfile(outfile) and not append and not overwrite_existing:
            self.logger.debug(f"File {outfile} already exists. Not performing call to cmdlet")
            return self.load_exo_cmdlet(save_file)

        response, err = await self.run_exo_cmdlet(cmdlet, Parameters)
        if err:
            raise Exception(err)
        response_dict = response
        new_values = []
        if "value" not in response_dict:
            return
        for value in response_dict["value"]:
            for field in remove_fields:
                del value[field]
            new_values.append(value)
        open_flags = "w"
        if append:
            open_flags = "a"
        output_string = ""
        for value in new_values:
            output_string += json.dumps(value) + "\n"
        if output_string != "":
            with open(outfile, open_flags, encoding="utf-8") as f:
                f.write(output_string)

        return new_values

    async def dump_exo_groups(self):
        """
        Dumps Exchange Online Role Group and Role Group Members information.
        """
        roles = await self.save_exo_cmdlet("Get-RoleGroup", "EXO_RoleGroups_PowerShell.json", Parameters={"ResultSize": "Unlimited"})

        append=False
        # Load save state and change the roles array to be only role groups that haven't been searched
        member_save_state_file = os.path.join(self.output_dir, ".EXO_RoleGroupMembers_savestate")
        last_role = load_state(member_save_state_file, is_datetime=False)
        if last_role:
            role_index = next((i for i, item in enumerate(roles) if item["Id"] == last_role), None)
            roles = roles[role_index+1:]
            append=True
        for role in roles:
            await self.save_exo_cmdlet("Get-RoleGroupMember", "EXO_RoleGroupsMembers_PowerShell.json", Parameters={"Identity": role["Id"]}, append=append)
            save_state(member_save_state_file, role["Id"], is_datetime=False)
            append=True

    async def dump_exo_mailbox(self) -> None:
        """
        Dumps Exchange Online Mailbox Information
        """
        self.logger.debug("Starting dumping EXO Mailboxes")
        new_values = await self.save_exo_cmdlet("Get-Mailbox", "EXO_Mailboxes_PowerShell.json", Parameters={"IncludeInactiveMailbox": "True", "ResultSize": "Unlimited"})
        mailboxes = []
        for value in new_values:
            mailboxes.append(value["WindowsEmailAddress"])
        self.logger.debug("Finished dumping EXO Mailboxes")

        self.logger.debug("Starting dumping EXO Mailbox Client Access Settings")
        await self.save_exo_cmdlet("Get-CASMailbox", "EXO_MailboxCAS_Settings_PowerShell.json", Parameters={"ResultSize": "Unlimited"})
        await self.save_exo_cmdlet("Get-CASMailboxPlan", "EXO_Tenant_CAS_Plan_PowerShell.json", Parameters={"ResultSize": "Unlimited"})
        self.logger.debug("Finished dumping EXO Mailboxes Client Access Settings")

        append=False
        # Load save state
        mailbox_save_state_file = os.path.join(self.output_dir, ".EXO_Mailbox_savestate")
        last_mailbox = load_state(mailbox_save_state_file, is_datetime=False)
        if last_mailbox:
            mailbox_index = mailboxes.index(last_mailbox)
            mailboxes = mailboxes[mailbox_index+1:]
            append=True
        # Go through each mailbox and grap permissions, folder permissions, and inbox rules
        self.logger.debug("Starting dumping EXO Mailbox Permissions")
        for mailbox in mailboxes:
            self.logger.debug(f"Dumping Mailbox Info for {mailbox}")
            await self.save_exo_cmdlet("Get-MailboxPermission", "EXO_MailboxPermissions_PowerShell.json", Parameters={"Identity": mailbox}, append=append)
            await self.save_exo_cmdlet("Get-MailboxFolderPermission", "EXO_TopLevelFolderPermissions_PowerShell.json", Parameters={"Identity": mailbox}, append=append)
            await self.save_exo_cmdlet("Get-InboxRule", "EXO_InboxRules_PowerShell.json", Parameters={"Mailbox": mailbox, "IncludeHidden": "True"}, append=append)
            save_state(mailbox_save_state_file, mailbox, is_datetime=False)
            append=True

        self.logger.debug("Finished dumping EXO Mailbox Permissions")

    async def dump_exo_config_info(self) -> None:
        """
        Get EXO config information
        """
        if self.check_savestate("exo_config_info"):
            return
        await asyncio.gather(
            self.save_exo_cmdlet("Get-MailboxAuditBypassAssociation", "EXO_MailboxAuditStatus_PowerShell.json", Parameters={"ResultSize": "Unlimited"}),
            self.save_exo_cmdlet("Get-AdminAuditLogConfig", "EXO_AdminAuditLogConfig_PowerShell.json"),
            # Below cmdlet is in the previous powershell script but gives an error here
            #self.save_exo_cmdlet("Get-UnifiedAuditLogRetentionPolicy", "EXO_UALRetentionPolicy_PowerShell.json"),
            self.save_exo_cmdlet("Get-OrganizationConfig", "EXO_OrganizationConfig_PowerShell.json"),
            self.save_exo_cmdlet("Get-PerimeterConfig", "EXO_PerimeterConfig_PowerShell.json"),
            self.save_exo_cmdlet("Get-TransportRule", "EXO_TransportRules_PowerShell.json"),
            self.save_exo_cmdlet("Get-TransportConfig", "EXO_TransportConfig_PowerShell.json")
        )
        self.write_savestate("exo_config_info")

    async def dump_exo_mobile_devices(self) -> None:
        """
        Get information on m365 mobile devices
        """
        devices = await self.save_exo_cmdlet("Get-MobileDevice", "EXO_MobileDevices_PowerShell.json", Parameters={"ResultSize": "Unlimited"})
        await self.save_exo_cmdlet("Get-MobileDeviceMailboxPolicy", "EXO_MobileDeviceMailboxPolicy_PowerShell.json")

        append=False
        # Load save state and change the devices array to be only devices that haven't been searched
        mobile_save_state_file = os.path.join(self.output_dir, ".EXO_MobileDevicesStats_savestate")
        last_device = load_state(mobile_save_state_file, is_datetime=False)
        if last_device:
            device_index = next((i for i, item in enumerate(devices) if item["Guid"] == last_device), None)
            devices = devices[device_index+1:]
            append=True
        for device in devices:
            device = device["Guid"]
            await self.save_exo_cmdlet("Get-MobileDeviceStatistics", "EXO_MobileDeviceStats_PowerShell.json", Parameters={"Identity": device, "ErrorAction": "SilentlyContinue"}, append=append)
            save_state(mobile_save_state_file, device, is_datetime=False)
            append=True

    async def dump_ediscovery_info(self) -> None:
        """
        Get Exchange discovery information
        """
        roles = await self.save_exo_cmdlet("Get-ManagementRoleEntry", "EXO_EDiscovery_Roles_PowerShell.json", Parameters={"Identity": "*\\New-MailboxSearch"})
        roles += await self.save_exo_cmdlet("Get-ManagementRoleEntry", "EXO_EDiscovery_Roles_PowerShell.json", Parameters={"Identity": "*\\Search-Mailbox"}, append=True)
        new_roles = []
        for role in roles:
            new_role = role["Role"]
            if new_role not in new_roles:
                new_roles.append(role["Role"])
        roles=new_roles
        append=False
        # Load save state and change the roles array to be only role groups that haven't been searched
        role_save_state_file = os.path.join(self.output_dir, ".EXO_EDiscovery_savestate")
        last_role = load_state(role_save_state_file, is_datetime=False)
        if last_role:
            self.logger.debug(f"save state role detected. Starting from {last_role}")
            role_index = roles.index(last_role)
            roles = roles[role_index+1:]
            append=True
        # Go through each role and pull cmdlets and assignments associated witht the roles
        for role in roles:
            await self.save_exo_cmdlet("Get-ManagementRoleEntry", "EXO_Ediscovery_RoleCmdlets_PowerShell.json", Parameters={"Identity": f"{role}\\*"}, append=append)
            await self.save_exo_cmdlet("Get-ManagementRoleAssignment", "EXO_Ediscovery_RoleAssignments_PowerShell.json", Parameters={"Role": role, "Delegating": "False"}, append=append)
            save_state(role_save_state_file, role, is_datetime=False)
            append=True



    async def dump_exo_addins(self, timeout=120) -> None:
        """
        Get all of the applications installed for the organization
        """
        if self.check_savestate("exo_addins"):
            return
        await self.save_exo_cmdlet("Get-App", "EXO_AddIns.json", Parameters={"OrganizationApp": "True", "PrivateCatalog": "True"}, remove_fields=["ManifestXml"])
        self.write_savestate("exo_addins")

    @requires_auth
    async def dump_exo_inboxrules(self) -> None:
        """
        Get all the messageRule objects defined for all users' inboxes
        """
        outfile = os.path.join(self.output_dir, 'users.json')
        if os.path.exists(outfile):
            data = [json.loads(line) for line in open (outfile, 'r')]
        else:
            await helper_single_object('users', self.call_object, self.failurefile)
            data = [json.loads(line) for line in open (outfile, 'r')]

        statefile = f'{self.output_dir}{os.path.sep}.inbox_state'
        if os.path.isfile(statefile):
            self.logger.debug(f'Save state file exists at {statefile}')
            self.logger.info(f'Inbox rules save state file found. Continuing from last checkpoint.')

            with open(statefile, "r") as f:
                save_state_type = f.readline().strip()
                if save_state_type:
                    save_state_start = save_state_type
                    self.logger.info("Save state: {}".format(str(save_state_start)))

            i = save_state_start
            self.logger.info("Value of I: {}".format(str(i)))
        else:
            self.logger.debug('No save state file found.')
            i = 0

        listOfIds = list(findkeys(data, 'userPrincipalName'))
        self.logger.info('Dumping inbox rules...')

        for i in range(int(i), len(listOfIds)):
            retries = 50
            while retries > 0:
                try:
                    if "'" in listOfIds[i]:
                        listOfIds[i] = listOfIds[i].replace("'", "%27")
                        self.logger.debug('Converted userprincipal: {}'.format(str(listOfIds[i])))
                    url = self.endpoints['graph_api'] + '/beta/users/' + listOfIds[i] + '/mailFolders/inbox/messageRules'
                    header = {'Authorization': '%s %s' % (self.app_auth['token_type'], self.app_auth['access_token'])}
                    additionalInfo = {"userPrincipalName": listOfIds[i]}
                    async with self.ahsession.request("GET", url, headers=header, raise_for_status=True) as r:
                        result = await r.json()
                        finalvalue = result['value']
                        self.logger.debug('Full result: {}'.format(str(result)))
                        outfile = os.path.join(self.output_dir, "EXO_InboxRules_Graph.json")
                        with open(outfile, 'a', encoding="utf-8") as f:
                            if finalvalue:
                                finalvalue.append(additionalInfo)
                                f.write(json.dumps(finalvalue))
                                f.write("\n")
                        with open(statefile, 'w') as f:
                            f.write(f'{i}')
                    i += 1
                    break
                except Exception as e:
                    if e.status == 429:
                        self.logger.error('Error on json retrieval: {}'.format(str(e)))
                        self.logger.info('Sleeping for 60 seconds because of API throttle limit was exceeded.')
                        await asyncio.sleep(60)
                        retries -= 1
                    elif e.status == 404:
                        self.logger.info('User does not have inbox rules: {}'.format(str(listOfIds[i])))
                        retries = 0
                    elif e.status == 503:
                        self.logger.error('Error on json retrieval: {}'.format(str(e)))
                        self.logger.info('Error on user pull {}'.format(str(listOfIds[i])))
                        with open(self.inboxfailfile, 'a+', encoding='utf-8') as f:
                            f.write(str(listOfIds[i]) + "_" + str(i) + '\n')
                        retries = 0
                    elif e.status == 401:
                        self.logger.error('Error on json retrieval: {}'.format(str(e)))
                        self.logger.error('Unauthorized message received. Skipping inbox rules.')
                        return
        self.logger.info('Finished dumping inbox rules.')

    def _insert_ual_record(self, record, boundsfile=None):
        """
        Description:
            Add a record to the sorted ual_bounds_state.

        Arguments:
            record: Tuple of (start, end, count, done_status)
            boundsfile: filepath to where to save the bounds data.

        Returns:
            None
        """
        # Unless the time period that logs are being pulled from changes
        # the bounds within a time range will become further segmented and pulling from
        # that time period will go faster. Saving the state of the bounds is difficult though
        # because we have to be careful to account for changing start and end times.

        # This could be an optional situation of the bounds with only one time frame being searched
        # where $ is the begining and ! is the end and - in the middle means it's done_status is true.
        # Notice that the bounds double as time goes on.
        # This is because the shrinking of bounds is done in a binary fashion
        # | $-!$ !$    !$             ! |
        # Here it is after the finished time bounds are removed. Which is done for efficiency
        # |    $ !$    !$             ! |

        # Here is an example with multiple time frames
        # | $  !  $ !$ !$    !

        # Perform insert
        #self.logger.debug(f"Inserting Record {record}")

        if len(self.ual_bounds_state) == 0:
            self.ual_bounds_state.append(record)
            if boundsfile!= None:
                save_state(boundsfile, self.ual_bounds_state, is_datetime=False, time_bounds=True)
            return

        record_inserted = False
        for idx, cur_record in enumerate(self.ual_bounds_state):
            # Situations for an insert here are
            # 1. where a record already exists with that start time and we just shrink the bounds
            # 2. Or it's a completely separate time range
            if record["start"] == cur_record["start"] and record["end"] <= cur_record["end"]:
                #self.logger.debug(f"Current Record {cur_record}")
                cur_record["start"] = record["end"]
                # if the count is less than 0 then it is not accurate
                # if the new record is within a bound then adjust the larger bound.
                if cur_record["count"] >= 0 and record["count"] > 0:
                    cur_record["count"] = max(0,cur_record["count"] - record["count"])

                new_records = [record.copy(), cur_record.copy()]
                if cur_record["count"] == 0 or cur_record["start"] == cur_record["end"]:
                    new_records = [record.copy()]
                    #self.logger.debug("Record overwritten")
                #self.logger.debug(f"New Records {new_records}")
                self.ual_bounds_state = self.ual_bounds_state[:idx] + new_records + self.ual_bounds_state[idx+1:]
                #self.logger.debug(f"Record inserted at index {idx}")
                record_inserted = True
                break
            # Record before existing bounds.
            elif record["start"] < cur_record["start"] and record["end"] <= cur_record["start"]:
                new_records = [record.copy(), cur_record.copy()]
                self.ual_bounds_state = self.ual_bounds_state[:idx] + new_records + self.ual_bounds_state[idx+1:]
                record_inserted = True
                break

        if not record_inserted:
            # Loop in reverse to insert a record at the end of bound ranges
            reversed_bounds = self.ual_bounds_state[::-1]
            for idx, cur_record in enumerate(self.ual_bounds_state[::-1]):
                # Record after existing bounds.
                if record["end"] > cur_record["end"] and record["start"] >= cur_record["end"]:
                    new_records = [record.copy(), cur_record.copy()]
                    reversed_bounds = reversed_bounds[:idx] + new_records + reversed_bounds[idx+1:]
                    self.ual_bounds_state = reversed_bounds[::-1]
                    record_inserted = True
                    break

        # Remove bounds with a done_status == True
        # They no longer matter and their status as being done is tracked in the state file
        self.ual_bounds_state = [r for r in self.ual_bounds_state if not r.get('done_status')]

        self.ual_bounds_state = sorted(self.ual_bounds_state, key=lambda x: x['start'])

        overlap_detected = False
        for idx in range(len(self.ual_bounds_state)-1):
            bound1 = self.ual_bounds_state[idx]
            bound2 = self.ual_bounds_state[idx+1]
            if bound1["end"] > bound2["start"]:
                self.logger.error(f"Overlap detected in bounds state: {bound1}, {bound2}")
                raise RuntimeError(f"Overlap detected in UAL bounds state")

        if boundsfile != None:
            save_state(boundsfile, self.ual_bounds_state, is_datetime=False, time_bounds=True)

    def find_bounds_end_size(self, start, end):
        """
        Description:
            find the bounds within a timeframe and return a good end time given the bounds. Also estimates the total number of logs

        Arguments:
            start: starting timestamp
            end: ending timestamp

        Returns:
            A good end time to search
        """
        # Use these to estimate how many logs are within this timeframe
        bound_logs = 0
        total_estimated_logs = 0
        total_time_delta = end - start
        record_time_delta = timedelta(0)

        matching_bounds = []
        for record in self.ual_bounds_state:
            if start <= record["start"] and end >= record["end"]:
                matching_bounds.append(record.copy())
                bound_logs += record["count"]
                record_time_delta += (record["end"] - record["start"])

        if record_time_delta != timedelta(0):
            total_estimated_logs = int(total_time_delta / record_time_delta * bound_logs)

        if len(matching_bounds) == 0:
            matching_bounds = [{"start": start, "end": end}]

        if start < matching_bounds[0]["start"]:
            return matching_bounds[0]["start"], total_estimated_logs



        return matching_bounds[0]["end"], total_estimated_logs

    def get_start_end_results(self, results):
        """Find the earliest and latest CreationTime across a batch of UAL results.

        Used to verify that returned results actually fall within the expected time bounds,
        since the UAL API can sometimes return results outside the requested range.
        """
        start = dateutil.parser.parse(json.loads(results[0]["AuditData"])["CreationTime"]).replace(tzinfo=None)
        end = start
        for idx, entry in enumerate(results):
            time = dateutil.parser.parse(json.loads(entry["AuditData"])["CreationTime"]).replace(tzinfo=None)
            start = min(time, start)
            end = max(time, end)

        return start, end

    async def _new_ual_timeframe(self, start, end, retries=5, statefile=None, boundsfile=None, session_results=[], sessionId=None, isolated=False, caller="", ual_progress=None, range_total_hours=None):
        """Core UAL collection engine: searches a time range and collects all audit logs.

        This implements a binary-search approach to handle large log volumes:
        1. Query Search-UnifiedAuditLog for the time range [start, end].
        2. If ResultCount > threshold, halve the time range and retry (binary split).
        3. If ResultCount <= threshold, paginate through results using sessionId.
        4. Once all results for a time slice are collected, save to file and advance.

        The method operates in two modes:
        - Non-isolated (initial): Explores the full time range, spawning isolated
          sub-tasks for time slices that need full pagination.
        - Isolated: Dedicated to a single time slice, uses larger ResultSize (5000)
          and longer timeouts for efficient bulk retrieval.

        Session handling:
        - Each query uses a random sessionId to maintain server-side cursor state.
        - The API's ReturnLargeSet command pages through results using the session.
        - Duplicate detection handles cases where the API restarts a session mid-query.

        Save state:
        - Completed time ranges are saved to statefile so interrupted runs can resume.
        - Bounds state tracks which sub-ranges have been searched and their log counts.

        Args:
            start: Start of the time range to search.
            end: End of the time range to search.
            retries: Max consecutive errors before giving up on a time slice.
            statefile: Path to save completed time ranges for resume support.
            boundsfile: Path to save bounds state (searched sub-ranges).
            session_results: Pre-existing results when continuing an isolated session.
            sessionId: Pre-existing session ID when continuing an isolated session.
            isolated: True when this is a dedicated sub-task for a single time slice.
            caller: Name of the parent task for labeling sub-tasks.
            ual_progress: Shared progress dict with 'bar', 'pm', 'bar_name', 'hours_done', 'total_hours'.
            range_total_hours: This range's share of total hours in the progress bar.
        """

        response_count = 0
        session_sizes = {}
        sessionCount = 0
        finalEnd = end
        tries = 0
        total_duplicates = 0
        continuing = False

        # Time-based progress tracking (only for non-isolated parent tasks)
        orig_start = start
        my_hours_reported = 0

        def _update_ual_progress(covered_end):
            """Update the shared UAL time-based progress bar."""
            nonlocal my_hours_reported
            if not ual_progress or not ual_progress.get("bar") or isolated:
                return
            covered_secs = max((covered_end - orig_start).total_seconds(), 0)
            total_secs = max((finalEnd - orig_start).total_seconds(), 1)
            fraction = min(covered_secs / total_secs, 1.0)
            my_covered = int(fraction * (range_total_hours or 0))
            delta = my_covered - my_hours_reported
            if delta > 0:
                ual_progress["bar"].update(delta)
                ual_progress["hours_done"] += delta
                my_hours_reported = my_covered

        def _complete_ual_progress():
            """Flush remaining hours for this range to the shared bar."""
            nonlocal my_hours_reported
            if not ual_progress or not ual_progress.get("bar") or isolated:
                return
            delta = (range_total_hours or 0) - my_hours_reported
            if delta > 0:
                ual_progress["bar"].update(delta)
                ual_progress["hours_done"] += delta
                my_hours_reported = range_total_hours or 0

        # continue the session if this is a created a task
        if isolated and sessionId and session_results:
            continuing = True

        #self.logger.debug(f"start/end before bounds {start}/{end}")
        end, totalResultCount = self.find_bounds_end_size(start, end)
        #self.logger.debug(f"start/end after bounds {start}/{end}")

        # Outer loop: advances through the full time range [start, finalEnd].
        # Each iteration handles one time slice, advancing `start` on success.
        while start < finalEnd and tries < retries:
            # Ensure the time slice has a non-zero duration
            startDate = start.strftime("%Y-%m-%dT%H:%M:%S")
            endDate = end.strftime("%Y-%m-%dT%H:%M:%S")
            if startDate == endDate:
                end += timedelta(seconds=1)
                endDate = end.strftime("%Y-%m-%dT%H:%M:%S")
            # Start a new search session unless continuing an existing isolated one
            if not continuing:
                session_results = []
                sessionId = str(random.randint(SESSION_ID_MIN, SESSION_ID_MAX))
            continuing = False
            sessionCount = -1
            session_set = set()
            bound = f'[{startDate} - {endDate}]'
            # Inner loop: pages through results within a single session/time slice
            status_code = None
            session_timeout = 60
            data_saved = False
            new_task_created = False

            while True:
                startDate = start.strftime("%Y-%m-%dT%H:%M:%S")
                endDate = end.strftime("%Y-%m-%dT%H:%M:%S")
                resultSize = 100
                parameters = {
                     'SessionCommand': "ReturnLargeSet",
                     'ResultSize': str(resultSize),
                     'SessionId': sessionId,
                     'StartDate': startDate,
                     'EndDate': endDate
                }
                # Inject UAL filter parameters if configured
                if self.ual_record_type:
                    parameters['RecordType'] = self.ual_record_type
                if self.ual_operations:
                    parameters['Operations'] = self.ual_operations
                if self.ual_user_ids:
                    parameters['UserIds'] = self.ual_user_ids
                if self.ual_free_text:
                    parameters['FreeText'] = self.ual_free_text
                if self.ual_ip_addresses:
                    parameters['IPAddresses'] = self.ual_ip_addresses
                if self.ual_object_ids:
                    parameters['ObjectIds'] = self.ual_object_ids
                # Non-isolated mode uses small ResultSize (100) for fast initial probing.
                # Isolated mode uses max ResultSize (5000) and longer timeout for bulk download.
                if isolated:
                    resultSize = 5000
                    parameters["ResultSize"] = str(resultSize)
                    session_timeout = 300

                first_iteration = False
                response, err = await self.run_exo_cmdlet("Search-UnifiedAuditLog", parameters, timeout=session_timeout)

                if err != None and "TimeoutError" in err:
                    # Timeout usually indicates too many logs. Need to reduce bounds
                    self.logger.debug(f"Encountered Timeout Error {err}")
                    new_end_ts = start.timestamp() + ((end.timestamp() - start.timestamp())/2)
                    end = datetime.fromtimestamp(new_end_ts).replace(microsecond=0)
                    break
                elif err != None:
                    # For other errors increase the tries and half the time
                    tries += 1
                    self.logger.debug(f"Encountered {err}. tries == {tries}/{retries}")
                    new_end_ts = start.timestamp() + ((end.timestamp() - start.timestamp())/2)
                    end = datetime.fromtimestamp(new_end_ts).replace(microsecond=0)
                    break


                if response == None:
                    tries += 1
                    self.logger.debug(f"No Results and no errors. tries == {tries}/{retries}")
                    break
                status_code = response["status"]
                if status_code == 200:
                    # If there are no more results within a session then break
                    # This could indicate that there an error or just that all results have been received
                    response_dict = response
                    if len(response_dict['value']) == 0:
                        tries += 1
                        self.logger.debug(f"No results in response? tries == {tries}/{retries}")
                        break
                    if int(response_dict['value'][0]['ResultCount']) == 0:
                        tries += 1
                        self.logger.debug(f"Too many logs. Couldn't calculate total count. Halving. tries == {tries}/{retries}")
                        new_end_ts = start.timestamp() + ((end.timestamp() - start.timestamp())/2)
                        end = datetime.fromtimestamp(new_end_ts).replace(microsecond=0)
                        break
                    tries = 0
                    sessionCount = int(response_dict['value'][0]['ResultCount'])
                    totalResultCount = max(sessionCount, totalResultCount)

                    # --- Duplicate detection ---
                    # The UAL API can produce duplicate results across pages, or restart
                    # sessions silently. We track unique AuditData IDs to detect both cases.
                    session_oldset = set([json.loads(result["AuditData"])["Id"] for result in session_results])
                    session_newset = set([json.loads(result["AuditData"])["Id"] for result in response_dict['value']])
                    session_set = session_oldset.union(session_newset)
                    old_duplicates = abs(len(session_results) - len(session_oldset))
                    new_duplicates = abs(sessionCount - len(session_newset))
                    total_duplicates = abs(len(session_results) + sessionCount - len(session_set))
                    duplicate_difference = abs(new_duplicates - old_duplicates)
                    # Detect session restart: if ALL new results are duplicates of old ones
                    # (or vice versa), the server has restarted the session. Discard old results
                    # and continue with the fresh session to avoid double-counting.
                    if total_duplicates - old_duplicates == sessionCount \
                       or total_duplicates - new_duplicates == len(session_results):
                        session_results = []
                        session_set = session_newset

                    if len(session_set) != len(session_results) + sessionCount:
                        self.logger.debug(f"Duplicates found. Found {len(session_set)} unique results. Expected {len(session_results)}.")


                    # --- Result validation and cache ---
                    # The UAL API occasionally returns results from the wrong time range
                    # (cross-query interference). Validate that results fall within [start, end]
                    # and that the count matches expectations. If not, cache the results and
                    # check if a previously cached batch is the correct one for this range.
                    response_start, response_end = self.get_start_end_results(response_dict['value'])
                    response_len = len(response_dict['value'])
                    self.logger.debug(f"{response_len} records returned from response")
                    concat_len = len(session_results) + response_len
                    if (concat_len == sessionCount \
                       or (response_len == resultSize and concat_len <= sessionCount)) \
                       and (response_start >= start and response_end <= end):
                        # return results are correct
                        session_results += response_dict['value']
                        # Special case where the session is ignored with existing results are excluded
                        if (response_len == sessionCount):
                            session_results = response_dict['value']
                    else:
                        self.logger.debug("Results returned are wrong. Adding to cache and checking for existing entries in cache")
                        self.logger.debug(f"response start {response_start}, response end {response_end}")
                        self.ual_results_cache.append({"start": response_start,
                                               "end": response_end,
                                               "results": response_dict['value']})
                        entry_found = False
                        for idx, cache_entry in enumerate(self.ual_results_cache):
                            response_len = len(cache_entry["results"])
                            concat_len = len(session_results) + response_len
                            if (concat_len == sessionCount \
                               or (response_len == resultSize and concat_len <= sessionCount)) \
                               and cache_entry["start"] >= start and cache_entry["end"] <= end:
                                self.logger.debug("Cache entry found")
                                session_results += cache_entry['results']
                                self.ual_results_cache.pop(idx)
                                break
                        if not entry_found:
                            self.logger.debug("No Cache entry found. Attempting again")
                            break

                    self._insert_ual_record({"start": start,
                                       "end": end,
                                       "count": sessionCount,
                                       "done_status": False}, boundsfile=boundsfile)

                    # Binary split: if too many logs in this time slice, halve the range.
                    # The 2-second minimum prevents infinite splitting on dense log bursts.
                    if sessionCount > self.threshold and end - start >= timedelta(seconds=2):
                        self.logger.debug(f"{sessionCount} results found within bounds. Exceeds result limit {self.threshold}")
                        # half the difference between the start and end time
                        new_end_ts = start.timestamp() + ((end.timestamp() - start.timestamp())/2)
                        end = datetime.fromtimestamp(new_end_ts).replace(microsecond=0)

                        break


                    self.logger.debug(f"{len(session_results)}/{sessionCount} records found in session {sessionId}")
                    self.logger.debug(f"Total results {response_count+len(session_results)}/{totalResultCount}")
                    if len(session_results) >= sessionCount:
                        # break out of session loop if all logs collected
                        break
                    elif not isolated:
                        # Spin off an isolated sub-task to finish paginating this time slice,
                        # while the main task continues exploring the next time range.
                        # Throttle concurrent tasks to max_ual_tasks to avoid API overload.
                        while len(self.ual_tasks) >= self.max_ual_tasks:
                            self.logger.debug("Waiting for ual dumpers to complete before starting more")
                            finished, ual_tasks_l = await asyncio.wait(self.ual_tasks, return_when=asyncio.FIRST_COMPLETED)
                            self.ual_tasks = list(ual_tasks_l)
                        self.ual_tasks.append(asyncio.create_task(self._new_ual_timeframe(start, end, statefile=statefile, isolated=True, session_results=session_results, sessionId=sessionId, boundsfile=boundsfile), name=f"{caller}_dumper_{start.isoformat()}_{end.isoformat()}"))
                        new_task_created = True
                        response_count += sessionCount
                        break
                elif status_code == 500:
                    self.logger.debug(f'\t[-] Services aren\'t available right now, sleeping for 30 seconds before retrying...')
                    self.logger.debug(str(response))
                    await asyncio.sleep(30)
                    tries += 1
                    break
                else:
                    try:
                        self.logger.debug(json.dumps(response, indent=2, sort_keys=True))
                    except:
                        self.logger.debug(response)
                    tries += 1
                    break

            # Check to see if the search was successful and the total results captured matches the ResultCount
            # from the session
            if status_code == 200 and len(session_results) == sessionCount:
                response_count += len(session_results)
                # save output for current session
                if len(session_results) > 0:
                    session_filename = f"ual_{startDate}_{endDate}.json".replace(":", "_")
                    session_filepath = os.path.join(self.output_dir, session_filename)
                    ual_session_output_str = ""
                    for ual_log in session_results:
                        audit_data_dict = json.loads(ual_log["AuditData"])
                        ual_session_output_str += json.dumps(audit_data_dict) + "\n"
                    open(session_filepath, "w").write(ual_session_output_str)

                # Save the latest date pulled to help with restart
                save_state(statefile, end, start=start, is_datetime=False, time_range=True)
                self._insert_ual_record({"start": start,
                                   "end": end,
                                   "count": sessionCount,
                                   "done_status": True}, boundsfile=boundsfile)
                data_saved = True

                self.total_ual_logs_saved += len(session_results)
                elapsed_time = time.perf_counter() - self.ual_seconds
                rate = int(self.total_ual_logs_saved / elapsed_time * 60 * 60)
                self.logger.info(f"Saved {len(session_results)} logs. Current rate is {rate} logs/hours")
                if ual_progress and ual_progress.get("bar"):
                    ual_progress["bar"].set_postfix_str(f"{self.total_ual_logs_saved} logs | {rate} logs/hr")

            if new_task_created or data_saved:
                start = end
                _update_ual_progress(start)
                end = finalEnd
                #self.logger.debug(f"start/end before bounds {start}/{end}")
                end,_ = self.find_bounds_end_size(start, end)
                #self.logger.debug(f"start/end after bounds {start}/{end}")

        if not isolated:
            await asyncio.gather(*self.ual_tasks)
        _complete_ual_progress()

    async def dump_ual(self):
        """Collect the Unified Audit Log (UAL) via Search-UnifiedAuditLog.

        The UAL is the primary audit log for M365. This method:
        1. Determines the time range to search (default: last 364 days, or from .conf filters).
        2. Loads save state to find already-completed time ranges and skip them.
        3. Handles an optional "extra" time range (ual_extra_start/end) for additional coverage.
        4. Merges completed ranges with the target range to find gaps that still need collection.
        5. Spawns _new_ual_timeframe tasks for each gap, which handle the actual API queries.

        Reference: https://learn.microsoft.com/en-us/powershell/module/exchange/search-unifiedauditlog
        """
        statefile = f'{self.output_dir}{os.path.sep}.ual_state'
        boundsfile = f'{self.output_dir}{os.path.sep}.ual_bounds'

        # Log active UAL filters
        active_filters = {}
        if self.ual_record_type: active_filters['RecordType'] = self.ual_record_type
        if self.ual_operations: active_filters['Operations'] = self.ual_operations
        if self.ual_user_ids: active_filters['UserIds'] = self.ual_user_ids
        if self.ual_free_text: active_filters['FreeText'] = self.ual_free_text
        if self.ual_ip_addresses: active_filters['IPAddresses'] = self.ual_ip_addresses
        if self.ual_object_ids: active_filters['ObjectIds'] = self.ual_object_ids
        if active_filters:
            self.logger.info(f"UAL filters active: {active_filters}")

        # Default: collect the last 364 days (UAL max retention is typically 1 year)
        end = get_end_time_yesterday()
        start = end - timedelta(days=364)

        if self.date_range:
            self.logger.debug(f'UAL Dump using specified date range: {self.date_start} to {self.date_end}')
            start = datetime.strptime(self.date_start,"%Y-%m-%d")
            end = datetime.strptime(self.date_end,"%Y-%m-%d")

        # Restore bounds state from previous run (tracks sub-range search progress)
        bounds_save_state = load_state(boundsfile, is_datetime=False, time_bounds=True)
        if bounds_save_state != None:
            self.ual_bounds_state = bounds_save_state

        # Load completed time ranges to find gaps that still need collection
        finished_time_ranges = load_state(statefile, is_datetime=False, time_range=True)

        search_time_ranges = []

        # Handle optional extra time range (ual_extra_start/end in .conf).
        # If it overlaps the main range, merge them to avoid duplicate queries.
        if self.ual_extra_start:
            extra_start = datetime.strptime(self.ual_extra_start,"%Y-%m-%d")
            extra_end = get_end_time_yesterday()
            if self.ual_extra_end:
                extra_end = datetime.strptime(self.ual_extra_end,"%Y-%m-%d")

            # Check if overlap in the extra time frame
            if start <= extra_start and extra_start <= end or \
               extra_start <= start and start <= extra_end:
                # overlap at the beginning
                if extra_start <= start:
                    swap = extra_end
                    extra_end = start
                    end = max(swap, end)
                # overlap at the end
                if start <= extra_start:
                    swap = end
                    end = extra_start
                    extra_end = max(swap, extra_end)
            search_time_ranges += find_time_gaps(finished_time_ranges, extra_start, extra_end)

        search_time_ranges += find_time_gaps(finished_time_ranges, start, end)

        self.logger.debug(search_time_ranges)

        self.total_ual_logs_saved = 0
        self.ual_seconds = time.perf_counter()

        # Calculate total hours across all time ranges for the progress bar
        range_hours_list = []
        for record in search_time_ranges:
            range_secs = max(int((record["end"] - record["start"]).total_seconds()), 1)
            range_hours_list.append(max(range_secs // 3600, 1))
        total_hours = sum(range_hours_list)

        # Create time-based progress bar
        pm = get_progress_manager()
        bar = None
        bar_name = "m365_ual"
        if pm:
            bar = pm.create_time_bar(bar_name, total_hours, desc=f"{'Collecting UAL':<35}", unit='hr')
            if bar:
                bar.bar_format = "{desc} |{bar}| {percentage:3.0f}% | {n_fmt}/{total_fmt} hrs | elapsed {elapsed} | {postfix}"
        ual_progress = {"bar": bar, "pm": pm, "bar_name": bar_name, "hours_done": 0, "total_hours": total_hours}

        # set the start time according to the save state
        tasks = []
        for i, record in enumerate(search_time_ranges):
            start, end = record["start"], record["end"]
            start = start.replace(microsecond=0)
            end = end.replace(microsecond=0)
            self.logger.info(f"Goosey collecting ual logs from : {start} -> {end}")
            caller_name = asyncio.current_task().get_name()
            tasks.append(asyncio.create_task(self._new_ual_timeframe(start, end, statefile=statefile, boundsfile=boundsfile, caller=caller_name, ual_progress=ual_progress, range_total_hours=range_hours_list[i]),name=f"{caller_name}_bounding_{start.isoformat()}_{end.isoformat()}"))

        try:
            await asyncio.gather(*tasks)
        finally:
            # Mark the bar complete
            if bar:
                remaining = total_hours - ual_progress["hours_done"]
                if remaining > 0:
                    bar.update(remaining)
            if pm:
                pm.complete_task(bar_name)
        elapsed = time.perf_counter() - self.ual_seconds
        self.logger.info("Goosey executed in {0:0.2f} seconds.".format(elapsed))

    dump_ual._manages_own_progress = True


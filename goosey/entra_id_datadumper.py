#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Untitled Goose Tool: entra_id_datadumper!
This module collects Entra ID (formerly Azure AD) telemetry via the Microsoft Graph API (beta).

Data collected includes:
- Sign-in logs (interactive/ADFS, non-interactive, service principal, managed identity)
- Audit logs (directory changes)
- Provisioning logs
- Configuration objects (apps, groups, users, roles, policies, devices, etc.)
- PIM (Privileged Identity Management) assignment and eligibility schedules/instances/requests
- Risk detections and risky objects (requires Entra ID P1/P2 licenses)
- Security alerts and secure scores

Most methods use helper_single_object for simple endpoints, with save state support
for sign-in and audit log collection to enable resumable incremental pulls.

@decision DEC-PIM-V3-001
@title Migrate PIM endpoints from deprecated v2 Schedules to v3 Instances+Requests
@status accepted
@rationale Microsoft deprecated roleAssignmentSchedules and roleEligibilitySchedules
  (Graph API beta) with removal targeted for October 2026. The v3 replacement splits
  each concept into two complementary endpoints:
    - *ScheduleInstances: current active state (who has access right now)
    - *ScheduleRequests:  full audit trail of PIM activations and assignments
  roleEligibilityScheduleInstances was already v3-compatible and is kept as-is.
  roleAssignmentScheduleInstances (new) replaces roleAssignmentSchedules.
  roleAssignmentScheduleRequests (new) provides the assignment audit trail.
  roleEligibilityScheduleRequests (new) provides the eligibility request audit trail.
  This migration ensures continued data collection after the deprecation deadline
  and improves forensic coverage by capturing the full PIM request lifecycle.
"""

import asyncio
import json
import os

from datetime import datetime, timedelta
from goosey.datadumper import DataDumper
from goosey.progress import get_progress_manager
from goosey.utils import *
from goosey.utils import (IdDedupe, PaginationIncomplete, collect_time_chunk, floor_to_day, get_incremental_lookback,
                          get_nextlink, iter_day_chunks,
                          resolve_date_bounds, resume_point, to_graph_ts)

class EntraIdDataDumper(DataDumper):
    """Collects Entra ID / Azure AD data via the Microsoft Graph API beta endpoint."""

    def __init__(self, output_dir, reports_dir, app_auth, session, config, debug, token_manager=None, force_repull=False,
                 now=None):
        super().__init__(f'{output_dir}{os.path.sep}entraid', reports_dir, app_auth, session, debug, token_manager=token_manager, endpoint_key="graph_api", force_repull=force_repull)
        self.logger = setup_logger(__name__, debug)
        self.gcc = config_get(config, 'config', 'gcc', self.logger).lower() == "true"
        self.gcc_high = config_get(config, 'config', 'gcc_high', self.logger).lower() == "true"
        endpoints = get_endpoints(gcc=self.gcc, gcc_high=self.gcc_high)
        self.graph_url = endpoints["graph_api"]
        self.failurefile = os.path.join(reports_dir, '_no_results.json')
        # One UTC 'now' snapshot per dumper invocation (DEC-DATEBOUNDS-001); `now` is injectable for tests.
        self.date_bounds = resolve_date_bounds(config, self.logger, now=now)
        self.date_range, self.date_start, self.date_end = self.date_bounds.legacy_tuple()
        self.lookback = get_incremental_lookback(config, self.logger)
        self.logger.info(f'Incremental lookback on resume: {self.lookback.total_seconds() / 60:g} minutes')

        self.call_object = [self.get_url(), self.app_auth, self.logger, self.output_dir, self.get_session()]

    @staticmethod
    def _read_state(statefile):
        """Read a save-state file. Formats (both still accepted):
        'time\\n<ts>' and 'skiptoken\\n<nexturl>\\n<ts>'. Returns (nexturl|None, ts).
        <ts> is either a legacy full-day end (DayT23:59:59.999999Z -> resume next midnight)
        or an exact exclusive coverage boundary (resume with `ge <ts>`)."""
        with open(statefile, "r") as f:
            kind = f.readline().strip()
            nexturl = None
            if kind == "skiptoken":
                nexturl = f.readline().strip() or None
            ts = f.readline().strip()
        return nexturl, ts

    @staticmethod
    def _write_state(statefile, covered_through):
        """Atomically record the exact UTC instant up to which data is complete."""
        tmp = statefile + '.tmp'
        with open(tmp, 'w') as f:
            f.write("time\n")
            f.write(to_graph_ts(covered_through))
        os.replace(tmp, statefile)

    async def dump_signins_adfs(self):
        """
        Dump interactive (adfs) sign in logs
        """
        return await self._dump_signins('adfs')
    dump_signins_adfs._manages_own_progress = True

    async def dump_signins_rt(self):
        """
        Dump non-interactive (rt) sign in logs
        """
        return await self._dump_signins('rt')
    dump_signins_rt._manages_own_progress = True

    async def dump_signins_sp(self):
        """
        Dump service principal (sp) signin logs
        """
        return await self._dump_signins('sp')
    dump_signins_sp._manages_own_progress = True

    async def dump_signins_msi(self):
        """
        Dump managed identity (msi) sign in logs
        """
        return await self._dump_signins('msi')
    dump_signins_msi._manages_own_progress = True

    @requires_auth
    async def _dump_signins(self, source: str) -> None:
        """Dumps signin based off of signin source type.
        API Reference: https://docs.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-beta

        :param source: Sign-in source type
        :type source: str
        :return: None
        :rtype: None
        """
        signin_directory = os.path.join(self.output_dir, "signin_" + source)
        if not os.path.exists(signin_directory):
            os.mkdir(signin_directory)

        statefile = f'{self.output_dir}{os.path.sep}.{source}_signin_state'
        end_dt = self.date_bounds.end  # exclusive, aware UTC; never beyond this
        resume_url = None
        checkpoint_dt = None
        if os.path.isfile(statefile):
            self.logger.debug(f'Save state file exists at {statefile}')
            self.logger.info(f'{source} signin dump save state file found. Continuing from last checkpoint.')
            resume_url, saved_ts = self._read_state(statefile)
            checkpoint_dt = resume_point(saved_ts)
            lower = self.date_bounds.start if self.date_range else floor_to_day(end_dt - timedelta(days=29))
            start_dt = max(checkpoint_dt - self.lookback, lower)
            if resume_url:
                outfile = os.path.join(signin_directory, source + '_signin_log_' + str(checkpoint_dt.date()) + '.json')
                try:
                    await get_nextlink(resume_url, outfile, self.ahsession, self.logger, self.app_auth)
                except PaginationIncomplete as e:
                    # A saved nextLink is stale; the checkpoint re-query below covers the same rows.
                    self.logger.warning(f'Saved nextLink could not be followed ({e}); re-querying from the checkpoint.')

        elif self.date_range:
            self.logger.debug(f'Specified date range found. Pulling signin logs for source {source} '
                              f'between {to_graph_ts(self.date_bounds.start)} and {to_graph_ts(end_dt)}')
            start_dt = self.date_bounds.start

        else:
            self.logger.debug(f'Save state file does not exist at {statefile}.')
            start_dt = floor_to_day(end_dt - timedelta(days=29))
            self.logger.info('Getting signin logs for source %s...' % (source))

        # Calculate total days for progress bar
        total_days = (end_dt - start_dt).days
        pm = get_progress_manager()
        pbar = None
        if pm and total_days > 0:
            task_name = f"entraid_signins_{source}"
            pbar = pm.create_time_bar(task_name, total_days, desc=f"{'entraid_signins_' + source:<35}")

        failure = None
        for chunk_start, chunk_end, covered_through, _full in iter_day_chunks(start_dt, end_dt):
            self.ensure_token()
            start = to_graph_ts(chunk_start)
            end_time = to_graph_ts(chunk_end)
            outfile = os.path.join(signin_directory, source + '_signin_log_' + str(chunk_start.date()) + '.json')
            # Overlap re-fetch (before the checkpoint): skip ids already in this day's file
            dedupe = IdDedupe(outfile if checkpoint_dt and chunk_start < checkpoint_dt else None)
            try:
                # Pages the whole window; resumes from the last timestamp written if paging breaks
                # (e.g. 410 Gone on an expired nextLink) -- see DEC-PAGINATION-001.
                await collect_time_chunk(
                    self.ahsession, self.logger, self.app_auth, self.graph_url + "/beta/auditLogs/signIns",
                    outfile, 'createdDateTime', start, end_time, dedupe,
                    extra_params={'source': source}, refresh_token=self.ensure_token,
                    label=f'Signin source {source}')
            except PaginationIncomplete as e:
                failure = e
            if os.path.isfile(outfile) and os.stat(outfile).st_size == 0:
                os.remove(outfile)
            if failure:
                # Never skip a failed chunk: a later checkpoint would claim coverage over the gap.
                self.logger.error(f'Signin source {source}: failed to collect {start} to {end_time}: {failure}; '
                                  'stopping so the checkpoint stays before the gap.')
                break
            # Never move the checkpoint backwards while re-reading the overlap
            if checkpoint_dt is None or covered_through > checkpoint_dt:
                self._write_state(statefile, covered_through)
            if pbar:
                pbar.update(1)

        if failure:
            raise failure  # func_wrapper reports this task as FAILED (not "Success")
        self.logger.info('Finished dumping signin logs for source: {}'.format(source))

    @requires_auth
    async def dump_entraid_audit(self) -> None:
        """Dumps Entra ID Audit logs
        API Reference: https://docs.microsoft.com/en-us/graph/api/resources/directoryaudit?view=graph-rest-beta

        :return: None
        :rtype: None
        """
        sub_dir = os.path.join(self.output_dir, 'entraid_audit_logs')
        check_output_dir(sub_dir, self.logger)

        url = self.graph_url + "/beta/auditLogs/directoryAudits"

        end_dt = self.date_bounds.end  # exclusive, aware UTC; never beyond this
        start_default_dt = floor_to_day(end_dt - timedelta(days=29))
        statefile = f'{self.output_dir}{os.path.sep}.audit_log_state'
        checkpoint_dt = None
        if os.path.isfile(statefile):
            self.logger.debug(f'Save state file exists at {statefile}')
            self.logger.info(f'Audit log dump save state file found. Continuing from last checkpoint.')
            resume_url, saved_ts = self._read_state(statefile)
            checkpoint_dt = resume_point(saved_ts)
            lower = self.date_bounds.start if self.date_range else start_default_dt
            start_dt = max(checkpoint_dt - self.lookback, lower)
            if resume_url:
                outfile = os.path.join(sub_dir, 'entraidauditlog_' + str(checkpoint_dt.date()) + '.json')
                try:
                    await get_nextlink(resume_url, outfile, self.ahsession, self.logger, self.app_auth)
                except PaginationIncomplete as e:
                    # A saved nextLink is stale; the checkpoint re-query below covers the same rows.
                    self.logger.warning(f'Saved nextLink could not be followed ({e}); re-querying from the checkpoint.')

        elif self.date_range:
            start_dt = self.date_bounds.start
            self.logger.debug(
                'Specified date range found. Pulling audit logs between '
                f'{to_graph_ts(start_dt)} and {to_graph_ts(end_dt)}')

        else:
            self.logger.debug(f'Save state file does not exist at {statefile}.')
            start_dt = start_default_dt

        if start_dt < start_default_dt:
            self.logger.debug('Specified start time longer than audit log retention period. Using default of 30 days')
            start_dt = start_default_dt

        self.logger.info('Getting Entra ID audit logs...')
        total_days = (end_dt - start_dt).days
        pm = get_progress_manager()
        pbar = None
        if pm and total_days > 0:
            pbar = pm.create_time_bar("entraid_audit", total_days, desc=f"{'entraid_audit':<35}")

        failure = None
        for chunk_start, chunk_end, covered_through, _full in iter_day_chunks(start_dt, end_dt):
            self.ensure_token()
            start = to_graph_ts(chunk_start)
            end_time = to_graph_ts(chunk_end)
            outfile = os.path.join(sub_dir, 'entraidauditlog_' + str(chunk_start.date()) + '.json')
            # Overlap re-fetch (before the checkpoint): skip ids already in this day's file
            dedupe = IdDedupe(outfile if checkpoint_dt and chunk_start < checkpoint_dt else None)

            self.logger.debug(f'Dumping Entra ID audit logs for time frame {start} to {end_time}')
            try:
                # Appends (never truncates) and resumes from the last timestamp on broken paging.
                await collect_time_chunk(
                    self.ahsession, self.logger, self.app_auth, url, outfile, 'activityDateTime',
                    start, end_time, dedupe, refresh_token=self.ensure_token, label='Entra audit')
            except PaginationIncomplete as e:
                failure = e
            if failure:
                self.logger.error(f'Entra audit: failed to collect {start} to {end_time}: {failure}; '
                                  'stopping so the checkpoint stays before the gap.')
                break
            # Checkpoint only what was actually covered (clipped to `now` for the final chunk).
            if checkpoint_dt is None or covered_through > checkpoint_dt:
                self._write_state(statefile, covered_through)
            if pbar:
                pbar.update(1)

        if failure:
            raise failure  # func_wrapper reports this task as FAILED (not "Success")
        self.logger.info('Finished dumping Entra ID audit logs.')
    dump_entraid_audit._manages_own_progress = True

    @requires_auth
    async def dump_entraid_provisioning(self) -> None:
        """Dumps Entra ID provisioning logs
        API Reference: https://docs.microsoft.com/en-us/graph/api/resources/provisioningobjectsummary?view=graph-rest-beta

        :return: None
        :rtype: None
        """
        if self.check_savestate("entraid_provisioning"):
            return
        url = self.graph_url + "/beta/auditLogs/provisioning"

        self.logger.info('Getting Entra ID provisioning logs...')
        outfile = os.path.join(self.output_dir, 'entraidprovisioninglogs.json')

        header = {'Authorization': '%s %s' % (self.app_auth['token_type'], self.app_auth['access_token'])}
        async with self.ahsession.get(url, headers=header, timeout=600) as r:
            result = await r.json()
            if 'value' not in result:
                self.logger.debug("Error with result: {}".format(str(result)))
                return

            nexturl = None
            if '@odata.nextLink' in result:
                nexturl = result['@odata.nextLink']
            if 'value' in result:
                if result['value']:
                    with open(outfile, 'w', encoding='utf-8') as f:
                        f.write("\n".join([json.dumps(x) for x in result['value']]) + '\n')
                elif not result['value']:
                    self.logger.debug('%s has no information (size is 0). No output file.' % (outfile))
                    with open(self.failurefile, 'a+', encoding='utf-8') as f:
                        f.write('No output file: entraidprovisioninglogs - ' + str((datetime.now())) + '\n')
            if '@odata.nextLink' in result:
                nexturl = result['@odata.nextLink']
                await get_nextlink(nexturl, outfile, self.ahsession, self.logger, self.app_auth)

        self.logger.info('Finished dumping Entra ID provisioning logs.')
        self.write_savestate("entraid_provisioning")

    def get_url(self):
        return self.graph_url + "/beta/"

    async def helper_multiple_object(self, parent, child, output_dir, identifier='id', caller=""):
        """Fetch a parent collection, then for each parent item, fetch its child collection.

        For example: parent='users', child='appRoleAssignments' fetches all users, then
        for each user fetches their app role assignments. Results are enriched with the
        parent object data and written as JSONL.

        Handles pagination via @odata.nextLink for both parent and child collections.
        """
        url_parent = self.get_url()

        current_task = asyncio.current_task()
        if "Task" in current_task.get_name():
            task_name = f"{parent}_{child}"
            if caller:
                task_name = f"{caller}_{task_name}"
            current_task.set_name(task_name)

        if 'token_type' not in self.app_auth or 'access_token' not in self.app_auth:
            self.logger.error(f"Missing token_type and access_token from auth. Did you auth correctly? (Skipping {parent})")
            return

        parent_list = []
        parent_entry_dict = {}
        header = {'Authorization': '%s %s' % (self.app_auth['token_type'], self.app_auth['access_token'])}
        parent_url = url_parent + parent

        async with self.ahsession.get(parent_url, headers=header) as r:
            result = await r.json()
            if 'value' not in result:
                if result['error']['code'] == 'InvalidAuthenticationToken':
                    self.logger.error("Error with authentication token: " + result['error']['message'])
                    self.logger.error("Please re-auth.")
                    asyncio.get_event_loop().stop()
                else:
                    self.logger.debug("Error with result: {}".format(str(result)))
                    return
            nexturl = None
            for entry in result['value']:
                parent_list.append(entry[identifier])
                parent_entry_dict[entry[identifier]] = entry
            if '@odata.nextLink' in result:
                nexturl = result['@odata.nextLink']
            retries = 5
            while nexturl:
                try:
                    skiptoken = nexturl.split('skiptoken=')[1] if 'skiptoken=' in nexturl else 'unknown'
                    async with self.ahsession.get(nexturl, headers=header, timeout=600) as r2:
                        result2 = await r2.json()
                        self.logger.debug('Received nextLink %s: %s' % (parent, skiptoken))
                        for entry in result2['value']:
                            parent_list.append(entry[identifier])
                            parent_entry_dict[entry[identifier]] = entry

                        if '@odata.nextLink' in result2:
                            if result2['@odata.nextLink'] == nexturl:
                                self.logger.warning("@odata.nextLink received is same as current. Setting nextLink to None.")
                                nexturl = None
                            else:
                                nexturl = result2['@odata.nextLink']
                                retries = 5
                        else:
                            nexturl = None
                except Exception as e:
                    self.logger.error('Error on nextLink retrieval {}: {}'.format(skiptoken, str(e)))
                    if retries == 0:
                        self.logger.error('Error. No more retries on {}.'.format(skiptoken))
                        # Writing a partial parent list would silently drop children (DEC-PAGINATION-001).
                        raise PaginationIncomplete(f'{parent} listing incomplete: {e!r}', url=nexturl, cause=e) from e
                    else:
                        self.logger.info('Error. Retrying {} up to {} more times'.format(skiptoken, retries))
                        retries -= 1
                        await asyncio.sleep(5)

        self.logger.info('Dumping %s %s information...' % (parent, child))
        child_list = []
        incomplete = []  # parents whose child pages could not be fully read
        for parent_id in parent_list:
            url2 = url_parent + parent + "/" + parent_id + '/%s' % (child)
            if child == 'appRoleAssignedResources':
                header['ConsistencyLevel'] = 'eventual'
            try:
                async with self.ahsession.get(url2, headers=header, timeout=600) as r:
                    result = await r.json()
                    if 'value' not in result:
                        if child == 'federationConfiguration':
                            continue
                        if result['error']['code'] == 'InvalidAuthenticationToken':
                            self.logger.error("Error with authentication token: " + result['error']['message'])
                            self.logger.error("Please re-auth.")
                            asyncio.get_event_loop().stop()
                        else:
                            self.logger.debug("Error with result: {}".format(str(result)))
                            return

                    nexturl = None
                    for entry in result['value']:
                        if "@odata.type" in entry.keys():
                            entry.pop("@odata.type")
                        temp = {parent : parent_entry_dict[parent_id]}
                        entry.update(temp)
                        child_list.append(entry)

                    if '@odata.nextLink' in result:
                        nexturl = result['@odata.nextLink']
                    retries = 5
                    while nexturl:
                        try:
                            skiptoken = nexturl.split('skiptoken=')[1] if 'skiptoken=' in nexturl else 'unknown'
                            async with self.ahsession.get(nexturl, headers=header, timeout=600) as r2:
                                result2 = await r2.json()
                                self.logger.debug('Received nextLink %s: %s' % (parent, skiptoken))
                                for entry in result2['value']:
                                    if "@odata.type" in entry.keys():
                                        entry.pop("@odata.type")
                                    temp = {parent: parent_entry_dict[parent_id]}
                                    entry.update(temp)
                                    child_list.append(entry)

                                if '@odata.nextLink' in result2:
                                    if result2['@odata.nextLink'] == nexturl:
                                        self.logger.warning("@odata.nextLink received is same as current. Setting nextLink to None.")
                                        nexturl = None
                                    else:
                                        nexturl = result2['@odata.nextLink']
                                        retries = 5
                                else:
                                    nexturl = None
                        except Exception as e:
                            self.logger.error('Error on nextLink retrieval {}: {}'.format(skiptoken, str(e)))
                            if retries == 0:
                                self.logger.error('Error. No more retries on {}.'.format(skiptoken))
                                incomplete.append(f'{parent}/{parent_id}/{child}')
                                nexturl = None
                            else:
                                self.logger.info('Error. Retrying {} up to {} more times'.format(skiptoken, retries))
                                retries -= 1
                                await asyncio.sleep(5)
            except Exception as e:
                self.logger.error('Error fetching child %s for %s %s: %s' % (child, parent, parent_id, str(e)))
                continue

        if '/' in child:
            temp = child.split('/')
            child = temp[-1]

        if '/' in parent:
            parent = parent.replace("/", "")

        outfile = os.path.join(output_dir, parent + "_" + child + '.json')
        if child_list:
            with open(outfile, 'w', encoding='utf-8') as f:
                for entry in child_list:
                    f.write(json.dumps(entry, sort_keys=True) + '\n')
        elif not child_list:
            with open(self.failurefile, 'a+', encoding='utf-8') as f:
                f.write('No output file: ' + parent + "_" + child + ' - ' + str((datetime.now())) + '\n')

        if incomplete:
            # Partial data is kept on disk, but the task must not report Success (DEC-PAGINATION-001).
            raise PaginationIncomplete(f'{parent} {child}: child pagination incomplete for '
                                       f'{len(incomplete)} parent(s), e.g. {incomplete[0]}')
        self.logger.info('Finished dumping %s %s information.' % (parent, child))

    async def dump_configs(self) -> None:
        """
        Dumps Entra ID configuration files
        """
        if self.check_savestate("entraid_configs"):
            return
        sub_dir = os.path.join(self.output_dir, 'entraid_configs')
        check_output_dir(sub_dir, self.logger)

        conf_call_object = [self.get_url(), self.app_auth, self.logger, sub_dir, self.get_session()]
        caller_name = asyncio.current_task().get_name()

        await asyncio.gather(
            helper_single_object('applications', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('directory/deleteditems/microsoft.graph.application', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('identityGovernance/appConsent/appConsentRequests', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('conditionalAccess/authenticationContextClassReferences', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('conditionalAccess/namedLocations',conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('conditionalAccess/policies', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('devices', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('directoryRoles', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('roleManagement/directory/roleDefinitions', conf_call_object, self.failurefile, caller=caller_name),
            # PIM v3 endpoints (replaces deprecated roleAssignmentSchedules and
            # roleEligibilitySchedules — removed October 2026; see DEC-PIM-V3-001)
            helper_single_object('roleManagement/directory/roleAssignmentScheduleInstances', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('roleManagement/directory/roleAssignmentScheduleRequests', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('roleManagement/directory/roleEligibilityScheduleInstances', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('roleManagement/directory/roleEligibilityScheduleRequests', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('groups', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('directory/deleteditems/microsoft.graph.group', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('identity/identityProviders', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('identity/identityProviders/availableProviderTypes', conf_call_object, self.failurefile, caller=caller_name),
            # not working anymore. Requires APIConnectors.ReadWrite.All
            #helper_single_object('identity/apiConnectors', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('directorySettingTemplates', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('directory/federationConfigurations/graph.samlOrWsFedExternalDomainFederation', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('directory/administrativeUnits', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('domains', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('organization', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('subscribedSkus', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('identity/continuousAccessEvaluationPolicy', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('identity/events/onSignupStart', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('policies/activityBasedTimeoutPolicies', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('policies/defaultAppManagementPolicy', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('policies/tokenLifetimePolicies', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('policies/tokenIssuancePolicies', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('policies/authenticationFlowsPolicy', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('policies/authenticationMethodsPolicy', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('policies/authorizationPolicy', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('policies/claimsMappingPolicies', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('policies/homeRealmDiscoveryPolicies', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('policies/permissionGrantPolicies', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('policies/identitySecurityDefaultsEnforcementPolicy', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('policies/accessReviewPolicy', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('policies/adminConsentRequestPolicy', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('policies/crossTenantAccessPolicy', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('policies/crossTenantAccessPolicy/partners', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('servicePrincipals', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object("reports/getRelyingPartyDetailedSummary(period='D30')", conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object("reports/getAzureAdApplicationSignInSummary(period='D30')", conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('reports/applicationSignInDetailedSummary', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object("reports/getCredentialUsageSummary(period='D30')", conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object("reports/getCredentialUserRegistrationCount", conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object("reports/credentialUserRegistrationDetails", conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object("reports/userCredentialUsageDetails", conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object("reports/authenticationMethods/userRegistrationDetails", conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('users', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('contacts', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('oauth2PermissionGrants', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('directory/deletedItems/microsoft.graph.user', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('policies/featureRolloutPolicies', conf_call_object, self.failurefile, caller=caller_name),
            self.helper_multiple_object(parent='users', child='appRoleAssignments', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='users', child='appRoleAssignedResources', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='applications', child='extensionProperties', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='applications', child='owners', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='applications', child='tokenIssuancePolicies', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='applications', child='tokenLifetimePolicies', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='applications', child='federatedIdentityCredentials', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='users', child='registeredDevices', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='directoryRoles', child='members', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='groups', child='appRoleAssignments', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='users', child='authentication/methods', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='domains', child='federationConfiguration', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='servicePrincipals', child='appRoleAssignments', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='servicePrincipals', child='appRoleAssignedTo', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='servicePrincipals', child='owners', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='servicePrincipals', child='createdObjects', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='servicePrincipals', child='ownedObjects', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='servicePrincipals', child='oauth2PermissionGrants', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='servicePrincipals', child='memberOf', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='servicePrincipals', child='transitiveMemberOf', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='servicePrincipals', child='homeRealmDiscoveryPolicies', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='servicePrincipals', child='synchronization/jobs', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='servicePrincipals', child='claimsMappingPolicies', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='servicePrincipals', child='tokenLifetimePolicies', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='servicePrincipals', child='delegatedPermissionClassifications', output_dir=sub_dir, caller=caller_name)
        )
        self.write_savestate("entraid_configs")

    async def dump_risk_detections(self) -> None:
        """
        Dumps risk detections from identity protection. Requires a minimum of Microsoft Entra ID P1 license and Microsoft Entra Workload ID premium license for full results.
        """
        if self.check_savestate("risk_detections"):
            return
        sub_dir = os.path.join(self.output_dir, 'entraid_riskdetections')
        check_output_dir(sub_dir, self.logger)
        caller_name = asyncio.current_task().get_name()

        ri_call_object = [self.get_url(), self.app_auth, self.logger, sub_dir, self.get_session()]
        await asyncio.gather(
            helper_single_object('identityProtection/riskDetections', ri_call_object, self.failurefile, caller=caller_name),
            helper_single_object('identityProtection/servicePrincipalRiskDetections', ri_call_object, self.failurefile, caller=caller_name)
        )
        self.write_savestate("risk_detections")

    async def dump_risky_objects(self) -> None:
        """
        Dumps risky users and service principal information. Requires a minimum of Microsoft Entra ID P2 license and Microsoft Entra Workload ID premium license for full results.
        """
        if self.check_savestate("risky_objects"):
            return
        sub_dir = os.path.join(self.output_dir, 'entraid_riskyobjects')
        check_output_dir(sub_dir, self.logger)
        caller_name = asyncio.current_task().get_name()

        ri2_call_object = [self.get_url(), self.app_auth, self.logger, sub_dir, self.get_session()]
        await asyncio.gather(
            helper_single_object('identityProtection/riskyUsers', ri2_call_object, self.failurefile, caller=caller_name),
            helper_single_object('identityProtection/riskyServicePrincipals', ri2_call_object, self.failurefile, caller=caller_name),
            self.helper_multiple_object(parent='riskyUsers', child='history', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='identityProtection/riskyServicePrincipals', child='history', output_dir=sub_dir, caller=caller_name)
        )
        self.write_savestate("risky_objects")

    async def dump_security(self) -> None:
        """
        Dump security actions, alerts, and scores
        """
        if self.check_savestate("security"):
            return
        sub_dir = os.path.join(self.output_dir, 'entraid_security')
        check_output_dir(sub_dir, self.logger)
        caller_name = asyncio.current_task().get_name()

        sec_call_object = [self.get_url(), self.app_auth, self.logger, sub_dir, self.get_session()]
        await asyncio.gather(
            helper_single_object('security/securityActions', sec_call_object, self.failurefile, caller=caller_name),
            helper_single_object('security/alerts', sec_call_object, self.failurefile, caller=caller_name),
            helper_single_object('security/secureScores', sec_call_object, self.failurefile, caller=caller_name)
        )
        self.write_savestate("security")

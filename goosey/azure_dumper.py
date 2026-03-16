#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Untitled Goose Tool: azure_datadumper!
This module collects Azure resource telemetry across subscriptions.

Uses two authentication mechanisms:
- Azure SDK (ClientSecretCredential): For Azure Resource Manager APIs (VMs, networking,
  storage, Security Center, etc.) via the azure-mgmt-* client libraries.
- aiohttp + Log Analytics API: For querying Log Analytics workspace tables via KQL.

Supports multi-subscription collection: if subscriptionid='all' in .conf, discovers
all accessible subscriptions and creates per-subscription output directories.

Key data sources:
- Compute: VMs, disks
- Networking: NICs, NSGs, public IPs, load balancers, virtual networks
- Storage: accounts, containers, blob enumeration
- Security: Security Center alerts, settings, auto-provisioning, contacts
- Monitoring: activity logs, diagnostic settings
- Web: App Services
- Log Analytics: KQL queries against workspace tables
"""

import asyncio
import getpass
import json
import os
import pytz
import sys
from pathvalidate import sanitize_filename

from azure.core.exceptions import *
from azure.identity import AzureAuthorityHosts
from azure.identity import ClientSecretCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import SubscriptionClient, ResourceManagementClient
from azure.mgmt.security import SecurityCenter
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.web import WebSiteManagementClient
from azure.storage.blob import BlobServiceClient
from goosey.datadumper import DataDumper
from goosey.progress import get_progress_manager
from goosey.utils import *
from typing import Optional

utc = pytz.UTC

class AzureDataDumper(DataDumper):
    """Collects Azure subscription resources and Log Analytics workspace data.

    Unlike other dumpers that primarily use aiohttp, this dumper also uses Azure SDK
    management clients (ComputeManagementClient, NetworkManagementClient, etc.) which
    authenticate via ClientSecretCredential.
    """

    def __init__(self, output_dir, reports_dir, session, app_auth, config, auth_un_pw, loganalytics_app_auth, debug, token_manager=None, force_repull=False):
        super().__init__(f'{output_dir}{os.path.sep}azure', reports_dir, app_auth, session, debug, token_manager=token_manager, endpoint_key="resource_manager", force_repull=force_repull)
        self.logger = setup_logger(__name__, debug)
        self.failurefile = os.path.join(reports_dir, '_no_results.json')
        self.loganalytics_app_auth = loganalytics_app_auth
        if auth_un_pw is not None:
            if auth_un_pw['auth']['appid']:
                self.app_id = auth_un_pw['auth']['appid']
            else:
                self.app_id = input("Please type your application client id: ")
            if auth_un_pw['auth']['clientsecret']:
                self.client_secret = auth_un_pw['auth']['clientsecret']
            else:
                self.client_secret = getpass.getpass("Please type your client secret: ")
        else:
             self.app_id = input("Please type your application client id: ")
             self.client_secret = getpass.getpass("Please type your client secret: ")
        self.tenant = config['config']['tenant']
        self.gcc_high = config['config']['gcc_high']
        gcc = config['config']['gcc'].lower() == "true"
        gcc_high = config['config']['gcc_high'].lower() == "true"
        self.endpoints = get_endpoints(gcc=gcc,gcc_high=gcc_high)
        if self.gcc_high.lower() == "true":
            self.authority = AzureAuthorityHosts.AZURE_GOVERNMENT
        else:
            self.authority = AzureAuthorityHosts.AZURE_PUBLIC_CLOUD

        os.environ.setdefault('AZURE_CLIENT_ID', self.app_id)
        os.environ.setdefault('AZURE_TENANT_ID', self.tenant)
        os.environ.setdefault('AZURE_CLIENT_SECRET', self.client_secret)

        self.logger.debug(f"Authority set to: {str(self.authority)}")

        self.credential = ClientSecretCredential(tenant_id=self.tenant, client_id=self.app_id, client_secret=self.client_secret, authority=self.authority, logging_enable=True)

        if config['config']['subscriptionid'].lower() == "all":
            if self.gcc_high.lower() == "true":
                self.subscription_client = SubscriptionClient(self.credential, base_url='https://management.usgovcloudapi.net', credential_scopes=['https://management.usgovcloudapi.net/.default'])
            else:
                self.subscription_client = SubscriptionClient(self.credential)
            subscription_list = self.subscription_client.subscriptions.list()
            self.subscription_id_list = []
            try:
                for sub in subscription_list:
                    sub_directory = os.path.join(self.output_dir, sub.subscription_id)
                    if not os.path.exists(sub_directory):
                        os.makedirs(sub_directory)

                    self.subscription_id_list.append(sub.subscription_id)
            except Exception as e:
                self.logger.error(f"Error getting subscriptions: {str(e)}\nDo you have the right subscription ids in your .conf file?")
                if len(self.subscription_id_list) == 0:
                    self.logger.error(f"Subscription list is empty, you won't get any data back for Azure data calls.")
        else:
            self.subscription_id_list = config['config']['subscriptionid'].split(",")

        self.network_managers, self.compute_clients, self.web_clients, self.storage_clients, \
            self.resource_clients, self.monitor_clients, self.security_clients = [], [], [], [], [], [], []

        for sub_id in self.subscription_id_list:
            sub_id = sub_id.strip()

            if self.gcc_high.lower() == "true":
                location = USGOV_LOCATION
                self.network_managers.append(NetworkManagementClient(credential=self.credential, subscription_id=sub_id, base_url='https://management.usgovcloudapi.net', credential_scopes=['https://management.usgovcloudapi.net/.default']))
                self.compute_clients.append(ComputeManagementClient(credential=self.credential, subscription_id=sub_id, base_url='https://management.usgovcloudapi.net', credential_scopes=['https://management.usgovcloudapi.net/.default']))
                self.web_clients.append(WebSiteManagementClient(credential=self.credential, subscription_id=sub_id, base_url='https://management.usgovcloudapi.net', credential_scopes=['https://management.usgovcloudapi.net/.default']))
                self.storage_clients.append(StorageManagementClient(credential=self.credential, subscription_id=sub_id, base_url='https://management.usgovcloudapi.net', credential_scopes=['https://management.usgovcloudapi.net/.default']))
                self.resource_clients.append(ResourceManagementClient(credential=self.credential, subscription_id=sub_id, base_url='https://management.usgovcloudapi.net', credential_scopes=['https://management.usgovcloudapi.net/.default']))
                self.monitor_clients.append(MonitorManagementClient(credential=self.credential, subscription_id=sub_id, base_url='https://management.usgovcloudapi.net', credential_scopes=['https://management.usgovcloudapi.net/.default']))
                locationclient = SecurityCenter(credential=self.credential, subscription_id=sub_id, base_url='https://management.usgovcloudapi.net', credential_scopes=['https://management.usgovcloudapi.net/.default'], asc_location=location)
                self.asclocation = locationclient.locations.list().next().as_dict()
                self.security_clients.append(SecurityCenter(credential=self.credential, subscription_id=sub_id, base_url='https://management.usgovcloudapi.net', credential_scopes=['https://management.usgovcloudapi.net/.default'], asc_location=self.asclocation))
            else:
                location = 'centralus'
                self.network_managers.append(NetworkManagementClient(credential=self.credential, subscription_id=sub_id))
                self.compute_clients.append(ComputeManagementClient(credential=self.credential, subscription_id=sub_id))
                self.web_clients.append(WebSiteManagementClient(credential=self.credential, subscription_id=sub_id))
                self.storage_clients.append(StorageManagementClient(credential=self.credential, subscription_id=sub_id))
                self.resource_clients.append(ResourceManagementClient(credential=self.credential, subscription_id=sub_id))
                self.monitor_clients.append(MonitorManagementClient(credential=self.credential, subscription_id=sub_id))
                locationclient = SecurityCenter(credential=self.credential, subscription_id=sub_id, asc_location=location)
                self.asclocation = locationclient.locations.list().next().as_dict()
                self.security_clients.append(SecurityCenter(credential=self.credential, subscription_id=sub_id, asc_location=self.asclocation))

        self.date_range, self.date_start, self.date_end = get_date_range(config, self.logger)

    def _get_mgmt_url(self, path):
        """Return the management API URL based on gov/commercial cloud."""
        if self.gcc_high.lower() == "true":
            return "https://management.azure.us" + path
        return "https://management.azure.com" + path

    def _make_auth_header(self):
        """Return standard auth header dict."""
        return {
            'Authorization': '%s %s' % (self.app_auth['token_type'], self.app_auth['access_token']),
            'Content-type': 'application/json'
        }

    async def dump_d4iot_portal_pcap(self) -> None:
        """
        Dump D4IOT portal pcaps from alerts
        """
        if self.check_savestate("d4iot_portal_pcap"):
            return
        header = self._make_auth_header()

        for subscriptionId in self.subscription_id_list:
            self.logger.info("Getting D4IOT portal pcaps from " + subscriptionId + "...")
            pcap_dir = os.path.join(self.output_dir, subscriptionId, 'd4iot_portal', 'pcaps')
            check_output_dir(pcap_dir, self.logger)

            devgrps_outfile = os.path.join(self.output_dir, subscriptionId, 'd4iot_portal', "portal_device_groups.json")

            locations = []
            loc_url = self._get_mgmt_url("/subscriptions/" + subscriptionId + "/providers/Microsoft.IoTSecurity/locations?api-version=2021-09-01-preview")

            async with self.ahsession.request('GET', loc_url, headers=header, ssl=False) as r:
                result = await r.json()
                if not result:
                    self.logger.debug("Error with result. Please check your auth: {}".format(str(result)))
                    return
                if 'value' in result:
                    for entry in result['value']:
                        locations.append(entry['name'])
                elif 'error' in result:
                    if result['error']['code'] == 'ExpiredAuthenticationToken':
                        self.logger.error("Error with authentication token: " + result['error']['message'])
                        self.logger.error("Please re-auth.")
                        return

            for location in locations:
                device_grps = []
                devgrp_url = self._get_mgmt_url("/subscriptions/" + subscriptionId + "/providers/Microsoft.IoTSecurity/locations/" + location + "/deviceGroups?api-version=2021-02-01-preview")

                async with self.ahsession.request('GET', devgrp_url, headers=header, ssl=False) as r:
                    result = await r.json()
                    if 'value' in result:
                        for entry in result['value']:
                            device_grps.append(entry['name'])
                        with open(devgrps_outfile, 'a+', encoding='utf-8') as f:
                                for x in result['value']:
                                    f.write(json.dumps(x) + "\n")
                    elif 'error' in result:
                        if result['error']['code'] == 'ExpiredAuthenticationToken':
                            self.logger.error("Error with authentication token: " + result['error']['message'])
                            self.logger.error("Please re-auth.")
                            return

                alert_ids = []
                for val in device_grps:
                    url = self._get_mgmt_url("/subscriptions/" + subscriptionId + "/providers/Microsoft.IoTSecurity/locations/" + location + "/deviceGroups/" + val + "/alerts?api-version=2021-07-01-preview")

                    async with self.ahsession.request('GET', url, headers=header, ssl=False) as r:
                        result = await r.json()
                        if 'value' in result:
                            for x in result['value']:
                                createdAt = dateutil.parser.parse(x["systemData"]["createdAt"]).replace(tzinfo=None)
                                # Check for date time range
                                if self.date_range:
                                    start = dateutil.parser.parse(self.date_start).replace(tzinfo=None)
                                    end = dateutil.parser.parse(self.date_end).replace(tzinfo=None)
                                    if start <= createdAt and createdAt <= end:
                                        alert_ids.append(x['id'])
                                else:
                                    alert_ids.append(x['id'])
                        elif 'error' in result:
                            if result['error']['code'] == 'ExpiredAuthenticationToken':
                                self.logger.error("Error with authentication token: " + result['error']['message'])
                                self.logger.error("Please re-auth.")
                                return

                for id in alert_ids:
                    availability_url = self._get_mgmt_url(id + "/pcapAvailability?api-version=2021-07-01-preview")
                    i = id.split("/")[-1]
                    outfile = os.path.join(pcap_dir, "pcap_" + str(i) + ".pcap")
                    async with self.ahsession.request('POST', availability_url, headers=header, ssl=False) as r:
                        result = await r.json()
                        if 'error' in result:
                            if result['error']['code'] == 'NotFound':
                                self.logger.debug("Resource not found. Exiting.")
                                return
                            elif result['error']['code'] == 'ExpiredAuthenticationToken':
                                self.logger.error("Error with authentication token: " + result['error']['message'])
                                self.logger.error("Please re-auth.")
                                return

                        if 'status' in result:
                            if result['status'] == 'Done':
                                self.logger.info("PCAP downloaded for alert id %s." % (i))
                                download_url = result['downloadUrl']
                                async with self.ahsession.request('GET', download_url,  ssl=False, allow_redirects=True) as r:
                                    output = await r.read()
                                    with open(outfile, 'wb') as f:
                                        f.write(output)

                            elif result['status'] == 'Available':
                                if 'error' in result:
                                    if result['error']['code'] == 'PCAP_NOT_FOUND':
                                        self.logger.debug("PCAP not found for alert id %s. Proceeding" % (i))
                                        continue
                                else:
                                    self.logger.debug("PCAP available for alert id %s." % (i))

                                request_url = self._get_mgmt_url(id + "/pcapRequest?api-version=2021-07-01-preview")

                                status = None

                                while status != "Done":
                                     async with self.ahsession.request('POST', request_url, headers=header, ssl=False) as r:
                                        result = await r.json()
                                        if 'error' in result:
                                            self.logger.error("Error: " + result['error']['message'])
                                        else:
                                            status = result['status']
                                        await asyncio.sleep(5)

                                download_url = result['downloadUrl']
                                async with self.ahsession.request('GET', download_url,  ssl=False, allow_redirects=True) as r:
                                    output = await r.read()
                                    with open(outfile, 'wb') as f:
                                        f.write(output)
                                    self.logger.info("PCAP downloaded for alert id %s." % (i))


                            elif result['status'] == "UnsupportedAlert":
                                 self.logger.debug("PCAP not available for alert id %s. Proceeding" % (i))
                            elif result['status'] == "DisconnectedSensor":
                                self.logger.error("Sensor is disconnected. Stopping PCAP pull.")
                                return
                            else:
                                self.logger.debug(result)
        self.write_savestate("d4iot_portal_pcap")

    async def _dump_portal_alerts(self) -> None:
        """
        Dump d4iot portal alerts
        """
        header = self._make_auth_header()

        for subscriptionId in self.subscription_id_list:

            self.logger.info("Getting D4IOT portal alerts from " + subscriptionId + "...")

            new_outfile = os.path.join(self.output_dir, subscriptionId, "d4iot_portal")
            check_output_dir(new_outfile, self.logger)

            devgrps_outfile = os.path.join(new_outfile, "portal_device_groups.json")
            outfile = os.path.join(new_outfile, "portal_alerts.json")

            if os.path.exists(devgrps_outfile) and os.path.exists(outfile):
                self.logger.debug("D4IOT portal alerts files exists.. Proceeding without pulling.")
            else:
                locations = []
                loc_url = self._get_mgmt_url("/subscriptions/" + subscriptionId + "/providers/Microsoft.IoTSecurity/locations?api-version=2021-09-01-preview")

                async with self.ahsession.request('GET', loc_url, headers=header, ssl=False) as r:
                    result = await r.json()
                    if 'value' in result:
                        for entry in result['value']:
                            locations.append(entry['name'])
                    elif 'error' in result:
                        if result['error']['code'] == 'ExpiredAuthenticationToken':
                            self.logger.error("Error with authentication token: " + result['error']['message'])
                            self.logger.error("Please re-auth.")
                            return

                for location in locations:
                    device_grps = []
                    devgrp_url = self._get_mgmt_url("/subscriptions/" + subscriptionId + "/providers/Microsoft.IoTSecurity/locations/" + location + "/deviceGroups?api-version=2021-02-01-preview")

                    async with self.ahsession.request('GET', devgrp_url, headers=header, ssl=False) as r:
                        result = await r.json()
                        if 'value' in result:
                            for entry in result['value']:
                                device_grps.append(entry['name'])
                            with open(devgrps_outfile, 'a+', encoding='utf-8') as f:
                                for x in result['value']:
                                    f.write(json.dumps(x) + "\n")
                                f.flush()
                                os.fsync(f)
                        elif 'error' in result:
                            if result['error']['code'] == 'ExpiredAuthenticationToken':
                                self.logger.error("Error with authentication token: " + result['error']['message'])
                                self.logger.error("Please re-auth.")
                                return

                    for val in device_grps:
                        url = self._get_mgmt_url("/subscriptions/" + subscriptionId + "/providers/Microsoft.IoTSecurity/locations/" + location + "/deviceGroups/" + val + "/alerts?api-version=2021-07-01-preview")

                        async with self.ahsession.request('GET', url, headers=header, ssl=False) as r:
                            result = await r.json()
                            nexturl = None
                            if '@odata.nextLink' in result:
                                nexturl = result['@odata.nextLink']
                            if 'value' in result:
                                with open(outfile, 'a+', encoding='utf-8') as f:
                                    for x in result['value']:
                                        f.write(json.dumps(x) + "\n")
                                    f.flush()
                                    os.fsync(f)
                            elif 'error' in result:
                                if result['error']['code'] == 'ExpiredAuthenticationToken':
                                    self.logger.error("Error with authentication token: " + result['error']['message'])
                                    self.logger.error("Please re-auth.")
                                    return
                            await get_nextlink(nexturl, outfile, self.ahsession, self.logger, self.app_auth)
                self.logger.info("Finished getting D4IOT portal alerts from " + subscriptionId + ".")

    async def _dump_portal_defendersettings(self) -> None:
        """
        Dump d4iot portal defender settings
        """
        header = self._make_auth_header()

        for subscriptionId in self.subscription_id_list:
            self.logger.info("Getting D4IOT portal defender settings from " + subscriptionId + "...")

            new_outfile = os.path.join(self.output_dir, subscriptionId, "d4iot_portal")
            check_output_dir(new_outfile, self.logger)

            outfile = os.path.join(new_outfile, "portal_defender_settings.json")
            if os.path.exists(outfile):
                self.logger.debug("D4IOT portal defender settings file exists.. Proceeding without pulling.")
            else:
                url = self._get_mgmt_url("/subscriptions/" + subscriptionId + "/providers/Microsoft.IoTSecurity/defenderSettings?api-version=2021-02-01-preview")

                async with self.ahsession.request('GET', url, headers=header, ssl=False) as r:
                    result = await r.json()
                    if 'value' in result:
                        with open(outfile, 'w', encoding='utf-8') as f:
                            for x in result['value']:
                                f.write(json.dumps(x) + "\n")
                            f.flush()
                            os.fsync(f)
                    elif 'error' in result:
                        if result['error']['code'] == 'ExpiredAuthenticationToken':
                            self.logger.error("Error with authentication token: " + result['error']['message'])
                            self.logger.error("Please re-auth.")
                            return

                self.logger.info("Finished getting D4IOT portal defender settings from " + subscriptionId + ".")

    async def _dump_portal_sensors(self) -> None:
        """
        Dump d4iot portal sensors
        """
        header = self._make_auth_header()

        for subscriptionId in self.subscription_id_list:
            self.logger.info("Getting D4IOT portal sensors from " + subscriptionId + "...")

            new_outfile = os.path.join(self.output_dir, subscriptionId, "d4iot_portal")
            check_output_dir(new_outfile, self.logger)

            sites_outfile = os.path.join(new_outfile, "portal_sites.json")
            outfile = os.path.join(new_outfile, "portal_sensors.json")
            onsite_outfile = os.path.join(new_outfile, "portal_onpremise_sensors.json")

            locations = []
            loc_url = self._get_mgmt_url("/subscriptions/" + subscriptionId + "/providers/Microsoft.IoTSecurity/locations?api-version=2021-09-01-preview")
            async with self.ahsession.request('GET', loc_url, headers=header, ssl=False) as r:
                result = await r.json()
                if 'value' in result:
                    for entry in result['value']:
                        locations.append(entry['name'])
                elif 'error' in result:
                    if result['error']['code'] == 'ExpiredAuthenticationToken':
                        self.logger.error("Error with authentication token: " + result['error']['message'])
                        self.logger.error("Please re-auth.")
                        return

            for location in locations:
                sites = []
                sites_url = self._get_mgmt_url("/subscriptions/" + subscriptionId + "/providers/Microsoft.IoTSecurity/locations/" + location + "/sites?api-version=2021-09-01-preview")

                async with self.ahsession.request('GET', sites_url, headers=header, ssl=False) as r:
                    result = await r.json()
                    if 'value' in result:
                        for entry in result['value']:
                            sites.append(entry['name'])
                        with open(sites_outfile, 'a+', encoding='utf-8') as f:
                            for x in result['value']:
                                f.write(json.dumps(x) + "\n")
                            f.flush()
                            os.fsync(f)
                    elif 'error' in result:
                        if result['error']['code'] == 'ExpiredAuthenticationToken':
                            self.logger.error("Error with authentication token: " + result['error']['message'])
                            self.logger.error("Please re-auth.")
                            return

                for val in sites:
                    url = self._get_mgmt_url("/subscriptions/" + subscriptionId + "/providers/Microsoft.IoTSecurity/locations/" + location + "/sites/" + val + "/sensors?api-version=2021-09-01-preview")
                    async with self.ahsession.request('GET', url, headers=header, ssl=False) as r:
                        result = await r.json()
                        nexturl = None
                        if '@odata.nextLink' in result:
                            nexturl = result['@odata.nextLink']
                        if 'value' in result:
                            with open(outfile, 'a+', encoding='utf-8') as f:
                                for x in result['value']:
                                    f.write(json.dumps(x) + "\n")
                                f.flush()
                                os.fsync(f)
                        elif 'error' in result:
                            if result['error']['code'] == 'ExpiredAuthenticationToken':
                                self.logger.error("Error with authentication token: " + result['error']['message'])
                                self.logger.error("Please re-auth.")
                                return
                        await get_nextlink(nexturl, outfile, self.ahsession, self.logger, self.app_auth)
            self.logger.info("Finished getting D4IOT portal sensors settings from " + subscriptionId + ".")

    async def dump_d4iot_portal_configs(self) -> None:
        """
        Dump D4IOT portal configs
        """
        if self.check_savestate("d4iot_portal_configs"):
            return
        caller_name = asyncio.current_task().get_name()
        async with asyncio.TaskGroup() as tg:
            tg.create_task(self._dump_portal_alerts(), name=f"{caller_name}_portal_alerts")
            tg.create_task(self._dump_portal_defendersettings(), name=f"{caller_name}_portal_defendersettings")
            tg.create_task(self._dump_portal_sensors(), name=f"{caller_name}_dump_portal_sensors")
        self.write_savestate("d4iot_portal_configs")

    async def _dump_diagnostic_settings(self) -> None:
        """
        Dump Monitor Management Client diagnostic settings
        """
        for i in range(0, len(self.subscription_id_list)):
            sub_id = self.subscription_id_list[i]
            resource_client = self.resource_clients[i]
            monitor_client = self.monitor_clients[i]
            config_dir = os.path.join(self.output_dir, sub_id, 'azure_configs')
            check_output_dir(config_dir, self.logger)
            output = os.path.join(config_dir, "diagnostic_settings.json")
            if os.path.exists(output):
                self.logger.debug("Diagnostic settings file exists.. Proceeding without pulling.")
            else:
                self.logger.info("Getting diagnostic settings configurations from " + sub_id + "...")
                for event in resource_client.resources.list(filter=None):
                    if event:
                        resource_id = event.as_dict()['id']
                        try:
                            for entry in monitor_client.diagnostic_settings.list(resource_id):
                                with open(output, 'a+', encoding='utf-8') as f:
                                    temp = {'resource': str(resource_id)}
                                    info = entry.as_dict()
                                    info.update(temp)
                                    f.write(json.dumps(info, sort_keys=True) + '\n')

                        except HttpResponseError as e:
                            continue
                    await asyncio.sleep(0)  # yield to event loop
                self.logger.info("Finished geting diagnostic settings from " + sub_id + ".")
            await asyncio.sleep(0)  # yield to event loop

    async def _dump_vm_config(self) -> None:
        """
        returns all of the vm configurations
        """
        for i in range(0, len(self.subscription_id_list)):
            try:
                compute_client = self.compute_clients[i]
                sub_id = self.subscription_id_list[i]

                config_dir = os.path.join(self.output_dir, sub_id, 'azure_configs')
                check_output_dir(config_dir, self.logger)
                output = os.path.join(config_dir, "vm_configs.json")
                if os.path.exists(output):
                    self.logger.debug("VM Configuration file exists.. Proceeding without pulling.")
                else:
                    self.logger.info("Getting virtual machine configurations from " + sub_id + "...")
                    for vm in compute_client.virtual_machines.list_all():
                        with open(output, 'a+', encoding='utf-8') as f:
                            general_view = vm.id.split("/")
                            resource_group = general_view[4]
                            vm_name = general_view[-1]
                            config = compute_client.virtual_machines.get(resource_group,vm_name, expand='instanceView').as_dict()
                            if config:
                                f.write(json.dumps(config))
                                f.write("\n")
                                f.flush()
                                os.fsync(f)
                        await asyncio.sleep(0)  # yield to event loop

                    self.logger.info("Finished geting virtual machine configurations from " + sub_id + ".")
                await asyncio.sleep(0)  # yield to event loop
            except HttpResponseError:
                self.logger.debug("Caught HTTP Response Error on subscription " + sub_id)
                continue

    async def _dump_container_config(self) -> None:
        """
        Returns all of the app container configs
        """
        for i in range(0, len(self.subscription_id_list)):
            try:
                sub_id = self.subscription_id_list[i]
                web_client = self.web_clients[i]
                config_dir = os.path.join(self.output_dir, sub_id, 'azure_configs')
                check_output_dir(config_dir, self.logger)
                output = os.path.join(config_dir, "container_configs.json")
                if os.path.exists(output):
                    self.logger.debug("Container Configuration file exists.. Proceeding without pulling.")
                else:
                    self.logger.info("Getting Azure web app container configurations for" + sub_id + "...")
                    for site in web_client.web_apps.list():
                        with open(output, 'a+', encoding='utf-8') as f:
                            general_view = site.id.split("/")
                            resource_group = general_view[4]
                            name = general_view[-1]
                            for config in web_client.web_apps.list_configurations(resource_group_name=resource_group, name=name):
                                if config:
                                    f.write(json.dumps(config.as_dict()))
                                    f.write("\n")
                                    f.flush()
                                    os.fsync(f)
                                await asyncio.sleep(0)  # yield to event loop
                        await asyncio.sleep(0)  # yield to event loop

                    self.logger.info('Finished getting all web app Azure Container Configs for ' + sub_id + '.')
            except HttpResponseError:
                self.logger.debug("Caught HTTP Response Error on subscription " + sub_id)
                continue

    async def dump_all_azure_subscriptions(self) -> None:
        """
        Returns all azure subscriptions
        :return:
        :rtype:
        """
        if self.check_savestate("azure_subscriptions"):
            return
        output = os.path.join(self.output_dir, "subscriptions.json")
        if os.path.exists(output):
            self.logger.debug("All subscriptions file exists... Proceeding without pulling")
        else:
            try:
                self.logger.info("Getting Azure Subscriptions...")
                for event in self.subscription_client.subscriptions.list():
                    with open(output, 'a+', encoding='utf-8') as f:
                        f.write(json.dumps(event.as_dict()))
                        f.write("\n")
                        f.flush()
                        os.fsync(f)
                    await asyncio.sleep(0)  # yield to event loop
                self.logger.info('Finished getting all Azure Subscriptions.')
            except Exception as e:
                self.logger.error(f"Error getting subscriptions: {str(e)}\nDo you have the right credentials in your .conf file?")
                return
        self.write_savestate("azure_subscriptions")

    async def _dump_file_shares(self) -> None:
        """
        Dumps all the files shares in azure for each of the storage accounts
        :return:
        :rtype:
        """
        for i in range(0, len(self.subscription_id_list)):
            try:
                sub_id = self.subscription_id_list[i]
                storage_client = self.storage_clients[i]
                config_dir = os.path.join(self.output_dir, sub_id, 'azure_configs')
                check_output_dir(config_dir, self.logger)
                output = os.path.join(config_dir, "file_share_list.json")
                if os.path.exists(output):
                    self.logger.debug("File share file exists.. Proceeding without pulling.")
                else:
                    for account in storage_client.storage_accounts.list():
                        self.logger.info("Dumping file shares for " + sub_id + "...")
                        if account:
                            general_view = account.id.split("/")
                            resource_group = general_view[4]
                            name = general_view[-1]
                            for fs in storage_client.file_shares.list(resource_group_name=resource_group, account_name=name):
                                if fs:
                                    with open(output, 'a+', encoding='utf-8') as f:
                                        f.write(json.dumps(fs.as_dict()))
                                        f.write("\n")
                                        f.flush()
                                        os.fsync(f)
                                await asyncio.sleep(0)  # yield to event loop
                        await asyncio.sleep(0)  # yield to event loop

                    self.logger.info('Finished dumping all file shares for' + sub_id + '.')
                    await asyncio.sleep(0)  # yield to event loop
            except HttpResponseError:
                self.logger.debug("Caught HTTP Response Error on subscription " + sub_id)
                continue

    async def _dump_all_resources(self) -> None:
        """
        Dumps all the resources in the azure account
        :return:
        :rtype:
        """
        for i in range(0, len(self.subscription_id_list)):
            try:
                sub_id = self.subscription_id_list[i]
                resource_client = self.resource_clients[i]
                config_dir = os.path.join(self.output_dir, sub_id, 'azure_configs')
                check_output_dir(config_dir, self.logger)
                output = os.path.join(config_dir, "all_resources_list.json")
                if os.path.exists(output):
                    self.logger.debug("All resources file exists.. Proceeding without pulling.")
                else:
                    self.logger.info("Dumping list of all resources for" + sub_id + "...")
                    for event in resource_client.resources.list(filter=None):
                        if event:
                            with open(output, 'a+', encoding='utf-8') as f:
                                f.write(json.dumps(event.as_dict()))
                                f.write("\n")
                                f.flush()
                                os.fsync(f)

                    self.logger.info('Finished getting all azure resources information for ' + sub_id + '.')
                    await asyncio.sleep(0)  # yield to event loop
            except HttpResponseError:
                self.logger.debug("Caught HTTP Response Error on subscription " + sub_id)
                continue

    async def _dump_storage_accounts(self) -> None:
        """
        Lists all the storage accounts
        :return:
        :rtype:

        """
        for i in range(0, len(self.subscription_id_list)):
            try:
                sub_id = self.subscription_id_list[i]
                storage_client = self.storage_clients[i]
                config_dir = os.path.join(self.output_dir, sub_id, 'azure_configs')
                check_output_dir(config_dir, self.logger)
                output = os.path.join(config_dir, "azure_storage_accounts.json")
                if os.path.exists(output):
                    self.logger.debug("Storage account file exists.. Proceeding without pulling.")
                else:
                    for element in storage_client.storage_accounts.list():
                        if element:
                            with open(output, 'a+', encoding='utf-8') as f:
                                f.write(json.dumps(element.as_dict()))
                                f.write("\n")
                                f.flush()
                                os.fsync(f)
                self.logger.info('Finished getting all Azure storage account information for ' + sub_id + '.')
                await asyncio.sleep(0)  # yield to event loop
            except HttpResponseError:
                self.logger.debug("Caught HTTP Response Error on subscription " + sub_id)
                continue

    async def auxiliary_activity_log(self, start, end, i, statefile=None):
        sub_id = self.subscription_id_list[i]
        monitor_client = self.monitor_clients[i]
        self.logger.info('Dumping Azure Activity Log for ' + sub_id +'...')

        sub_directory = os.path.join(self.output_dir, sub_id, "Activity Log")
        if not os.path.exists(sub_directory):
            os.mkdir(sub_directory)

        if statefile is None:
            statefile = os.path.join(self.output_dir, sub_id, '.activity_log_state')
        start_datetime = dateutil.parser.parse(start).replace(tzinfo=None)
        end_datetime = dateutil.parser.parse(end).replace(tzinfo=None)
        while start_datetime < end_datetime:
            end_time = '%sT23:59:59.999999Z' % (datetime.strptime(start, ("%Y-%m-%dT%H:%M:%S.%fZ")).date())

            filters = 'eventTimestamp ge %s' % (start) + ' and eventTimestamp le %s' % (end_time)
            outfile = os.path.join(sub_directory, 'azure_activity_log_' + str(datetime.strptime(end_time, ("%Y-%m-%dT%H:%M:%S.%fZ")).date()) + '.json')
            self.logger.debug(f'Dumping Azure Activity logs for time frame {start} to {end_time}')
            activity_log = monitor_client.activity_logs

            with open(outfile, 'w', encoding='utf-8') as f:
                for event in activity_log.list(filter=filters):
                    f.write(json.dumps(event.as_dict()))
                    f.write("\n")
                    f.flush()
                    os.fsync(f)
                    await asyncio.sleep(0)  # yield to event loop
            with open(statefile, 'w') as f:
                f.write(end_time)
            await asyncio.sleep(0)  # yield to event loop

            start = '%sT00:00:00.000000Z' % ((datetime.strptime(start, ("%Y-%m-%dT%H:%M:%S.%fZ")).date() + timedelta(days=1)).strftime("%Y-%m-%d"))
            start_datetime = dateutil.parser.parse(start).replace(tzinfo=None)

    async def dump_activity_log(self) -> None:
        """
        Dumps activity log from azure
        :return:
        :rtype:
        """
        save_state = False
        sub_statefile = os.path.join(self.output_dir, '.sub_savestate')

        # default start_date and final_time
        start_date = '%sT00:00:00.000000Z' % ((datetime.now(utc) - timedelta(days=89)).strftime("%Y-%m-%d"))
        final_time = '%sT00:00:00.000000Z' % ((datetime.now(utc)).strftime("%Y-%m-%d"))

        if os.path.isfile(sub_statefile):
            self.logger.debug(f'Subscription save state file exists at {sub_statefile}')
            statefile=""

            with open(sub_statefile, "r") as f:
                subscription_id_num = f.readline().strip()
                subscription_id_num = int(subscription_id_num)
                subscript_id = self.subscription_id_list[subscription_id_num]
                statefile = os.path.join(self.output_dir, subscript_id, '.activity_log_state')
                self.logger.debug(statefile)

            if os.path.isfile(statefile):
                self.logger.info(f'Activity log save state file found. Continuing from last checkpoint.')
                with open(statefile, 'r') as reader:
                    save_state_end_time = reader.readline().strip()
                    start_time_saved_sub = '%sT00:00:00.000000Z' % (datetime.strptime(save_state_end_time, ("%Y-%m-%dT%H:%M:%S.%fZ")).date() + timedelta(days=1))
                save_state = True
            else:
                self.logger.info(f'Activity log save state file not found. Starting a fresh pull.')
                subscription_id_num = 0
                save_state = False

            end_time_saved_sub = '%sT00:00:00.000000Z' % ((datetime.now(utc)).strftime("%Y-%m-%d"))
        else:
            subscription_id_num = 0
            save_state = False
            statefile = os.path.join(self.output_dir, self.subscription_id_list[subscription_id_num], '.activity_log_state')

        if self.date_range:
            self.logger.debug(f'Date Range exists {self.date_start} - {self.date_end}')
            self.date_start  = self.date_start + 'T00:00:00.000000Z'
            self.date_end  = self.date_end + 'T00:00:00.000000Z'
            subscription_id_num = 0
            statefile = os.path.join(self.output_dir, self.subscription_id_list[subscription_id_num], '.activity_log_state')


        for i in range(subscription_id_num, len(self.subscription_id_list)):
            with open(sub_statefile, 'w') as f:
                f.write(f'{i}')
            try:
                if save_state:
                    self.logger.debug(f'Using Saved State {start_time_saved_sub} - {end_time_saved_sub}')
                    await self.auxiliary_activity_log(start_time_saved_sub, end_time_saved_sub, i, statefile)
                    save_state = False
                elif self.date_range:
                    self.logger.debug(f'Using Date Range {self.date_start} - {self.date_end}')
                    await self.auxiliary_activity_log(self.date_start, self.date_end, i, statefile)
                else:
                    self.logger.debug(f'No state. Using {start_date} - {final_time}')
                    await self.auxiliary_activity_log(start_date, final_time, i, statefile)
                await asyncio.sleep(0)  # yield to event loop

            except HttpResponseError as e:
                self.logger.error(f"HTTP Response Error on subscription {self.subscription_id_list[i]}: {e}")
                continue

    async def dump_log_analytic_workspaces(self):
        """
        Dump list of log analytic workspaces and their table contents
        """
        self.ensure_token("log_analytics_api")
        # default end time. Now
        end = utc.localize(datetime.now())

        # defult start tiem
        # For LAW 12 years is the maximum storage period
        start = end - timedelta(days=364*12)

        if self.date_range:
            self.logger.debug(f'MDE Dump using specified date range: {self.date_start} to {self.date_end}')
            start = dateutil.parser.parse(self.date_start).replace(tzinfo=utc)
            end = dateutil.parser.parse(self.date_end).replace(tzinfo=utc)

        # Discover all tables across all workspaces, then create a single progress bar
        table_tasks = []  # list of (table, table_start, table_end, url, statefile, outfile) tuples
        for subscriptionId in self.subscription_id_list:
            url = f"{self.endpoints['resource_manager']}/subscriptions/{subscriptionId}/providers/Microsoft.OperationalInsights/"
            self.logger.debug(url)
            output_dir = os.path.join(self.output_dir, os.path.join(subscriptionId, "log_analytics_workspace"))
            check_output_dir(output_dir, self.logger)
            call_object = [url, self.app_auth, self.logger, output_dir, self.get_session()]
            await helper_single_object("workspaces?api-version=2023-09-01", call_object, self.failurefile)
            workspaces_file = os.path.join(output_dir, "workspaces.json")
            if not os.path.isfile(workspaces_file):
                self.logger.debug("No workspaces exist")
                return
            with open(workspaces_file, "r") as f:
                for line in f:
                    workspace_dict = json.loads(line)
                    workspace_name = workspace_dict["name"]
                    workspace_id = workspace_dict["id"]
                    self.logger.debug(f"summarizing {workspace_name}")
                    query_url = f"{self.endpoints['log_analytics_api']}/v1{workspace_id}/query"
                    results, err, _, _ = await run_kql_query("search \"*\"", start, end, None, query_url, self.loganalytics_app_auth, self.logger, self.ahsession, summarize=True)
                    for row in results:
                        self.logger.debug(row)
                        table = row["$table"]

                        workspace_log_dir = os.path.join(output_dir, workspace_name)
                        check_output_dir(workspace_log_dir, self.logger)

                        statefile = os.path.join(workspace_log_dir, f".{table}.savestate")
                        outfile = os.path.join(workspace_log_dir, f"{table}.json")
                        saved_end = load_state(statefile)
                        table_start = start
                        table_end = end
                        if saved_end:
                            table_start = max(saved_end, table_start)
                        self.logger.debug(f"Generating table dump task for table: {table}, start: {start}, end: {end}")
                        table_tasks.append((table, table_start, table_end, query_url, statefile, outfile))

        if not table_tasks:
            return

        # Single progress bar: total = sum of hours across all tables
        pm = get_progress_manager()
        table_hours = []
        for _, ts, te, _, _, _ in table_tasks:
            secs = max(int((te - ts).total_seconds()), 1)
            table_hours.append(max(secs // 3600, 1))
        total_hours = sum(table_hours)
        bar = None
        bar_name = "azure_log_analytics"
        if pm:
            bar = pm.create_time_bar(bar_name, total_hours, desc=f"{'Log Analytics Workspaces':<35}", unit='hr')
            if bar:
                bar.bar_format = "{desc} |{bar}| {percentage:3.0f}% | {n_fmt}/{total_fmt} hrs | elapsed {elapsed}"

        # Shared mutable progress state for all table tasks
        law_progress = {"bar": bar, "pm": pm, "bar_name": bar_name, "hours_done": 0, "total_hours": total_hours}

        tasks = []
        for i, (table, ts, te, qurl, sf, of) in enumerate(table_tasks):
            caller_name = asyncio.current_task().get_name()
            tasks.append(asyncio.create_task(
                self._dump_table(table, ts, te, qurl, statefile=sf, outfile=of, law_progress=law_progress, table_total_hours=table_hours[i]),
                name=f"{caller_name}_{table}"))
        await asyncio.gather(*tasks)

        # Mark the single bar complete
        if bar:
            remaining = total_hours - law_progress["hours_done"]
            if remaining > 0:
                bar.update(remaining)
        if pm:
            pm.complete_task(bar_name)
    dump_log_analytic_workspaces._manages_own_progress = True


    async def _dump_table(self, base_query, start, end, url, statefile, outfile, retries=3, law_progress=None, table_total_hours=None):
        """
        Query the log analytics workspace and pull logs for the table under the timeframe.

        Args:
            base_query: table name / KQL query
            start: starting timestamp
            end: ending timestamp
            url: Log Analytics API endpoint
            statefile: path to save state checkpoint
            outfile: path to write JSONL output
            retries: max retry attempts
            law_progress: shared dict with 'bar', 'pm', 'bar_name', 'hours_done', 'total_hours'
            table_total_hours: this table's share of the total hours in the progress bar
        """
        totalResultCount = 0
        totalResultEnd = start
        totalSavedResults = 0
        origStart = start
        finalEnd = end
        tries = 0

        # Track this table's contribution to the shared progress bar
        my_total_hours = table_total_hours or 1
        my_hours_reported = 0

        def _update_progress(covered_end):
            """Update the shared LAW progress bar based on time covered."""
            nonlocal my_hours_reported
            if not law_progress or not law_progress.get("bar"):
                return
            covered_secs = max((covered_end - origStart).total_seconds(), 0)
            total_secs = max((finalEnd - origStart).total_seconds(), 1)
            fraction = min(covered_secs / total_secs, 1.0)
            my_covered = int(fraction * my_total_hours)
            delta = my_covered - my_hours_reported
            if delta > 0:
                law_progress["bar"].update(delta)
                law_progress["hours_done"] += delta
                my_hours_reported = my_covered

        def _complete_progress():
            """Flush remaining hours for this table to the shared bar."""
            nonlocal my_hours_reported
            if not law_progress or not law_progress.get("bar"):
                return
            delta = my_total_hours - my_hours_reported
            if delta > 0:
                law_progress["bar"].update(delta)
                law_progress["hours_done"] += delta
                my_hours_reported = my_total_hours
        # final record is so that it will stop when it gets to the last record
        # and we don't have to worry about the list being empty or changing the logic for
        # an edge case
        final_record = {"count": None,
                        "start": end,
                        "end": end + timedelta(1000),
                        "done_status": False}
        bounds = [final_record]
        # initial query loop to set a baseline
        summary = None
        while start < finalEnd and tries < retries*2:
            # Narrow down until we have a valid timeframe
            summary, err, new_end, bounds = await run_kql_query(base_query, start, end, bounds, url, self.loganalytics_app_auth, self.logger, self.ahsession, summarize=True)
            # If there are no results then we want to get to a timeframe that does contain results
            if err:
                tries += 1
            elif summary != None and summary[0]["Count"] == 0:
                tries = 0
                # Check if there are no results in the whole time range. If so we return
                if origStart == start and finalEnd == end:
                    self.logger.debug(f"No logs for {base_query} from {start} to {end}")
                    save_state(statefile, end)
                    _complete_progress()
                    return
                # Otherwise it just means this lower time segment has no logs and we remove it and continue
                start = end
                end = finalEnd
                bounds = [final_record]
                _update_progress(start)
                continue
            elif summary != None and summary[0]["Count"] > 0:
                tries = 0
                totalResultCount = summary[0]["Count"]
                totalResultEnd = end
                start = dateutil.parser.parse(summary[0]["FirstEvent"])
                # Need to make sure the start of each entry in the bounds matches the first start time
                bounds[0]["start"] = start
                break
            end = new_end


        while start < finalEnd and tries < retries:
            self.ensure_token("log_analytics_api")
            startDate = start.strftime("%Y-%m-%dT%H:%M:%S")
            endDate = end.strftime("%Y-%m-%dT%H:%M:%S")
            session_set = set() # Unique results returned. Used to detect duplicates
            bound = f'[{startDate} - {endDate}]'

            # Run a search to get a summary of the timeframe. Faster and provides more info
            if bounds[0]["count"] == None or \
               (bounds[0]["count"] >= LAW_QUERY_THRESHOLD and end <= bounds[0]["end"]):
                summary, err, end, bounds = await run_kql_query(base_query, start, end, bounds, url, self.loganalytics_app_auth, self.logger, self.ahsession, summarize=True)
                if err:
                    tries += 1
                    continue
                tries = 0
                if summary[0]["Count"] >= LAW_QUERY_THRESHOLD:
                    continue
                if summary[0]["Count"] == 0:
                    end = bounds[0]["end"]
                    start = bounds[0]["start"]
                    _update_progress(start)
                    continue

            results, err, end, bounds = await run_kql_query(base_query, start, end, bounds, url, self.loganalytics_app_auth, self.logger, self.ahsession)
            if err:
                tries += 1
                continue
            if len(results) >= 0:
                if start >= totalResultEnd:
                    totalResultCount += len(results)
                #self.logger.debug('Size of table: %s' % len(results))
                #self.logger.debug('Size of table: %s' % result['Stats']['dataset_statistics'][0]['table_row_count'])
                with open(outfile, 'a', encoding='utf-8') as f:
                    for x in results:
                        f.write(json.dumps(x) + '\n')

                save_state(statefile, end)
                _update_progress(end)

                tries = 0
                end = bounds[0]["end"]
                start = bounds[0]["start"]
                if bounds[0]["count"] != None and bounds[0]["count"] >= LAW_QUERY_THRESHOLD:
                    new_end_ts = start.timestamp() + ((end.timestamp() - start.timestamp())/2)
                    end = datetime.fromtimestamp(new_end_ts, utc)

        # Mark this table's share of progress complete
        _complete_progress()


    async def auxiliary_storage_log_pull(self, container_name, log_type):
        for i in range(0, len(self.subscription_id_list)):
            try:
                sub_id = self.subscription_id_list[i]
                storage_client = self.storage_clients[i]

                output_dir =  os.path.join(self.output_dir, sub_id, log_type + "_logs/")
                check_output_dir(output_dir, self.logger)

                self.logger.info("Dumping " + log_type + " logs from blob storage...")
                storage_accounts = []
                for element in storage_client.storage_accounts.list():
                    storage_accounts.append(element.as_dict()['name'])

                for account in storage_accounts:
                    save_state_path = os.path.join(output_dir, f".{account}_savestate")
                    save_state_set = set()
                    if os.path.exists(save_state_path):
                        self.logger.debug(save_state_path)
                        save_state_set = set(json.load(open(save_state_path, "r"))["set"])
                    if self.gcc_high.lower() == "true":
                        url = "https://" + account + ".blob.core.usgovcloudapi.net/"
                        blob_service_client = BlobServiceClient(account_url=url, credential=self.credential)
                    else:
                        url = "https://" + account + ".blob.core.windows.net/"
                        blob_service_client = BlobServiceClient(account_url=url, credential=self.credential)
                    try:
                        container_client = blob_service_client.get_container_client(container=container_name)
                        start_date = utc.localize((datetime.now() - timedelta(days=365*2)))
                        end_date = utc.localize(datetime.now())
                        if self.date_range:
                            start_date = dateutil.parser.parse(self.date_start).replace(tzinfo=utc)
                            end_date = dateutil.parser.parse(self.date_end).replace(tzinfo=utc)
                        for blob in container_client.list_blobs():
                            # Check the save state
                            if str(blob.name) in save_state_set:
                                self.logger.debug(f"blob found in save state. Continuing")
                                continue
                            if start_date <= blob.last_modified and blob.last_modified <= end_date:
                                self.logger.debug(f"{log_type} log present in {account} with last_modified date {blob.last_modified}")
                                downloader = container_client.download_blob(blob)

                                output = os.path.join(output_dir, "log_" + sanitize_filename(blob.name))
                                if log_type == "nsg_flow":
                                    data = json.loads(downloader.readall().decode(("utf-8")))
                                    with open(output, 'a+', encoding='utf-8') as f:
                                        for record in data['records']:
                                            f.write(json.dumps(record))
                                            f.write("\n")
                                else:
                                    data = downloader.readall().decode(("utf-8"))
                                    lines = data.split("\n")
                                    with open(output, 'a+', encoding='utf-8') as f:
                                        for entry in lines:
                                            f.write(entry)
                                save_state_set.add(str(blob.name))
                                json.dump({"set": list(save_state_set)}, open(save_state_path, "w"))
                            await asyncio.sleep(0)  # yield to event loop



                    except HttpResponseError as e:
                        self.logger.debug(log_type + " log not present in " + account + " continuing.")
                        await asyncio.sleep(0)  # yield to event loop
                        continue
                    await asyncio.sleep(0)  # yield to event loop
                    self.logger.info("Finished dumping " + log_type + " logs from blob storage.")

            except HttpResponseError as e:
                self.logger.debug("Caught HTTP Response Error on subscription " + sub_id)
                continue

    async def dump_key_vault_log(self):
        """
        Dump insights audit events for key_vault
        """
        await self.auxiliary_storage_log_pull("insights-logs-auditevent", "key_vault")

    async def dump_nsg_flow_logs(self):
        """
        Dump insights network security group flow events from blob storage.

        NOTE: NSG flow logs are deprecated. No new NSG flow log resources can be created after
        June 2025, and the feature will be fully retired September 2027. Use dump_vnet_flow_logs
        for VNet flow logs (the recommended replacement). This method is kept for backwards
        compatibility with environments that still have legacy NSG flow log data in blob storage.
        See: https://learn.microsoft.com/en-us/azure/network-watcher/nsg-flow-logs-overview
        """
        await self.auxiliary_storage_log_pull("insights-logs-networksecuritygroupflowevent", "nsg_flow")

    async def dump_vnet_flow_logs(self):
        """
        Dump VNet flow logs from Log Analytics workspaces via KQL query against NTANetAnalytics table.

        VNet flow logs are the replacement for deprecated NSG flow logs (deprecated June 2025,
        retired September 2027). VNet flow log data is stored in the NTANetAnalytics table
        (or NTANetAnalytics_CL for custom log destinations) in Log Analytics workspaces.

        Queries all Log Analytics workspaces across all subscriptions for NTANetAnalytics
        and NTANetAnalytics_CL tables, using the same incremental save-state pattern as
        dump_log_analytic_workspaces.

        See: https://learn.microsoft.com/en-us/azure/network-watcher/vnet-flow-logs-overview
        """
        # @decision DEC-AZURE-VNET-001
        # @title Query NTANetAnalytics table for VNet flow logs via LAW KQL
        # @status accepted
        # @rationale VNet flow logs write to Log Analytics via the NTANetAnalytics table.
        # Unlike legacy NSG flow logs (blob storage), VNet flow logs are LAW-native.
        # We discover workspaces the same way as dump_log_analytic_workspaces (reusing the
        # workspaces.json artifact if already present from that run) and target only the
        # VNet flow log tables rather than all tables. This avoids re-listing workspaces
        # from the API when the artifact already exists, and scopes the query to minimize
        # cost and latency.

        # VNet flow log tables: NTANetAnalytics (standard) and NTANetAnalytics_CL (custom)
        vnet_flow_tables = ["NTANetAnalytics", "NTANetAnalytics_CL"]

        end = utc.localize(datetime.now())
        # VNet flow logs retention: up to 2 years by default; use 2 years as default window
        start = end - timedelta(days=365 * 2)

        if self.date_range:
            self.logger.debug(f'VNet flow logs dump using specified date range: {self.date_start} to {self.date_end}')
            start = dateutil.parser.parse(self.date_start).replace(tzinfo=utc)
            end = dateutil.parser.parse(self.date_end).replace(tzinfo=utc)

        tasks = []
        for subscriptionId in self.subscription_id_list:
            url = f"{self.endpoints['resource_manager']}/subscriptions/{subscriptionId}/providers/Microsoft.OperationalInsights/"
            output_dir = os.path.join(self.output_dir, subscriptionId, "vnet_flow_logs")
            check_output_dir(output_dir, self.logger)

            # Reuse workspaces.json from log_analytics_workspace output if available,
            # otherwise fetch workspace list from ARM API
            law_output_dir = os.path.join(self.output_dir, subscriptionId, "log_analytics_workspace")
            workspaces_file = os.path.join(law_output_dir, "workspaces.json")
            if not os.path.isfile(workspaces_file):
                # Fall back to fetching workspaces for this subscription
                check_output_dir(law_output_dir, self.logger)
                call_object = [url, self.app_auth, self.logger, law_output_dir, self.get_session()]
                await helper_single_object("workspaces?api-version=2023-09-01", call_object, self.failurefile)

            if not os.path.isfile(workspaces_file):
                self.logger.debug(f"No Log Analytics workspaces found for subscription {subscriptionId}, skipping VNet flow log collection")
                continue

            with open(workspaces_file, "r") as f:
                for line in f:
                    workspace_dict = json.loads(line)
                    workspace_name = workspace_dict["name"]
                    workspace_id = workspace_dict["id"]
                    query_url = f"{self.endpoints['log_analytics_api']}/v1{workspace_id}/query"

                    # Check which VNet flow log tables exist in this workspace
                    self.logger.debug(f"Checking VNet flow log tables in workspace {workspace_name}")
                    summary, err, _, _ = await run_kql_query(
                        "search \"*\"", start, end, None,
                        query_url, self.loganalytics_app_auth,
                        self.logger, self.ahsession, summarize=True
                    )

                    if err or not summary:
                        self.logger.debug(f"Could not enumerate tables in workspace {workspace_name}, skipping")
                        continue

                    available_tables = {row.get("$table") for row in summary if "$table" in row}
                    workspace_log_dir = os.path.join(output_dir, workspace_name)
                    check_output_dir(workspace_log_dir, self.logger)

                    for table in vnet_flow_tables:
                        if table not in available_tables:
                            self.logger.debug(f"Table {table} not present in workspace {workspace_name}, skipping")
                            continue

                        self.logger.debug(f"Scheduling VNet flow log dump for table {table} in workspace {workspace_name}")
                        statefile = os.path.join(workspace_log_dir, f".{table}.savestate")
                        outfile = os.path.join(workspace_log_dir, f"{table}.json")
                        saved_end = load_state(statefile)
                        table_start = start
                        table_end = end
                        if saved_end:
                            table_start = max(saved_end, table_start)
                        caller_name = asyncio.current_task().get_name()
                        tasks.append(asyncio.create_task(
                            self._dump_table(table, table_start, table_end, query_url, statefile=statefile, outfile=outfile),
                            name=f"{caller_name}_{workspace_name}_{table}"
                        ))

        if tasks:
            await asyncio.gather(*tasks)
        else:
            self.logger.info("No VNet flow log tables (NTANetAnalytics / NTANetAnalytics_CL) found across any workspace")

    async def dump_bastion_logs(self):
        """
        Dump insights bastion audit logs
        """
        await self.auxiliary_storage_log_pull("insights-logs-bastionauditlogs", "bastion")

    async def auxiliary_list_all(self, func, sub_id, ops, args: Optional[str] = None, caller="", api_version=None) -> None:
        try:
            name = str(func.__class__)
            name = name.strip("\'<>").split(".")[-1]
            if 'Operations' in name:
                name = name.replace('Operations', "")

            current_task = asyncio.current_task()
            if "Task" in current_task.get_name():
                task_name = name
                if caller:
                    task_name = f"{caller}_{name}"
                current_task.set_name(task_name)

            config_dir = os.path.join(self.output_dir, sub_id, 'azure_configs')
            check_output_dir(config_dir, self.logger)
            output = os.path.join(config_dir, name + ".json")

            if os.path.exists(output):
                self.logger.debug(name + " file exists.. Proceeding without pulling.")
            else:
                self.logger.info("Dumping Azure " + name + "...")
                named_args = {}
                if args:
                    named_args["scope"] = args
                if api_version:
                    named_args["api_version"] = api_version
                func = getattr(func, ops)(**named_args)

                for element in func:
                    if element:
                        with open(output, 'a+', encoding='utf-8') as f:
                            f.write(json.dumps(element.as_dict()))
                            f.write("\n")
                            f.flush()
                            os.fsync(f)
                    await asyncio.sleep(0)  # yield to event loop

                self.logger.info("Finished dumping Azure " + name)
        except HttpResponseError as e:
            self.logger.debug("Caught HTTP Response Error on subscription " + sub_id + " for " + name)
            self.logger.debug('Error: {}'.format(str(e)))

    async def dump_rbac_role_assignments(self) -> None:
        """Dump all RBAC role assignments for each subscription via ARM REST API.

        Queries GET /subscriptions/{id}/providers/Microsoft.Authorization/roleAssignments
        for each configured subscription. Role assignments describe who (principalId) has
        what role (roleDefinitionId) at what scope, making this essential for privilege
        auditing during incident response.

        Output: {output_dir}/{subscriptionId}/rbac_role_assignments.json (JSONL format)
        API version: 2022-04-01 (supports filter, includes deleted assignments via
        $filter=atScope() or includeClassicAdministrators)

        @decision DEC-AZURE-RBAC-001
        @title Use direct aiohttp ARM REST calls for RBAC data collection
        @status accepted
        @rationale The Azure SDK does not expose azure-mgmt-authorization as a dependency
        in this project. The ARM REST API surface for RBAC is stable and well-documented.
        Using the same aiohttp + resource_manager token pattern as other azure_dumper methods
        keeps authentication consistent and avoids adding a new SDK dependency.
        ARM paginates via 'nextLink' (not '@odata.nextLink'), so we handle that inline.
        """
        if self.check_savestate("rbac_role_assignments"):
            return
        header = self._make_auth_header()

        for subscriptionId in self.subscription_id_list:
            self.logger.info(f"Getting RBAC role assignments from {subscriptionId}...")
            sub_dir = os.path.join(self.output_dir, subscriptionId)
            check_output_dir(sub_dir, self.logger)
            outfile = os.path.join(sub_dir, "rbac_role_assignments.json")

            url = self._get_mgmt_url(
                f"/subscriptions/{subscriptionId}/providers/Microsoft.Authorization"
                f"/roleAssignments?api-version=2022-04-01"
            )

            record_count = 0
            while url:
                async with self.ahsession.request('GET', url, headers=header, ssl=False) as r:
                    result = await r.json()

                if 'error' in result:
                    err = result['error']
                    if err.get('code') == 'ExpiredAuthenticationToken':
                        self.logger.error(
                            f"Authentication token expired: {err.get('message')} — please re-auth."
                        )
                        return
                    self.logger.error(
                        f"Error fetching RBAC role assignments for {subscriptionId}: "
                        f"{err.get('code')} — {err.get('message')}"
                    )
                    break

                entries = result.get('value', [])
                if entries:
                    with open(outfile, 'a+', encoding='utf-8') as f:
                        for entry in entries:
                            f.write(json.dumps(entry) + "\n")
                        f.flush()
                        os.fsync(f)
                    record_count += len(entries)

                # ARM pagination uses 'nextLink', not '@odata.nextLink'
                url = result.get('nextLink')
                await asyncio.sleep(0)  # yield to event loop

            self.logger.info(
                f"Finished getting RBAC role assignments from {subscriptionId} "
                f"({record_count} records)."
            )

        self.write_savestate("rbac_role_assignments")

    async def dump_rbac_role_definitions(self) -> None:
        """Dump all RBAC role definitions for each subscription via ARM REST API.

        Queries GET /subscriptions/{id}/providers/Microsoft.Authorization/roleDefinitions
        for each configured subscription. Returns both built-in and custom role definitions,
        allowing analysts to map roleDefinitionId values from role assignments to human-readable
        role names and permission sets.

        Output: {output_dir}/{subscriptionId}/rbac_role_definitions.json (JSONL format)
        API version: 2022-04-01
        """
        if self.check_savestate("rbac_role_definitions"):
            return
        header = self._make_auth_header()

        for subscriptionId in self.subscription_id_list:
            self.logger.info(f"Getting RBAC role definitions from {subscriptionId}...")
            sub_dir = os.path.join(self.output_dir, subscriptionId)
            check_output_dir(sub_dir, self.logger)
            outfile = os.path.join(sub_dir, "rbac_role_definitions.json")

            url = self._get_mgmt_url(
                f"/subscriptions/{subscriptionId}/providers/Microsoft.Authorization"
                f"/roleDefinitions?api-version=2022-04-01"
            )

            record_count = 0
            while url:
                async with self.ahsession.request('GET', url, headers=header, ssl=False) as r:
                    result = await r.json()

                if 'error' in result:
                    err = result['error']
                    if err.get('code') == 'ExpiredAuthenticationToken':
                        self.logger.error(
                            f"Authentication token expired: {err.get('message')} — please re-auth."
                        )
                        return
                    self.logger.error(
                        f"Error fetching RBAC role definitions for {subscriptionId}: "
                        f"{err.get('code')} — {err.get('message')}"
                    )
                    break

                entries = result.get('value', [])
                if entries:
                    with open(outfile, 'a+', encoding='utf-8') as f:
                        for entry in entries:
                            f.write(json.dumps(entry) + "\n")
                        f.flush()
                        os.fsync(f)
                    record_count += len(entries)

                # ARM pagination uses 'nextLink', not '@odata.nextLink'
                url = result.get('nextLink')
                await asyncio.sleep(0)  # yield to event loop

            self.logger.info(
                f"Finished getting RBAC role definitions from {subscriptionId} "
                f"({record_count} records)."
            )

        self.write_savestate("rbac_role_definitions")

    async def _get_workspaces_for_subscription(self, subscriptionId: str) -> list:
        """Return a list of workspace dicts for a subscription.

        Reuses the workspaces.json artifact written by dump_log_analytic_workspaces
        if it already exists (same pattern as dump_vnet_flow_logs), otherwise fetches
        the workspace list from ARM and caches it for subsequent callers.

        @decision DEC-SENTINEL-001
        @title Reuse workspaces.json artifact to avoid redundant ARM list calls
        @status accepted
        @rationale dump_log_analytic_workspaces already writes workspaces.json.
        All three Sentinel dump methods need the same workspace list.  Sharing the
        artifact avoids N extra ARM API calls per sentinel method and keeps the
        collection idempotent when multiple methods run concurrently.
        """
        law_output_dir = os.path.join(self.output_dir, subscriptionId, "log_analytics_workspace")
        workspaces_file = os.path.join(law_output_dir, "workspaces.json")

        if not os.path.isfile(workspaces_file):
            check_output_dir(law_output_dir, self.logger)
            url = (
                f"{self.endpoints['resource_manager']}/subscriptions/{subscriptionId}"
                f"/providers/Microsoft.OperationalInsights/"
            )
            call_object = [url, self.app_auth, self.logger, law_output_dir, self.get_session()]
            await helper_single_object("workspaces?api-version=2023-09-01", call_object, self.failurefile)

        if not os.path.isfile(workspaces_file):
            self.logger.debug(
                f"No Log Analytics workspaces found for subscription {subscriptionId}"
            )
            return []

        workspaces = []
        with open(workspaces_file, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    workspaces.append(json.loads(line))
        return workspaces

    async def _dump_sentinel_resource(
        self,
        subscriptionId: str,
        api_path: str,
        api_version: str,
        output_name: str,
    ) -> int:
        """Fetch a Sentinel resource collection from all Log Analytics workspaces in a subscription.

        Discovers workspaces via _get_workspaces_for_subscription, then for each workspace
        calls the given Microsoft.SecurityInsights API path with nextLink pagination.
        Results are written as JSONL to:
            {output_dir}/{subscriptionId}/sentinel/{output_name}.json

        Workspaces that return 404 (Sentinel not enabled) are skipped silently.
        Workspaces that return other errors are logged at error level and skipped.

        Args:
            subscriptionId: Azure subscription ID.
            api_path: Sentinel resource path segment, e.g. "incidents" or "alertRules".
            api_version: API version string, e.g. "2024-03-01".
            output_name: Output filename stem, e.g. "incidents".

        Returns:
            Total record count written across all workspaces.
        """
        header = self._make_auth_header()
        sentinel_dir = os.path.join(self.output_dir, subscriptionId, "sentinel")
        check_output_dir(sentinel_dir, self.logger)
        outfile = os.path.join(sentinel_dir, f"{output_name}.json")

        workspaces = await self._get_workspaces_for_subscription(subscriptionId)
        if not workspaces:
            self.logger.debug(
                f"No workspaces in {subscriptionId}; skipping Sentinel {output_name}"
            )
            return 0

        record_count = 0
        for ws in workspaces:
            ws_id: str = ws.get("id", "")
            ws_name: str = ws.get("name", ws_id)

            # Extract resource group from workspace ARM ID:
            # /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{name}
            id_parts = ws_id.split("/")
            try:
                rg_index = [p.lower() for p in id_parts].index("resourcegroups")
                resource_group = id_parts[rg_index + 1]
            except (ValueError, IndexError):
                self.logger.error(
                    f"Could not parse resource group from workspace ID {ws_id!r}; skipping"
                )
                continue

            url = self._get_mgmt_url(
                f"/subscriptions/{subscriptionId}/resourceGroups/{resource_group}"
                f"/providers/Microsoft.OperationalInsights/workspaces/{ws_name}"
                f"/providers/Microsoft.SecurityInsights/{api_path}?api-version={api_version}"
            )

            ws_count = 0
            while url:
                async with self.ahsession.request('GET', url, headers=header, ssl=False) as r:
                    result = await r.json()

                if 'error' in result:
                    err = result['error']
                    code = err.get('code', '')
                    if code in ('WorkspaceNotFound', 'ResourceNotFound', 'NotFound') or r.status == 404:
                        # Sentinel not enabled on this workspace — skip silently
                        self.logger.debug(
                            f"Sentinel not enabled on workspace {ws_name} "
                            f"(subscription {subscriptionId}); skipping"
                        )
                        break
                    if code == 'ExpiredAuthenticationToken':
                        self.logger.error(
                            f"Authentication token expired: {err.get('message')} — please re-auth."
                        )
                        return record_count
                    self.logger.error(
                        f"Error fetching Sentinel {output_name} for workspace {ws_name} "
                        f"in {subscriptionId}: {code} — {err.get('message')}"
                    )
                    break

                entries = result.get('value', [])
                if entries:
                    with open(outfile, 'a+', encoding='utf-8') as f:
                        for entry in entries:
                            f.write(json.dumps(entry) + "\n")
                        f.flush()
                        os.fsync(f)
                    ws_count += len(entries)
                    record_count += len(entries)

                # Sentinel API uses 'nextLink' for pagination
                url = result.get('nextLink')
                await asyncio.sleep(0)  # yield to event loop

            if ws_count:
                self.logger.debug(
                    f"  Sentinel {output_name}: {ws_count} records from workspace {ws_name}"
                )

        return record_count

    async def dump_sentinel_incidents(self) -> None:
        """Dump Microsoft Sentinel incidents from all Log Analytics workspaces.

        Queries the Sentinel Incidents API for every Log Analytics workspace across
        all configured subscriptions.  Workspace discovery reuses the workspaces.json
        artifact produced by dump_log_analytic_workspaces when available, falling back
        to a live ARM list call otherwise.

        Workspaces that return 404 (Sentinel not provisioned) are skipped silently
        so that mixed environments (some workspaces with Sentinel, some without) are
        handled gracefully.

        API:
            GET /subscriptions/{id}/resourceGroups/{rg}/providers/
                Microsoft.OperationalInsights/workspaces/{ws}/providers/
                Microsoft.SecurityInsights/incidents?api-version=2024-03-01

        Output: {output_dir}/{subscriptionId}/sentinel/incidents.json  (JSONL)
        """
        # @decision DEC-SENTINEL-002
        # @title Use 2024-03-01 API version for all Sentinel resource types
        # @status accepted
        # @rationale 2024-03-01 is the current stable GA version for the SecurityInsights
        # resource provider as of the implementation date.  It supports incidents, alertRules,
        # and dataConnectors under a single consistent version, simplifying maintenance.
        if self.check_savestate("sentinel_incidents"):
            return

        total = 0
        for subscriptionId in self.subscription_id_list:
            self.logger.info(f"Getting Sentinel incidents from {subscriptionId}...")
            count = await self._dump_sentinel_resource(
                subscriptionId, "incidents", "2024-03-01", "incidents"
            )
            total += count
            self.logger.info(
                f"Finished getting Sentinel incidents from {subscriptionId} ({count} records)."
            )

        self.write_savestate("sentinel_incidents")
        self.logger.debug(f"Sentinel incidents total across all subscriptions: {total}")

    async def dump_sentinel_analytics_rules(self) -> None:
        """Dump Microsoft Sentinel analytics rules (alert rules) from all Log Analytics workspaces.

        Analytics rules define detection logic in Sentinel (scheduled queries, ML rules,
        fusion rules, etc.).  Collecting them during incident response reveals which
        detections were active and whether any may have been tampered with.

        Workspace discovery and 404 handling follow the same pattern as
        dump_sentinel_incidents.

        API:
            GET /subscriptions/{id}/resourceGroups/{rg}/providers/
                Microsoft.OperationalInsights/workspaces/{ws}/providers/
                Microsoft.SecurityInsights/alertRules?api-version=2024-03-01

        Output: {output_dir}/{subscriptionId}/sentinel/analytics_rules.json  (JSONL)
        """
        if self.check_savestate("sentinel_analytics_rules"):
            return

        total = 0
        for subscriptionId in self.subscription_id_list:
            self.logger.info(f"Getting Sentinel analytics rules from {subscriptionId}...")
            count = await self._dump_sentinel_resource(
                subscriptionId, "alertRules", "2024-03-01", "analytics_rules"
            )
            total += count
            self.logger.info(
                f"Finished getting Sentinel analytics rules from {subscriptionId} ({count} records)."
            )

        self.write_savestate("sentinel_analytics_rules")
        self.logger.debug(f"Sentinel analytics rules total across all subscriptions: {total}")

    async def dump_sentinel_data_connectors(self) -> None:
        """Dump Microsoft Sentinel data connectors from all Log Analytics workspaces.

        Data connectors describe which data sources are feeding into Sentinel
        (e.g. Azure Active Directory, Office 365, MDE, third-party SIEMs).
        Collecting them provides a map of the tenant's detection coverage and can
        reveal connectors that have been disabled or misconfigured during an attack.

        Workspace discovery and 404 handling follow the same pattern as
        dump_sentinel_incidents.

        API:
            GET /subscriptions/{id}/resourceGroups/{rg}/providers/
                Microsoft.OperationalInsights/workspaces/{ws}/providers/
                Microsoft.SecurityInsights/dataConnectors?api-version=2024-03-01

        Output: {output_dir}/{subscriptionId}/sentinel/data_connectors.json  (JSONL)
        """
        if self.check_savestate("sentinel_data_connectors"):
            return

        total = 0
        for subscriptionId in self.subscription_id_list:
            self.logger.info(f"Getting Sentinel data connectors from {subscriptionId}...")
            count = await self._dump_sentinel_resource(
                subscriptionId, "dataConnectors", "2024-03-01", "data_connectors"
            )
            total += count
            self.logger.info(
                f"Finished getting Sentinel data connectors from {subscriptionId} ({count} records)."
            )

        self.write_savestate("sentinel_data_connectors")
        self.logger.debug(f"Sentinel data connectors total across all subscriptions: {total}")

    # Max concurrent config pulls per batch to avoid event loop starvation
    CONFIG_BATCH_SIZE = 15

    async def dump_configs(self) -> None:
        """
        Dump Azure configuration information.

        Batches API calls into groups to avoid event loop starvation when running
        alongside other dumpers. Uses a per-subscription save state to skip
        re-pulling configs that were already collected.
        """
        for i in range(0, len(self.subscription_id_list)):
            sub_id = self.subscription_id_list[i]
            security_client = self.security_clients[i]
            network_manager = self.network_managers[i]
            scope = "/subscriptions/" + sub_id
            caller_name = asyncio.current_task().get_name()

            # Check save state: skip this subscription if configs already pulled
            config_state_name = f"azure_configs_{sub_id}"
            if self.check_savestate(config_state_name):
                continue

            # Build the full list of config coroutines to run
            config_coros = []

            if self.gcc_high.lower() == "false":
                config_coros.append(self.auxiliary_list_all(security_client.settings, sub_id, "list", caller=caller_name))
                config_coros.append(self.auxiliary_list_all(security_client.security_solutions, sub_id, "list", caller=caller_name))

            # Security configs
            config_coros.extend([
                self.auxiliary_list_all(security_client.alerts, sub_id, "list", caller=caller_name),
                self.auxiliary_list_all(security_client.allowed_connections, sub_id, "list", caller=caller_name),
                self.auxiliary_list_all(security_client.applications, sub_id, "list", caller=caller_name),
                self.auxiliary_list_all(security_client.assessments, sub_id, "list", scope, caller=caller_name),
                self.auxiliary_list_all(security_client.auto_provisioning_settings, sub_id, "list", caller=caller_name),
                self.auxiliary_list_all(security_client.automations, sub_id, "list", caller=caller_name),
                self.auxiliary_list_all(security_client.compliance_results, sub_id, "list", scope, caller=caller_name),
                self.auxiliary_list_all(security_client.compliances, sub_id, "list", scope, caller=caller_name),
                self.auxiliary_list_all(security_client.discovered_security_solutions, sub_id, "list", caller=caller_name),
                self.auxiliary_list_all(security_client.external_security_solutions, sub_id, "list", caller=caller_name),
                self.auxiliary_list_all(security_client.governance_rules, sub_id, "list", scope, caller=caller_name),
                self.auxiliary_list_all(security_client.information_protection_policies, sub_id, "list", scope, caller=caller_name),
                self.auxiliary_list_all(security_client.jit_network_access_policies, sub_id, "list", caller=caller_name),
                self.auxiliary_list_all(security_client.locations, sub_id, "list", caller=caller_name),
                self.auxiliary_list_all(security_client.secure_score_controls, sub_id, "list", caller=caller_name),
                self.auxiliary_list_all(security_client.secure_scores, sub_id, "list", caller=caller_name),
                self.auxiliary_list_all(security_client.security_contacts, sub_id, "list", api_version="2023-12-01-preview", caller=caller_name),
                self.auxiliary_list_all(security_client.sub_assessments, sub_id, "list_all", scope, caller=caller_name),
                self.auxiliary_list_all(security_client.tasks, sub_id, "list", caller=caller_name),
                self.auxiliary_list_all(security_client.topology, sub_id, "list", caller=caller_name),
                self.auxiliary_list_all(security_client.workspace_settings, sub_id, "list", caller=caller_name),
            ])

            # Network configs
            config_coros.extend([
                self.auxiliary_list_all(network_manager.application_gateways, sub_id, "list_all", caller=caller_name),
                self.auxiliary_list_all(network_manager.application_security_groups, sub_id, "list_all", caller=caller_name),
                self.auxiliary_list_all(network_manager.azure_firewall_fqdn_tags, sub_id, "list_all", caller=caller_name),
                self.auxiliary_list_all(network_manager.azure_firewalls, sub_id, "list_all", caller=caller_name),
                self.auxiliary_list_all(network_manager.bastion_hosts, sub_id, "list", caller=caller_name),
                self.auxiliary_list_all(network_manager.custom_ip_prefixes, sub_id, "list_all", caller=caller_name),
                self.auxiliary_list_all(network_manager.ddos_protection_plans, sub_id, "list", caller=caller_name),
                self.auxiliary_list_all(network_manager.dscp_configuration, sub_id, "list_all", caller=caller_name),
                self.auxiliary_list_all(network_manager.express_route_circuits, sub_id, "list_all", caller=caller_name),
                self.auxiliary_list_all(network_manager.express_route_ports, sub_id, "list", caller=caller_name),
                self.auxiliary_list_all(network_manager.firewall_policies, sub_id, "list_all", caller=caller_name),
                self.auxiliary_list_all(network_manager.ip_allocations, sub_id, "list", caller=caller_name),
                self.auxiliary_list_all(network_manager.ip_groups, sub_id, "list", caller=caller_name),
                self.auxiliary_list_all(network_manager.load_balancers, sub_id, "list_all", caller=caller_name),
                self.auxiliary_list_all(network_manager.nat_gateways, sub_id, "list_all", caller=caller_name),
                self.auxiliary_list_all(network_manager.network_interfaces, sub_id, "list_all", caller=caller_name),
                self.auxiliary_list_all(network_manager.network_managers, sub_id, "list_by_subscription", caller=caller_name),
                self.auxiliary_list_all(network_manager.network_profiles, sub_id, "list_all", caller=caller_name),
                self.auxiliary_list_all(network_manager.network_security_groups, sub_id, "list_all", caller=caller_name),
                self.auxiliary_list_all(network_manager.network_security_perimeters, sub_id, "list_by_subscription", api_version="2023-07-01-preview", caller=caller_name),
                self.auxiliary_list_all(network_manager.network_virtual_appliances, sub_id, "list", caller=caller_name),
                self.auxiliary_list_all(network_manager.network_watchers, sub_id, "list_all", caller=caller_name),
                self.auxiliary_list_all(network_manager.p2_svpn_gateways, sub_id, "list", caller=caller_name),
                self.auxiliary_list_all(network_manager.private_endpoints, sub_id, "list_by_subscription", caller=caller_name),
                self.auxiliary_list_all(network_manager.private_link_services, sub_id, "list_by_subscription", caller=caller_name),
                self.auxiliary_list_all(network_manager.public_ip_addresses, sub_id, "list_all", caller=caller_name),
                self.auxiliary_list_all(network_manager.public_ip_prefixes, sub_id, "list_all", caller=caller_name),
                self.auxiliary_list_all(network_manager.route_filters, sub_id, "list", caller=caller_name),
                self.auxiliary_list_all(network_manager.route_tables, sub_id, "list_all", caller=caller_name),
                self.auxiliary_list_all(network_manager.security_partner_providers, sub_id, "list", caller=caller_name),
                self.auxiliary_list_all(network_manager.service_endpoint_policies, sub_id, "list", caller=caller_name),
                self.auxiliary_list_all(network_manager.subscription_network_manager_connections, sub_id, "list", caller=caller_name),
                self.auxiliary_list_all(network_manager.virtual_hubs, sub_id, "list", caller=caller_name),
                self.auxiliary_list_all(network_manager.virtual_network_taps, sub_id, "list_all", caller=caller_name),
                self.auxiliary_list_all(network_manager.virtual_networks, sub_id, "list_all", caller=caller_name),
                self.auxiliary_list_all(network_manager.virtual_routers, sub_id, "list", caller=caller_name),
                self.auxiliary_list_all(network_manager.virtual_wans, sub_id, "list", caller=caller_name),
                self.auxiliary_list_all(network_manager.vpn_gateways, sub_id, "list", caller=caller_name),
                self.auxiliary_list_all(network_manager.vpn_server_configurations, sub_id, "list", caller=caller_name),
                self.auxiliary_list_all(network_manager.vpn_sites, sub_id, "list", caller=caller_name),
                self.auxiliary_list_all(network_manager.web_application_firewall_policies, sub_id, "list_all", caller=caller_name),
            ])

            # Run config pulls in batches to avoid event loop starvation
            for batch_start in range(0, len(config_coros), self.CONFIG_BATCH_SIZE):
                batch = config_coros[batch_start:batch_start + self.CONFIG_BATCH_SIZE]
                await asyncio.gather(*batch)

            # Resource/compute/storage configs (already naturally bounded)
            async with asyncio.TaskGroup() as tg:
                tg.create_task(self._dump_container_config(), name=f"{caller_name}_dump_container_config")
                tg.create_task(self._dump_vm_config(), name=f"{caller_name}_dump_vm_config")
                tg.create_task(self._dump_all_resources(), name=f"{caller_name}_dump_all_resources")
                tg.create_task(self._dump_diagnostic_settings(), name=f"{caller_name}_dump_diagnostic_settings")
                tg.create_task(self._dump_file_shares(), name=f"{caller_name}_dump_file_shares")
                tg.create_task(self._dump_storage_accounts(), name=f"{caller_name}_dump_storage_accounts")

            # Mark this subscription's configs as complete
            self.write_savestate(config_state_name)

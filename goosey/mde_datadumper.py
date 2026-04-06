#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Untitled Goose Tool: mde_datadumper!
This module has all the telemetry pulls for Microsoft Defender for Endpoint (MDE).

MDE data collection uses two approaches:
- Simple REST endpoints (machines, alerts, indicators, etc.) via helper_single_object.
- Advanced Hunting KQL queries for detailed device telemetry tables (DeviceEvents,
  DeviceProcessEvents, etc.), which use a time-slicing algorithm similar to UAL.

Two auth tokens are used:
- app_auth (securitycenter_api): For MDE-specific REST APIs (api/machines, api/advancedqueries).
- app_auth2 (security_api): For the unified Microsoft 365 Defender advanced hunting API
  (api/advancedhunting), used for AlertInfo/AlertEvidence and Identity tables.
"""

from datetime import datetime, timedelta, timezone
import itertools
from goosey.datadumper import DataDumper
from goosey.progress import get_progress_manager
from goosey.utils import *
import pytz

utc=pytz.UTC

end_29_days_ago = datetime.today().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=29)
today_date = datetime.today().replace(hour=0, minute=0, second=0, microsecond=0)

class MDEDataDumper(DataDumper):
    """Collects Microsoft Defender for Endpoint telemetry.

    Supports two query modes for advanced hunting (set via mde_query_mode in .conf):
    - 'table' (default): Queries each table globally across all machines.
    - 'machine': Queries each table per-machine, creating separate output dirs per device.
    """

    def __init__(self, output_dir, reports_dir, app_auth, app_auth2, app_auth3, app_auth4, session, config, debug, token_manager=None, portal_auth=None, force_repull=False):
        super().__init__(f'{output_dir}{os.path.sep}mde', reports_dir, app_auth, session, debug, token_manager=token_manager, endpoint_key="securitycenter_api", force_repull=force_repull)
        self.app_auth2 = app_auth2  # security_api token for M365 Defender advanced hunting
        self.app_auth3 = app_auth3  # graph_api token for Graph-based hunting queries
        self.app_auth4 = app_auth4  # cloudapp_defender token for Cloud App Security API
        self.portal_auth = portal_auth  # Optional portal session cookies for timeline APIs
        self.failurefile = os.path.join(reports_dir, '_no_results.json')
        self.logger = setup_logger(__name__, debug)
        self.gcc = config_get(config, 'config', 'gcc', self.logger).lower() == "true"
        self.gcc_high = config_get(config, 'config', 'gcc_high', self.logger).lower() == "true"
        self.endpoints = get_endpoints(gcc=self.gcc, gcc_high=self.gcc_high)
        self.mde_url = self.endpoints["securitycenter_api"] + "/"
        self.identity_url = self.endpoints["security_api"]
        self.call_object = [self.mde_url, self.app_auth, self.logger, self.output_dir, self.get_session()]
        self.graph_call_object = [self.endpoints["graph_api"] + "/v1.0/", self.app_auth3, self.logger, self.output_dir, self.get_session()]
        self.threshold = int(config_get(config, 'variables', 'mde_threshold'))
        self.mde_query_mode = config_get(config, 'variables', 'mde_query_mode')
        self.date_range, self.date_start, self.date_end = get_date_range(config, self.logger)
        self.machine_api_semaphore = asyncio.Semaphore(10)
        self.portal_semaphore = asyncio.Semaphore(3)
        self._portal_auth_method = portal_auth.get('auth_method', 'ests_cookie') if portal_auth else None

    async def dump_machines(self) -> None:
        """
        Dump machines with mde
        """
        if self.check_savestate("machines"):
            return
        await helper_single_object("api/machines", self.call_object, self.failurefile)
        self.write_savestate("machines")

    async def dump_alerts(self) -> None:
        """
        Dump alerts
        """
        if self.check_savestate("alerts"):
            return
        await helper_single_object("api/alerts", self.call_object, self.failurefile)
        self.write_savestate("alerts")

    async def dump_indicators(self) -> None:
        """
        Dump indicators
        """
        if self.check_savestate("indicators"):
            return
        await helper_single_object("api/indicators", self.call_object, self.failurefile)
        self.write_savestate("indicators")

    async def dump_investigations(self) -> None:
        """
        Dump investigations
        """
        if self.check_savestate("investigations"):
            return
        await helper_single_object("api/investigations", self.call_object, self.failurefile)
        self.write_savestate("investigations")

    async def dump_library_files(self) -> None:
        """
        Dump library files
        """
        if self.check_savestate("library_files"):
            return
        await helper_single_object("api/libraryfiles", self.call_object, self.failurefile)
        self.write_savestate("library_files")

    async def dump_machine_vulns(self) -> None:
        """
        Dump known machine vulnerabilities
        """
        if self.check_savestate("machine_vulns"):
            return
        await helper_single_object("api/vulnerabilities/machinesVulnerabilities", self.call_object, self.failurefile)
        self.write_savestate("machine_vulns")

    async def dump_software(self) -> None:
        """
        Dump known installed software
        """
        if self.check_savestate("software"):
            return
        await helper_single_object("api/Software", self.call_object, self.failurefile)
        self.write_savestate("software")

    async def dump_recommendations(self) -> None:
        """
        Dump mde recommendations
        """
        if self.check_savestate("recommendations"):
            return
        await helper_single_object("api/recommendations", self.call_object, self.failurefile)
        self.write_savestate("recommendations")

    async def dump_incidents(self) -> None:
        """Dump Defender XDR incidents from the MDE security API.

        Queries GET /api/incidents to collect correlated multi-alert incidents from
        Microsoft Defender XDR. Each incident groups related alerts across endpoints,
        identities, and cloud apps into a single investigation unit.

        Uses self.app_auth (securitycenter_api token) via self.call_object.
        Output: {output_dir}/mde/api_incidents.json (one JSON object per line, JSONL).

        @decision DEC-MDE-INCIDENTS-001
        @title Use helper_single_object for incidents endpoint
        @status accepted
        @rationale The /api/incidents endpoint follows the same OData @odata.nextLink
          pagination contract as /api/alerts, /api/machines, etc. helper_single_object
          handles this transparently, including rate-limit backoff and file output.
        """
        if self.check_savestate("incidents"):
            return
        await helper_single_object("api/incidents", self.call_object, self.failurefile)
        self.write_savestate("incidents")

    async def dump_machine_actions(self) -> None:
        """Dump machine response actions from the MDE security API.

        Queries GET /api/machineactions to collect all containment and remediation
        actions taken on devices: isolation, antivirus scans, live response sessions,
        package collection, and offboarding actions. Useful for reconstructing the
        incident response timeline.

        Uses self.app_auth (securitycenter_api token) via self.call_object.
        Output: {output_dir}/mde/api_machineactions.json (one JSON object per line, JSONL).

        @decision DEC-MDE-MACHINEACTIONS-001
        @title Use helper_single_object for machineactions endpoint
        @status accepted
        @rationale The /api/machineactions endpoint follows the same OData pagination
          contract as all other simple MDE REST endpoints. No custom logic needed —
          same pattern as dump_machines and dump_alerts.
        """
        if self.check_savestate("machine_actions"):
            return
        await helper_single_object("api/machineactions", self.call_object, self.failurefile)
        self.write_savestate("machine_actions")

    async def dump_cloudappactivity(self) -> None:
        """Dump Microsoft Defender for Cloud App activity logs.

        Uses the Cloud App Security API to collect activity logs, supporting both
        current (last 30 days) and archived (up to 6 months) endpoints.
        https://learn.microsoft.com/en-us/defender-cloud-apps/api-activities-list
        """
        caa_output_dir = os.path.join(self.output_dir, "cloud_app_activity")
        statefile = os.path.join(caa_output_dir, ".caa_savestate")
        check_output_dir(caa_output_dir, self.logger)
        app_auth = self.app_auth4
        err = None
        header = {
            'Authorization': '%s %s' % (app_auth.get('token_type', ''), app_auth.get('access_token', '')),
            'Content-Type': 'application/json'
        }
        if not app_auth.get('access_token'):
            self.logger.warning("No cloudapp_defender auth token available, skipping cloud app activity dump")
            return
        unique_ids = set()

        # default end time. Now
        default_end = datetime.now(timezone.utc)

        # default start time
        default_start = (default_end - timedelta(days=31*6))

        if self.date_range:
            default_start = self.date_start
            default_end = self.date_end

        saved_end = load_state(statefile)
        if saved_end:
            default_start = saved_end

        # By default Cloud app activity log can only search 30 days back
        # If searching more than that (up to 6 months) then we need to use the archived endpoint
        # which supports less filtering options and is slower
        unarchived_end = (default_end - timedelta(days=30))
        archived = False
        url = self.endpoints["cloudapp_defender"] + "/api/v1/activities/"
        if default_start < unarchived_end:
            archived = True
            url = self.endpoints["cloudapp_defender"] + "/api/v1/archived_activities/"
            self.logger.debug("Using Archived endpoint")
        # Filters need to be in epoch time
        start = default_start.timestamp() * 1000
        orig_start = start
        last_date = start
        end = default_end.timestamp() * 1000
        self.logger.debug(f"Dumping cloud app activity logs from {default_start} to {default_end}")
        # Total Count is not accurate. Changes on each pull. Is more of an estimate
        tries = 0
        retries = 3
        while last_date < end and tries < retries and err is None:
            total_count = 0
            skip = 0
            has_data = True
            start = last_date
            filters = {
                "date": {
                    "range": [{"start": start, "end": end}]
                }
            }
            prev_percent_done = 0.0
            while has_data and tries < retries:
                data = json.dumps({"isScan": True, "sortField": "date", "sortDirection": "asc", "limit": 5000, "filters": filters})
                if archived:
                    data = json.dumps({"skip": skip, "sortField": "date", "sortDirection": "asc", "filters": filters})
                try:
                    async with self.ahsession.request("POST", url=url, headers=header, data=data) as r:
                        result = await r.json()
                        if r.status == 401:
                            self.logger.error("Detected 401 unauthorized for cloud app activity.")
                            return
                        elif r.status == 403:
                            err = "Insufficient role based permissions"
                            self.logger.error(err)
                            return err
                        elif r.status == 429:
                            error = result['error']
                            message = error['message']
                            seconds = message.split(' ')[-2]
                            self.logger.debug("Sleeping for %s seconds" % (seconds))
                            await asyncio.sleep(int(seconds))
                            err = message
                            tries += 1
                            result = None
                        elif r.status == 200:
                            tries = 0
                            has_data = result["hasNext"]
                            if has_data and "nextQueryFilters" in result.keys():
                                filters = result["nextQueryFilters"]
                            skip += len(result["data"])
                            # Handle weird edge case where the total amount of data does not match what was pulled
                            # The endpoint is acting buggy. Current fix is to adjust by 1 ms to prevent errors
                            first_date = end
                            if len(result["data"]) > 0:
                                first_date = result["data"][0]["timestamp"]
                                last_date = result["data"][0]["timestamp"]
                            for log in result["data"]:
                                if log["timestamp"] < first_date:
                                    first_date = log["timestamp"]
                                if log["timestamp"] > last_date:
                                    last_date = log["timestamp"]
                                unique_ids.add(log["_id"])
                            self.logger.debug(f"Total Logs pulled {skip}")
                            percent_done = ((last_date - orig_start) / (end - orig_start)) * 100
                            if percent_done == prev_percent_done and not archived and result["total"] > 0:
                                filters["date"]["gte"] += 100
                                filters["date"]["range"][0]["start"] = filters["date"]["gte"]
                                has_data = True
                                self.logger.debug(f'New start {filters["date"]["gte"]}')
                                self.logger.debug("Got to a weird state. Adjusting time by 1 ms to fix")
                            prev_percent_done = percent_done
                            self.logger.debug(f"{percent_done}% Done")
                            cur_end = utc.localize(datetime.utcfromtimestamp(last_date/1000))
                            cur_start = utc.localize(datetime.utcfromtimestamp(first_date/1000))
                            # Create the outfile
                            startDate = cur_start.strftime("%Y-%m-%dT%H_%M_%S")
                            endDate = cur_end.strftime("%Y-%m-%dT%H_%M_%S")
                            session_filename = f"cloudappactivity_{startDate}_{endDate}.json"
                            output_file = os.path.join(caa_output_dir, session_filename)
                            with open(output_file, 'a', encoding='utf-8') as f:
                                for x in result["data"]:
                                    f.write(json.dumps(x) + '\n')
                            if len(result["data"]) > 0:
                                self.logger.debug(f"Saving State {cur_end}")
                                save_state(statefile, cur_end)
                        else:
                            self.logger.debug(result)
                            if "error" in result:
                                err = result["error"]["message"]
                                self.logger.error(err)
                            else:
                                self.logger.debug(result)
                except Exception as e:
                    self.logger.error(e, exc_info=True)
                    tries += 1
                    continue
            if total_count == 0:
                break
        if tries >= retries:
            return err

    async def dump_graph_incidents(self) -> None:
        """Dump Microsoft Defender incidents via Graph API.
        https://learn.microsoft.com/en-us/graph/api/security-list-incidents
        """
        await helper_single_object("security/incidents?$expand=alerts", self.graph_call_object, self.failurefile)

    async def check_machines(self):
        self.ensure_token()
        outfile = os.path.join(self.output_dir, 'api_machines.json')
        data = []
        if os.path.exists(outfile):
            with open(outfile, 'r') as f:
                for line in f:
                    data.append(json.loads(line))
        else:
            await helper_single_object('api/machines', self.call_object)
            with open(outfile, 'r') as f:
                for line in f:
                    data.append(json.loads(line))
        return data

    async def dump_advanced_hunting_alerts_incidents(self) -> None:
        """Dumps alerts, incidents, email, cloud app, and behavior events from Defender XDR.

        Queries unified Defender XDR tables via api/advancedhunting/run using the
        security_api token (app_auth2). Tables include:
        - AlertInfo, AlertEvidence: MDE alert and evidence data
        - EmailEvents, EmailAttachmentInfo, EmailUrlInfo, EmailPostDeliveryEvents:
          Defender for Office 365 email telemetry
        - CloudAppEvents: Microsoft Defender for Cloud Apps activity
        - BehaviorInfo: Behavioral detections across Defender XDR

        API Reference: https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-overview
        """

        # default end time. Now
        end = utc.localize(datetime.now())

        # defult start tiem
        start = end - timedelta(days=364)

        if self.date_range:
            self.logger.debug(f'MDE Dump using specified date range: {self.date_start} to {self.date_end}')
            start = utc.localize(datetime.strptime(self.date_start,"%Y-%m-%d"))
            end = utc.localize(datetime.strptime(self.date_end,"%Y-%m-%d"))

        tables = [
            'AlertInfo',
            'AlertEvidence',
            # Defender XDR unified tables (email, cloud app, and behavior telemetry)
            # These require the security_api token (api/advancedhunting/run endpoint)
            'EmailEvents',
            'EmailAttachmentInfo',
            'EmailUrlInfo',
            'EmailPostDeliveryEvents',
            'CloudAppEvents',
            'BehaviorInfo',
        ]

        # Collect table info for shared progress bar
        table_tasks = []
        for table in tables:
            mde_log_dir = os.path.join(self.output_dir, table)
            base_query = table
            check_output_dir(mde_log_dir, self.logger)
            statefile = os.path.join(mde_log_dir, f".{table}.savestate")
            outfile = os.path.join(mde_log_dir, f"{table}.json")
            saved_end = load_state(statefile)
            table_start = start
            if saved_end:
                table_start = max(saved_end, table_start)
            self.logger.debug(f"Generating table dump task for table: {table}, start: {table_start}, end: {end}")
            table_tasks.append((base_query, table_start, end, statefile, outfile))

        if not table_tasks:
            return

        # Single time-based progress bar across all tables
        pm = get_progress_manager()
        table_hours = [max(int((te - ts).total_seconds()) // 3600, 1) for _, ts, te, _, _ in table_tasks]
        total_hours = sum(table_hours)
        bar = None
        bar_name = "mde_alerts_incidents"
        if pm:
            bar = pm.create_time_bar(bar_name, total_hours, desc=f"{'mde_alerts_incidents':<35}", unit='hr')
            if bar:
                bar.bar_format = "{desc} |{bar}| {percentage:3.0f}% | {n_fmt}/{total_fmt} hrs | elapsed {elapsed}"
        mde_progress = {"bar": bar, "pm": pm, "bar_name": bar_name, "hours_done": 0, "total_hours": total_hours}

        tasks = []
        for i, (bq, ts, te, sf, of) in enumerate(table_tasks):
            caller_name = asyncio.current_task().get_name()
            tasks.append(asyncio.create_task(
                self._dump_table(bq, ts, te, path="api/advancedhunting/run", statefile=sf, outfile=of,
                                 shared_progress=mde_progress, table_total_hours=table_hours[i]),
                name=f"{caller_name}_{bq}"))

        await asyncio.gather(*tasks)
        if bar:
            remaining = total_hours - mde_progress["hours_done"]
            if remaining > 0:
                bar.update(remaining)
        if pm:
            pm.complete_task(bar_name)
    dump_advanced_hunting_alerts_incidents._manages_own_progress = True

    async def dump_advanced_hunting_query(self) -> None:
        """Collect MDE advanced hunting data for device telemetry tables.

        Queries 9 device tables (Events, Logon, Registry, Process, Network, File, ImageLoad,
        DeviceInfo, DeviceNetworkInfo) via the MDE-specific advanced queries API
        (api/advancedqueries/run).

        Supports two modes controlled by mde_query_mode in .conf:
        - 'table': One task per table, queries all machines globally.
        - 'machine': One task per (machine, table) combination, filters by DeviceId.
          Creates per-machine output directories named by computerDnsName.

        API Reference: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/run-advanced-query-api
        """
        # Build machine ID -> DNS name mapping for per-machine output directories
        data = await self.check_machines()
        machine_ids = list(findkeys(data, 'id'))
        machine_names = list(findkeys(data, 'computerDnsName'))
        mapOfIds = dict(zip(machine_ids, machine_names))

        end = utc.localize(datetime.now())
        start = end - timedelta(days=364)

        if self.date_range:
            self.logger.debug(f'MDE Dump using specified date range: {self.date_start} to {self.date_end}')
            start = utc.localize(datetime.strptime(self.date_start,"%Y-%m-%d"))
            end = utc.localize(datetime.strptime(self.date_end,"%Y-%m-%d"))

        tables = [
            'DeviceEvents',
            'DeviceLogonEvents',
            'DeviceRegistryEvents',
            'DeviceProcessEvents',
            'DeviceNetworkEvents',
            'DeviceFileEvents',
            'DeviceImageLoadEvents',
            # Device inventory and network interface tables (MDE-specific, securitycenter_api)
            'DeviceInfo',
            'DeviceNetworkInfo',
        ]

        # In 'table' mode: iterate ("", table) pairs — no machine filter.
        # In 'machine' mode: iterate (machine_id, table) pairs — filter by DeviceId.
        machine_mode = False
        machine_table_list = itertools.product([""], tables)
        if self.mde_query_mode == "machine":
            machine_mode = True
            machine_table_list = list(itertools.product(machine_ids, tables))

        # Convert to list so we can count total tasks for the progress bar
        machine_table_list = list(machine_table_list)

        # Collect table info for shared progress bar
        table_tasks = []
        for machine_id, table in machine_table_list:
            mde_log_dir = os.path.join(self.output_dir, table)
            machine_name = str(mapOfIds.get(machine_id, ""))
            base_query = table
            if machine_mode:
                base_query = f"{table} | where DeviceId=='{machine_id}'"
                mde_log_dir = os.path.join(self.output_dir, machine_name)
            check_output_dir(mde_log_dir, self.logger)

            statefile = os.path.join(mde_log_dir, f".{table}_{machine_id}.savestate")
            outfile = os.path.join(mde_log_dir, f"{table}_{machine_id}.json")
            saved_end = load_state(statefile)
            table_start = start
            if saved_end:
                table_start = max(saved_end, table_start)
            self.logger.debug(f"Generating table dump task for table: {table}, machine: {machine_name}, start: {table_start}, end: {end}")
            table_tasks.append((base_query, table_start, end, statefile, outfile, table))

        if not table_tasks:
            return

        # Single time-based progress bar across all tables
        pm = get_progress_manager()
        table_hours = [max(int((te - ts).total_seconds()) // 3600, 1) for _, ts, te, _, _, _ in table_tasks]
        total_hours = sum(table_hours)
        bar = None
        bar_name = "mde_adv_hunting"
        if pm:
            bar = pm.create_time_bar(bar_name, total_hours, desc=f"{'mde_adv_hunting':<35}", unit='hr')
            if bar:
                bar.bar_format = "{desc} |{bar}| {percentage:3.0f}% | {n_fmt}/{total_fmt} hrs | elapsed {elapsed}"
        mde_progress = {"bar": bar, "pm": pm, "bar_name": bar_name, "hours_done": 0, "total_hours": total_hours}

        tasks = []
        for i, (bq, ts, te, sf, of, tname) in enumerate(table_tasks):
            caller_name = asyncio.current_task().get_name()
            tasks.append(asyncio.create_task(
                self._dump_table(bq, ts, te, path="api/advancedqueries/run", statefile=sf, outfile=of,
                                 shared_progress=mde_progress, table_total_hours=table_hours[i]),
                name=f"{caller_name}_{tname}"))
        await asyncio.gather(*tasks)
        if bar:
            remaining = total_hours - mde_progress["hours_done"]
            if remaining > 0:
                bar.update(remaining)
        if pm:
            pm.complete_task(bar_name)
    dump_advanced_hunting_query._manages_own_progress = True

    async def dump_advanced_identity_hunting_query(self) -> None:
        """Collect identity-related tables from M365 Defender advanced hunting.

        Queries IdentityDirectoryEvents, IdentityLogonEvents, and IdentityQueryEvents
        via the unified M365 Defender API (api/advancedhunting/run), which uses the
        security_api token (app_auth2) rather than the MDE-specific token.

        API Reference: https://learn.microsoft.com/en-us/microsoft-365/security/defender/api-advanced-hunting
        """
        self.ensure_token("security_api")

        # default end time. Now
        end = utc.localize(datetime.now())

        # defult start tiem
        start = end - timedelta(days=364)

        if self.date_range:
            self.logger.debug(f'MDE Dump using specified date range: {self.date_start} to {self.date_end}')
            start = utc.localize(datetime.strptime(self.date_start,"%Y-%m-%d"))
            end = utc.localize(datetime.strptime(self.date_end,"%Y-%m-%d"))

        id_tables = ['IdentityDirectoryEvents', 'IdentityLogonEvents', 'IdentityQueryEvents']

        # Collect table info for shared progress bar
        table_tasks = []
        for table in id_tables:
            mde_log_dir = os.path.join(self.output_dir, table)
            base_query = table
            check_output_dir(mde_log_dir, self.logger)
            statefile = os.path.join(mde_log_dir, f".{table}.savestate")
            outfile = os.path.join(mde_log_dir, f"{table}.json")
            saved_end = load_state(statefile)
            table_start = start
            if saved_end:
                table_start = max(saved_end, table_start)
            self.logger.debug(f"Generating table dump task for table: {table}, start: {table_start}, end: {end}")
            table_tasks.append((base_query, table_start, end, statefile, outfile))

        if not table_tasks:
            return

        # Single time-based progress bar across all tables
        pm = get_progress_manager()
        table_hours = [max(int((te - ts).total_seconds()) // 3600, 1) for _, ts, te, _, _ in table_tasks]
        total_hours = sum(table_hours)
        bar = None
        bar_name = "mde_identity_hunting"
        if pm:
            bar = pm.create_time_bar(bar_name, total_hours, desc=f"{'mde_identity_hunting':<35}", unit='hr')
            if bar:
                bar.bar_format = "{desc} |{bar}| {percentage:3.0f}% | {n_fmt}/{total_fmt} hrs | elapsed {elapsed}"
        mde_progress = {"bar": bar, "pm": pm, "bar_name": bar_name, "hours_done": 0, "total_hours": total_hours}

        tasks = []
        for i, (bq, ts, te, sf, of) in enumerate(table_tasks):
            caller_name = asyncio.current_task().get_name()
            tasks.append(asyncio.create_task(
                self._dump_table(bq, ts, te, path="api/advancedhunting/run", statefile=sf, outfile=of,
                                 shared_progress=mde_progress, table_total_hours=table_hours[i]),
                name=f"{caller_name}_{bq}"))

        await asyncio.gather(*tasks)
        if bar:
            remaining = total_hours - mde_progress["hours_done"]
            if remaining > 0:
                bar.update(remaining)
        if pm:
            pm.complete_task(bar_name)
    dump_advanced_identity_hunting_query._manages_own_progress = True

    async def dump_advanced_hunting_cloud_apps(self) -> None:
        """Dumps results from Microsoft Defender for Cloud Apps tables via Graph API.

        Queries CloudAppEvents, CloudAuditEvents, CloudProcessEvents, BehaviorEntities,
        BehaviorInfo tables using the Graph Security runHuntingQuery endpoint.
        API Reference: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables
        """
        tables = ['CloudAppEvents', 'CloudAuditEvents', 'CloudProcessEvents', 'BehaviorEntities', 'BehaviorInfo']
        await self._dump_graph_tables_helper(tables=tables)

    async def dump_advanced_hunting_email_url(self) -> None:
        """Dumps results from Microsoft XDR email and URL click event tables via Graph API.
        API Reference: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables
        """
        tables = ['EmailAttachmentInfo', 'EmailEvents', 'EmailPostDeliveryEvents', 'EmailUrlInfo', 'UrlClickEvents']
        await self._dump_graph_tables_helper(tables=tables)

    async def dump_advanced_vulnerability_management(self) -> None:
        """Dumps results from Microsoft Defender vulnerability management tables via Graph API.
        API Reference: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables
        """
        tables = [
            'DeviceBaselineComplianceAssessment', 'DeviceBaselineComplianceAssessmentKB',
            'DeviceBaselineComplianceProfiles', 'DeviceTvmBrowserExtensions',
            'DeviceTvmBrowserExtensionsKB', 'DeviceTvmCertificateInfo',
            'DeviceTvmHardwareFirmware', 'DeviceTvmInfoGathering',
            'DeviceTvmInfoGatheringKB', 'DeviceTvmSecureConfigurationAssessment',
            'DeviceTvmSecureConfigurationAssessmentKB', 'DeviceTvmSoftwareEvidenceBeta',
            'DeviceTvmSoftwareInventory', 'DeviceTvmSoftwareVulnerabilities',
            'DeviceTvmSoftwareVulnerabilitiesKB'
        ]
        await self._dump_graph_tables_helper(tables=tables)

    async def dump_advanced_hunting_exposure(self) -> None:
        """Dumps results from Microsoft Security Exposure Management tables via Graph API.
        API Reference: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables
        """
        tables = ['ExposureGraphEdges', 'ExposureGraphNodes']
        await self._dump_graph_tables_helper(tables=tables)

    async def dump_advanced_hunting_devices_graph(self) -> None:
        """Dumps device telemetry tables via Graph API runHuntingQuery endpoint.
        API Reference: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables
        """
        tables = [
            'DeviceEvents', 'DeviceFileCertificateInfo', 'DeviceLogonEvents',
            'DeviceRegistryEvents', 'DeviceProcessEvents', 'DeviceNetworkEvents',
            'DeviceFileEvents', 'DeviceImageLoadEvents', 'DeviceInfo', 'DeviceNetworkInfo'
        ]
        await self._dump_graph_tables_helper(tables=tables)

    async def dump_advanced_hunting_identity_graph(self) -> None:
        """Dumps identity tables via Graph API runHuntingQuery endpoint.
        API Reference: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables
        """
        tables = [
            'IdentityDirectoryEvents', 'IdentityLogonEvents', 'IdentityQueryEvents',
            'IdentityInfo', 'AADSignInEventsBeta', 'AADSpnSignInEventsBeta'
        ]
        await self._dump_graph_tables_helper(tables=tables)

    async def _dump_graph_tables_helper(self, tables=[]) -> None:
        """Helper for dumping tables via Graph Security runHuntingQuery endpoint."""
        default_end = datetime.now(timezone.utc)
        default_start = default_end - timedelta(days=364)

        if self.date_range:
            self.logger.debug(f'Graph hunt using specified date range: {self.date_start} to {self.date_end}')
            default_start = self.date_start
            default_end = self.date_end

        tasks = []
        for table in tables:
            start = default_start
            end = default_end
            mde_log_dir = os.path.join(self.output_dir, table)
            base_query = table
            check_output_dir(mde_log_dir, self.logger)
            statefile = os.path.join(mde_log_dir, f".{table}.savestate")
            outfile_start = os.path.join(mde_log_dir, f"{table}_")
            saved_end = load_state(statefile)
            if saved_end:
                start = max(saved_end, start)
            self.logger.debug(f"Generating graph table dump task for table: {table}, start: {start}, end: {end}")
            caller_name = asyncio.current_task().get_name()
            tasks.append(asyncio.create_task(
                self._dump_graph_table(base_query, start, end, statefile=statefile, outfile_start=outfile_start),
                name=f"{caller_name}_{table}"))
        await asyncio.gather(*tasks)

    async def run_graph_hunting_query(self, query, start, end, bounds, summarize=False):
        """Execute a KQL query via the Graph Security runHuntingQuery endpoint.

        Uses app_auth3 (graph_api token) to query the unified Graph Security API.
        This is separate from run_mde_query which uses MDE/security_api tokens.
        """
        sleep_errors = ["Server disconnected", "Cannot connect", "WinError 10054"]
        slice_errors = ['exceeded the allowed limits', 'exceeded the allowed result size']

        app_auth = self.app_auth3
        header = {
            'Authorization': '%s %s' % (app_auth['token_type'], app_auth['access_token']),
            'Content-Type': 'application/json'
        }
        full_query = query
        if start and not end:
            full_query += f"|where Timestamp > datetime({start})"
        elif end and not start:
            full_query += f"|where Timestamp < datetime({end})"
        elif end and start:
            full_query += f"|where Timestamp between(datetime({start})..datetime({end}))"

        if summarize:
            full_query += f"| summarize Count=count(), FirstEvent=min(Timestamp), LastEvent=max(Timestamp)"

        self.logger.debug(full_query)
        payload = {"Query": full_query}
        data = json.dumps(payload)
        result = None
        err = None
        url = self.endpoints["graph_api"] + "/v1.0/security/runHuntingQuery"
        try:
            async with self.ahsession.request("POST", url=url, headers=header, data=data) as r:
                result = await r.json()
                if r.status == 401:
                    self.logger.error("Detected 401 unauthorized for Graph hunting query.")
                    err = "Unauthorized (401)"
                    result = None
                elif r.status == 429:
                    error = result['error']
                    message = error['message']
                    seconds = message.split(' ')[-2]
                    self.logger.debug("Sleeping for %s seconds" % (seconds))
                    await asyncio.sleep(int(seconds))
                    err = message
                    result = None
                else:
                    if "error" in result:
                        err = result["error"]["message"]
                    if "results" in result:
                        result = result["results"]
                    else:
                        result = None
        except Exception as e:
            self.logger.error('Error on retrieval: {}'.format(str(e)))
            err = str(e)

        count = None
        done_status = False
        if summarize and result:
            count = result[0]["Count"]
        elif result:
            count = len(result)
        if count is not None:
            done_status = count < self.threshold
        bounds = insert_bounds_record({"count": count,
                  "start": start,
                  "end": end,
                  "done_status": done_status}, bounds)

        if err:
            self.logger.debug(err)
        if err is TimeoutError or \
           err and any(e in err for e in slice_errors) or \
           (count and count >= self.threshold):
           new_end_ts = start.timestamp() + ((end.timestamp() - start.timestamp())/2)
           end = datetime.fromtimestamp(new_end_ts, utc)
        elif err and any(e in err for e in sleep_errors):
            await asyncio.sleep(60)

        return result, err, end, bounds

    async def _dump_graph_table(self, base_query, start, end, statefile, outfile_start, retries=3):
        """Query a table via Graph runHuntingQuery and pull logs for the timeframe."""
        totalResultCount = 0
        totalResultEnd = start
        totalSavedResults = 0
        origStart = start
        finalEnd = end
        tries = 0
        final_record = {"count": None, "start": end, "end": end + timedelta(1000), "done_status": False}
        bounds = [final_record]

        # initial query loop to set a baseline
        while start < finalEnd and tries < retries*2:
            summary, err, new_end, bounds = await self.run_graph_hunting_query(base_query, start, end, bounds, summarize=True)
            if err:
                tries += 1
            elif summary is not None and summary[0]["Count"] == 0:
                tries = 0
                if origStart == start and finalEnd == end:
                    self.logger.debug(f"No logs for {base_query} from {start} to {end}")
                    save_state(statefile, end)
                    return
                start = end
                end = finalEnd
                bounds = [final_record]
                continue
            elif summary is not None and summary[0]["Count"] > 0:
                tries = 0
                totalResultCount = summary[0]["Count"]
                totalResultEnd = end
                start = dateutil.parser.parse(summary[0]["FirstEvent"])
                bounds[0]["start"] = start
                break
            end = new_end

        while start < finalEnd and tries < retries:
            startDate = start.strftime("%Y-%m-%dT%H:%M:%S")
            endDate = end.strftime("%Y-%m-%dT%H:%M:%S")
            bound = f'[{startDate} - {endDate}]'

            if bounds[0]["count"] is None or \
               (bounds[0]["count"] >= self.threshold and end <= bounds[0]["end"]):
                summary, err, end, bounds = await self.run_graph_hunting_query(base_query, start, end, bounds, summarize=True)
                if err:
                    tries += 1
                    continue
                tries = 0
                if summary[0]["Count"] >= self.threshold:
                    continue
                if summary[0]["Count"] == 0:
                    end = bounds[0]["end"]
                    start = bounds[0]["start"]
                    continue

            results, err, end, bounds = await self.run_graph_hunting_query(base_query, start, end, bounds)
            if err:
                tries += 1
                continue
            if len(results) >= 0:
                if start >= totalResultEnd:
                    totalResultCount += len(results)
                self.logger.debug('Size of table: %s' % len(results))
                session_filename = outfile_start + f"{startDate}_{endDate}.json".replace(":", "_")
                with open(session_filename, 'a', encoding='utf-8') as f:
                    for x in results:
                        f.write(json.dumps(x) + '\n')

                save_state(statefile, end)

                tries = 0
                end = bounds[0]["end"]
                start = bounds[0]["start"]
                if bounds[0]["count"] is not None and bounds[0]["count"] >= self.threshold:
                    new_end_ts = start.timestamp() + ((end.timestamp() - start.timestamp())/2)
                    end = datetime.fromtimestamp(new_end_ts, utc)

                totalSavedResults += len(results)
                self.logger.debug(f"Total results {totalSavedResults}/{totalResultCount}")
                continue

    async def run_mde_query(self, query, start, end, bounds, path='api/advancedqueries/run', summarize=False):
        """Execute a KQL query against MDE's advanced hunting API.

        Builds a full KQL query by appending time filters and optional summarize clause,
        then POSTs it to the specified API path. Handles rate limiting (429), auth errors (401),
        and result-size errors by adjusting the time range (halving) or sleeping.

        Args:
            query: Base KQL query (e.g. 'DeviceEvents' or "DeviceEvents | where DeviceId=='...'").
            start: Start of time filter (appended as Timestamp filter).
            end: End of time filter.
            bounds: List of time-bound records for tracking search progress.
            path: API endpoint path. Two options:
                  - 'api/advancedqueries/run': MDE-specific (uses securitycenter_api token)
                  - 'api/advancedhunting/run': M365 Defender unified (uses security_api token)
            summarize: If True, appends a summarize clause to get count/time range only.

        Returns:
            Tuple of (results_list, error_string, adjusted_end, updated_bounds).
        """

        # Errors that indicate server-side issues — sleep and retry
        sleep_errors = ["Server disconnected", "Cannot connect", "WinError 10054"]
        # Errors that indicate the time slice has too much data — halve the range
        slice_errors = ['exceeded the allowed limits', 'exceeded the allowed result size']

        # Select the correct auth token based on which API endpoint is being used
        app_auth = self.app_auth
        if path == "api/advancedhunting/run":
            self.ensure_token("security_api")
            app_auth = self.app_auth2
        else:
            self.ensure_token()
        header = {
            'Authorization': '%s %s' % (app_auth['token_type'], app_auth['access_token']),
            'Content-Type': 'application/json'
        }
        # Apply time filters
        full_query = query
        if start and not end:
            full_query += f"|where Timestamp > datetime({start})"
        elif end and not start:
            full_query += f"|where Timestamp < datetime({end})"
        elif end and start:
            full_query += f"|where Timestamp between(datetime({start})..datetime({end}))"

        if summarize:
            full_query += f"| summarize Count=count(), FirstEvent=min(Timestamp), LastEvent=max(Timestamp)"

        self.logger.debug(full_query)
        payload = {"Query": full_query}
        data=json.dumps(payload)
        splits = full_query.split('|where Timestamp')
        result = None
        err = None
        url = self.mde_url + path
        try:
            async with self.ahsession.request("POST", url=url, headers=header, data=data) as r:
                result = await r.json()
                if r.status == 401:
                    self.logger.error("Detected 401 unauthorized for MDE query.")
                    err = "Unauthorized (401)"
                    result = None
                elif r.status == 429:
                    error = result['error']
                    message = error['message']
                    seconds = message.split(' ')[-2]
                    self.logger.debug("Sleeping for %s seconds" % (seconds))
                    await asyncio.sleep(int(seconds))
                    err = message
                    result = None
                else:
                    if "error" in result:
                        err = result["error"]["message"]
                    if "Results" in result:
                        result = result["Results"]
                    else:
                        result = None

        except Exception as e:
            self.logger.error('Error on retrieval: {}'.format(str(e)))
            err = str(e)

        # Insert a new record into the bounds.
        count = None
        done_status = False
        if summarize and result:
            count = result[0]["Count"]
        elif result:
            count = len(result)
        if count != None:
            done_status = count < self.threshold
        bounds = insert_bounds_record({"count": count,
                  "start": start,
                  "end": end,
                  "done_status": done_status}, bounds)

        # Checking errors and if the time should be cut
        if err:
            self.logger.debug(err)
        if err is TimeoutError or \
           err and any(e in err for e in slice_errors) or \
           (count and count >= self.threshold):
           new_end_ts = start.timestamp() + ((end.timestamp() - start.timestamp())/2)
           end = datetime.fromtimestamp(new_end_ts, utc)
        elif err and any(e in err for e in sleep_errors):
            await asyncio.sleep(RATE_LIMIT_SLEEP_SECONDS)

        return result, err, end, bounds


    async def _dump_table(self, base_query, start, end, path, statefile, outfile, retries=3, on_complete=None, shared_progress=None, table_total_hours=None):
        """Query an MDE/M365 Defender table and collect all logs for a time range.

        Uses a two-phase approach:
        Phase 1 (summarize loop): Runs summarize queries to find time ranges with data
            and narrow down to ranges below the threshold. Skips empty ranges quickly.
        Phase 2 (data loop): For ranges confirmed to be below threshold, runs full queries
            to retrieve actual log records and writes them to the output file.

        The bounds list tracks progress through the time range, similar to UAL bounds.
        A sentinel "final_record" at the end prevents edge cases with empty bounds.

        Args:
            base_query: KQL table name or query prefix (e.g. 'DeviceEvents').
            start: Start of the collection time range.
            end: End of the collection time range.
            path: API endpoint path for the query.
            statefile: Path to save checkpoint after each successful time slice.
            outfile: Path to append collected log records.
            retries: Max consecutive errors before abandoning.
            on_complete: Legacy callback invoked when table finishes.
            shared_progress: Shared dict with 'bar', 'hours_done' for time-based progress.
            table_total_hours: This table's share of the total hours in the progress bar.
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
            """Update the shared progress bar based on time covered."""
            nonlocal my_hours_reported
            if not shared_progress or not shared_progress.get("bar"):
                return
            covered_secs = max((covered_end - origStart).total_seconds(), 0)
            total_secs = max((finalEnd - origStart).total_seconds(), 1)
            fraction = min(covered_secs / total_secs, 1.0)
            my_covered = int(fraction * my_total_hours)
            delta = my_covered - my_hours_reported
            if delta > 0:
                shared_progress["bar"].update(delta)
                shared_progress["hours_done"] += delta
                my_hours_reported = my_covered

        def _complete_progress():
            """Flush remaining hours for this table to the shared bar."""
            nonlocal my_hours_reported
            if not shared_progress or not shared_progress.get("bar"):
                return
            delta = my_total_hours - my_hours_reported
            if delta > 0:
                shared_progress["bar"].update(delta)
                shared_progress["hours_done"] += delta
                my_hours_reported = my_total_hours
        # Sentinel record: prevents empty-bounds edge cases. Placed at the end of
        # the time range so the loop terminates naturally when all real bounds are consumed.
        final_record = {"count": None,
                        "start": end,
                        "end": end + timedelta(1000),
                        "done_status": False}
        bounds = [final_record]
        # Phase 1: summarize queries to find ranges with data and estimate counts
        summary = None
        while start < finalEnd and tries < retries*2:
            # Narrow down until we have a valid timeframe
            summary, err, new_end, bounds = await self.run_mde_query(base_query, start, end, bounds, path=path, summarize=True)
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
                    if on_complete:
                        on_complete()
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
            startDate = start.strftime("%Y-%m-%dT%H:%M:%S")
            endDate = end.strftime("%Y-%m-%dT%H:%M:%S")
            session_set = set() # Unique results returned. Used to detect duplicates
            bound = f'[{startDate} - {endDate}]'

            # Run a search to get a summary of the timeframe. Faster and provides more info
            if bounds[0]["count"] == None or \
               (bounds[0]["count"] >= self.threshold and end <= bounds[0]["end"]):
                summary, err, end, bounds = await self.run_mde_query(base_query, start, end, bounds, path=path, summarize=True)
                if err:
                    tries += 1
                    continue
                tries = 0
                if summary[0]["Count"] >= self.threshold:
                    continue
                if summary[0]["Count"] == 0:
                    end = bounds[0]["end"]
                    start = bounds[0]["start"]
                    _update_progress(start)
                    continue

            results, err, end, bounds = await self.run_mde_query(base_query, start, end, bounds, path=path)
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
                if bounds[0]["count"] != None and bounds[0]["count"] >= self.threshold:
                    new_end_ts = start.timestamp() + ((end.timestamp() - start.timestamp())/2)
                    end = datetime.fromtimestamp(new_end_ts, utc)

                totalSavedResults += len(results)
                self.logger.debug(f"Total results {totalSavedResults}/{totalResultCount}")
                continue

        _complete_progress()
        if on_complete:
            on_complete()

    def _build_portal_headers(self, extra_headers=None):
        """Build request headers for portal proxy API calls.

        Supports two auth methods:
        - 'refresh_token': Uses Bearer token in Authorization header.
        - 'ests_cookie': Uses sccauth cookie and X-XSRF-TOKEN header.
        """
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0',
        }
        if self._portal_auth_method == 'refresh_token':
            access_token = self.portal_auth.get('access_token', '')
            headers['Authorization'] = f'Bearer {access_token}'
        else:
            sccauth = self.portal_auth.get('sccauth', '')
            xsrf = self.portal_auth.get('xsrf_token', '')
            headers['Cookie'] = f'sccauth={sccauth}'
            headers['X-XSRF-TOKEN'] = xsrf
        if extra_headers:
            headers.update(extra_headers)
        return headers

    async def _fetch_paginated_endpoint(self, url, outfile, statefile=None, params=None, retries=5):
        """Fetch a paginated MDE REST API endpoint following @odata.nextLink.

        Handles 429 rate limiting with exponential backoff, 401 auth errors,
        and writes results as JSONL. Saves state after each page.

        Args:
            url: Full API URL for the initial request.
            outfile: Path to append JSONL results.
            statefile: Optional path for save state checkpoint.
            params: Optional query parameters dict.
            retries: Max consecutive errors before giving up.
        """
        self.ensure_token()
        header = {
            'Authorization': '%s %s' % (self.app_auth['token_type'], self.app_auth['access_token']),
            'Content-Type': 'application/json'
        }
        tries = 0
        total_count = 0
        while url and tries < retries:
            try:
                async with self.ahsession.get(url, headers=header, params=params, timeout=aiohttp.ClientTimeout(total=600)) as r:
                    if r.status == 401:
                        self.logger.error(f"401 Unauthorized fetching {url}. Re-auth may be needed.")
                        self.ensure_token()
                        header['Authorization'] = '%s %s' % (self.app_auth['token_type'], self.app_auth['access_token'])
                        tries += 1
                        continue
                    elif r.status == 429:
                        retry_after = int(r.headers.get('Retry-After', RATE_LIMIT_SLEEP_SECONDS))
                        self.logger.debug(f"429 rate limited. Sleeping {retry_after}s.")
                        await asyncio.sleep(retry_after)
                        tries += 1
                        continue
                    elif r.status >= 400:
                        body = await r.text()
                        self.logger.error(f"HTTP {r.status} from {url}: {body[:500]}")
                        tries += 1
                        continue

                    result = await r.json()
                    values = result.get('value', [])
                    if values:
                        with open(outfile, 'a', encoding='utf-8') as f:
                            for item in values:
                                f.write(json.dumps(item) + '\n')
                        total_count += len(values)

                    if statefile:
                        # Save the count as a simple checkpoint
                        open(statefile, 'w').write(str(total_count))

                    url = result.get('@odata.nextLink')
                    params = None  # nextLink includes params already
                    tries = 0  # Reset on success

            except asyncio.TimeoutError:
                self.logger.error(f"Timeout fetching {url}")
                tries += 1
            except Exception as e:
                self.logger.error(f"Error fetching {url}: {e}")
                tries += 1

        return total_count

    async def dump_machine_alerts(self) -> None:
        """Collect per-machine alerts from the official MDE REST API.

        Iterates over all known machines and fetches alerts for each one via
        GET /api/machines/{id}/alerts. Uses a semaphore to respect the MDE
        rate limit of ~100 calls/min. Writes JSONL per machine.
        """
        self.ensure_token()
        data = await self.check_machines()
        machine_ids = list(findkeys(data, 'id'))
        machine_names = list(findkeys(data, 'computerDnsName'))
        id_to_name = dict(zip(machine_ids, machine_names))

        alerts_dir = os.path.join(self.output_dir, 'machine_alerts')
        check_output_dir(alerts_dir, self.logger)

        # Build date filter if configured
        date_filter = ""
        if self.date_range:
            date_filter = f"?$filter=alertCreationTime ge {self.date_start}T00:00:00Z"
            if self.date_end:
                date_filter += f" and alertCreationTime le {self.date_end}T23:59:59Z"

        async def _fetch_machine(machine_id):
            hostname = id_to_name.get(machine_id, 'unknown')
            safe_hostname = hostname.replace('/', '_').replace('\\', '_')
            outfile = os.path.join(alerts_dir, f"{safe_hostname}_{machine_id}_alerts.json")
            statefile = os.path.join(alerts_dir, f".{machine_id}.savestate")

            # Skip if already completed (savestate exists and outfile exists)
            if os.path.isfile(statefile) and os.path.isfile(outfile):
                self.logger.debug(f"Skipping machine {hostname} ({machine_id}) - already collected.")
                return

            url = f"{self.mde_url}api/machines/{machine_id}/alerts{date_filter}"
            async with self.machine_api_semaphore:
                count = await self._fetch_paginated_endpoint(url, outfile, statefile)
                if count > 0:
                    self.logger.debug(f"Collected {count} alerts for {hostname} ({machine_id})")

        tasks = [asyncio.create_task(_fetch_machine(mid), name=f"machine_alerts_{mid}") for mid in machine_ids]
        if tasks:
            self.logger.info(f"Collecting alerts for {len(tasks)} machines...")
            await asyncio.gather(*tasks)
            self.logger.info("Machine alerts collection complete.")
        else:
            self.logger.info("No machines found for alert collection.")

    async def dump_missing_kbs(self) -> None:
        """Collect missing KB patches per machine from the MDE REST API.

        Iterates over all known machines and fetches the list of missing
        security updates (KBs) for each one via GET /api/machines/{id}/getmissingkbs.
        Uses a semaphore (machine_api_semaphore) to respect the MDE rate limit of
        ~100 calls/min, matching the pattern used by dump_machine_alerts.

        Machine list is sourced from check_machines(), which re-uses a cached
        api_machines.json if dump_machines has already run in this session.
        Per-machine save state is stored alongside output files so interrupted
        runs resume from the last completed machine.

        Output: {output_dir}/mde/missing_kbs/<hostname>_<machine_id>_missing_kbs.json
                One JSONL file per machine; machines with zero results produce no file.

        @decision DEC-MDE-MISSING-KBS-001
        @title Per-machine semaphore-limited fetching for missing KBs
        @status accepted
        @rationale The /api/machines/{id}/getmissingkbs endpoint is a per-machine call
          with the same MDE rate-limit characteristics as /api/machines/{id}/alerts.
          Reusing check_machines(), machine_api_semaphore, and _fetch_paginated_endpoint
          keeps the code consistent with dump_machine_alerts and avoids duplicating
          rate-limit and pagination logic.
        """
        self.ensure_token()
        data = await self.check_machines()
        machine_ids = list(findkeys(data, 'id'))
        machine_names = list(findkeys(data, 'computerDnsName'))
        id_to_name = dict(zip(machine_ids, machine_names))

        missing_kbs_dir = os.path.join(self.output_dir, 'missing_kbs')
        check_output_dir(missing_kbs_dir, self.logger)

        async def _fetch_machine_missing_kbs(machine_id):
            hostname = id_to_name.get(machine_id, 'unknown')
            safe_hostname = hostname.replace('/', '_').replace('\\', '_')
            outfile = os.path.join(missing_kbs_dir, f"{safe_hostname}_{machine_id}_missing_kbs.json")
            statefile = os.path.join(missing_kbs_dir, f".{machine_id}.savestate")

            # Skip if already completed (savestate exists and outfile exists)
            if os.path.isfile(statefile) and os.path.isfile(outfile):
                self.logger.debug(f"Skipping machine {hostname} ({machine_id}) - missing KBs already collected.")
                return

            url = f"{self.mde_url}api/machines/{machine_id}/getmissingkbs"
            async with self.machine_api_semaphore:
                count = await self._fetch_paginated_endpoint(url, outfile, statefile)
                if count > 0:
                    self.logger.debug(f"Collected {count} missing KBs for {hostname} ({machine_id})")
                elif os.path.isfile(statefile):
                    # Mark completion even when no KBs are missing (no output file written)
                    pass

        tasks = [asyncio.create_task(_fetch_machine_missing_kbs(mid), name=f"missing_kbs_{mid}") for mid in machine_ids]
        if tasks:
            self.logger.info(f"Collecting missing KBs for {len(tasks)} machines...")
            await asyncio.gather(*tasks)
            self.logger.info("Missing KBs collection complete.")
        else:
            self.logger.info("No machines found for missing KB collection.")

    async def _fetch_portal_timeline(self, url, outfile, statefile, headers,
                                     method="GET", json_body=None, max_pages=500):
        """Fetch timeline data from the M365 Defender portal proxy API.

        Supports both GET (device timeline) and POST (identity timeline) methods.
        Response fields: device timeline uses 'Items'/'Next', identity uses list responses.
        Handles 403 as a rate limit signal (portal uses 403 instead of 429).

        Args:
            url: Initial portal API URL.
            outfile: Path to append JSONL results.
            statefile: Path for save state checkpoint.
            headers: Request headers including sccauth cookies and XSRF token.
            method: HTTP method - "GET" for device timeline, "POST" for identity timeline.
            json_body: JSON body for POST requests (identity timeline pagination).
            max_pages: Maximum pages to fetch before stopping.

        Returns:
            Total number of events collected.
        """
        total_count = 0
        retries = 5
        tries = 0
        page = 0

        while url and page < max_pages and tries < retries:
            try:
                request_kwargs = {
                    'headers': headers,
                    'timeout': aiohttp.ClientTimeout(total=300),
                }
                if method == "POST" and json_body is not None:
                    request_kwargs['json'] = json_body

                async with self.ahsession.request(method, url, **request_kwargs) as r:
                    if r.status == 403:
                        body = await r.text()
                        if "User is not exposed to machine" in body:
                            # Stealth rate limiting disguised as 403 - treat like 429
                            self.logger.debug("Portal API 403 (stealth rate limit). Sleeping 30s.")
                        else:
                            self.logger.debug(f"Portal API 403 (rate limited): {body[:200]}. Sleeping 30s.")
                        await asyncio.sleep(30)
                        tries += 1
                        continue
                    elif r.status == 401:
                        self.logger.error("Portal API 401 Unauthorized. ESTS cookie may have expired.")
                        return total_count
                    elif r.status >= 400:
                        body = await r.text()
                        self.logger.error(f"Portal API HTTP {r.status}: {body[:500]}")
                        tries += 1
                        continue

                    result = await r.json()

                    # Device timeline uses 'Items', identity uses list or 'results'/'value'
                    events = result.get('Items', result.get('results', result.get('value', [])))
                    if events:
                        with open(outfile, 'a', encoding='utf-8') as f:
                            for event in events:
                                f.write(json.dumps(event) + '\n')
                        total_count += len(events)

                    save_state(statefile, str(total_count), is_datetime=False)

                    # Device timeline uses 'Next', identity uses 'next'
                    next_url = result.get('Next', result.get('next'))
                    if next_url and not next_url.startswith('http'):
                        base = url.split('/apiproxy/')[0]
                        next_url = base + next_url

                    # For POST-based pagination (identity), return after one page;
                    # caller handles skip-based pagination
                    if method == "POST":
                        url = None
                    else:
                        url = next_url
                    page += 1
                    tries = 0

            except asyncio.TimeoutError:
                self.logger.error(f"Timeout on portal API: {url}")
                tries += 1
            except Exception as e:
                self.logger.error(f"Error on portal API: {e}")
                tries += 1

        return total_count

    async def dump_machine_timeline(self) -> None:
        """Collect per-machine device timelines from the M365 Defender portal API.

        Uses the unofficial portal proxy API (/apiproxy/mtp/mdeTimelineExperience/machines/)
        which requires browser-session (ESTS cookie) authentication via portal_auth.
        The API enforces max 7-day windows per initial request; pagination handles
        continuation beyond that via 'Next' links.

        Includes enrichment flags (generateIdentityEvents, includeSentinelEvents) to
        capture identity and Sentinel events alongside standard device timeline data.
        Time range is split into configurable chunks (default 2 days) for throughput.
        """
        if not self.portal_auth:
            self.logger.error("Portal auth not configured. Skipping machine_timeline. "
                              "Set ests_cookie in .auth and run 'goosey auth' to enable.")
            return

        data = await self.check_machines()
        machine_ids = list(findkeys(data, 'id'))
        machine_names = list(findkeys(data, 'computerDnsName'))
        id_to_name = dict(zip(machine_ids, machine_names))

        timeline_dir = os.path.join(self.output_dir, 'machine_timeline')
        check_output_dir(timeline_dir, self.logger)

        portal_base = self.portal_auth.get('portal_url', 'https://security.microsoft.com')
        headers = self._build_portal_headers()

        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=180)

        if self.date_range:
            start_date = datetime.strptime(self.date_start, "%Y-%m-%d")
            if self.date_end:
                end_date = datetime.strptime(self.date_end, "%Y-%m-%d")

        # Progress bar: track machines completed
        pm = get_progress_manager()
        pbar = None
        if pm and machine_ids:
            pbar = pm.create_time_bar("mde_machine_timeline", len(machine_ids), desc="mde_machine_timeline", unit="machine")
            if pbar:
                pbar.bar_format = "{desc} |{bar}| {percentage:3.0f}% | machine {n_fmt}/{total_fmt} | elapsed {elapsed}"

        async def _fetch_timeline(machine_id):
            hostname = id_to_name.get(machine_id, 'unknown')
            safe_hostname = hostname.replace('/', '_').replace('\\', '_')
            outfile = os.path.join(timeline_dir, f"{safe_hostname}_{machine_id}_timeline.jsonl")
            statefile = os.path.join(timeline_dir, f".{machine_id}.savestate")

            if os.path.isfile(statefile) and os.path.isfile(outfile):
                self.logger.debug(f"Skipping timeline for {hostname} ({machine_id}) - already collected.")
                if pbar:
                    pbar.update(1)
                return

            # Chunk into 2-day windows for parallel throughput (API max is 7 days per initial request)
            chunk_start = start_date
            total_count = 0
            while chunk_start < end_date:
                chunk_end = min(chunk_start + timedelta(days=2), end_date)
                from_date = chunk_start.strftime("%Y-%m-%dT00:00:00.000Z")
                to_date = chunk_end.strftime("%Y-%m-%dT23:59:59.999Z")

                # Use the correct path-based URL format with enrichment flags
                url = (f"{portal_base}/apiproxy/mtp/mdeTimelineExperience"
                       f"/machines/{machine_id}/events/"
                       f"?fromDate={from_date}"
                       f"&toDate={to_date}"
                       f"&pageSize=1000"
                       f"&generateIdentityEvents=true"
                       f"&includeSentinelEvents=true"
                       f"&supportMdiOnlyEvents=true"
                       f"&includeIdentityEvents=true")

                async with self.portal_semaphore:
                    count = await self._fetch_portal_timeline(url, outfile, statefile, headers)
                    total_count += count

                chunk_start = chunk_end

            if total_count > 0:
                self.logger.debug(f"Collected {total_count} timeline events for {hostname} ({machine_id})")
            if pbar:
                pbar.update(1)

        tasks = [asyncio.create_task(_fetch_timeline(mid), name=f"machine_timeline_{mid}") for mid in machine_ids]
        if tasks:
            self.logger.info(f"Collecting timeline for {len(tasks)} machines...")
            await asyncio.gather(*tasks)
            self.logger.info("Machine timeline collection complete.")
    dump_machine_timeline._manages_own_progress = True

    async def dump_identity_timeline(self) -> None:
        """Collect identity timelines from the M365 Defender portal API.

        Uses the unofficial portal proxy API (/apiproxy/mdi/identity/userapiservice/timeline/mtp)
        which requires browser-session (ESTS cookie) authentication via portal_auth.
        Uses POST-based pagination with count/skip body. The API hard limit is skip=9000;
        when reached, the query restarts from the minimum timestamp in the last batch
        to continue collecting older events (matching timeline-downloader behavior).

        Identity search uses POST to /apiproxy/mdi/identity/userapiservice/identities
        with proper m-package and tenant-id headers.
        """
        if not self.portal_auth:
            self.logger.error("Portal auth not configured. Skipping identity_timeline. "
                              "Set ests_cookie in .auth and run 'goosey auth' to enable.")
            return

        identity_dir = os.path.join(self.output_dir, 'identity_timeline')
        check_output_dir(identity_dir, self.logger)

        portal_base = self.portal_auth.get('portal_url', 'https://security.microsoft.com')
        tenant_id = self.portal_auth.get('tenant_id', '')

        # Identity API requires m-package and tenant-id headers
        extra = {'m-package': 'identities'}
        if tenant_id:
            extra['tenant-id'] = tenant_id
        identity_headers = self._build_portal_headers(extra_headers=extra)

        # Search identities via POST (matches the portal's actual API contract)
        identities_url = f"{portal_base}/apiproxy/mdi/identity/userapiservice/identities"
        users = []
        search_skip = 0
        search_page_size = 100
        try:
            while True:
                search_body = {
                    "PageSize": search_page_size,
                    "Skip": search_skip,
                    "Filters": {},
                    "SearchText": "",
                }
                async with self.ahsession.post(identities_url, headers=identity_headers,
                                                json=search_body,
                                                timeout=aiohttp.ClientTimeout(total=120)) as r:
                    if r.status == 200:
                        result = await r.json()
                        batch = result if isinstance(result, list) else result.get('results', result.get('value', []))
                        if not batch:
                            break
                        users.extend(batch)
                        if len(batch) < search_page_size:
                            break
                        search_skip += search_page_size
                    else:
                        body = await r.text()
                        self.logger.error(f"Identity lookup failed with HTTP {r.status}: {body[:500]}")
                        return
        except Exception as e:
            self.logger.error(f"Error fetching identities: {e}")
            return

        if not users:
            self.logger.info("No identities found for timeline collection.")
            return

        self.logger.info(f"Found {len(users)} identities for timeline collection.")

        # Deduplicate identities by accountId
        seen_ids = set()
        unique_users = []
        for u in users:
            uid = u.get('accountId', u.get('id'))
            if uid and uid not in seen_ids:
                seen_ids.add(uid)
                unique_users.append(u)
        users = unique_users

        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=180)

        if self.date_range:
            start_date = datetime.strptime(self.date_start, "%Y-%m-%d")
            if self.date_end:
                end_date = datetime.strptime(self.date_end, "%Y-%m-%d")

        # Progress bar: track identities completed
        pm = get_progress_manager()
        pbar = None
        if pm and users:
            pbar = pm.create_time_bar("mde_identity_timeline", len(users), desc="mde_identity_timeline", unit="identity")
            if pbar:
                pbar.bar_format = "{desc} |{bar}| {percentage:3.0f}% | identity {n_fmt}/{total_fmt} | elapsed {elapsed}"

        async def _fetch_identity(user):
            user_id = user.get('accountId', user.get('id', 'unknown'))
            user_name = user.get('displayName', user.get('accountName', 'unknown'))
            safe_name = user_name.replace('/', '_').replace('\\', '_').replace(' ', '_')
            outfile = os.path.join(identity_dir, f"{safe_name}_{user_id}_timeline.jsonl")
            statefile = os.path.join(identity_dir, f".{user_id}.savestate")

            if os.path.isfile(statefile) and os.path.isfile(outfile):
                self.logger.debug(f"Skipping identity timeline for {user_name} ({user_id}) - already collected.")
                if pbar:
                    pbar.update(1)
                return

            timeline_url = f"{portal_base}/apiproxy/mdi/identity/userapiservice/timeline/mtp"
            page_size = 1000
            skip = 0
            total_count = 0
            max_skip = 9000  # API hard limit
            current_end_iso = end_date.strftime("%Y-%m-%dT23:59:59.999Z")
            current_start_iso = start_date.strftime("%Y-%m-%dT00:00:00.000Z")

            while True:
                body = {
                    "accountId": user_id,
                    "startTime": current_start_iso,
                    "endTime": current_end_iso,
                    "count": page_size,
                    "skip": skip,
                }

                async with self.portal_semaphore:
                    count = await self._fetch_portal_timeline(
                        timeline_url, outfile, statefile, identity_headers,
                        method="POST", json_body=body
                    )
                    total_count += count

                if count < page_size:
                    break  # No more results

                skip += page_size

                # When approaching the skip=9000 limit, restart query from boundary timestamp
                if skip >= max_skip:
                    # Read the last batch of events to find the minimum timestamp
                    min_time = self._find_min_timestamp_in_file(outfile, page_size)
                    if min_time:
                        # Restart from 1 second after the boundary to avoid infinite loops
                        boundary = dateutil.parser.parse(min_time) - timedelta(seconds=1)
                        new_end = boundary.strftime("%Y-%m-%dT%H:%M:%S.000Z")
                        if new_end <= current_start_iso:
                            break  # No more time range to query
                        self.logger.debug(f"Identity {user_name}: skip limit reached, restarting from {new_end}")
                        current_end_iso = new_end
                        skip = 0
                    else:
                        self.logger.warning(f"Identity {user_name}: skip limit reached but couldn't determine boundary timestamp. Some events may be missing.")
                        break

            if total_count > 0:
                self.logger.debug(f"Collected {total_count} identity events for {user_name} ({user_id})")
            if pbar:
                pbar.update(1)

        tasks = [asyncio.create_task(_fetch_identity(u), name=f"identity_timeline_{u.get('accountId', 'unknown')}") for u in users]
        if tasks:
            self.logger.info(f"Collecting identity timeline for {len(tasks)} users...")
            await asyncio.gather(*tasks)
            self.logger.info("Identity timeline collection complete.")
    dump_identity_timeline._manages_own_progress = True

    def _find_min_timestamp_in_file(self, filepath, last_n_lines=1000):
        """Find the minimum timestamp in the last N lines of a JSONL file.

        Used to determine the boundary timestamp when identity timeline pagination
        hits the skip=9000 API limit, allowing the query to restart from that point.

        Returns the minimum timestamp string, or None if not found.
        """
        try:
            lines = []
            with open(filepath, 'r', encoding='utf-8') as f:
                # Read all lines and take the last N
                all_lines = f.readlines()
                lines = all_lines[-last_n_lines:] if len(all_lines) > last_n_lines else all_lines

            min_time = None
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    # Try common timestamp field names
                    for field in ('EventTime', 'Timestamp', 'timestamp', 'eventTime', 'StartTime', 'startTime'):
                        if field in event and event[field]:
                            t = event[field]
                            if min_time is None or t < min_time:
                                min_time = t
                            break
                except (json.JSONDecodeError, KeyError):
                    continue
            return min_time
        except (IOError, OSError):
            return None


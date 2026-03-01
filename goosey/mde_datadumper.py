#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Untitled Goose Tool: mde_datadumper!
This module has all the telemetry pulls for MDE.
"""

from datetime import datetime, timedelta
import itertools
from goosey.auth import check_app_auth_token
from goosey.datadumper import DataDumper
from goosey.utils import *
import pytz

utc=pytz.UTC

end_29_days_ago = datetime.today().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=29)
today_date = datetime.today().replace(hour=0, minute=0, second=0, microsecond=0)

class MDEDataDumper(DataDumper):

    def __init__(self, output_dir, reports_dir, app_auth, app_auth2, session, config, debug):
        super().__init__(f'{output_dir}{os.path.sep}mde', reports_dir, app_auth, session, debug)
        self.app_auth2 = app_auth2
        self.failurefile = os.path.join(reports_dir, '_no_results.json')
        self.logger = setup_logger(__name__, debug)
        self.gcc = config_get(config, 'config', 'gcc', self.logger).lower() == "true"
        self.gcc_high = config_get(config, 'config', 'gcc_high', self.logger).lower() == "true"
        endpoints = get_endpoints(gcc=self.gcc, gcc_high=self.gcc_high)
        self.mde_url = endpoints["securitycenter_api"] + "/"
        self.identity_url = endpoints["security_api"]
        self.call_object = [self.mde_url, self.app_auth, self.logger, self.output_dir, self.get_session()]
        self.threshold = int(config_get(config, 'variables', 'mde_threshold'))
        self.mde_query_mode = config_get(config, 'variables', 'mde_query_mode')
        self.date_range, self.date_start, self.date_end = get_date_range(config, self.logger)

    async def dump_machines(self) -> None:
        """
        Dump machines with mde
        """
        await helper_single_object("api/machines", self.call_object, self.failurefile)

    async def dump_alerts(self) -> None:
        """
        Dump alerts
        """
        await helper_single_object("api/alerts", self.call_object, self.failurefile)

    async def dump_indicators(self) -> None:
        """
        Dump indicators
        """
        await helper_single_object("api/indicators", self.call_object, self.failurefile)

    async def dump_investigations(self) -> None:
        """
        Dump investigations
        """
        await helper_single_object("api/investigations", self.call_object, self.failurefile)

    async def dump_library_files(self) -> None:
        """
        Dump library files
        """
        await helper_single_object("api/libraryfiles", self.call_object, self.failurefile)

    async def dump_machine_vulns(self) -> None:
        """
        Dump known machine vulnerabilities
        """
        await helper_single_object("api/vulnerabilities/machinesVulnerabilities", self.call_object, self.failurefile)

    async def dump_software(self) -> None:
        """
        Dump known installed software
        """
        await helper_single_object("api/Software", self.call_object, self.failurefile)

    async def dump_recommendations(self) -> None:
        """
        Dump mde recommendations
        """
        await helper_single_object("api/recommendations", self.call_object, self.failurefile)


    async def check_machines(self):
        check_app_auth_token(self.app_auth, self.logger)
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
        """Dumps the results from incidents and alerts.
        API Reference: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/run-advanced-query-api?view=o365-worldwide
        """

        # default end time. Now
        end = utc.localize(datetime.now())

        # defult start tiem
        start = end - timedelta(days=364)

        if self.date_range:
            self.logger.debug(f'MDE Dump using specified date range: {self.date_start} to {self.date_end}')
            start = utc.localize(datetime.strptime(self.date_start,"%Y-%m-%d"))
            end = utc.localize(datetime.strptime(self.date_end,"%Y-%m-%d"))

        tables = ['AlertInfo', 'AlertEvidence']

        tasks = []
        for table in tables:
            # Set the output directory for the mde table logs
            mde_log_dir = os.path.join(self.output_dir, table)
            base_query = table

            check_output_dir(mde_log_dir, self.logger)

            statefile = os.path.join(mde_log_dir, f".{table}.savestate")
            outfile = os.path.join(mde_log_dir, f"{table}.json")
            saved_end = load_state(statefile)
            if saved_end:
                start = max(saved_end, start)
            # Use asyncio to use asyncronous coroutines to help ensure we get data before it rolls off
            self.logger.debug(f"Generating table dump task for table: {table}, start: {start}, end: {end}")
            caller_name = asyncio.current_task().get_name()
            tasks.append(asyncio.create_task(self._dump_table(base_query, start, end, path="api/advancedhunting/run", statefile=statefile, outfile=outfile),name=f"{caller_name}_{table}"))

        await asyncio.gather(*tasks)

    async def dump_advanced_hunting_query(self) -> None:
        """Dumps the results from advanced hunting queries.
        API Reference: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/run-advanced-query-api?view=o365-worldwide
        """
        # Generate a map of machine ids/names
        data = await self.check_machines()
        machine_ids = list(findkeys(data, 'id'))
        machine_names = list(findkeys(data, 'computerDnsName'))
        mapOfIds = dict(zip(machine_ids, machine_names))

        # default end time. Now
        end = utc.localize(datetime.now())

        # defult start tiem
        start = end - timedelta(days=364)

        if self.date_range:
            self.logger.debug(f'MDE Dump using specified date range: {self.date_start} to {self.date_end}')
            start = utc.localize(datetime.strptime(self.date_start,"%Y-%m-%d"))
            end = utc.localize(datetime.strptime(self.date_end,"%Y-%m-%d"))

        tables = ['DeviceEvents', 'DeviceLogonEvents', 'DeviceRegistryEvents', 'DeviceProcessEvents', 'DeviceNetworkEvents', 'DeviceFileEvents', 'DeviceImageLoadEvents']

        # default to mode table
        machine_mode = False
        machine_table_list = itertools.product([""], tables)
        if self.mde_query_mode == "machine":
            machine_mode = True
            machine_table_list = list(itertools.product(machine_ids, tables))

        tasks = []
        for machine_id, table in machine_table_list:
            # Set the output directory for the mde table logs
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
            if saved_end:
                start = max(saved_end, start)
            # Use asyncio to use asyncronous coroutines to help ensure we get data before it rolls off
            self.logger.debug(f"Generating table dump task for table: {table}, machine: {machine_name}, start: {start}, end: {end}")
            caller_name = asyncio.current_task().get_name()
            tasks.append(asyncio.create_task(self._dump_table(base_query, start, end, path="api/advancedqueries/run", statefile=statefile, outfile=outfile), name=f"{caller_name}_{table}"))
        await asyncio.gather(*tasks)

    async def dump_advanced_identity_hunting_query(self) -> None:
        """Dumps the results from advanced hunting API queries.
        API Reference: https://learn.microsoft.com/en-us/microsoft-365/security/defender/api-advanced-hunting?view=o365-worldwide
        """
        check_app_auth_token(self.app_auth2, self.logger)

        # default end time. Now
        end = utc.localize(datetime.now())

        # defult start tiem
        start = end - timedelta(days=364)

        if self.date_range:
            self.logger.debug(f'MDE Dump using specified date range: {self.date_start} to {self.date_end}')
            start = utc.localize(datetime.strptime(self.date_start,"%Y-%m-%d"))
            end = utc.localize(datetime.strptime(self.date_end,"%Y-%m-%d"))

        id_tables = ['IdentityDirectoryEvents', 'IdentityLogonEvents', 'IdentityQueryEvents']

        tasks = []
        for table in id_tables:
            # Set the output directory for the mde table logs
            mde_log_dir = os.path.join(self.output_dir, table)
            base_query = table

            check_output_dir(mde_log_dir, self.logger)

            statefile = os.path.join(mde_log_dir, f".{table}.savestate")
            outfile = os.path.join(mde_log_dir, f"{table}.json")
            saved_end = load_state(statefile)
            if saved_end:
                start = max(saved_end, start)
            # Use asyncio to use asyncronous coroutines to help ensure we get data before it rolls off
            self.logger.debug(f"Generating table dump task for table: {table}, start: {start}, end: {end}")
            caller_name = asyncio.current_task().get_name()
            tasks.append(asyncio.create_task(self._dump_table(base_query, start, end, path="api/advancedhunting/run", statefile=statefile, outfile=outfile),name=f"{caller_name}_{table}"))

        await asyncio.gather(*tasks)

    async def run_mde_query(self, query, start, end, bounds, path='api/advancedqueries/run', summarize=False):
        """
        Run an advanced query or hunt and return the result
        """

        # errors from the query that will cause the dumper to sleep
        sleep_errors = ["Server disconnected", "Cannot connect", "WinError 10054"]
        # errors from the query that will cause the dumper to cut the tim in half
        slice_errors = ['exceeded the allowed limits', 'exceeded the allowed result size']

        app_auth = self.app_auth
        if path == "api/advancedhunting/run":
            app_auth = self.app_auth2
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
                    self.logger.error("Detected 401 unauthorized, exiting.")
                    sys.exit(1)
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


    async def _dump_table(self, base_query, start, end, path, statefile, outfile, retries=3):
        """
        Description:
            Query the mde table and pull logs for the timeframe

        Arguments:
            base_query: what to start with for the query
            start: starting timestamp
            end: ending timestamp
            path: path to the endpoint for the queries
            output_dir: where to place the logs
            machine_id: Optional id of a mahcine to filter down the query
        """
        totalResultCount = 0
        totalResultEnd = start
        totalSavedResults = 0
        origStart = start
        finalEnd = end
        tries = 0
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
                    return
                # Otherwise it just means this lower time segment has no logs and we remove it and continue
                start = end
                end = finalEnd
                bounds = [final_record]
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

                tries = 0
                end = bounds[0]["end"]
                start = bounds[0]["start"]
                if bounds[0]["count"] != None and bounds[0]["count"] >= self.threshold:
                    new_end_ts = start.timestamp() + ((end.timestamp() - start.timestamp())/2)
                    end = datetime.fromtimestamp(new_end_ts, utc)

                totalSavedResults += len(results)
                self.logger.debug(f"Total results {totalSavedResults}/{totalResultCount}")
                continue


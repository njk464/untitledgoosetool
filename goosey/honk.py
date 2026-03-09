#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Untitled Goose Tool: Honk!
This is the main orchestrator module that coordinates data collection across all platforms.

The `honk` command:
1. Reads auth tokens from .ugt_auth and credentials from .auth
2. Parses the .conf file to determine which data sources are enabled
3. Creates platform-specific dumper instances (M365, Entra ID, Azure, MDE)
4. Schedules all enabled dump_* methods as concurrent asyncio tasks
5. Runs all tasks via asyncio.gather() and reports results

The `autohonk` command wraps honk with automatic authentication and token refresh
via TokenManager, enabling unattended long-running collection.
"""

import aiohttp
import asyncio
import configparser
import json
import os
import sys
import time
import warnings

from tqdm import tqdm

from goosey.entra_id_datadumper import EntraIdDataDumper
from goosey.azure_dumper import AzureDataDumper
from goosey.datadumper import DataDumper
from goosey.m365_datadumper import M365DataDumper
from goosey.mde_datadumper import MDEDataDumper
from goosey.utils import *
from goosey.auth import auth as gooseyauth, TokenManager
from goosey.progress import init_progress_manager

if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

warnings.simplefilter('ignore')

logger = setup_logger(__name__, debug=False)
data_calls = {}

async def run(args, config, auth, init_sections, auth_un_pw=None):
    """Main async run loop

    :param args: argparse object with populated namespace
    :type args: Namespace argparse object
    :param auth: All token auth credentials
    :type auth: dict
    :return: None
    :rtype: None
    """
    global data_calls, logger

    # Set name of current task
    asyncio.current_task().set_name("honk_run")

    session = aiohttp.ClientSession(trust_env=True)

    # Extract per-endpoint token dicts from the auth file.
    # These are mutable dicts — TokenManager will update them in-place when refreshing,
    # so all dumpers holding references automatically see fresh tokens.
    msft_graph_app_auth = {}
    loganalytics_app_auth = {}

    o365_app_auth = auth["app_auth"]["outlook_office_api"]
    msft_graph_app_auth = auth["app_auth"]["graph_api"]
    mgmt_app_auth = auth["app_auth"]["resource_manager"]
    msft_security_center_auth = auth["app_auth"]["securitycenter_api"]
    loganalytics_app_auth = auth["app_auth"]["log_analytics_api"]
    msft_security_auth = auth["app_auth"]["security_api"]

    # TokenManager monitors token expiry and refreshes proactively (5 min before expiry)
    gcc = config_get(config, 'config', 'gcc', logger)
    gcc = gcc.lower() == "true" if gcc else False
    gcc_high = config_get(config, 'config', 'gcc_high', logger)
    gcc_high = gcc_high.lower() == "true" if gcc_high else False
    endpoints_dict = get_endpoints(gcc=gcc, gcc_high=gcc_high)
    token_manager = TokenManager(auth, endpoints_dict, logger)

    maindumper = DataDumper(args.output_dir, args.reports_dir, msft_graph_app_auth, session, args.debug, token_manager=token_manager, endpoint_key="graph_api")

    m365, entraid, azure, mde = False, False, False, False

    if args.dry_run:
        m365dumper = maindumper
        entraiddumper = maindumper
        azure_dumper = maindumper
        mdedumper = maindumper

    else:
        if 'm365' in init_sections:
            m365dumper = M365DataDumper(args.output_dir, args.reports_dir, msft_graph_app_auth, maindumper.ahsession, config, args.debug, o365_app_auth, token_manager=token_manager)
            m365 = True
        if 'entraid' in init_sections:
            entraiddumper = EntraIdDataDumper(args.output_dir, args.reports_dir, msft_graph_app_auth, maindumper.ahsession, config, args.debug, token_manager=token_manager)
            entraid = True
        if 'azure' in init_sections:
            azure_dumper = AzureDataDumper(args.output_dir, args.reports_dir, maindumper.ahsession, mgmt_app_auth, config, auth_un_pw, loganalytics_app_auth, args.debug, token_manager=token_manager)
            azure = True
        if 'mde' in init_sections:
            portal_auth = auth.get('portal_auth')
            mdedumper = MDEDataDumper(args.output_dir, args.reports_dir, msft_security_center_auth, msft_security_auth, maindumper.ahsession, config, args.debug, token_manager=token_manager, portal_auth=portal_auth)
            mde = True

    pm = init_progress_manager(enabled=not args.debug)

    async with maindumper.ahsession as ahsession:
        tasks = []
        if m365:
            tasks.extend(m365dumper.data_dump(data_calls['m365'], "m365"))
        if entraid:
            tasks.extend(entraiddumper.data_dump(data_calls['entraid'], "entraid"))
        if azure:
            tasks.extend(azure_dumper.data_dump(data_calls['azure'], "azure"))
        if mde:
            tasks.extend(mdedumper.data_dump(data_calls['mde'], "mde"))

        honk_results = await asyncio.gather(*tasks)

        pm.close_all()

        succeeded = 0
        failed = 0
        failed_tasks = []
        error_occured = False
        for class_name, func_name, err in honk_results:
            if err:
                logger.error(f"[{class_name}] {func_name[5:]}: Failed with error {err}")
                error_occured = True
                failed += 1
                failed_tasks.append(f"  {func_name[5:]}: {err}")
            else:
                logger.info(f"[{class_name}] {func_name[5:]}: Success")
                succeeded += 1

        # Print summary to console even in quiet mode
        tqdm.write(f"\nCollection complete: {succeeded} succeeded, {failed} failed out of {succeeded + failed} tasks.")
        if failed_tasks:
            tqdm.write("Failed tasks:")
            for line in failed_tasks:
                tqdm.write(line)

        if error_occured:
            sys.exit(1)

def _get_section_dict(config, s):
    return get_section_dict(config, s, logger)

def parse_config(configfile, args, auth=None):
    """Parse the .conf file and determine which dump methods to run.

    The .conf file has sections like [m365], [entraid], [azure], [mde] with boolean
    options (e.g. ual=true, exo_mailbox=true). Each enabled option maps to a dump_<key>
    method in the corresponding dumper class.

    CLI flags (--azure, --m365, etc.) override the config to enable ALL methods for a platform.

    Returns:
        Tuple of (config, init_sections) where init_sections lists which platforms to initialize.
    """
    global data_calls
    config = configparser.ConfigParser()
    config.read(configfile)

    if not auth:
        sections = ['azure', 'm365', 'entraid', 'mde']
    else:
        sections = ['auth']

    init_sections = []
    for section in sections:
        d = _get_section_dict(config, section)
        data_calls[section] = {}
        for key in d:
            if d[key]:
                data_calls[section][key] = True
                init_sections.append(section)

    # CLI flags override .conf: enable ALL dump_* methods for the specified platform
    logger.debug(args.__dict__)
    if args.azure:
        for item in [x.replace('dump_', '') for x in dir(AzureDataDumper) if x.startswith('dump_')]:
            data_calls['azure'][item] = True
        init_sections.append("azure")
    if args.entraid:
        for item in [x.replace('dump_', '') for x in dir(EntraIdDataDumper) if x.startswith('dump_')]:
            data_calls['entraid'][item] = True
        init_sections.append("entraid")
    if args.m365:
        for item in [x.replace('dump_', '') for x in dir(M365DataDumper) if x.startswith('dump_')]:
            data_calls['m365'][item] = True
        init_sections.append("m365")
    if args.mde:
        for item in [x.replace('dump_', '') for x in dir(MDEDataDumper) if x.startswith('dump_')]:
            data_calls['mde'][item] = True
        init_sections.append("mde")

    # Apply CLI overrides to config sections (CLI args take precedence over .conf values)
    cli_overrides = {
        'config': {'tenant': 'tenant', 'gcc': 'gcc', 'gcc_high': 'gcc_high', 'subscriptionid': 'subscriptionid'},
        'filters': {'date_start': 'date_start', 'date_end': 'date_end'},
        'variables': {
            'ual_threshold': 'ual_threshold', 'max_ual_tasks': 'max_ual_tasks',
            'ual_extra_start': 'ual_extra_start', 'ual_extra_end': 'ual_extra_end',
            'ual_record_type': 'ual_record_type', 'ual_operations': 'ual_operations',
            'ual_user_ids': 'ual_user_ids', 'ual_free_text': 'ual_free_text',
            'ual_ip_addresses': 'ual_ip_addresses', 'ual_object_ids': 'ual_object_ids',
            'mde_threshold': 'mde_threshold', 'mde_query_mode': 'mde_query_mode',
        },
    }
    for section, mappings in cli_overrides.items():
        for conf_key, attr_name in mappings.items():
            val = getattr(args, attr_name, None)
            if val is not None:
                if not config.has_section(section):
                    config.add_section(section)
                config.set(section, conf_key, str(val))
                logger.debug(f"CLI override: [{section}] {conf_key} = {val}")

    logger.debug(json.dumps(data_calls, indent=2))
    return config, init_sections

def honk(authfile=".ugt_auth",
         config=".conf",
         auth=".auth",
         output_dir="output",
         reports_dir="reports",
         debug=False,
         dry_run=False,
         azure=False,
         entraid=False,
         m365=False,
         mde=False,
         encryption_pw=None,
         # [config] overrides
         tenant=None,
         gcc=None,
         gcc_high=None,
         subscriptionid=None,
         # [filters] overrides
         date_start=None,
         date_end=None,
         # [variables] overrides
         ual_threshold=None,
         max_ual_tasks=None,
         ual_extra_start=None,
         ual_extra_end=None,
         ual_record_type=None,
         ual_operations=None,
         ual_user_ids=None,
         ual_free_text=None,
         ual_ip_addresses=None,
         ual_object_ids=None,
         mde_threshold=None,
         mde_query_mode=None):
    """
    Untitled Goose Tool Information Gathering

    Args:
        authfile: File to store the authentication tokens and cookies
        config: Path to config file
        auth: File to store the credentials used for authentication
        output_dir: Directory for storing the results
        reports_dir: Directory for storing debugging/informational logs
        debug: Enable debug logging
        dry_run: Dry run (do not do any API calls)
        azure: Set all of the Azure calls to true
        entraid: Set all of the Entra ID calls to true
        m365: Set all of the M365 calls to true
        mde: Set all of the MDE calls to true
        encryption_pw: Password for the auth file encryption. SHOULD ONLY BE USED WITH AUTOHONK
        tenant: Override tenant ID from .conf
        gcc: Override GCC setting (true/false)
        gcc_high: Override GCC High setting (true/false)
        subscriptionid: Override Azure subscription ID(s)
        date_start: Override date range start (YYYY-MM-DD)
        date_end: Override date range end (YYYY-MM-DD)
        ual_threshold: Override UAL threshold (100-50000)
        max_ual_tasks: Override max concurrent UAL tasks
        ual_extra_start: Override UAL extra time range start (YYYY-MM-DD)
        ual_extra_end: Override UAL extra time range end (YYYY-MM-DD)
        ual_record_type: Filter UAL by record type (comma-separated)
        ual_operations: Filter UAL by operation type (comma-separated)
        ual_user_ids: Filter UAL by user (comma-separated UPNs)
        ual_free_text: Filter UAL by free text search
        ual_ip_addresses: Filter UAL by IP address (comma-separated)
        ual_object_ids: Filter UAL by object ID (comma-separated)
        mde_threshold: Override MDE query threshold
        mde_query_mode: Override MDE query mode (table or machine)
    """
    global logger
    args = dict2obj(locals())

    if not args.debug:
        set_quiet_mode(True)

    logger = setup_logger(__name__, args.debug)

    auth_un_pw, auth = get_authfile(authfile=args.auth, ugt_authfile=args.authfile, logger=logger, encryption_pw=encryption_pw)

    check_output_dir(args.output_dir, logger)
    check_output_dir(args.reports_dir, logger)
    check_output_dir(f'{args.output_dir}{os.path.sep}azure', logger)
    check_output_dir(f'{args.output_dir}{os.path.sep}m365', logger)
    check_output_dir(f'{args.output_dir}{os.path.sep}entraid', logger)
    check_output_dir(f'{args.output_dir}{os.path.sep}mde', logger)
    config, init_sections = parse_config(args.config, args)

    logger.info("Goosey beginning to honk.")
    if not args.debug:
        print("Goosey beginning to honk. Detailed logs in debug.log and error.log.\n")
    seconds = time.perf_counter()
    try:
        asyncio.run(run(args, config, auth, init_sections, auth_un_pw=auth_un_pw))
    except RuntimeError as e:
        sys.exit(1)
    elapsed = time.perf_counter() - seconds
    logger.info("Goosey executed in {0:0.2f} seconds.".format(elapsed))

def autohonk(authfile=".ugt_auth",
         config=".conf",
         auth=".auth",
         output_dir="output",
         reports_dir="reports",
         debug=False,
         azure=False,
         entraid=False,
         m365=False,
         mde=False,
         insecure=False,
         **kwargs):
    """
    Untitled Goose Tool Information Gathering. With auto authentication!
    Authenticates once, then runs collection to completion with automatic token refresh.

    Args:
        authfile: File to store the authentication tokens and cookies
        config: Path to config file
        auth: File to store the credentials used for authentication
        output_dir: Directory for storing the results
        reports_dir: Directory for storing debugging/informational logs
        debug: Enable debug logging
        azure: Set all of the Azure calls to true
        entraid: Set all of the Entra ID calls to true
        m365: Set all of the M365 calls to true
        mde: Set all of the MDE calls to true
        insecure: Disable secure authentication handling (file encryption)

    All other keyword arguments (tenant, gcc, date_start, ual_threshold, etc.)
    are passed through to honk() as CLI overrides for .conf values.
    """
    encryption_pw = None
    if not insecure:
        encryption_pw = getpass.getpass("Please type the password for file encryption: ")

    # Authenticate once
    gooseyauth(
        authfile=authfile,
        config=config,
        auth=auth,
        debug=debug,
        encryption_pw=encryption_pw,
    )

    # Run collection once — TokenManager handles mid-run token refresh
    honk(
        authfile=authfile,
        config=config,
        auth=auth,
        output_dir=output_dir,
        reports_dir=reports_dir,
        debug=debug,
        azure=azure,
        entraid=entraid,
        m365=m365,
        mde=mde,
        encryption_pw=encryption_pw,
        **kwargs,
    )



# Untitled Goose Tool Change Log

All notable changes to this project will be documented in this file.

## [3.0.0] - 2026-11-02
**Breaking:** Python 3.14 free-threaded (`python3.14t`) is now required.

### Changed
- **Python 3.14 free-threaded (`python3.14t`) is now required** (was 3.9-3.13). `setup.py` fails the install with a clear message on older Pythons and on GIL-enabled 3.14 builds, because the HQL engine's polars runtime wheels exist only for the `cp314t` ABI
- HQL engine is now upstream [Hashfastr/Hql](https://github.com/Hashfastr/Hql) `main`, pinned to an exact commit in `requirements.txt` (replaces PyPI `pyhql==0.0.9`). Installing needs `git` on `PATH`
- All dependencies re-pinned from a real 3.14t resolution (direct dependencies only; the old full freeze with unused packages such as `zstandard` was dropped). `azure-mgmt-monitor` is held at 6.0.2 (7.x removed `diagnostic_settings`)
- `setup.py` parses `requirements.txt` line by line, so `pkg @ url` requirement lines work

### Fixed
- **Silent data loss in paginated collection:** a `410 Gone` (expired skiptoken) or exhausted retries on an `@odata.nextLink` made `get_nextlink` stop quietly, so the sign-in collector reported success and advanced its checkpoint past the missing rows. `get_nextlink` now raises `PaginationIncomplete`; Entra sign-in and audit windows resume from the last timestamp written (de-duplicated, up to 5 attempts) and otherwise leave the checkpoint before the gap and report the task as FAILED. Also hardened: Entra provisioning/config/relationship collectors, D4IoT portal, MDE paged endpoints, eDiscovery collections and Graph UAL (a skipped/truncated day no longer lets the checkpoint advance past it)
- Azure: `SubscriptionClient` import for current Azure SDKs (`azure-mgmt-resource-subscriptions`); `goosey honk`/`goosey setup` no longer fail at import
- HQL queries containing `": "` (for example `where Col == "Foo: bar"`) were misrouted to the Sigma parser and failed with "Invalid sigma supplied to parser" (fixed in upstream Hql; regression-tested)
- HQL: files below subdirectories of the output folder now resolve under Hql main (patched in `goosey/hql_compat.py`) and reads are confined to the output directory

### Removed
- Obsolete `goosey/hql_compat.py` patches now fixed upstream: the `from __future__ import annotations` import hook for Python < 3.14, the resilient Table init and schema fallbacks, the MvExpand fix and the NDJSON seek fix. Retained: JSON file resolution, single-object files and dotted-name columns, `dcount()`, numeric/string tolerant `==`/`!=`, each guarded by a sentinel test that fails once upstream fixes the gap
- Hunting queries feature removed entirely: web UI Hunting Queries panel, /api/hunting/* endpoints, goosey/data/hunting_queries.json, scripts/validate_hunting_queries.py, and the KQL-to-HQL translation guide

## [2.2.0] - CyberFire Goose Lab readiness - 2026-11-02
### Added
- Log Analytics: authoritative table discovery via the Tables - List By Workspace API, with automatic fallback to search-based discovery
  - Tables that exist but return no rows now produce an empty (0-byte) artifact so "queried, nothing returned" is distinguishable from "never queried"
  - Per-workspace `_collection_status.json` manifest (`schema_version`, `discovery_method` of `tables_api`/`search_fallback`, and per-table `status` of `success`/`failed`/`unavailable`, `row_count`, `artifact`, `error`)
  - Explicit table queries are limited: a summary search selects tables with rows in the window (manifest `data_check`: `search_summary`/`search_failed`); other listed tables get status `skipped`. `AADGraphActivityLogs` and `MicrosoftGraphActivityLogs` are always queried; if the summary fails, all listed tables are queried
  - LAW queries are concurrency-limited; rate-limit errors are retried with backoff and persistent failures are recorded as `failed` with the error
  - `AADGraphActivityLogs` sourcetype (Entra diagnostic category `AzureADGraphActivityLogs`)
- `GOOSEY_ENCRYPTION_PW` environment variable for the auth-file encryption password in `goosey conf`, `goosey honk`, `goosey auth` and `goosey d4iot`. Precedence: `--encryption_pw`, then the env variable, then an interactive prompt. Empty value is treated as unset; the password is never logged (debug argument dumps are redacted)
- `docs/CYBERFIRE_QUICKSTART.md` student quickstart; `requirements-dev.txt` and `MANIFEST.in`; `goosey version` command alongside `goosey --version`

### Changed
- Incremental runs re-check a lookback window before the saved checkpoint (default 30 minutes; `[variables] incremental_lookback_minutes`) to catch late-arriving records, de-duplicating by id (Entra) or exact-row multiset (LAW, so genuine source duplicates are preserved). The LAW manifest gains `lookback_minutes` and per-table `duplicates_skipped`; `row_count` is rows newly written this run
- A blank `date_end` now means the current UTC time at execution. An explicit `date_end` remains an exclusive UTC-midnight bound, and checkpoints never exceed the resolved end
- eDiscovery export download (`ediscovery_export_download`) now defaults to False in generated configs (opt-in)
- Version unified: `goosey/__init__.py` is the single source of truth and `setup.py` reads it (previously 2.0.1 vs 2.0.4)

### Fixed
- HQL: `summarize` and nested-field handling fixes


## [2.2.0, earlier work] - eDiscovery, web UI (previously Unreleased)
### Added
- eDiscovery: New `EdiscoveryDataDumper` (`[ediscovery]` section, `--ediscovery` flag) collecting Microsoft Purview eDiscovery via the Graph v1.0 API
  - Snapshot (read-only): cases, case settings, custodians, noncustodial data sources, searches, legal holds, review sets, review set queries, tags, and operations
  - Copilot interactions (read-only): per-user prompts/responses via the dedicated `aiInteractionHistory:getAllEnterpriseInteractions` API, date-range bounded
  - Content export (read/write, opt-in): `dump_ediscovery_export` orchestrates create case → search → estimate → export → download for email/Teams/Copilot/SharePoint, resumable via save-state; double-gated behind a toggle and `ediscovery_export_confirm`
  - Optional eDiscovery/Copilot Graph permissions (`eDiscovery.Read.All`, `eDiscovery.ReadWrite.All`, `AiEnterpriseInteraction.Read.All`), granted only on request via `goosey setup --ediscovery`, `Create_SP.ps1 -Ediscovery`, or the web UI Setup tab checkbox (off by default; requires E5)
- Web UI: Device code OAuth login flow for MDE portal auth — automated alternative to manual ESTS cookie entry, with refresh token persistence

### Fixed
- M365: Rewrite UAL progress bar to sync from state file instead of closure-based tracking — eliminates stale progress on retry/resume
- Entra ID: Fix hang bugs in sign-in log collection (missing nextLink exits, retry overflow) and collapse progress bars on completion
- Web UI: Fix dump_ key naming bug in conf save/load (keys written with `dump_` prefix caused data_dump() method lookup failures)
- Web UI: Replace tqdm progress bars with JSON-based progress polling (tqdm ANSI output corrupted web UI terminal)
- HQL: Increase max_file_size_mb from 200 to 1024 (1 GB) for large forensic exports
- HQL: Bump Schema sample_size from 100 to 10000 for reliable type inference on heterogeneous NDJSON
- HQL: Fallback from to_dicts() to write_json() for Polars Struct columns (nested JSON fields)
- Web UI: Fix Jinja2 template syntax error in JSDoc comment (index.html line 1580)

### Added
- Entra ID: administrative units and cross-tenant access policy endpoints for forensic coverage
- MDE: 8 new advanced hunting tables (DeviceInfo, DeviceNetworkInfo, Defender XDR tables)
- Azure: VNet flow logs collection (`dump_vnet_flow_logs`) with NSG flow log deprecation notice

## [2.1.0] - Enter the honk - 2024-02-19
### Added
- Added support for python 3.13

## [2.0.4] - Enter the honk - 2024-01-28
### Changed
- Create_SP.ps1 script no longer prompts for cloudshell
- Create_SP.ps1 script supports gcc high
- goosey conf command now prompts for the client secret instead of having it provided as an argument

### Fixed
- Support for gcc and gcc high
- Fixed errors in install script Create_SP.ps1

## [2.0.3] - Enter the honk - 2024-09-23
### Added
- Better task naming for logging
- Added Microsoft Graph role ThreatHunting.Read.All
- Added Log Analytics API role Data.Read
- Added dumping for Log Analytics Workspace

### Changed
- Updated versions of required packages
- Create_SP.ps1 script will find existing an existing role group with the app name instead of erroring

### Fixed
- Resolved issue with dumper cmd arguments for honk command not working (e.g. goosey honk --entraid)
- Issue identified in d4iot dumpers 

## [2.0.2] - Enter the honk - 2024-08-21
### Added
- Better task naming for logging

### Changed
- Updated versions of required packages

### Fixed
- Resolved some errors for config collection. Specifically relating to the security contacts collection


## [2.0.1] - Enter the honk - 2024-07-31
### Added
- More Documentation

### Changed
- Changed all azuread to entraid
- Removed version and author information from every file

### Fixed
- Endless pulling issue for sign in logs when endtime wasn't specified 

## [2.0.0] - Enter the honk - 2024-05-08
### Added
- autohonk. No more manual authentication
- Variables added to the conf to modify ual tasks running as well as optional extra time field

### Changed
- more efficient ual pulling. Lots of improvements that led to an 800% speed up.
- fixed asynchronous issue with azure dumpers
- Better Logging for python3.12. Changed the docker image to use that as well

### Fixed
- Asynchronous issues with azure dumpers
- No save state for azure activity log

## [2.0.0-b] - Enter the honk - 2024-02-08
### Added
- Powershell script for tying service principal to exchange online
- App only authentication
- `goosey conf` command to generate the conf. Includes comments for each field
- Variables added to the conf to modify thresholds and modes during goosey honk

### Changed
- Ual changed endpoints due to previous endpoint deprecation. New endpoint uses app auth tied to exchange online. No user tokens required for anything anymore.
- Mde improvements and mode added to choose between table mode and machine.
- Cli framework switched to fire instead of argparse
- Graze is gone. Due to ual change
- GUI is gone due to not being supported.
- Powershell dumper for m365 switched to python implementation
- delegated auth pull removed. Permissions too strong
- auth no longer saves unencrypted creds/tokens to disk in secure mode at any point
- Summarized configuration pulls in AzureAD and Azure.

### Fixed
- duplication in ual logs. Duplicates returned are now deduped before saving

## [1.2.6] - The goose is loose - 2023-09-15
### Added
- Delegated auth pull for featureRolloutPolicies
- Made goose proxy aware

### Changed
- Consolidated auth code and enabled secure by default
- Made graze faster

### Fixed
- Fixed AzureAD activity log dumper bug that failed if there were multiple subscriptions

## [1.2.5] - The goose is loose - 2023-08-04
### Added

### Changed
- Updated `cryptography` to 41.0.3 based on dependabot.

### Fixed
- Incorporated fix for function `helper_multiple_object` when parent object contains a `/`
- Updated authentication fix for graze.py and messagetrace.py

## [1.2.4] - The goose is loose - 2023-07-27
### Added

### Changed
- Updated and pinned `MSAL` dependencies.

### Fixed
- Updated `validationkey` logic for m365 authentication.
- Updated `MSAL` calls to align with the `MSAL` 1.23.0 change.

## [1.2.3] - The goose is loose - 2023-07-20
### Added

### Changed
- Updated `cryptography` and `aiohttp` based on dependabot.
- Updated SBOM files.

### Fixed

## [1.2.2] - The goose is loose - 2023-07-17
### Added
- Better catches for when password for the account needs to be updated, when a conditional access policy blocks user account access, or when the user account is flagged for risky actions.
- Added catch for empty `.conf` fields, will allow more graceful exiting. 

### Changed
- Updated and pinned `aiohttp`, `colored`, `cryptography`, and `selenium` dependencies and updated Python version to 3.10.11.
- Pinned 3.1.0 version of ExchangeOnlineManagement PowerShell module.
- Improved logic for grabbing `validationkey` from requests.

### Fixed
- Fixed MFA logic for messagetrace.py.
- Fixed data dumper logic, they will only run if something in their section is set to `True`.

## [1.2.1] - The goose is loose - 2023-06-06
### Added
- Implemented new tables to be pulled from MDE.
- Added two SBOM files.

### Changed
- Updated readme with cloud-only account requirement.
- Better logging for _no_results.json.

### Fixed
- Fixed Azure government calls.
- Fixed minor debug logging issues.
- Fixed the AttributeError encountered during AzureAD calls.

## [1.2.0] - The goose is loose - 2023-04-21
### Added
- Implemented delegated application authentication.
- Implemented support for more MFA methods: number matching push notification, app OTP code, and SMS OTP code.

### Changed
- Added more debugging statements for `goosey auth --debug`.

### Fixed
- Implemented monkey patch for `goosey-gui` on Windows machines.
- Fixed logic for errorneous token check when `m365` in the `.conf` was set to `False`.

## [1.1.1] - The goose is loose - 2023-04-12
### Added
- Readme prerequisites regarding Microsoft Visual C++ redistributable package (14.x) for Windows machines

### Changed
- Updated selenium logic regarding push notification MFA prompts. It will detect if MFA was never accepted and exit.

### Fixed
- Implemented more checks for the .ugt_file to see if cookies and tokens are correctly exported.
- Updated certain AzureAD call outputs, making it easier for users to track call results.

## [1.1.0] - The goose is loose - 2023-04-05
### Added
- Implemented file encryption for credential file(s) with the `--secure` parameter.
- Added more authentication expiration checks and implemented better logic for handling an expired authentication token/cookie.
- Added more logging for `goosey auth` and `goosey auth --debug`.
- Added support for Python 3.10.

### Changed
- Separated .conf and .d4iot_conf files into .auth, .conf, .auth_d4iot, and .d4iot_conf.
- Removed token_cache.bin.
- Added longer timeouts for selenium.
- Added validationkey pull as part of the regular M365 authentication flow.

### Fixed
- Added a section in the Installing section of the readme for Ubuntu 22.04 users running into wxpython issues.

## [1.0.0] - The goose is loose - 2023-03-23
### Added
- Goose is released

### Changed


### Fixed

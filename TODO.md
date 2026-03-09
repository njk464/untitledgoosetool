# Untitled Goose Tool - Task List

## Tasks

- [x] **1. Document all datadumpers and their log sources** *(completed)*
  - Created `docs/DATADUMPERS.md` cataloging every datadumper class, each `dump_*` method, what API it calls, and what data it collects
  - Covers: EntraIdDataDumper, M365DataDumper, MDEDataDumper, AzureDataDumper, D4IoTDumper
  - Includes output file names, formats, save state files, and auth token mapping

- [x] **2. Add better code comments** *(completed)*
  - Added docstrings and inline comments across all modules
  - Focus areas: token refresh flow (auth.py, TokenManager), UAL bounding/session logic (m365_datadumper.py), KQL query slicing (mde_datadumper.py, utils.py), save state management, auth flow
  - Added module-level docstrings explaining each file's purpose and key concepts
  - Added class-level docstrings explaining auth patterns, data flow, and key design decisions
  - Added docstrings to DataDumper base class methods (data_dump, func_wrapper, __getattr__)

- [x] **3. Integrate timeline-downloader as MDE datadumper** *(completed)*
  - Source: https://github.com/matthieugras/timeline-downloader
  - Studied the Go repo's approach to pulling MDE timeline data via portal proxy APIs
  - Found existing `dump_machine_timeline` and `dump_identity_timeline` methods; improved them with:
    - Fixed device timeline URL to correct path format (`/machines/{id}/events/`)
    - Added enrichment flags (`generateIdentityEvents`, `includeSentinelEvents`, etc.)
    - Reduced time chunk size from 7 days to 2 days for better throughput
    - Fixed identity search to use POST with pagination (matching portal API contract)
    - Added `m-package` and `tenant-id` headers for identity API
    - Implemented skip=9000 boundary restart (requery from min timestamp instead of stopping)
    - Added identity deduplication
    - Added OAuth refresh token auth as alternative to ESTS cookies (more reliable for long runs)
    - Improved 403 handling to detect stealth rate limiting
    - Refactored portal auth header building to support both auth methods

- [x] **4. Add UAL filtering options** *(completed)*
  - Added 6 filter options under [variables] in .conf: ual_record_type, ual_operations, ual_user_ids, ual_free_text, ual_ip_addresses, ual_object_ids
  - All accept comma-separated values matching Search-UnifiedAuditLog parameter format
  - Read in M365DataDumper.__init__, injected into parameters in _new_ual_timeframe
  - Active filters logged at start of dump_ual for visibility
  - Added conf.py docstrings with parameter descriptions and MS docs links

- [x] **5. Expose all .conf options as CLI arguments** *(completed)*
  - Added 16 CLI parameters to `honk()`: tenant, gcc, gcc_high, subscriptionid, date_start, date_end, ual_threshold, max_ual_tasks, ual_extra_start, ual_extra_end, ual_record_type, ual_operations, ual_user_ids, ual_free_text, ual_ip_addresses, ual_object_ids, mde_threshold, mde_query_mode
  - CLI args override .conf file values via `parse_config()` applying overrides to configparser
  - `autohonk()` passes through all extra kwargs to `honk()`
  - All parameters documented in docstrings (fire auto-generates --help from these)

## Progress Notes

_Updated as tasks are completed. Each entry notes what was done and any follow-up needed._

- **Task 1** (completed): Created `docs/DATADUMPERS.md` — comprehensive reference of all 5 datadumper classes, ~80 dump methods, API endpoints, output files, save state files, and auth token mapping.
- **Task 2** (completed): Added comments and docstrings across all 11 Python modules. Key focus areas: auth.py (Authentication class, TokenManager, MSAL flows), datadumper.py (auto-discovery, task scheduling, error isolation), m365_datadumper.py (UAL binary-search bounding, session management, duplicate detection, result caching), mde_datadumper.py (KQL query slicing, dual-token auth, machine vs table modes), utils.py (pagination, KQL queries, save state, bounds tracking, file encryption), and all remaining modules (honk.py, entra_id_datadumper.py, azure_dumper.py, d4iot_dumper.py, csv.py, conf.py, main.py).
- **Task 3** (completed): Studied matthieugras/timeline-downloader (Go tool using undocumented portal proxy APIs). Found existing dump_machine_timeline and dump_identity_timeline already covered the same APIs. Improved them with: correct URL path format, enrichment flags, POST-based identity search with pagination, skip=9000 boundary restart, identity deduplication, m-package/tenant-id headers, OAuth refresh token auth (alternative to fragile ESTS cookies), stealth rate limit detection, and refactored portal header building. Files changed: mde_datadumper.py, auth.py, conf.py.
- **Task 4** (completed): Added 6 UAL filter options (ual_record_type, ual_operations, ual_user_ids, ual_free_text, ual_ip_addresses, ual_object_ids) under [variables] in .conf. Filters read in M365DataDumper.__init__, injected into Search-UnifiedAuditLog parameters in _new_ual_timeframe. Active filters logged at dump_ual start. Files changed: m365_datadumper.py, conf.py.
- **Task 5** (completed): Added 16 CLI parameters to honk() for all [config], [filters], and [variables] options. CLI args override .conf values via parse_config(). autohonk() passes through kwargs. Files changed: honk.py.

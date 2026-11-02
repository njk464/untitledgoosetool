# CyberFire Goose Lab: Student Quickstart

Collect Entra ID sign-in and audit logs plus Azure Log Analytics (LAW) tables, then check what you got. Everything below runs from a fresh clone.

## 1. Install

Supported Python: 3.9 through 3.13 (3.12+ recommended for better log output).

```sh
git clone https://github.com/cisagov/untitledgoosetool.git
cd untitledgoosetool
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install .
goosey --version
```

## 2. Credentials and encryption password

Choose your own encryption password and export it. Goosey reads it before ever prompting, so nothing is typed or left in shell history by Goosey:

```sh
export GOOSEY_ENCRYPTION_PW='<student-selected-password>'
goosey conf --config_tenant <TENANT_ID>
```

`goosey conf` prompts for the **application (client) ID** and **client secret** (hidden input) and writes them, encrypted with your password, to `.auth.aes`. Tenant ID goes in the generated `.conf`. If `GOOSEY_ENCRYPTION_PW` is unset you are prompted instead. Precedence: `--encryption_pw` (avoid: it shows in process args and shell history), then `GOOSEY_ENCRYPTION_PW`, then prompt. An empty value counts as unset.

**Never commit** `.auth`, `.auth.aes`, `.conf`, `.ugt_auth*`, or the `output/` directory. The repo `.gitignore` covers `*.auth*`, `*_auth*`, `*.aes`, `*.conf` and `output`; still check `git status` before every commit.

## 3. Minimal collector config

Edit `.conf` so only these collectors are True. Set the lab day in UTC and leave `date_end` blank:

```ini
[filters]
date_start=<lab day in UTC, YYYY-MM-DD>
date_end=

[entraid]
entraid_audit=True
signins_rt=True
signins_sp=True

[azure]
log_analytic_workspaces=True
```

Every other collector stays False, including eDiscovery (`[ediscovery]`) and any export/download option: those are opt-in and not part of this lab.

Date semantics:

- Blank `date_end` = the actual current UTC time when you run the collection.
- An explicit `date_end=YYYY-MM-DD` is an **exclusive UTC midnight** bound (that day is not included).

Run it:

```sh
goosey honk
```

## 4. Where the output lands

| Data | Path |
|------|------|
| Entra real-time (interactive/non-interactive) sign-ins | `output/entraid/signin_rt/rt_signin_log_YYYY-MM-DD.json` |
| Entra service principal sign-ins | `output/entraid/signin_sp/sp_signin_log_YYYY-MM-DD.json` |
| Entra audit logs | `output/entraid/entraid_audit_logs/entraidauditlog_YYYY-MM-DD.json` |
| Log Analytics tables | `output/azure/<subscriptionId>/log_analytics_workspace/<workspace_name>/<Table>.json` |

Tables to look for: `AADGraphActivityLogs.json` and `MicrosoftGraphActivityLogs.json`.

Three similar names, three different things:

- `AzureADGraphActivityLogs` is the Entra **diagnostic setting category** you enable.
- `AADGraphActivityLogs` is the **LAW table** that category writes to.
- `MicrosoftGraphActivityLogs` is a **separate** table (its own diagnostic category) for Microsoft Graph requests.

## 5. Empty file: nothing happened, or collection failed?

Each workspace directory gets a `_collection_status.json` manifest:

```sh
python3 -c "import json,sys; m=json.load(open(sys.argv[1])); print(m['discovery_method']); [print(t['table'], t['status'], t['row_count']) for t in m['tables']]" \
  output/azure/<subscriptionId>/log_analytics_workspace/<workspace_name>/_collection_status.json
```

(or with jq: `jq -r '.tables[] | [.table,.status,.row_count] | @tsv' _collection_status.json`)

Schema: `schema_version`, `generated_at`, `workspace_name`, `workspace_resource_id`, `workspace_customer_id`, `discovery_method` (`tables_api` or `search_fallback`), `discovery_error`, `data_check` (`search_summary` or `search_failed`), `lookback_minutes`, and `tables[]` with `table`, `requested_start`, `requested_end`, `status`, `row_count`, `duplicates_skipped`, `artifact`, `error`.

| status | Meaning |
|--------|---------|
| `success`, `row_count` 0, 0-byte artifact | The table exists and was queried; nothing was returned for the window. |
| `success`, `row_count` > 0 | Data collected into `artifact`. |
| `failed` | The query errored (after retries). `error` is non-empty; read it. |
| `skipped` | The table is listed, but a summary search found no rows for the window, so it was not queried individually: no artifact, `row_count` null. |
| `unavailable` | The table is not in the workspace table list: the diagnostic setting is not sending that category (for example `AzureADGraphActivityLogs`), or table discovery failed (see `discovery_error`). |

Notes on the fields:

- To keep LAW load down, Goosey first runs one summary search to see which listed tables have rows in the window (`data_check`: `search_summary`), and only queries those. `AADGraphActivityLogs` and `MicrosoftGraphActivityLogs` are **always** queried when listed, so `success` with 0 rows and an empty artifact is still possible for them. If the summary search fails (`data_check`: `search_failed`), every listed table is queried.
- LAW queries are concurrency-limited, and rate-limit errors (200 requests per 30 seconds per user) are retried with backoff. A failure that persists shows up as `failed` with a non-empty `error`.

- `row_count` is the number of rows newly written **in this run**, not the table total. `duplicates_skipped` counts rows re-fetched by the lookback (below) that were already on disk. Incremental runs append to `<Table>.json`, so a second run with `row_count` 0 is normal if nothing new arrived.
- For `unavailable` entries, `requested_start` and `requested_end` still carry the run window (they are not null).
- If `discovery_method` is `search_fallback`, an absent `AADGraphActivityLogs` is **not** proof the table is empty: search discovery cannot see empty tables. Fix the table listing error (`discovery_error`) and rerun before drawing conclusions.

Log lines you can grep for in the console or `debug.log`:

```
Log Analytics workspace <ws>: discovered <N> table(s) via <tables_api|search_fallback>
Log Analytics workspace <ws>: AADGraphActivityLogs status=<success|failed|unavailable> row_count=<n|None>
WARNING ...table listing failed (<reason>); falling back to search discovery, which cannot see empty tables.
```

**Incremental runs and late-arriving data.** Log ingestion lags: in testing, `MicrosoftGraphActivityLogs` showed a median lag of about 4 minutes, 95th percentile about 7, maximum about 19; Entra sign-ins were similar. A strict checkpoint would silently miss records that arrive after it. So each incremental run re-checks a lookback window before the saved checkpoint (default 30 minutes; override with `incremental_lookback_minutes` under `[variables]` in `.conf`; the manifest records it as `lookback_minutes`) and skips records already collected: Entra by record `id`, LAW by exact-row match. Data that arrives later than the lookback can still be missed. For a final, authoritative pull, run again at least 30 minutes after the activity, or use a fresh output directory with an explicit window.

LAW tables can contain genuine exact-duplicate rows from Microsoft (61 were seen in `MicrosoftGraphActivityLogs`). Goosey preserves them faithfully, so identical rows in the output are not necessarily a Goosey bug.

**Wait before concluding it is empty.** AAD Graph activity takes roughly 2 to 5 minutes to show up in Log Analytics, and `TimeGenerated` can be minutes later than the request time (`TimeRequested`). A run made immediately after generating activity, or with a narrow window, can legitimately look empty. Wait 5 minutes and run `goosey honk` again; the incremental run picks up the newly elapsed time.

## 6. Recollect a wider window

Goosey checkpoints progress in save-state files so reruns are incremental. To go back further, delete only the relevant ones and change `date_start`:

- Entra sign-ins: `output/entraid/.rt_signin_state`, `output/entraid/.sp_signin_state`
- Entra audit: `output/entraid/.audit_log_state`
- LAW: `output/azure/<subscriptionId>/log_analytics_workspace/<workspace_name>/.<Table>.savestate`

Deleting state and rerunning **appends** to existing artifacts, so they may then contain duplicate records. For a clean wider recollection, use a fresh output directory (`goosey honk --output_dir output_wide`) instead.

## 7. Web UI and hunting

```sh
goosey web                      # http://127.0.0.1:8000
goosey web --host 0.0.0.0 --port 8000   # inside a dev container
```

In a dev container or Codespace, forward port 8000 (VS Code Ports tab, "Forward a Port") and open the forwarded URL. Binding `0.0.0.0` exposes the UI to your network; only do that inside the container.

Browse Data has a hunting-query catalog, including two hunts for this lab: **ROADrecon AAD Graph burst** and **Azure CLI legacy AAD Graph token acquisition**.

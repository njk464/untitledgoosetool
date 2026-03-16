# MASTER_PLAN: Untitled Goose Tool

## Identity

**Type:** CLI tool (Python collector + Rust analyzer)
**Languages:** Python (85%), Rust (15% -- new analyzer binary)
**Root:** `/home/analyst/untitledgoosetool`
**Created:** 2026-03-16
**Last updated:** 2026-03-16

Untitled Goose Tool (Goosey) is a CISA-published hunt and incident response tool for collecting telemetry from Microsoft cloud environments (Entra ID, Azure, M365, MDE, D4IoT). The Python collector exports JSONL data; the Rust analyzer (`goosey-analyzer`) scans that output for indicators of compromise using data-driven detection rules.

## Architecture

    goosey/              -- Python collector: auth, datadumpers, CLI, web UI
    goosey-analyzer/     -- Rust binary: JSONL log analyzer (new)
      src/
        main.rs          -- CLI entry point (clap)
        lib.rs           -- Public API, pipeline orchestration
        config.rs        -- TOML rule loading and validation
        scanner.rs       -- Directory auto-detection, file routing
        finding.rs       -- Finding struct, severity, MITRE mapping
        output.rs        -- JSONL output, terminal summary report
        analyzers/
          mod.rs         -- Analyzer trait definition
          signin.rs      -- Sign-in log detections
          ual.rs         -- UAL detections (double-encoded AuditData)
          oauth.rs       -- OAuth/app permission detections
          mde.rs         -- MDE alert/incident detections
          azure.rs       -- Azure activity log detections
      rules/             -- Default TOML rule files shipped with binary
        signin.toml      -- Blacklisted ASNs, UAs, countries, auth flows
        ual.toml         -- Inbox rule patterns, forwarding, evidence destruction
        oauth.toml       -- Blacklisted apps, dangerous permissions
        mde.toml         -- MDE-specific patterns
        azure.toml       -- Azure activity patterns
    docs/                -- Existing documentation
    scripts/             -- Build and utility scripts

## Original Intent

> Create a fast Rust-based log analyzer companion binary called `goosey-analyzer` that scans Goose's JSONL output for suspicious activity. Detection logic is modeled after Microsoft-Analyzer-Suite but implemented as streaming Rust with data-driven TOML rules. The analyzer covers sign-in logs, UAL, OAuth permissions, MDE, and Azure activity logs, outputting JSONL findings with severity levels and MITRE ATT&CK mappings.

## Principles

1. **Data-Driven Detection** -- All blacklists, patterns, and thresholds live in TOML config files, never hardcoded in Rust source. Adding a detection means editing a TOML file, not recompiling.
2. **Streaming First** -- Process JSONL line-by-line. Never load entire files into memory. The tool must handle multi-GB output directories from large tenant collections.
3. **Evidence in Findings** -- Every finding includes the original log entry (or relevant fields) as evidence. An analyst must be able to act on a finding without going back to the raw log.
4. **Composable Analyzers** -- Each analyzer module implements a common trait. New log types or detection categories are added by implementing the trait and registering in the pipeline.
5. **Zero Python Dependencies** -- The Rust analyzer is a standalone binary. It reads Goose's output directory but has no runtime dependency on the Python collector.

---

## Decision Log

| Date | DEC-ID | Initiative | Decision | Rationale |
|------|--------|-----------|----------|-----------|
| 2026-03-16 | DEC-LANG-001 | goosey-analyzer | Use Rust for the analyzer binary | Performance (streaming multi-GB JSONL), single static binary distribution, memory safety without GC pauses |
| 2026-03-16 | DEC-CONFIG-001 | goosey-analyzer | TOML for rule configuration (not YAML) | Rust ecosystem has first-class TOML support (toml crate), aligns with Cargo.toml convention, simpler syntax than YAML for flat key-value blacklists |
| 2026-03-16 | DEC-ARCH-001 | goosey-analyzer | Analyzer trait with per-log-type modules | Clean separation of concerns, each module owns its detection logic, new log types added without touching existing code |
| 2026-03-16 | DEC-IO-001 | goosey-analyzer | JSONL output format for findings | Machine-parseable, composable with jq/grep, same format as input for familiarity |
| 2026-03-16 | DEC-PARSE-001 | goosey-analyzer | Use serde_json::StreamDeserializer for line-by-line parsing | Zero-copy where possible, constant memory regardless of file size, handles malformed lines gracefully |
| 2026-03-16 | DEC-SESSION-001 | goosey-analyzer | In-memory session correlation for AiTM detection | Sign-in session anomalies (same SessionId, different IP/OS) require cross-line state; bounded by session count not file size |

---

## Active Initiatives

### Initiative: goosey-analyzer
**Status:** active
**Started:** 2026-03-16
**Goal:** Build a Rust CLI that scans Goose JSONL output and reports indicators of compromise with severity and MITRE ATT&CK mappings.

> Untitled Goose Tool collects Microsoft cloud telemetry but provides no analysis capability. Analysts must manually review JSONL files or use the slow PowerShell-based Microsoft-Analyzer-Suite. A fast Rust analyzer enables immediate triage of collected data during incident response, where speed matters. Detection rules are based on Microsoft-Analyzer-Suite's proven logic but implemented as streaming analysis with data-driven configuration.

**Dominant Constraint:** performance

#### Goals
- REQ-GOAL-001: Analyze a 1GB JSONL output directory in under 30 seconds on commodity hardware
- REQ-GOAL-002: Detect the same IOC categories as Microsoft-Analyzer-Suite (sign-in anomalies, UAL manipulation, OAuth abuse, session hijacking)
- REQ-GOAL-003: Produce actionable findings with severity, MITRE ATT&CK IDs, and evidence excerpts
- REQ-GOAL-004: Enable analysts to customize detection rules without recompilation via TOML config files

#### Non-Goals
- REQ-NOGO-001: GUI or web interface -- CLI-only for this initiative; visualization is a separate concern
- REQ-NOGO-002: Real-time collection integration -- analyzer reads static output directories, not live streams
- REQ-NOGO-003: D4IoT analysis -- D4IoT uses cookie auth and non-standard formats; defer to future initiative
- REQ-NOGO-004: Automated remediation -- findings are reports, not actions; no API calls back to Microsoft
- REQ-NOGO-005: Windows installer/packaging -- focus on Linux binary; cross-compilation is future work

#### Requirements

**Must-Have (P0)**

- REQ-P0-001: CLI accepts `--input <dir>` and `--config <dir>` with sensible defaults (`./output/`, `./rules/`)
  Acceptance: Given a Goose output directory, When `goosey-analyzer --input ./output/` is run, Then all recognized log files are scanned and findings written to stdout as JSONL
- REQ-P0-002: Auto-detect log types by directory structure and filename patterns (signin_*, ual_*, entraid_*, m365/EXO_*, mde/*, azure/*)
  Acceptance: Given a mixed output directory, When scanner runs, Then each file is routed to the correct analyzer module
- REQ-P0-003: Sign-in log analyzer detects blacklisted ASNs, user agents, countries, suspicious auth flows, legacy auth, risk fields, device compliance, and session anomalies
  Acceptance: Given sign-in logs containing a python-requests user agent and deviceCode auth flow, When analyzed, Then findings are emitted with correct severity and MITRE IDs
- REQ-P0-004: UAL analyzer handles double-encoded AuditData JSON and detects inbox rule manipulation, email forwarding, transport rules, evidence destruction, OAuth abuse, eDiscovery abuse, delegation, and audit tampering
  Acceptance: Given UAL JSONL with AuditData containing New-InboxRule with DeleteMessage action, When analyzed, Then a high-severity finding is emitted with T1564.008
- REQ-P0-005: OAuth/config analyzer detects blacklisted apps, suspicious app patterns, and dangerous permissions (both delegated and application)
  Acceptance: Given entraid_configs/oauthPermissionGrants.json containing Mail.ReadWrite, When analyzed, Then a high-severity finding is emitted
- REQ-P0-006: All detection lists (ASNs, user agents, countries, app IDs, permissions, inbox rule patterns) loaded from TOML config files
  Acceptance: Given a custom signin.toml with an additional blacklisted country "XX", When analyzer runs, Then sign-ins from "XX" are flagged
- REQ-P0-007: Finding output includes: timestamp, severity (critical/high/medium/low/info), category, description, MITRE ATT&CK ID, source file, line number, evidence (relevant fields from the original record)
  Acceptance: Given any detection, When a finding is emitted, Then all seven fields are present and the evidence field contains the triggering record fields
- REQ-P0-008: Terminal summary report showing counts by severity, by category, and top 10 findings
  Acceptance: Given findings from a scan, When `--summary` flag is used (default on), Then a formatted table is printed to stderr

**Nice-to-Have (P1)**

- REQ-P1-001: `--filter` flag to limit analysis to specific log types (e.g., `--filter signin,ual`)
- REQ-P1-002: `--severity` flag to set minimum severity threshold for output (e.g., `--severity high`)
- REQ-P1-003: Parallel file processing using rayon for multi-core speedup
- REQ-P1-004: `--output <file>` flag to write findings to a file instead of stdout
- REQ-P1-005: MDE analyzer for alerts, incidents, and advanced hunting results
- REQ-P1-006: Azure activity log analyzer for suspicious resource operations

**Future Consideration (P2)**

- REQ-P2-001: SARIF output format for integration with security tooling
- REQ-P2-002: HTML report generation
- REQ-P2-003: Custom rule DSL beyond TOML pattern matching
- REQ-P2-004: Integration with Goose CLI (`goosey analyze` subcommand calling the Rust binary)
- REQ-P2-005: Cross-log correlation (e.g., sign-in from blacklisted IP followed by inbox rule creation)

#### Definition of Done

`goosey-analyzer` binary compiles, passes unit tests, and correctly analyzes sign-in logs, UAL, and OAuth configs from a Goose output directory. Detection rules are loaded from TOML files. Findings are output as JSONL with severity and MITRE ATT&CK IDs. Terminal summary report displays counts. REQ-P0-001 through REQ-P0-008 acceptance criteria are met.

#### Architectural Decisions

- DEC-LANG-001: Use Rust for the analyzer binary
  Addresses: REQ-GOAL-001.
  Rationale: Streaming JSONL parsing at multi-GB scale requires predictable performance. Rust provides zero-cost abstractions, no GC pauses, and compiles to a single static binary for easy distribution alongside the Python collector.

- DEC-CONFIG-001: TOML for rule configuration
  Addresses: REQ-GOAL-004, REQ-P0-006.
  Rationale: Rust has first-class TOML support via the `toml` crate. TOML is simpler than YAML for the flat lists and key-value patterns used in detection rules. Aligns with Cargo.toml convention familiar to Rust developers.

- DEC-ARCH-001: Analyzer trait with per-log-type modules
  Addresses: REQ-GOAL-002, REQ-P0-002.
  Rationale: Each log type has distinct schema and detection logic. A common `Analyzer` trait (`fn analyze(&self, record: &Value) -> Vec<Finding>`) enables clean separation. New log types are added by implementing the trait and registering in the scanner, without modifying existing analyzers.

- DEC-IO-001: JSONL output format for findings
  Addresses: REQ-GOAL-003, REQ-P0-007.
  Rationale: JSONL is machine-parseable, composable with jq/grep, and matches the input format for analyst familiarity. Structured output enables downstream tooling.

- DEC-PARSE-001: Line-by-line serde_json parsing (not StreamDeserializer)
  Addresses: REQ-GOAL-001, REQ-P0-004.
  Rationale: JSONL files are one JSON object per line. Reading with BufReader line-by-line and calling `serde_json::from_str` per line gives constant memory usage, graceful handling of malformed lines (skip and warn), and natural line-number tracking for evidence. StreamDeserializer is better for continuous JSON streams but less useful for JSONL with line semantics.

- DEC-SESSION-001: In-memory HashMap for session correlation
  Addresses: REQ-P0-003 (session anomalies).
  Rationale: AiTM/cookie theft detection requires comparing sign-ins with the same SessionId across different IPs/OS/browsers. A HashMap<SessionId, Vec<SignInSummary>> bounded by session count (typically thousands, not millions) keeps memory usage reasonable while enabling cross-record correlation.

#### Waves

##### Initiative Summary
- **Total items:** 6
- **Critical path:** 4 waves (W1-1 -> W2-1 -> W3-1 -> W4-1)
- **Max width:** 2 (Wave 2, Wave 3)
- **Gates:** 1 review (W1-1), 0 approve

##### Wave 1 (no dependencies)
**Parallel dispatches:** 1

**W1-1: Core framework -- Cargo project, CLI, JSONL streaming, config loading, scanner, finding output** -- Weight: L, Gate: review
- Initialize `goosey-analyzer/` Cargo project with workspace-independent structure
- `Cargo.toml` dependencies:
  ```toml
  [dependencies]
  clap = { version = "4", features = ["derive"] }
  serde = { version = "1", features = ["derive"] }
  serde_json = "1"
  toml = "0.8"
  glob = "0.3"
  chrono = { version = "0.4", features = ["serde"] }
  anyhow = "1"
  colored = "2"
  ```
- `src/main.rs`: Clap-derived CLI struct with `--input`, `--config`, `--filter`, `--severity`, `--summary`, `--output` args
- `src/config.rs`: Load and validate TOML rule files from a directory. Define `RuleSet` struct containing `Vec<String>` blacklists, pattern lists, permission lists. Deserialize with serde.
- `src/scanner.rs`: Walk `--input` directory, match filename patterns to log types:
  - `signin_*/` -> SignIn
  - `ual_*.json` -> UAL
  - `entraid_configs/` -> OAuthConfig
  - `entraid_audit_logs/` -> EntraAudit
  - `m365/EXO_InboxRules_*.json` -> EXOInboxRules
  - `mde/api_*.json` -> MDE
  - `*/Activity Log/` -> AzureActivity
- `src/finding.rs`: `Finding` struct with fields: id (uuid), timestamp, severity (enum Critical/High/Medium/Low/Info), category (String), description, mitre_id (Option), source_file, line_number, evidence (serde_json::Value). Serialize to JSONL.
- `src/output.rs`: Write findings as JSONL to stdout or file. Print summary table to stderr (counts by severity, by category, top 10 descriptions).
- `src/analyzers/mod.rs`: Define `Analyzer` trait:
  ```rust
  pub trait Analyzer {
      fn name(&self) -> &str;
      fn analyze(&self, record: &serde_json::Value, ctx: &AnalysisContext) -> Vec<Finding>;
      fn finalize(&self) -> Vec<Finding> { vec![] } // for cross-record analysis
  }
  ```
  `AnalysisContext` holds source_file, line_number, config reference.
- `src/lib.rs`: Pipeline orchestration -- for each file from scanner, open BufReader, iterate lines, route to appropriate analyzer, collect findings, call finalize() at end of each file.
- `rules/` directory with stub TOML files (empty blacklists, to be populated in Wave 2-3)
- Unit tests: config loading with valid/invalid TOML, scanner routing with mock directory structure, finding serialization round-trip
- **Integration:** New `goosey-analyzer/` directory at project root. Add to `.gitignore`: `goosey-analyzer/target/`. No changes to existing Python code.

##### Wave 2
**Parallel dispatches:** 2
**Blocked by:** W1-1

**W2-1: Sign-in log analyzer** -- Weight: L, Gate: none, Deps: W1-1
- `src/analyzers/signin.rs`: Implement `Analyzer` trait for `SignInAnalyzer`
- Detection logic (all pattern-matched against TOML config):
  - Blacklisted ASN check: extract `autonomousSystemNumber` field, match against `signin.toml` `blacklisted_asns` list (400+ entries)
  - Blacklisted User Agent: extract `userAgent` or `deviceDetail.browser`, match against `signin.toml` `blacklisted_user_agents` (AADInternals, azurehound, bloodhound, curl, Go-http-client, python-requests, PowerShell, fasthttp, BAV2ROPC, etc.)
  - Blacklisted Country: extract `location.countryOrRegion`, match against `signin.toml` `blacklisted_countries` (CN, RU, IR, NG, PK, UA, etc.)
  - Suspicious Auth Flows: check `authenticationProtocol` or `originalTransferMethod` for deviceCode, deviceCodeFlow
  - Suspicious AppIds: check `appId` against `signin.toml` `suspicious_app_ids` (Auth Broker, My Apps portal, VS Code)
  - Privacy Service: check `networkLocationDetails` or `ipAddressFromResourceProvider` for VPN/Proxy/Tor/Relay/Hosting indicators
  - Risk Fields: check `riskLevelDuringSignIn`, `riskLevelAggregated` for non-"none" values
  - Legacy Auth: check `clientAppUsed` for "Authenticated SMTP", "Other clients", etc.
  - Device Compliance: check `deviceDetail.isCompliant` == false, `deviceDetail.isManaged` == false
  - Session anomalies (AiTM): Accumulate `sessionId` -> (IP, OS, browser) in HashMap. At `finalize()`, emit findings for sessions with multiple distinct IPs or OS/browser combos
- `rules/signin.toml`: Full blacklists populated from Microsoft-Analyzer-Suite reference data
- MITRE mappings: T1078 (Valid Accounts), T1110.001 (Password Guessing), T1110.003 (Password Spraying), T1539 (Session Cookie Theft), T1090.003 (Proxy/Multi-hop)
- Unit tests: one test per detection category with crafted JSON records
- **Integration:** Register `SignInAnalyzer` in `analyzers/mod.rs` factory. Scanner routes `signin_*/*.json` files to it.

**W2-2: UAL analyzer** -- Weight: L, Gate: none, Deps: W1-1
- `src/analyzers/ual.rs`: Implement `Analyzer` trait for `UalAnalyzer`
- **Critical: AuditData double-encoding.** UAL records have an `AuditData` field that is a JSON string within the JSON record. The analyzer must: (1) parse the outer record, (2) extract `AuditData` as a string, (3) parse that string as JSON to get the inner record, (4) run detections against the inner record.
- Detection logic (all pattern-matched against TOML config):
  - Inbox Rule Manipulation: check `Operation` for New-InboxRule, Set-InboxRule. Check `Parameters` for suspicious names/actions (MarkAsRead, DeleteMessage, ForwardTo, RedirectTo)
  - Email Forwarding: check `Parameters` for DeliverToMailboxAndForward, ForwardingAddress, ForwardingSmtpAddress
  - Transport Rule Abuse: check `Operation` for New-TransportRule, Set-TransportRule
  - Evidence Destruction: check `Operation` for HardDelete, SoftDelete, MoveToDeletedItems
  - OAuth/App Abuse: check `Operation` for "Add application", "Consent to application", "Add delegated permission grant"
  - eDiscovery Abuse: check `Operation` for SearchStarted, SearchExportDownloaded, New-ComplianceSearch
  - Delegation: check `Operation` for Add-MailboxPermission with FullAccess, SendAs
  - Power Automate: check `Operation` for CreateFlow
  - Audit Tampering: check `Operation` matching `*-UnifiedAuditLogRetentionPolicy`
  - AiTM indicator: check `ClientInfoString` for "Client=OWA;Action=ViaProxy"
- `rules/ual.toml`: Operation patterns, suspicious parameter values, forwarding indicators
- MITRE mappings: T1114.003 (Email Forwarding Rules), T1564.008 (Email Hiding Rules), T1098 (Account Manipulation)
- Unit tests: crafted double-encoded UAL records for each detection category
- **Integration:** Register `UalAnalyzer` in `analyzers/mod.rs` factory. Scanner routes `ual_*.json` and `m365/` files to it.

##### Wave 3
**Parallel dispatches:** 2
**Blocked by:** W1-1

**W3-1: OAuth/Config analyzer** -- Weight: M, Gate: none, Deps: W1-1
- `src/analyzers/oauth.rs`: Implement `Analyzer` trait for `OAuthAnalyzer`
- Detection logic:
  - Blacklisted Apps: check `appId` or `appDisplayName` against `oauth.toml` `blacklisted_apps` (rclone, eM Client, PerfectData, etc. -- 12 apps)
  - Suspicious App Patterns: check `appDisplayName` for non-alphanumeric chars, check `replyUrls` for localhost, check for "test" in name
  - Dangerous Delegated Permissions: check `scope` or `consentedPermissions` against `oauth.toml` `dangerous_delegated_permissions` (Mail.Read, Mail.Send, Files.ReadWrite.All, etc. -- 48+ permissions)
  - Dangerous Application Permissions: check `appRoleAssignments` against `oauth.toml` `dangerous_application_permissions` (Mail.ReadWrite, Application.ReadWrite.All, etc. -- 20+ permissions)
- Handles multiple config file formats: `oauthPermissionGrants.json`, `appRoleAssignments.json`, `applications.json`, `servicePrincipals.json`
- `rules/oauth.toml`: Full blacklists and permission lists from Microsoft-Analyzer-Suite reference
- Unit tests: crafted config records for each detection category
- **Integration:** Register `OAuthAnalyzer` in `analyzers/mod.rs` factory. Scanner routes `entraid_configs/*.json` files to it.

**W3-2: MDE and Azure analyzers** -- Weight: M, Gate: none, Deps: W1-1
- `src/analyzers/mde.rs`: Implement `Analyzer` trait for `MdeAnalyzer`
  - Alert severity passthrough: read MDE alerts and map severity to finding severity
  - Incident correlation: flag incidents with multiple alerts
  - Advanced hunting results: scan for known IOC patterns in hunting query output
- `src/analyzers/azure.rs`: Implement `Analyzer` trait for `AzureAnalyzer`
  - Suspicious operations: resource deletion, role assignment changes, policy modifications
  - Failed operations at scale (potential brute force)
  - Sentinel incident passthrough
- `rules/mde.toml` and `rules/azure.toml`: Operation blacklists and patterns
- Unit tests for each analyzer
- **Integration:** Register `MdeAnalyzer` and `AzureAnalyzer` in `analyzers/mod.rs` factory. Scanner routes `mde/*.json` and `*/Activity Log/*.json` files to them.

##### Wave 4
**Parallel dispatches:** 1
**Blocked by:** W2-1, W2-2, W3-1, W3-2

**W4-1: Summary reporting, MITRE mapping, integration testing** -- Weight: M, Gate: review, Deps: W2-1, W2-2, W3-1, W3-2
- `src/output.rs` enhancements:
  - Summary table: counts by severity (Critical: N, High: N, ...), counts by category, counts by MITRE technique
  - Top 10 most frequent finding descriptions
  - Top 10 unique source IPs/users across findings (if extractable)
  - Colored terminal output using `colored` crate
- MITRE ATT&CK mapping table: compile a static HashMap of technique ID to name/description, used for enriching output
- Integration tests:
  - Create a `tests/fixtures/` directory with sample Goose output (crafted JSONL files with known IOCs)
  - End-to-end test: run analyzer against fixtures, assert expected findings count and categories
  - Test `--filter` flag: only specified analyzers run
  - Test `--severity` flag: findings below threshold are excluded from output
  - Test malformed JSONL handling: bad lines are skipped with warnings, valid lines still processed
- README.md for `goosey-analyzer/`: installation, usage, rule customization, example output
- **Integration:** No new registrations. Enhances existing output.rs and adds integration test harness.

##### Critical Files
- `goosey-analyzer/src/lib.rs` -- Pipeline orchestration, the heart of the analyzer
- `goosey-analyzer/src/analyzers/mod.rs` -- Analyzer trait definition and registry
- `goosey-analyzer/src/config.rs` -- Rule loading; every analyzer depends on this
- `goosey-analyzer/src/scanner.rs` -- File routing; wrong routing means missed detections
- `goosey-analyzer/rules/signin.toml` -- Largest rule file (400+ ASNs, 24+ UAs, 46+ countries)

##### Decision Log
<!-- Guardian appends here after wave completion -->

#### goosey-analyzer Worktree Strategy

Main is sacred. Each wave dispatches parallel worktrees:
- **Wave 1:** `.worktrees/analyzer-core` on branch `feature/analyzer-core`
- **Wave 2:** `.worktrees/analyzer-signin` on branch `feature/analyzer-signin`, `.worktrees/analyzer-ual` on branch `feature/analyzer-ual`
- **Wave 3:** `.worktrees/analyzer-oauth` on branch `feature/analyzer-oauth`, `.worktrees/analyzer-mde-azure` on branch `feature/analyzer-mde-azure`
- **Wave 4:** `.worktrees/analyzer-reporting` on branch `feature/analyzer-reporting`

#### goosey-analyzer References

- Microsoft-Analyzer-Suite detection logic (PowerShell reference implementation)
- Goose output directory structure: `output/{entraid,m365,mde,azure}/` with JSONL files
- Goose sign-in file naming: `signin_{source}/{source}_signin_log_YYYY-MM-DD.json` (sources: adfs, rt, sp, msi)
- Goose UAL file naming: `ual_YYYY-MM-DDTHH_MM_SS_YYYY-MM-DDTHH_MM_SS.json`
- UAL AuditData is double-encoded: outer JSON has `AuditData` field containing a JSON string that must be parsed again
- Goose Entra config files: `entraid_configs/{endpoint}.json` (~50 files)
- MITRE ATT&CK techniques: T1078, T1110.001, T1110.003, T1539, T1114.003, T1564.008, T1090.003, T1098

---

## Completed Initiatives

| Initiative | Period | Phases | Key Decisions | Archived |
|-----------|--------|--------|---------------|----------|

---

## Parked Issues

| Issue | Description | Reason Parked |
|-------|-------------|---------------|
| D4IoT Analysis | Analyze D4IoT sensor/alert data for IOCs | Non-standard auth (cookie-based), different data format; defer to future initiative |
| Cross-log Correlation | Correlate events across log types (e.g., sign-in + inbox rule) | Requires all analyzers to be mature first; complex state management |

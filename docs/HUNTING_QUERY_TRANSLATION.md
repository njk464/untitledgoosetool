# Hunting Query Translation Guide

This guide helps analysts translate KQL (Kusto Query Language) queries from
Microsoft Sentinel / Log Analytics into HQL (Hash Query Language) queries that
run against Goosey-collected output files.

---

## Supported HQL Operators

| HQL operator | Description | KQL equivalent |
|---|---|---|
| `where <condition>` | Filter rows | `where <condition>` |
| `project <fields>` | Select specific columns | `project <fields>` |
| `summarize <agg>() by <field>` | Group and aggregate | `summarize <agg>() by <field>` |
| `sort by <field> asc\|desc` | Order results | `order by <field> asc\|desc` |
| `take <N>` | Limit output rows | `take <N>` / `limit <N>` |
| `mv-expand <field>` | Expand array field to rows | `mv-expand <field>` |

### Supported aggregation functions

`count()`, `sum(<field>)`, `avg(<field>)`, `min(<field>)`, `max(<field>)`, `dcount(<field>)`

---

## Unsupported Operators (and Workarounds)

The following KQL constructs have **no direct HQL equivalent**.  Use the
workaround described, or note the limitation in query documentation.

| KQL construct | Why unsupported | Workaround |
|---|---|---|
| `let x = …` | HQL has no variable binding | Inline the expression |
| `ago(Nd)` | No time arithmetic functions | Pre-filter the source file by date before querying, or omit the time filter and note it in the query description |
| `union TableA, TableB` | No multi-table union | Run separate queries per file; combine results manually |
| `make_set(<field>)` | Not in pyhql aggregations | Use `dcount()` to count distinct values instead |
| `parse_json(<field>)` | No dynamic field parsing | HQL reads JSON fields natively; access nested fields with bracket notation (see below) |
| `has_any(<list>)` | Not in pyhql grammar | Chain `contains` comparisons with `or` |
| `extend` | No computed column operator | Use `project` with only the fields you need, or accept the raw field in output |
| `join` | Not in pyhql grammar | Run two separate queries; join results in Python / spreadsheet |
| `tostring()`, `toint()` | No type cast functions | Goosey outputs JSON with native types; comparisons usually work without casting |
| `isempty()`, `isnotempty()` | No predicate functions | Use `== ""` or `!= ""` for string emptiness checks |
| `startofday()`, `endofday()` | No date truncation functions | Filter by ISO 8601 prefix: `where eventTimestamp startswith "2024-03-"` |

---

## Field Name Mapping

KQL queries reference **Log Analytics table column names**.  HQL queries
reference the **actual JSON field names** written to disk by Goosey.  They
are often different.

### Entra ID Sign-in Logs

| KQL (SigninLogs) | Goosey JSON field | Notes |
|---|---|---|
| `UserPrincipalName` | `userPrincipalName` | camelCase in Goosey |
| `IPAddress` | `ipAddress` | |
| `Location` | `['location.countryOrRegion']` | Nested; use bracket notation |
| `ClientAppUsed` | `clientAppUsed` | |
| `ResultType` | `['status.errorCode']` | `"0"` = success (string, not int) |
| `ResultDescription` | `['status.failureReason']` | |
| `RiskLevelDuringSignIn` | `riskLevelDuringSignIn` | |
| `RiskState` | `riskState` | |
| `AppDisplayName` | `appDisplayName` | |
| `DeviceDetail.Browser` | `['deviceDetail.browser']` | Nested |
| `DeviceDetail.OperatingSystem` | `['deviceDetail.operatingSystem']` | Nested |
| `DeviceDetail.IsCompliant` | `['deviceDetail.isCompliant']` | Boolean |
| `AuthenticationProtocol` | `authenticationProtocol` | |
| `ConditionalAccessStatus` | `conditionalAccessStatus` | |
| `AuthenticationRequirement` | `authenticationRequirement` | |
| `ServicePrincipalId` | `servicePrincipalId` | Present for SP sign-ins |

### UAL (Unified Audit Log)

| KQL (OfficeActivity) | Goosey JSON field | Notes |
|---|---|---|
| `Operation` | `Operations` | Note capital O and plural |
| `UserId` | `UserIds` | Capital U, plural |
| `TimeGenerated` | `CreationDate` | |
| `AuditData` | `AuditData` | Double-encoded JSON string; must be parsed separately |

**Note on AuditData:** The `AuditData` field is a JSON-encoded string inside
the outer JSON record.  HQL queries can filter on `Operations` and `UserIds`
directly.  To inspect inner AuditData fields (e.g. `Parameters`, `ClientIP`),
export the matching rows and parse the `AuditData` string with `json.loads()`
in Python.

### Entra ID Config Files

| Entity | Goosey file | Key fields |
|---|---|---|
| OAuth permission grants | `entraid_configs/oauth_permission_grants.json` | `clientId`, `principalId`, `resourceId`, `scope`, `consentType` |
| Applications | `entraid_configs/applications.json` | `appId`, `displayName`, `createdDateTime` |
| Service principals | `entraid_configs/service_principals.json` | `appId`, `displayName`, `accountEnabled`, `appOwnerOrganizationId` |
| App role assignments | `entraid_configs/app_role_assignments.json` | `principalDisplayName`, `resourceDisplayName`, `appRoleId` |

### MDE Alerts

| KQL (AlertInfo) | Goosey JSON field |
|---|---|
| `Title` | `["title"]` (reserved word — bracket notation required) |
| `Severity` | `severity` |
| `Status` | `status` |
| `Category` | `category` |
| `DeviceName` | `computerDnsName` |
| `DeviceId` | `machineId` |
| `Timestamp` | `alertCreationTime` |
| `LastEventTime` | `lastUpdateTime` |
| `AttackTechniques` | `mitreTechniques` (array — use `mv-expand`) |

### Azure Activity Log

| KQL (AzureActivity) | Goosey JSON field |
|---|---|
| `OperationNameValue` | `['operationName.value']` |
| `ActivityStatus` | `['status.value']` |
| `Caller` | `caller` |
| `ResourceGroup` | `resourceGroupName` |
| `ResourceProviderValue` | `resourceType` |
| `TimeGenerated` | `eventTimestamp` |

---

## Common Translation Patterns

### 1. String containment

```
KQL:  | where X has "value"
HQL:  | where X contains "value"
```

`contains` in HQL is case-insensitive, matching `has` in KQL.

```
KQL:  | where X has_any ("a", "b", "c")
HQL:  | where X contains "a" or X contains "b" or X contains "c"
```

### 2. Prefix / suffix matching

```
KQL:  | where X startswith "prefix"
HQL:  | where X startswith "prefix"    (same syntax)

KQL:  | where X endswith "suffix"
HQL:  | where X endswith "suffix"      (same syntax)
```

### 3. Equality and inequality

```
KQL:  | where X == "value"   →  HQL: | where X == "value"
KQL:  | where X != "value"   →  HQL: | where X != "value"
KQL:  | where X =~ "VALUE"   →  HQL: | where X == "VALUE"   (HQL string == is case-sensitive; use contains for case-insensitive)
```

### 4. Dotted / nested field access

```
KQL:  | where DeviceDetail.Browser has "python"
HQL:  | where ['deviceDetail.browser'] contains "python"
```

Use `['field.subfield']` bracket notation for any field whose name contains a dot.

### 5. Expanding array fields

```
KQL:  | mv-expand todynamic(AttackTechniques)
HQL:  | mv-expand mitreTechniques
```

After `mv-expand`, the field contains individual string elements instead of a list.

### 6. Time range filtering

```
KQL:  | where TimeGenerated > ago(7d)
HQL:  | where eventTimestamp > "2024-03-17"   (use a literal ISO 8601 date)
```

There is no `ago()` function in HQL.  Calculate the cutoff date before writing
the query and use a string comparison with an ISO 8601 prefix.

### 7. Counting distinct values

```
KQL:  | summarize make_set(UserPrincipalName) by IPAddress
HQL:  | summarize dcount(userPrincipalName) by ipAddress
```

`dcount()` gives the count of distinct values.  HQL has no equivalent of
`make_set()` (which returns the actual set of values).

### 8. Reserved word fields

Some field names are HQL reserved words and must use bracket notation:

```
KQL:  | project Title, Severity
HQL:  | project ["title"], severity
```

Known reserved words encountered in Goosey data: `title`, `type`, `count`.
When in doubt, wrap any field name in `["…"]`.

### 9. Inline variable elimination (`let`)

```
KQL:  let threshold = 10;
      SigninLogs | where Count > threshold

HQL:  (no let support — inline the value)
      | where count_ > 10
```

### 10. Full query structure

Every HQL query run via `hql_compat.run_hql_query()` is automatically prefixed
with a database/file preamble.  In the catalog `hql_query` field, write only
the pipe-separated operators:

```
hql_query: "where severity == \"High\" | summarize count() by category"
```

At runtime this becomes:

```
database("goose").file("path/to/file.json") | where severity == "High" | summarize count() by category
```

---

## Quick Reference Card

```
Supported           Unsupported (use workaround)
─────────────       ──────────────────────────────────────
where               let
project             ago() / datetime arithmetic
summarize           union
sort by             make_set()
take                parse_json() / todynamic()
mv-expand           has_any()
count()             extend (computed columns)
dcount()            join
sum() avg()         isempty() / isnotempty()
min() max()         tostring() / toint()
== != < > <= >=     startofday() / endofday()
contains
startswith
endswith
and / or / not
['dotted.field']
```

# Datadumper Reference

This document catalogs every data collection module in Untitled Goose Tool, the APIs each method calls, and the output files produced.

All output is written as JSONL (one JSON object per line) unless otherwise noted. Output directories are relative to the `--output_dir` (default: `output/`).

---

## Table of Contents

- [Entra ID (Azure AD)](#entra-id-azure-ad)
- [M365 / Exchange Online](#m365--exchange-online)
- [Microsoft Defender for Endpoint (MDE)](#microsoft-defender-for-endpoint-mde)
- [Azure](#azure)
- [Defender for IoT (D4IoT) — Sensor & Management Console](#defender-for-iot-d4iot--sensor--management-console)
- [eDiscovery (Microsoft Purview)](#ediscovery-microsoft-purview)

---

## Entra ID (Azure AD)

**Class:** `EntraIdDataDumper` (`goosey/entra_id_datadumper.py`)
**Auth token:** `graph_api` (Microsoft Graph)
**Base URL:** `https://graph.microsoft.com/beta/`
**Output directory:** `output/entraid/`
**Config section:** `[entraid]`

### Sign-in Logs

All sign-in methods call the same underlying `_dump_signins(source)` helper, which queries the Graph API sign-in endpoint with a source filter. Logs are chunked by day.

| Config Key | Method | Source | API Endpoint | Output |
|---|---|---|---|---|
| `signins_adfs` | `dump_signins_adfs()` | `adfs` (interactive) | `GET /beta/auditLogs/signIns?source=adfs` | `signin_adfs/adfs_signin_log_YYYY-MM-DD.json` |
| `signins_rt` | `dump_signins_rt()` | `rt` (non-interactive) | `GET /beta/auditLogs/signIns?source=rt` | `signin_rt/rt_signin_log_YYYY-MM-DD.json` |
| `signins_sp` | `dump_signins_sp()` | `sp` (service principal) | `GET /beta/auditLogs/signIns?source=sp` | `signin_sp/sp_signin_log_YYYY-MM-DD.json` |
| `signins_msi` | `dump_signins_msi()` | `msi` (managed identity) | `GET /beta/auditLogs/signIns?source=msi` | `signin_msi/msi_signin_log_YYYY-MM-DD.json` |

- **Default range:** Last 29 days (or configured `date_start`/`date_end`)
- **Save state:** `.{source}_signin_state` — resumes from last completed day
- **Pagination:** `@odata.nextLink` with retry on 429

### Audit Logs

| Config Key | Method | API Endpoint | Output |
|---|---|---|---|
| `entraid_audit` | `dump_entraid_audit()` | `GET /beta/auditLogs/directoryAudits` | `entraid_audit_logs/entraidauditlog_YYYY-MM-DD.json` |

- **Default range:** Last 29 days (audit log retention limit)
- **Save state:** `.audit_log_state`
- **Filter:** `activityDateTime` date range

### Provisioning Logs

| Config Key | Method | API Endpoint | Output |
|---|---|---|---|
| `entraid_provisioning` | `dump_entraid_provisioning()` | `GET /beta/auditLogs/provisioning` | `entraidprovisioninglogs.json` |

- No date filtering; single pull with pagination

### Configuration & Inventory

| Config Key | Method | Output Directory |
|---|---|---|
| `configs` | `dump_configs()` | `entraid_configs/` |

Runs ~50 Graph API calls in parallel via `asyncio.gather()`. All use `GET /beta/{endpoint}`.

**Single-object endpoints** (one file each in `entraid_configs/`):

| Endpoint | Output File |
|---|---|
| `applications` | `applications.json` |
| `directory/deleteditems/microsoft.graph.application` | `directory_deleteditems_microsoft.graph.application.json` |
| `identityGovernance/appConsent/appConsentRequests` | `identityGovernance_appConsent_appConsentRequests.json` |
| `conditionalAccess/authenticationContextClassReferences` | `conditionalAccess_authenticationContextClassReferences.json` |
| `conditionalAccess/namedLocations` | `conditionalAccess_namedLocations.json` |
| `conditionalAccess/policies` | `conditionalAccess_policies.json` |
| `devices` | `devices.json` |
| `directoryRoles` | `directoryRoles.json` |
| `roleManagement/directory/roleDefinitions` | `roleManagement_directory_roleDefinitions.json` |
| `roleManagement/directory/roleAssignmentSchedules` | `roleManagement_directory_roleAssignmentSchedules.json` |
| `roleManagement/directory/roleEligibilitySchedules` | `roleManagement_directory_roleEligibilitySchedules.json` |
| `roleManagement/directory/roleEligibilityScheduleInstances` | `roleManagement_directory_roleEligibilityScheduleInstances.json` |
| `groups` | `groups.json` |
| `directory/deleteditems/microsoft.graph.group` | `directory_deleteditems_microsoft.graph.group.json` |
| `identity/identityProviders` | `identity_identityProviders.json` |
| `identity/identityProviders/availableProviderTypes` | `identity_identityProviders_availableProviderTypes.json` |
| `directorySettingTemplates` | `directorySettingTemplates.json` |
| `directory/federationConfigurations/graph.samlOrWsFedExternalDomainFederation` | `directory_federationConfigurations_graph.samlOrWsFedExternalDomainFederation.json` |
| `domains` | `domains.json` |
| `organization` | `organization.json` |
| `subscribedSkus` | `subscribedSkus.json` |
| `identity/continuousAccessEvaluationPolicy` | `identity_continuousAccessEvaluationPolicy.json` |
| `identity/events/onSignupStart` | `identity_events_onSignupStart.json` |
| `policies/activityBasedTimeoutPolicies` | `policies_activityBasedTimeoutPolicies.json` |
| `policies/defaultAppManagementPolicy` | `policies_defaultAppManagementPolicy.json` |
| `policies/tokenLifetimePolicies` | `policies_tokenLifetimePolicies.json` |
| `policies/tokenIssuancePolicies` | `policies_tokenIssuancePolicies.json` |
| `policies/authenticationFlowsPolicy` | `policies_authenticationFlowsPolicy.json` |
| `policies/authenticationMethodsPolicy` | `policies_authenticationMethodsPolicy.json` |
| `policies/authorizationPolicy` | `policies_authorizationPolicy.json` |
| `policies/claimsMappingPolicies` | `policies_claimsMappingPolicies.json` |
| `policies/homeRealmDiscoveryPolicies` | `policies_homeRealmDiscoveryPolicies.json` |
| `policies/permissionGrantPolicies` | `policies_permissionGrantPolicies.json` |
| `policies/identitySecurityDefaultsEnforcementPolicy` | `policies_identitySecurityDefaultsEnforcementPolicy.json` |
| `policies/accessReviewPolicy` | `policies_accessReviewPolicy.json` |
| `policies/adminConsentRequestPolicy` | `policies_adminConsentRequestPolicy.json` |
| `servicePrincipals` | `servicePrincipals.json` |
| `reports/getRelyingPartyDetailedSummary(period='D30')` | `reports_getRelyingPartyDetailedSummary(period='D30').json` |
| `reports/getAzureAdApplicationSignInSummary(period='D30')` | `reports_getAzureAdApplicationSignInSummary(period='D30').json` |
| `reports/applicationSignInDetailedSummary` | `reports_applicationSignInDetailedSummary.json` |
| `reports/getCredentialUsageSummary(period='D30')` | `reports_getCredentialUsageSummary(period='D30').json` |
| `reports/getCredentialUserRegistrationCount` | `reports_getCredentialUserRegistrationCount.json` |
| `reports/credentialUserRegistrationDetails` | `reports_credentialUserRegistrationDetails.json` |
| `reports/userCredentialUsageDetails` | `reports_userCredentialUsageDetails.json` |
| `users` | `users.json` |
| `contacts` | `contacts.json` |
| `oauth2PermissionGrants` | `oauth2PermissionGrants.json` |
| `directory/deletedItems/microsoft.graph.user` | `directory_deletedItems_microsoft.graph.user.json` |
| `policies/featureRolloutPolicies` | `policies_featureRolloutPolicies.json` |

**Parent-child relationship endpoints** (fetches child objects for every parent entity):

| Parent | Child | Output File |
|---|---|---|
| `users` | `appRoleAssignments` | `users_appRoleAssignments.json` |
| `users` | `appRoleAssignedResources` | `users_appRoleAssignedResources.json` |
| `users` | `registeredDevices` | `users_registeredDevices.json` |
| `users` | `authentication/methods` | `users_authentication_methods.json` |
| `applications` | `extensionProperties` | `applications_extensionProperties.json` |
| `applications` | `owners` | `applications_owners.json` |
| `applications` | `tokenIssuancePolicies` | `applications_tokenIssuancePolicies.json` |
| `applications` | `tokenLifetimePolicies` | `applications_tokenLifetimePolicies.json` |
| `applications` | `federatedIdentityCredentials` | `applications_federatedIdentityCredentials.json` |
| `directoryRoles` | `members` | `directoryRoles_members.json` |
| `groups` | `appRoleAssignments` | `groups_appRoleAssignments.json` |
| `domains` | `federationConfiguration` | `domains_federationConfiguration.json` |
| `servicePrincipals` | `appRoleAssignments` | `servicePrincipals_appRoleAssignments.json` |
| `servicePrincipals` | `appRoleAssignedTo` | `servicePrincipals_appRoleAssignedTo.json` |
| `servicePrincipals` | `owners` | `servicePrincipals_owners.json` |
| `servicePrincipals` | `createdObjects` | `servicePrincipals_createdObjects.json` |
| `servicePrincipals` | `ownedObjects` | `servicePrincipals_ownedObjects.json` |
| `servicePrincipals` | `oauth2PermissionGrants` | `servicePrincipals_oauth2PermissionGrants.json` |
| `servicePrincipals` | `memberOf` | `servicePrincipals_memberOf.json` |
| `servicePrincipals` | `transitiveMemberOf` | `servicePrincipals_transitiveMemberOf.json` |
| `servicePrincipals` | `homeRealmDiscoveryPolicies` | `servicePrincipals_homeRealmDiscoveryPolicies.json` |
| `servicePrincipals` | `synchronization/jobs` | `servicePrincipals_synchronization_jobs.json` |
| `servicePrincipals` | `claimsMappingPolicies` | `servicePrincipals_claimsMappingPolicies.json` |
| `servicePrincipals` | `tokenLifetimePolicies` | `servicePrincipals_tokenLifetimePolicies.json` |
| `servicePrincipals` | `delegatedPermissionClassifications` | `servicePrincipals_delegatedPermissionClassifications.json` |

### Risk & Security

| Config Key | Method | Output Directory | Endpoints |
|---|---|---|---|
| `risk_detections` | `dump_risk_detections()` | `entraid_riskdetections/` | `identityProtection/riskDetections`, `identityProtection/servicePrincipalRiskDetections` |
| `risky_objects` | `dump_risky_objects()` | `entraid_riskyobjects/` | `identityProtection/riskyUsers`, `identityProtection/riskyServicePrincipals`, plus `history` child for each |
| `security` | `dump_security()` | `entraid_security/` | `security/securityActions`, `security/alerts`, `security/secureScores` |

- Risk detections require Entra ID P1 + Workload ID Premium
- Risky objects require Entra ID P2 + Workload ID Premium

---

## M365 / Exchange Online

**Class:** `M365DataDumper` (`goosey/m365_datadumper.py`)
**Auth tokens:** `graph_api` (Microsoft Graph) + `outlook_office_api` (Exchange Online)
**Output directory:** `output/m365/`
**Config section:** `[m365]`

### Exchange Online PowerShell Cmdlets

These methods use the EXO Admin API (`/adminapi/beta/{tenantId}/InvokeCommand`) with the `outlook_office_api` token.

| Config Key | Method | Cmdlet(s) | Output File(s) |
|---|---|---|---|
| `exo_groups` | `dump_exo_groups()` | `Get-RoleGroup`, `Get-RoleGroupMember` | `EXO_RoleGroups_PowerShell.json`, `EXO_RoleGroupsMembers_PowerShell.json` |
| `exo_mailbox` | `dump_exo_mailbox()` | `Get-Mailbox`, `Get-CASMailbox`, `Get-CASMailboxPlan`, `Get-MailboxPermission`, `Get-MailboxFolderPermission`, `Get-InboxRule` | `EXO_Mailboxes_PowerShell.json`, `EXO_MailboxCAS_Settings_PowerShell.json`, `EXO_Tenant_CAS_Plan_PowerShell.json`, `EXO_MailboxPermissions_PowerShell.json`, `EXO_TopLevelFolderPermissions_PowerShell.json`, `EXO_InboxRules_PowerShell.json` |
| `exo_config_info` | `dump_exo_config_info()` | `Get-MailboxAuditBypassAssociation`, `Get-AdminAuditLogConfig`, `Get-OrganizationConfig`, `Get-PerimeterConfig`, `Get-TransportRule`, `Get-TransportConfig` | `EXO_MailboxAuditStatus_PowerShell.json`, `EXO_AdminAuditLogConfig_PowerShell.json`, `EXO_OrganizationConfig_PowerShell.json`, `EXO_PerimeterConfig_PowerShell.json`, `EXO_TransportRules_PowerShell.json`, `EXO_TransportConfig_PowerShell.json` |
| `exo_mobile_devices` | `dump_exo_mobile_devices()` | `Get-MobileDevice`, `Get-MobileDeviceMailboxPolicy`, `Get-MobileDeviceStatistics` | `EXO_MobileDevices_PowerShell.json`, `EXO_MobileDeviceMailboxPolicy_PowerShell.json`, `EXO_MobileDeviceStats_PowerShell.json` |
| `ediscovery_info` | `dump_ediscovery_info()` | `Get-ManagementRoleEntry`, `Get-ManagementRoleAssignment` | `EXO_EDiscovery_Roles_PowerShell.json`, `EXO_Ediscovery_RoleCmdlets_PowerShell.json`, `EXO_Ediscovery_RoleAssignments_PowerShell.json` |
| `exo_addins` | `dump_exo_addins()` | `Get-App` | `EXO_AddIns.json` |

Save state files: `.EXO_RoleGroupMembers_savestate`, `.EXO_Mailbox_savestate`, `.EXO_MobileDevicesStats_savestate`, `.EXO_EDiscovery_savestate`

### Inbox Rules (Graph API)

| Config Key | Method | API Endpoint | Output File |
|---|---|---|---|
| `exo_inboxrules` | `dump_exo_inboxrules()` | `GET /beta/users/{upn}/mailFolders/inbox/messageRules` | `EXO_InboxRules_Graph.json` |

- Iterates all users; save state: `.inbox_state`
- 503 failures logged to `reports/_user_inbox_503.json`

### Unified Audit Log (UAL)

| Config Key | Method | Cmdlet | Output Files |
|---|---|---|---|
| `ual` | `dump_ual()` | `Search-UnifiedAuditLog` | `ual_YYYY-MM-DDTHH_MM_SS_YYYY-MM-DDTHH_MM_SS.json` (one per time window) |

- **Default range:** Last 364 days from yesterday
- **Save state:** `.ual_state` (completed time ranges), `.ual_bounds` (binary bounding state)
- **Config variables:**
  - `ual_threshold` — max results per session before time-splitting (default: 5000)
  - `max_ual_tasks` — concurrent async tasks (default: 5)
  - `ual_extra_start` / `ual_extra_end` — additional priority time window
- **Algorithm:** Binary time-bisection when result count exceeds threshold. Creates isolated async tasks for bounded time windows. Deduplicates results across sessions.
- Manages its own progress bar

---

## Microsoft Defender for Endpoint (MDE)

**Class:** `MDEDataDumper` (`goosey/mde_datadumper.py`)
**Auth tokens:** `securitycenter_api` (MDE API) + `security_api` (Microsoft Security API)
**Base URL:** `https://api.securitycenter.windows.com/`
**Output directory:** `output/mde/`
**Config section:** `[mde]`

### Simple Endpoint Queries

All use `securitycenter_api` token via `helper_single_object()`.

| Config Key | Method | API Endpoint | Output File |
|---|---|---|---|
| `machines` | `dump_machines()` | `GET /api/machines` | `api_machines.json` |
| `alerts` | `dump_alerts()` | `GET /api/alerts` | `api_alerts.json` |
| `indicators` | `dump_indicators()` | `GET /api/indicators` | `api_indicators.json` |
| `investigations` | `dump_investigations()` | `GET /api/investigations` | `api_investigations.json` |
| `library_files` | `dump_library_files()` | `GET /api/libraryfiles` | `api_libraryfiles.json` |
| `machine_vulns` | `dump_machine_vulns()` | `GET /api/vulnerabilities/machinesVulnerabilities` | `api_vulnerabilities_machinesVulnerabilities.json` |
| `software` | `dump_software()` | `GET /api/Software` | `api_Software.json` |
| `recommendations` | `dump_recommendations()` | `GET /api/recommendations` | `api_recommendations.json` |

### Advanced Hunting — Device Telemetry

| Config Key | Method | API Endpoint | Tables |
|---|---|---|---|
| `advanced_hunting_query` | `dump_advanced_hunting_query()` | `POST /api/advancedqueries/run` | `DeviceEvents`, `DeviceLogonEvents`, `DeviceRegistryEvents`, `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceImageLoadEvents` |

- **Output:** `{TableName}/{TableName}_{MachineId}.json` (or `{MachineName}/` in machine mode)
- **Query mode:** `table` (default) queries tables directly; `machine` filters per device
- **Save state:** `.{TableName}_{MachineId}.savestate`
- **Default range:** 364 days; time-bisection when results exceed `mde_threshold`

### Advanced Hunting — Alerts & Incidents

| Config Key | Method | API Endpoint | Tables |
|---|---|---|---|
| `advanced_hunting_alerts_incidents` | `dump_advanced_hunting_alerts_incidents()` | `POST /api/advancedhunting/run` | `AlertInfo`, `AlertEvidence` |

- Uses `securitycenter_api` token (via `app_auth2`)
- **Output:** `{TableName}/{TableName}.json`
- **Save state:** `.{TableName}.savestate`

### Advanced Hunting — Identity Events

| Config Key | Method | API Endpoint | Tables |
|---|---|---|---|
| `advanced_identity_hunting_query` | `dump_advanced_identity_hunting_query()` | `POST /api/advancedhunting/run` | `IdentityDirectoryEvents`, `IdentityLogonEvents`, `IdentityQueryEvents` |

- Uses `security_api` token (Microsoft Defender for Identity)
- **Output:** `{TableName}/{TableName}.json`
- **Save state:** `.{TableName}.savestate`

---

## Azure

**Class:** `AzureDataDumper` (`goosey/azure_dumper.py`)
**Auth tokens:** `resource_manager` (Azure Management) + `log_analytics_api` (Log Analytics)
**Output directory:** `output/azure/`
**Config section:** `[azure]`

Most Azure methods iterate across all configured subscription IDs.

### Activity Log

| Config Key | Method | SDK Client | Output |
|---|---|---|---|
| `activity_log` | `dump_activity_log()` | `MonitorManagementClient.activity_logs.list()` | `{subscriptionId}/Activity Log/azure_activity_log_YYYY-MM-DD.json` |

- **Default range:** Last 89 days
- **Save state:** `.activity_log_state`, `.sub_savestate`
- Daily chunking with per-day checkpoint

### Log Analytics Workspaces

| Config Key | Method | API | Output |
|---|---|---|---|
| `log_analytic_workspaces` | `dump_log_analytic_workspaces()` | REST: `GET /workspaces`, KQL via `POST /v1{workspaceId}/query` | `{subscriptionId}/log_analytics_workspace/{workspaceName}/{tableName}.json` |

- **Default range:** 12 years (LAW max retention)
- **Save state:** `.{tableName}.savestate` per table per workspace
- Auto-discovers tables via `search "*"` summarize query
- Time-bisection when results exceed `LAW_QUERY_THRESHOLD` (10,000)

### Blob Storage Logs

| Config Key | Method | Container | Output |
|---|---|---|---|
| `key_vault_log` | `dump_key_vault_log()` | `insights-logs-auditevent` | `{subscriptionId}/key_vault_logs/log_{blobName}` |
| `nsg_flow_logs` | `dump_nsg_flow_logs()` | `insights-logs-networksecuritygroupflowevent` | `{subscriptionId}/nsg_flow_logs/log_{blobName}` |
| `bastion_logs` | `dump_bastion_logs()` | `insights-logs-bastionauditlogs` | `{subscriptionId}/bastion_logs/log_{blobName}` |

- **Default range:** 730 days (2 years)
- **Save state:** `.{storageAccountName}_savestate`
- Uses Azure Blob SDK to enumerate and download

### Azure Subscriptions

| Config Key | Method | SDK Client | Output |
|---|---|---|---|
| `all_azure_subscriptions` | `dump_all_azure_subscriptions()` | `SubscriptionClient.subscriptions.list()` | `subscriptions.json` |

### D4IoT Portal (Azure-side)

| Config Key | Method | API | Output |
|---|---|---|---|
| `d4iot_portal_pcap` | `dump_d4iot_portal_pcap()` | Azure REST: IoTSecurity locations/deviceGroups/alerts | `{subscriptionId}/d4iot_portal/pcaps/pcap_{alertId}.pcap` |
| `d4iot_portal_configs` | `dump_d4iot_portal_configs()` | Azure REST: IoTSecurity alerts, defenderSettings, sensors | `{subscriptionId}/d4iot_portal/portal_alerts.json`, `portal_defender_settings.json`, `portal_sensors.json`, `portal_sites.json`, `portal_device_groups.json` |

### Azure Configuration Inventory

| Config Key | Method | Output Directory |
|---|---|---|
| `configs` | `dump_configs()` | `{subscriptionId}/azure_configs/` |

Collects configuration snapshots using Azure SDK clients. Runs in parallel via `asyncio.gather()`. Skips files that already exist.

**Security Center** (`SecurityCenter` SDK):
`alerts`, `allowed_connections`, `applications`, `assessments`, `auto_provisioning_settings`, `automations`, `compliance_results`, `compliances`, `discovered_security_solutions`, `external_security_solutions`, `governance_rules`, `information_protection_policies`, `jit_network_access_policies`, `locations`, `secure_score_controls`, `secure_scores`, `security_contacts`, `settings` (non-GCC-High only), `security_solutions` (non-GCC-High only), `sub_assessments`, `tasks`, `topology`, `workspace_settings`

**Network** (`NetworkManagementClient` SDK):
`application_gateways`, `application_security_groups`, `azure_firewall_fqdn_tags`, `azure_firewalls`, `bastion_hosts`, `custom_ip_prefixes`, `ddos_protection_plans`, `dscp_configuration`, `express_route_circuits`, `express_route_ports`, `firewall_policies`, `ip_allocations`, `ip_groups`, `load_balancers`, `nat_gateways`, `network_interfaces`, `network_managers`, `network_profiles`, `network_security_groups`, `network_security_perimeters`, `network_virtual_appliances`, `network_watchers`, `p2_svpn_gateways`, `private_endpoints`, `private_link_services`, `public_ip_addresses`, `public_ip_prefixes`, `route_filters`, `route_tables`, `security_partner_providers`, `service_endpoint_policies`, `subscription_network_manager_connections`, `virtual_hubs`, `virtual_network_taps`, `virtual_networks`, `virtual_routers`, `virtual_wans`, `vpn_gateways`, `vpn_server_configurations`, `vpn_sites`, `web_application_firewall_policies`

**Compute, Storage, Web, Resources:**
- `vm_configs` — VMs with instance view (`ComputeManagementClient`)
- `container_configs` — App Service web app configs (`WebSiteManagementClient`)
- `azure_storage_accounts` — Storage accounts (`StorageManagementClient`)
- `file_share_list` — File shares per storage account (`StorageManagementClient`)
- `all_resources_list` — All resources (`ResourceManagementClient`)
- `diagnostic_settings` — Diagnostic settings per resource (`MonitorManagementClient`)

---

## Defender for IoT (D4IoT) — Sensor & Management Console

**Class:** `DefenderIoTDumper` (`goosey/d4iot_dumper.py`)
**Auth:** Cookie-based (sensor) + API token (sensor & management console)
**Output directory:** `output/d4iot/`
**Config section:** `[d4iot]` (in `.d4iot_conf`)
**Command:** `goosey d4iot` (separate from `goosey honk`)

### Sensor Endpoints

Base URL: `https://{sensor_ip}/api/v1/`

| Config Key | Method | API Endpoint | Output File |
|---|---|---|---|
| `sensor_devices` | `dump_sensor_devices()` | `GET /api/v1/devices` | `sensor/devices.json` |
| `sensor_alerts` | `dump_sensor_alerts()` | `GET /api/v1/alerts` | `sensor/alerts.json` |
| `sensor_device_connections` | `dump_sensor_device_connections()` | `GET /api/v1/devices/connections` | `sensor/device_connections.json` |
| `sensor_device_cves` | `dump_sensor_device_cves()` | `GET /api/v1/devices/cves` | `sensor/devices_cves.json` |
| `sensor_events` | `dump_sensor_events()` | `GET /api/v1/events` | `sensor/events.json` |
| `sensor_device_vuln` | `dump_sensor_device_vuln()` | `GET /api/v1/reports/vulnerabilities/devices` | `sensor/device_vulnerabilities.json` |
| `sensor_security_vuln` | `dump_sensor_security_vuln()` | `GET /api/v1/reports/vulnerabilities/security` | `sensor/security_vulnerabilities.json` |
| `sensor_operational_vuln` | `dump_sensor_operational_vuln()` | `GET /api/v1/reports/vulnerabilities/operational` | `sensor/operational_vulnerabilities.json` |
| `sensor_pcap` | `dump_sensor_pcap()` | `GET /api/alert/filtered-pcap/{alertId}` | `sensor_alert_pcaps/alert_{alertId}.pcap` |

### Management Console Endpoints

Base URL: `https://{mgmt_ip}/external/`

| Config Key | Method | API Endpoint | Output File |
|---|---|---|---|
| `mgmt_devices` | `dump_mgmt_devices()` | `GET /external/v1/devices` | `mgmt_console/mgmt_devices.json` |
| `mgmt_alerts` | `dump_mgmt_alerts()` | `GET /external/v1/alerts` | `mgmt_console/mgmt_alerts.json` |
| `mgmt_sensor_info` | `dump_mgmt_sensor_info()` | `GET /external/v3/integration/sensors` | `mgmt_console/sensor_info.json` |
| `mgmt_pcap` | `dump_mgmt_pcap()` | `GET /external/v2/alerts/pcap/{alertId}` | `mgmt_console_alert_pcaps/alert_{alertId}.pcap` |

---

## eDiscovery (Microsoft Purview)

**Class:** `EdiscoveryDataDumper` (`goosey/ediscovery_datadumper.py`)
**Auth token:** `graph_api` (Microsoft Graph)
**Base URL:** `https://graph.microsoft.com/v1.0/`
**Output directory:** `output/ediscovery/`
**Config section:** `[ediscovery]`
**Graph permissions:** `eDiscovery.Read.All` (snapshot), `eDiscovery.ReadWrite.All` (export), `AiEnterpriseInteraction.Read.All` (Copilot)

> **Optional permissions:** These are **not** granted by the default setup. Add them by running setup with the eDiscovery option:
> - Python: `goosey setup --app_name GooseApp --create --ediscovery`
> - PowerShell: `./scripts/Create_SP.ps1 -AppName GooseApp -Create -Ediscovery`
> - Web UI: check **"Add eDiscovery permissions"** on the Setup tab.
>
> **Licensing:** Goosey authenticates to Graph app-only (client credentials). App-only eDiscovery access requires an **E5** / eDiscovery add-on subscription (it is not available on E3, which requires delegated auth). The Copilot interaction API requires a Copilot license and is available in the **Global cloud only** (not GCC/GCC High).

### Snapshot (read-only) — existing eDiscovery objects

Each method enumerates cases, then fetches the case-scoped children. Records are flattened to JSONL and enriched with `caseId` / `caseDisplayName` (plus `reviewSetId` for review set queries).

| Config Key | Method | API Endpoint | Output File |
|---|---|---|---|
| `ediscovery_cases` | `dump_ediscovery_cases()` | `GET /security/cases/ediscoveryCases` | `ediscovery_cases.json` |
| `ediscovery_case_settings` | `dump_ediscovery_case_settings()` | `GET .../ediscoveryCases/{id}/settings` | `ediscovery_case_settings.json` |
| `ediscovery_custodians` | `dump_ediscovery_custodians()` | `GET .../{id}/custodians` | `ediscovery_custodians.json` |
| `ediscovery_noncustodial_sources` | `dump_ediscovery_noncustodial_sources()` | `GET .../{id}/noncustodialDataSources` | `ediscovery_noncustodial_sources.json` |
| `ediscovery_searches` | `dump_ediscovery_searches()` | `GET .../{id}/searches` | `ediscovery_searches.json` |
| `ediscovery_holds` | `dump_ediscovery_holds()` | `GET .../{id}/legalHolds` | `ediscovery_holds.json` |
| `ediscovery_review_sets` | `dump_ediscovery_review_sets()` | `GET .../{id}/reviewSets` | `ediscovery_review_sets.json` |
| `ediscovery_review_set_queries` | `dump_ediscovery_review_set_queries()` | `GET .../{id}/reviewSets/{rsId}/queries` | `ediscovery_review_set_queries.json` |
| `ediscovery_tags` | `dump_ediscovery_tags()` | `GET .../{id}/tags` | `ediscovery_tags.json` |
| `ediscovery_operations` | `dump_ediscovery_operations()` | `GET .../{id}/operations` | `ediscovery_operations.json` |

### Copilot interactions (read-only)

| Config Key | Method | API Endpoint | Output File |
|---|---|---|---|
| `copilot_interactions` | `dump_copilot_interactions()` | `GET /copilot/users/{id}/interactionHistory/getAllEnterpriseInteractions` (per user) | `copilot_interactions.json` |

Enumerates users, then fetches each user's Copilot prompts/responses via the dedicated `aiInteractionHistory` API. Bounded by the configured date range (`createdDateTime` `$filter`) and enriched with `userId` / `userPrincipalName`. Global cloud only; users without a Copilot license are skipped.

### Content export (read/write — creates objects in the tenant)

| Config Key | Method | Output |
|---|---|---|
| `ediscovery_export` | `dump_ediscovery_export()` | `ediscovery_export_manifest.json`, `export/{content_type}/*` |

Sequential, resumable pipeline: create (or reuse) an `UntitledGooseTool-<timestamp>` case → optionally add custodians for targeted UPNs → for each content type create a search, run `estimateStatistics`, `exportResult`, poll the operation, and download the package(s). **Double-gated:** the `ediscovery_export` toggle is off by default, and the method is a hard no-op unless `[variables] ediscovery_export_confirm=true`. Never runs under `--dry-run`. Progress is checkpointed to `.ediscovery_export.savestate`.

Configured via `[variables]`:

| Variable | Default | Description |
|---|---|---|
| `ediscovery_export_confirm` | `false` | HARD safety gate — must be `true` for any export to run |
| `ediscovery_export_content_types` | `email,teams,copilot,sharepoint` | Content types to export |
| `ediscovery_export_targets` | *(empty)* | Custodian UPNs to target; empty = tenant-wide |
| `ediscovery_case_name` | `UntitledGooseTool` | Case display-name prefix (timestamp appended) |
| `ediscovery_export_format` | `pst` | Email export format (`pst`/`msg`) |
| `ediscovery_export_download` | `true` | Download the export package(s) after completion |
| `ediscovery_content_query` | *(empty)* | Optional KQL override applied to all export searches |

---

## Authentication Tokens

| Token Key | Scope | Used By |
|---|---|---|
| `graph_api` | Microsoft Graph | EntraIdDataDumper, M365DataDumper, EdiscoveryDataDumper |
| `outlook_office_api` | Exchange Online | M365DataDumper (EXO cmdlets) |
| `resource_manager` | Azure Resource Manager | AzureDataDumper |
| `log_analytics_api` | Log Analytics | AzureDataDumper (LAW queries) |
| `securitycenter_api` | MDE Security Center | MDEDataDumper |
| `security_api` | Microsoft Security | MDEDataDumper (identity hunting, alert hunting) |

All tokens are automatically refreshed by `TokenManager` when they expire (5 minutes before expiry).

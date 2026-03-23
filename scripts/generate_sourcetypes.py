#!/usr/bin/env python3
# @decision DEC-BROWSE-001
# @title Static sourcetypes.json with prefix-based LAW sub-categories
# @status accepted
# @rationale Decouples the web UI from Splunk's inputs.conf. Pre-computes LAW grouping
#   (670 tables) into prefix-based subcategories at generation time so the UI can
#   render the full tree without runtime parsing. Ships as static data in goosey/data/.
"""
generate_sourcetypes.py -- Build goosey/data/sourcetypes.json from conf/inputs.conf.

This script parses the Splunk inputs.conf monitor paths to extract all 876 sourcetypes,
transforms them into a type->subtype->[subcategory->]sourcetype hierarchy, and writes
the result to goosey/data/sourcetypes.json.

The resulting JSON is consumed by the web UI browse-data feature as the authoritative
sourcetype registry, decoupled from Splunk (DEC-BROWSE-001).

Usage:
    python scripts/generate_sourcetypes.py [--inputs conf/inputs.conf] [--output goosey/data/sourcetypes.json]
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict

TYPE_META = {
    "azure": {
        "display_name": "Azure",
        "description": "Azure resource configurations, activity logs, security data, and Log Analytics Workspace tables",
    },
    "eid": {
        "display_name": "Entra ID",
        "description": "Azure Active Directory / Entra ID sign-in logs, audit logs, identity configurations, and risk detections",
    },
    "mde": {
        "display_name": "Microsoft Defender for Endpoint",
        "description": "MDE advanced hunting tables, alerts, incidents, device telemetry, and threat/vulnerability management",
    },
    "m365": {
        "display_name": "M365 / Exchange Online",
        "description": "Microsoft 365 Unified Audit Log, Exchange Online configurations, mailbox data, and inbox rules",
    },
}

SUBTYPE_META = {
    "azure:core": {
        "display_name": "Core Resources",
        "description": "Subscriptions, resource inventory, activity logs, and baseline configurations",
    },
    "azure:securitycenter": {
        "display_name": "Microsoft Defender for Cloud",
        "description": "Security Center scores, policies, contacts, and JIT access",
    },
    "azure:network": {
        "display_name": "Networking",
        "description": "Virtual networks, firewalls, load balancers, NSGs, and routing tables",
    },
    "azure:d4iot": {
        "display_name": "Defender for IoT",
        "description": "Defender for IoT sensor portal data: alerts, device groups, sites, and settings",
    },
    "azure:law": {
        "display_name": "Log Analytics Workspace",
        "description": "All 670 Log Analytics Workspace (LAW) table exports, grouped by Azure service area",
    },
    "eid:core": {
        "display_name": "Core Identity",
        "description": "Audit logs, provisioning, users, groups, devices, and deleted items",
    },
    "eid:signin": {
        "display_name": "Sign-In Logs",
        "description": "Interactive, non-interactive, service principal, MSI, and ADFS sign-in logs",
    },
    "eid:applications": {
        "display_name": "Applications",
        "description": "App registrations, delegated permissions, token policies, and federated identity credentials",
    },
    "eid:ca": {
        "display_name": "Conditional Access",
        "description": "Conditional Access policies, named locations, and authentication context references",
    },
    "eid:rolemanagement": {
        "display_name": "Role Management (PIM)",
        "description": "Privileged Identity Management role definitions, assignment schedules, and eligibility",
    },
    "eid:policy": {
        "display_name": "Policies",
        "description": "Authentication, authorization, token lifetime, consent, and compliance policies",
    },
    "eid:org": {
        "display_name": "Organization",
        "description": "Tenant settings, domain federation, directory settings, and SKU subscriptions",
    },
    "eid:identity": {
        "display_name": "Identity Providers",
        "description": "External identity providers, API connectors, and user authentication methods",
    },
    "eid:risk": {
        "display_name": "Risk Detections",
        "description": "Identity Protection risky users, service principals, and risk event history",
    },
    "eid:security": {
        "display_name": "Security",
        "description": "Security alerts and Secure Scores for Entra ID",
    },
    "eid:reports": {
        "display_name": "Reports",
        "description": "App sign-in summaries, credential usage, and user registration analytics",
    },
    "eid:sp": {
        "display_name": "Service Principals",
        "description": "Service principal objects, role assignments, delegated permissions, and owned objects",
    },
    "eid:users": {
        "display_name": "Users",
        "description": "User accounts and app role assignments",
    },
    "mde:api": {
        "display_name": "MDE API",
        "description": "MDE REST API exports: alerts, machines, vulnerabilities, investigations, and indicators",
    },
    "mde:hunting": {
        "display_name": "Advanced Hunting",
        "description": "Defender advanced hunting table exports for threat detection and investigation",
    },
    "m365:core": {
        "display_name": "Core",
        "description": "Unified Audit Log and M365 user listings",
    },
    "m365:exchange": {
        "display_name": "Exchange Online",
        "description": "Exchange Online configurations, mailboxes, permissions, mobile devices, and transport rules",
    },
}

# LAW subcategory prefix table.
# Each entry is (prefix, subcategory_id, display_name).
# Prefixes matched in order: list longer/more-specific prefixes before shorter ones.
LAW_SUBCATEGORIES = [
    ("aaddomainservices", "aad", "Azure AD / Entra ID"),
    ("aadmanagedidentity", "aad", "Azure AD / Entra ID"),
    ("aadnoninteractive", "aad", "Azure AD / Entra ID"),
    ("aadprovisioning", "aad", "Azure AD / Entra ID"),
    ("aadrisky", "aad", "Azure AD / Entra ID"),
    ("aadserviceprincipal", "aad", "Azure AD / Entra ID"),
    ("aaduser", "aad", "Azure AD / Entra ID"),
    ("aadb2c", "aad", "Azure AD / Entra ID"),
    ("aadcustom", "aad", "Azure AD / Entra ID"),
    ("aac", "aac", "Azure API Center"),
    ("abs", "abs", "Azure Bot Service"),
    ("acicollaboration", "aci", "Azure Container Instances"),
    ("acrconnected", "acr", "Azure Container Registry"),
    ("acs", "acs", "Azure Communication Services"),
    ("adassessmentrecommendation", "assessment", "Azure Assessment"),
    ("addonazurebackup", "addon_backup", "Azure Backup Add-on"),
    ("adfreplication", "ad_replication", "Active Directory Replication"),
    ("adreplicationresult", "ad_replication", "Active Directory Replication"),
    ("adsecurity", "ad_security", "Active Directory Security Assessment"),
    ("adf", "adf", "Azure Data Factory"),
    ("adp", "adp", "Azure Data Manager for Energy"),
    ("adt", "adt", "Azure Digital Twins"),
    ("adx", "adx", "Azure Data Explorer"),
    ("aegdataplane", "aeg", "Azure Event Grid"),
    ("aegdelivery", "aeg", "Azure Event Grid"),
    ("aegpublish", "aeg", "Azure Event Grid"),
    ("aewassignment", "aew", "Azure Elastic Workloads"),
    ("aewaudit", "aew", "Azure Elastic Workloads"),
    ("aewcompute", "aew", "Azure Elastic Workloads"),
    ("afsaudit", "afs", "Azure Front Door / CDN"),
    ("agcaccess", "agc", "Application Gateway for Containers"),
    ("agrifood", "agrifood", "Azure FarmBeats / AgriFoodOps"),
    ("agsgrafana", "ags", "Azure Managed Grafana"),
    ("agwaccess", "agw", "Application Gateway WAF"),
    ("agwfirewall", "agw", "Application Gateway WAF"),
    ("agwperformance", "agw", "Application Gateway WAF"),
    ("ahds", "ahds", "Azure Health Data Services"),
    ("airflowdag", "airflow", "Apache Airflow (Managed Airflow)"),
    ("aksaudit", "aks", "Azure Kubernetes Service"),
    ("akscontrol", "aks", "Azure Kubernetes Service"),
    ("albhealth", "alb", "Azure Load Balancer"),
    ("alertevidence", "alert", "Azure Monitor Alerts"),
    ("alerthistory", "alert", "Azure Monitor Alerts"),
    ("alertinfo", "alert", "Azure Monitor Alerts"),
    ("alert", "alert", "Azure Monitor Alerts"),
    ("amlcompute", "aml", "Azure Machine Learning"),
    ("amldatalabel", "aml", "Azure Machine Learning"),
    ("amldataset", "aml", "Azure Machine Learning"),
    ("amldatastore", "aml", "Azure Machine Learning"),
    ("amldeployment", "aml", "Azure Machine Learning"),
    ("amlenvironment", "aml", "Azure Machine Learning"),
    ("amlinferencing", "aml", "Azure Machine Learning"),
    ("amlmodels", "aml", "Azure Machine Learning"),
    ("amlonline", "aml", "Azure Machine Learning"),
    ("amlpipeline", "aml", "Azure Machine Learning"),
    ("amlregistry", "aml", "Azure Machine Learning"),
    ("amlrun", "aml", "Azure Machine Learning"),
    ("amskeydelivery", "ams", "Azure Media Services"),
    ("amslive", "ams", "Azure Media Services"),
    ("amsmedia", "ams", "Azure Media Services"),
    ("amsstreaming", "ams", "Azure Media Services"),
    ("amwmetrics", "amw", "Azure Monitor Workspace"),
    ("anomalies", "sentinel", "Microsoft Sentinel"),
    ("aoidatabasequery", "aoi", "Azure OpenAI"),
    ("aoiquery", "aoi", "Azure OpenAI"),
    ("aoidigestion", "aoi", "Azure OpenAI"),
    ("aoistorage", "aoi", "Azure OpenAI"),
    ("apimanagement", "apim", "API Management"),
    ("apimdev", "apim", "API Management"),
    ("appavailability", "appinsights", "Application Insights"),
    ("appbrowser", "appinsights", "Application Insights"),
    ("appcenter", "appinsights", "Application Insights"),
    ("appdependencies", "appinsights", "Application Insights"),
    ("appenv", "springapps", "Azure Spring Apps"),
    ("appevents", "appinsights", "Application Insights"),
    ("appexceptions", "appinsights", "Application Insights"),
    ("appmetrics", "appinsights", "Application Insights"),
    ("apppageviews", "appinsights", "Application Insights"),
    ("appperformance", "appinsights", "Application Insights"),
    ("appplatform", "springapps", "Azure Spring Apps"),
    ("apprequests", "appinsights", "Application Insights"),
    ("appservice", "appservice", "App Service"),
    ("appsystem", "appinsights", "Application Insights"),
    ("apptraces", "appinsights", "Application Insights"),
    ("arck8saudit", "arck8s", "Azure Arc Kubernetes"),
    ("arck8scontrol", "arck8s", "Azure Arc Kubernetes"),
    ("ascaudit", "asc", "Microsoft Defender for Cloud (Legacy)"),
    ("ascdevice", "asc", "Microsoft Defender for Cloud (Legacy)"),
    ("asrjobs", "asr", "Azure Site Recovery"),
    ("asrreplicated", "asr", "Azure Site Recovery"),
    ("atcexpress", "atc", "Azure Traffic Collector"),
    ("atcprivate", "atc", "Azure Traffic Collector"),
    ("auditlogs", "aad", "Azure AD / Entra ID"),
    ("auievents", "auiev", "Azure Update Manager"),
    ("autoscale", "autoscale", "Azure Autoscale"),
    ("avnm", "avnm", "Azure Virtual Network Manager"),
    ("avssyslog", "avs", "Azure VMware Solution"),
    ("awscloud", "aws", "AWS (via Azure Monitor)"),
    ("awsguardduty", "aws", "AWS (via Azure Monitor)"),
    ("awsvpc", "aws", "AWS (via Azure Monitor)"),
    ("azfwapplication", "azfw", "Azure Firewall"),
    ("azfwdns", "azfw", "Azure Firewall"),
    ("azfwfat", "azfw", "Azure Firewall"),
    ("azfwflow", "azfw", "Azure Firewall"),
    ("azfwidps", "azfw", "Azure Firewall"),
    ("azfwinternal", "azfw", "Azure Firewall"),
    ("azfwnat", "azfw", "Azure Firewall"),
    ("azfwnetwork", "azfw", "Azure Firewall"),
    ("azfwthreat", "azfw", "Azure Firewall"),
    ("azkvaudit", "azkv", "Azure Key Vault"),
    ("azkvpolicy", "azkv", "Azure Key Vault"),
    ("azmsapplication", "azms", "Azure Service Bus"),
    ("azmsarchive", "azms", "Azure Service Bus"),
    ("azmsautoscale", "azms", "Azure Service Bus"),
    ("azmscustomer", "azms", "Azure Service Bus"),
    ("azmsdiagnostic", "azms", "Azure Service Bus"),
    ("azmshybrid", "azms", "Azure Service Bus"),
    ("azmskafka", "azms", "Azure Service Bus / Event Hubs"),
    ("azmsoperational", "azms", "Azure Service Bus"),
    ("azmsruntime", "azms", "Azure Service Bus"),
    ("azmsvnet", "azms", "Azure Service Bus"),
    ("azureactivity", "azure_activity", "Azure Activity Log (LAW mirror)"),
    ("azureassessment", "assessment", "Azure Assessment"),
    ("azureattestation", "attestation", "Azure Attestation"),
    ("azurebackup", "backup", "Azure Backup"),
    ("azuredevops", "devops", "Azure DevOps"),
    ("azurediagnostics", "azurediag", "Azure Diagnostics (Generic)"),
    ("azureloadtesting", "loadtesting", "Azure Load Testing"),
    ("azuremetrics", "metrics", "Azure Metrics"),
    ("behavioranalytics", "sentinel", "Microsoft Sentinel"),
    ("blockchainapp", "blockchain", "Azure Blockchain"),
    ("blockchainproxy", "blockchain", "Azure Blockchain"),
    ("cassandraaudit", "cosmos", "Cosmos DB"),
    ("cassandralogs", "cosmos", "Cosmos DB"),
    ("ccfapp", "ccf", "Azure Confidential Ledger"),
    ("cdbcassandra", "cosmos", "Cosmos DB"),
    ("cdbcontrol", "cosmos", "Cosmos DB"),
    ("cdbdataplane", "cosmos", "Cosmos DB"),
    ("cdbgremlin", "cosmos", "Cosmos DB"),
    ("cdbmongo", "cosmos", "Cosmos DB"),
    ("cdbpartition", "cosmos", "Cosmos DB"),
    ("cdbquery", "cosmos", "Cosmos DB"),
    ("cdbtable", "cosmos", "Cosmos DB"),
    ("chaosstudio", "chaos", "Azure Chaos Studio"),
    ("chsmmanagement", "chsm", "Azure Dedicated HSM"),
    ("cievents", "ciev", "Container Insights Events"),
    ("cloudappevents", "mde_law", "MDE / Defender (LAW)"),
    ("commonsecuritylog", "sentinel", "Microsoft Sentinel"),
    ("computergroup", "la_legacy", "Log Analytics Legacy"),
    ("confidentialwatchlist", "sentinel", "Microsoft Sentinel"),
    ("configurationchange", "changetracking", "Change Tracking"),
    ("configurationdata", "changetracking", "Change Tracking"),
    ("containerappconsolelog", "containerapps", "Azure Container Apps"),
    ("containerappsystem", "containerapps", "Azure Container Apps"),
    ("containerevent", "container_insights", "Container Insights"),
    ("containerimage", "container_insights", "Container Insights"),
    ("containerinstance", "container_insights", "Container Insights"),
    ("containerinventory", "container_insights", "Container Insights"),
    ("containerlog", "container_insights", "Container Insights"),
    ("containernode", "container_insights", "Container Insights"),
    ("containerregistry", "acr", "Azure Container Registry"),
    ("containerservice", "container_insights", "Container Insights"),
    ("databricks", "databricks", "Azure Databricks"),
    ("datatransfer", "datatransfer", "Azure Data Transfer"),
    ("dataverseactivity", "dataverse", "Dataverse / Power Platform"),
    ("dcrlog", "dcr", "Data Collection Rules"),
    ("defenderiotrawevent", "defenderiot", "Defender for IoT"),
    ("devcenter", "devcenter", "Azure Dev Center"),
    ("deviceappcrash", "dh", "Device Health / Desktop Analytics"),
    ("deviceapplaunch", "dh", "Device Health / Desktop Analytics"),
    ("devicebaselinecompliance", "mde_law", "MDE / Defender (LAW)"),
    ("devicecalendar", "dh", "Device Health / Desktop Analytics"),
    ("devicecleanup", "dh", "Device Health / Desktop Analytics"),
    ("deviceconnect", "dh", "Device Health / Desktop Analytics"),
    ("deviceetw", "mde_law", "MDE / Defender (LAW)"),
    ("deviceevents", "mde_law", "MDE / Defender (LAW)"),
    ("devicefile", "mde_law", "MDE / Defender (LAW)"),
    ("devicehardware", "dh", "Device Health / Desktop Analytics"),
    ("devicehealth", "dh", "Device Health / Desktop Analytics"),
    ("deviceheartbeat", "dh", "Device Health / Desktop Analytics"),
    ("deviceimage", "mde_law", "MDE / Defender (LAW)"),
    ("deviceinfo", "mde_law", "MDE / Defender (LAW)"),
    ("devicelogon", "mde_law", "MDE / Defender (LAW)"),
    ("devicenetwork", "mde_law", "MDE / Defender (LAW)"),
    ("deviceprocess", "mde_law", "MDE / Defender (LAW)"),
    ("deviceregistry", "mde_law", "MDE / Defender (LAW)"),
    ("deviceskype", "dh", "Device Health / Desktop Analytics"),
    ("devicetvm", "mde_law", "MDE / Defender (LAW)"),
    ("dhappreliability", "dh", "Device Health / Desktop Analytics"),
    ("dhdriver", "dh", "Device Health / Desktop Analytics"),
    ("dhlogon", "dh", "Device Health / Desktop Analytics"),
    ("dhos", "dh", "Device Health / Desktop Analytics"),
    ("dhwip", "dh", "Device Health / Desktop Analytics"),
    ("dnsevents", "dns", "Azure DNS"),
    ("dnsinventory", "dns", "Azure DNS"),
    ("dnsquerylogs", "dns", "Azure DNS"),
    ("dsmazure", "purview", "Microsoft Purview / Data Security"),
    ("dsmdataclass", "purview", "Microsoft Purview / Data Security"),
    ("dsmdatalabel", "purview", "Microsoft Purview / Data Security"),
    ("dynamicevent", "dynamics", "Dynamics 365"),
    ("dynamics365", "dynamics", "Dynamics 365"),
    ("dynamicsummary", "sentinel", "Microsoft Sentinel"),
    ("egnfailed", "event_grid_ns", "Azure Event Grid Namespace"),
    ("egnmqtt", "event_grid_ns", "Azure Event Grid Namespace"),
    ("egnsuccessful", "event_grid_ns", "Azure Event Grid Namespace"),
    ("emailattachment", "mde_law", "MDE / Defender (LAW)"),
    ("emailevents", "mde_law", "MDE / Defender (LAW)"),
    ("emailpostdelivery", "mde_law", "MDE / Defender (LAW)"),
    ("emailurlinfo", "mde_law", "MDE / Defender (LAW)"),
    ("enrichedmicrosoft365", "sentinel", "Microsoft Sentinel"),
    ("etwevent", "etw", "ETW Events"),
    ("event", "event", "Windows Event Log"),
    ("exchangeassessment", "exchange", "Exchange Assessment"),
    ("exchangeonlineassessment", "exchange", "Exchange Assessment"),
    ("failedingestion", "la_ingestion", "Log Analytics Ingestion"),
    ("functionapplogs", "functions", "Azure Functions"),
    ("gcpaudit", "gcp", "GCP (via Azure Monitor)"),
    ("googlecloudscc", "gcp", "GCP (via Azure Monitor)"),
    ("hdinsight", "hdinsight", "Azure HDInsight"),
    ("healthstatechange", "workload_monitor", "Azure Monitor Workload Health"),
    ("heartbeat", "la_legacy", "Log Analytics Legacy"),
    ("huntingbookmark", "sentinel", "Microsoft Sentinel"),
    ("identitydirectory", "mde_law", "MDE / Defender (LAW)"),
    ("identityinfo", "mde_law", "MDE / Defender (LAW)"),
    ("identitylogon", "mde_law", "MDE / Defender (LAW)"),
    ("identityquery", "mde_law", "MDE / Defender (LAW)"),
    ("iisassessment", "iis", "IIS Assessment"),
    ("insightsmetrics", "la_legacy", "Log Analytics Legacy"),
    ("intuneaudit", "intune", "Microsoft Intune"),
    ("intunedevice", "intune", "Microsoft Intune"),
    ("intuneoperational", "intune", "Microsoft Intune"),
    ("iothubdistributed", "iothub", "Azure IoT Hub"),
    ("kubeevents", "aks", "Azure Kubernetes Service"),
    ("kubehealth", "aks", "Azure Kubernetes Service"),
    ("kubemon", "aks", "Azure Kubernetes Service"),
    ("kubenode", "aks", "Azure Kubernetes Service"),
    ("kubepod", "aks", "Azure Kubernetes Service"),
    ("kubepv", "aks", "Azure Kubernetes Service"),
    ("kubeservice", "aks", "Azure Kubernetes Service"),
    ("laquery", "la_ingestion", "Log Analytics Ingestion"),
    ("lasummary", "la_ingestion", "Log Analytics Ingestion"),
    ("logicapp", "logicapps", "Azure Logic Apps"),
    ("maapp", "ma", "Desktop Analytics"),
    ("madeployment", "ma", "Desktop Analytics"),
    ("madevice", "ma", "Desktop Analytics"),
    ("madriver", "ma", "Desktop Analytics"),
    ("maoffice", "ma", "Desktop Analytics"),
    ("maproposed", "ma", "Desktop Analytics"),
    ("mawindows", "ma", "Desktop Analytics"),
    ("mcasshadow", "mcas", "Microsoft Cloud App Security"),
    ("mccevent", "mcc", "Microsoft Connected Cache"),
    ("mcvpaudit", "mcvp", "Microsoft Cloud PKI / Verified ID"),
    ("mcvpoperation", "mcvp", "Microsoft Cloud PKI / Verified ID"),
    ("mdcfile", "mdc", "Microsoft Defender for Cloud (FIM)"),
    ("mdecustom", "mde_law", "MDE / Defender (LAW)"),
    ("microsoftazurebastion", "bastion", "Azure Bastion"),
    ("microsoftdatashare", "datashare", "Azure Data Share"),
    ("microsoftdynamics", "dynamics", "Microsoft Dynamics"),
    ("microsoftgraph", "msgraph", "Microsoft Graph Activity"),
    ("microsofthealthcare", "ahds", "Azure Health Data Services"),
    ("microsoftpurview", "purview", "Microsoft Purview"),
    ("mnfdevice", "mnf", "Microsoft Network Function"),
    ("mnfsystem", "mnf", "Microsoft Network Function"),
    ("ncbm", "ncbm", "Azure Nexus Baremetal"),
    ("nccku", "ncc", "Azure Nexus Cluster"),
    ("nccv", "ncc", "Azure Nexus Cluster"),
    ("ncmcluster", "ncc", "Azure Nexus Cluster"),
    ("ncsstorage", "ncs", "Azure Nexus Storage"),
    ("ncsstore", "ncs", "Azure Nexus Storage"),
    ("networkaccesstraffic", "entra_internet_access", "Entra Internet Access"),
    ("networksessions", "sentinel", "Microsoft Sentinel"),
    ("ngxoperation", "nginx", "NGINX Ingress"),
    ("ngxsecurity", "nginx", "NGINX Ingress"),
    ("nspaccess", "nsp", "Azure Network Security Perimeter"),
    ("ntainsights", "nta", "Network Traffic Analytics"),
    ("ntaip", "nta", "Network Traffic Analytics"),
    ("ntanet", "nta", "Network Traffic Analytics"),
    ("ntatopology", "nta", "Network Traffic Analytics"),
    ("nwconnectionmonitor", "network_watcher", "Network Watcher"),
    ("oepairflow", "oep", "Azure Open Energy Platform"),
    ("oepaudit", "oep", "Azure Open Energy Platform"),
    ("oepdataplane", "oep", "Azure Open Energy Platform"),
    ("oepelastic", "oep", "Azure Open Energy Platform"),
    ("officeactivity", "m365_law", "M365 / Office Activity (LAW)"),
    ("olpsupplychain", "olp", "Microsoft Open Logistics Platform"),
    ("operation", "la_legacy", "Log Analytics Legacy"),
    ("perf", "la_legacy", "Log Analytics Legacy"),
    ("pftitleaudit", "playfab", "Azure PlayFab"),
    ("powerapps", "powerplatform", "Power Platform"),
    ("powerautomate", "powerplatform", "Power Platform"),
    ("powerbiactivity", "powerbi", "Power BI"),
    ("powerbiaudit", "powerbi", "Power BI"),
    ("powerbidatasets", "powerbi", "Power BI"),
    ("powerbireport", "powerbi", "Power BI"),
    ("powerplatform", "powerplatform", "Power Platform"),
    ("projectactivity", "project", "Microsoft Project"),
    ("protectionstatus", "la_legacy", "Log Analytics Legacy"),
    ("purviewdata", "purview", "Microsoft Purview"),
    ("purviewscan", "purview", "Microsoft Purview"),
    ("purviewsecurity", "purview", "Microsoft Purview"),
    ("redconnection", "ciam", "Microsoft Entra External ID (CIAM)"),
    ("remotenetwork", "global_secure_access", "Global Secure Access"),
    ("resourcemanagement", "la_legacy", "Log Analytics Legacy"),
    ("sccmassessment", "sccm", "Microsoft Endpoint Configuration Manager"),
    ("scomassessment", "scom", "System Center Operations Manager"),
    ("securescorecontrols", "sentinel", "Microsoft Sentinel"),
    ("securescores", "sentinel", "Microsoft Sentinel"),
    ("securityattackpath", "sentinel", "Microsoft Sentinel"),
    ("securitybaseline", "sentinel", "Microsoft Sentinel"),
    ("securitydetection", "sentinel", "Microsoft Sentinel"),
    ("securityevent", "event", "Windows Event Log"),
    ("securityincident", "sentinel", "Microsoft Sentinel"),
    ("securityiotrawevent", "defenderiot", "Defender for IoT"),
    ("securitynested", "sentinel", "Microsoft Sentinel"),
    ("securityrecommendation", "sentinel", "Microsoft Sentinel"),
    ("securityregulatory", "sentinel", "Microsoft Sentinel"),
    ("sentinelaudit", "sentinel", "Microsoft Sentinel"),
    ("sentinelhealth", "sentinel", "Microsoft Sentinel"),
    ("servicefabric", "servicefabric", "Azure Service Fabric"),
    ("sfbassessment", "sfb", "Skype for Business Assessment"),
    ("sfbonline", "sfb", "Skype for Business Assessment"),
    ("sharepointonline", "sharepoint", "SharePoint Assessment"),
    ("signalrservice", "signalr", "Azure SignalR Service"),
    ("signinlogs", "aad", "Azure AD / Entra ID"),
    ("spassessment", "sharepoint", "SharePoint Assessment"),
    ("sqlassessment", "sql", "Azure SQL"),
    ("sqlatp", "sql", "Azure SQL"),
    ("sqldataclass", "sql", "Azure SQL"),
    ("sqlsecurity", "sql", "Azure SQL"),
    ("sqlvulnerability", "sql", "Azure SQL"),
    ("storageblob", "storage", "Azure Storage"),
    ("storagecache", "storage", "Azure Storage"),
    ("storagefile", "storage", "Azure Storage"),
    ("storagemalware", "storage", "Azure Storage"),
    ("storagemover", "storage", "Azure Storage"),
    ("storagequeue", "storage", "Azure Storage"),
    ("storagetable", "storage", "Azure Storage"),
    ("succeededingestion", "la_ingestion", "Log Analytics Ingestion"),
    ("synapse", "synapse", "Azure Synapse Analytics"),
    ("syslog", "syslog", "Linux Syslog"),
    ("threatintelligence", "sentinel", "Microsoft Sentinel"),
    ("tsiingress", "tsi", "Azure Time Series Insights"),
    ("uaapp", "ua", "Desktop Analytics"),
    ("uacomputer", "ua", "Desktop Analytics"),
    ("uadriver", "ua", "Desktop Analytics"),
    ("uafeedback", "ua", "Desktop Analytics"),
    ("uaiesite", "ua", "Desktop Analytics"),
    ("uaoffice", "ua", "Desktop Analytics"),
    ("uaproposed", "ua", "Desktop Analytics"),
    ("uasys", "ua", "Desktop Analytics"),
    ("uaupgraded", "ua", "Desktop Analytics"),
    ("ucclient", "uc", "Update Compliance"),
    ("ucdevice", "uc", "Update Compliance"),
    ("ucdo", "uc", "Update Compliance"),
    ("ucservice", "uc", "Update Compliance"),
    ("ucupdate", "uc", "Update Compliance"),
    ("update", "update_management", "Azure Update Management"),
    ("urlclickevents", "mde_law", "MDE / Defender (LAW)"),
    ("usage", "la_ingestion", "Log Analytics Ingestion"),
    ("useraccess", "sentinel", "Microsoft Sentinel"),
    ("userpeer", "sentinel", "Microsoft Sentinel"),
    ("vcoremongo", "cosmos", "Cosmos DB"),
    ("viaudit", "vi", "Azure Video Indexer"),
    ("vmbound", "vm_insights", "VM Insights"),
    ("vmcomputer", "vm_insights", "VM Insights"),
    ("vmconnection", "vm_insights", "VM Insights"),
    ("vmprocess", "vm_insights", "VM Insights"),
    ("w3ciis", "iis_w3c", "IIS W3C Logs"),
    ("waasdeploy", "waas", "Windows Update for Business"),
    ("waasinsider", "waas", "Windows Update for Business"),
    ("waasupdate", "waas", "Windows Update for Business"),
    ("watchlist", "sentinel", "Microsoft Sentinel"),
    ("wdavstatus", "wdav", "Windows Defender AV"),
    ("wdavthreat", "wdav", "Windows Defender AV"),
    ("webpubsub", "webpubsub", "Azure Web PubSub"),
    ("wildcard", "other", "Other / Wildcard"),
    ("windows365", "windows365", "Windows 365"),
    ("windowsclient", "windows", "Windows Assessment"),
    ("windowsevent", "event", "Windows Event Log"),
    ("windowsfirewall", "event", "Windows Event Log"),
    ("windowsserver", "windows", "Windows Assessment"),
    ("wiredata", "la_legacy", "Log Analytics Legacy"),
    ("workloaddiagnostic", "workload_monitor", "Workload Monitoring"),
    ("workloadmonitoring", "workload_monitor", "Workload Monitoring"),
    ("wudoaggregated", "waas", "Windows Update for Business"),
    ("wudostatus", "waas", "Windows Update for Business"),
    ("wvd", "avd", "Azure Virtual Desktop"),
]

LAW_SUBCAT_DISPLAY: dict = {}
for _prefix, _id, _display in LAW_SUBCATEGORIES:
    if _id not in LAW_SUBCAT_DISPLAY:
        LAW_SUBCAT_DISPLAY[_id] = _display


def display_from_table(table_name: str) -> tuple:
    """Return (display_name, description) for a LAW table name."""
    display = table_name[0].upper() + table_name[1:]
    return (display, f"Log Analytics Workspace table: {table_name}")


def get_law_subcategory(table_name: str) -> str:
    """Return the subcategory_id for a LAW table name using prefix matching."""
    low = table_name.lower()
    for prefix, cat_id, _ in LAW_SUBCATEGORIES:
        if low.startswith(prefix):
            return cat_id
    return "other"


def parse_inputs_conf(path: str) -> list:
    """
    Parse inputs.conf and return list of {sourcetype, monitor} dicts.

    Strips the user-specific Splunk base path prefix and replaces the Splunk
    wildcard directory separator '.../' with '{sub_id}/' for Azure subscription IDs.
    """
    BASE = "Users/nkantor/Documents/Sandia/cloud_stuff/vxnstategoose/output/"
    results = []
    current_monitor = None

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip()
            m = re.match(r"^\[monitor:/(.+)\]\s*$", line)
            if m:
                current_monitor = m.group(1)
            elif current_monitor and re.match(r"^\s*sourcetype\s*=", line):
                st = line.split("=", 1)[1].strip()
                path_val = current_monitor
                if path_val.startswith(BASE):
                    path_val = path_val[len(BASE):]
                path_val = path_val.replace(".../", "{sub_id}/")
                results.append({"sourcetype": st, "monitor": path_val})
                current_monitor = None

    return results


def sourcetype_display_name(st_id: str) -> str:
    """Generate a human-readable display name from a sourcetype ID."""
    parts = st_id.split(":")
    last = parts[-1]
    last = last.replace("_", " ")
    last = re.sub(r"([a-z])([A-Z])", r"\1 \2", last)
    return last.title()


def build_sourcetypes_json(entries: list) -> dict:
    """Build the full sourcetypes.json structure from parsed inputs.conf entries."""
    data: dict = {"version": "1.0", "types": {}}

    by_type: dict = defaultdict(list)
    for e in entries:
        st = e["sourcetype"]
        parts = st.split(":")
        if len(parts) < 2:
            continue
        type_id = parts[1]
        by_type[type_id].append(e)

    for type_id, type_entries in by_type.items():
        meta = TYPE_META.get(type_id, {
            "display_name": type_id.upper(),
            "description": f"{type_id} data",
        })
        type_obj: dict = {
            "display_name": meta["display_name"],
            "description": meta["description"],
            "subtypes": {},
        }

        if type_id == "azure":
            _build_azure_subtypes(type_obj, type_entries)
        elif type_id == "eid":
            _build_eid_subtypes(type_obj, type_entries)
        elif type_id == "mde":
            _build_mde_subtypes(type_obj, type_entries)
        elif type_id == "m365":
            _build_m365_subtypes(type_obj, type_entries)

        data["types"][type_id] = type_obj

    return data


def _make_sourcetype_entry(st_id: str, monitor_path: str) -> dict:
    """Create a single sourcetype entry dict."""
    display = sourcetype_display_name(st_id)
    top = monitor_path.split("/")[0]
    return {
        "display_name": display,
        "description": f"Data collected via {top} dumper",
        "file_glob": monitor_path,
    }


def _build_azure_subtypes(type_obj: dict, entries: list):
    """Populate azure subtypes: core, securitycenter, network, d4iot, law."""
    core_entries: list = []
    securitycenter_entries: list = []
    network_entries: list = []
    d4iot_entries: list = []
    law_entries: list = []

    for e in entries:
        st = e["sourcetype"]
        parts = st.split(":")
        if len(parts) < 3:
            continue
        seg = parts[2]
        if seg == "law":
            law_entries.append(e)
        elif seg == "securitycenter":
            securitycenter_entries.append(e)
        elif seg == "network":
            network_entries.append(e)
        elif seg == "d4iot":
            d4iot_entries.append(e)
        else:
            core_entries.append(e)

    for subtype_id, sub_entries in [
        ("core", core_entries),
        ("securitycenter", securitycenter_entries),
        ("network", network_entries),
        ("d4iot", d4iot_entries),
    ]:
        if not sub_entries:
            continue
        meta = SUBTYPE_META.get(f"azure:{subtype_id}", {
            "display_name": subtype_id.title(), "description": "",
        })
        sourcetypes: dict = {}
        for e in sub_entries:
            st = e["sourcetype"]
            key = ":".join(st.split(":")[2:])
            sourcetypes[key] = _make_sourcetype_entry(st, e["monitor"])
        type_obj["subtypes"][subtype_id] = {
            "display_name": meta["display_name"],
            "description": meta["description"],
            "sourcetypes": sourcetypes,
        }

    if law_entries:
        _build_law_subtype(type_obj, law_entries)


def _build_law_subtype(type_obj: dict, entries: list):
    """Build the law subtype with prefix-based subcategories for the 670 LAW tables."""
    meta = SUBTYPE_META["azure:law"]

    by_subcat: dict = defaultdict(dict)
    for e in entries:
        st = e["sourcetype"]
        parts = st.split(":")
        if len(parts) < 4:
            continue
        table_name = parts[3]
        subcat_id = get_law_subcategory(table_name)
        display, desc = display_from_table(table_name)
        by_subcat[subcat_id][table_name] = {
            "display_name": display,
            "description": desc,
            "file_glob": e["monitor"],
        }

    subcategories: dict = {}
    for subcat_id, sourcetypes in sorted(by_subcat.items()):
        display = LAW_SUBCAT_DISPLAY.get(subcat_id, subcat_id.replace("_", " ").title())
        subcategories[subcat_id] = {
            "display_name": display,
            "sourcetypes": sourcetypes,
        }

    type_obj["subtypes"]["law"] = {
        "display_name": meta["display_name"],
        "description": meta["description"],
        "subcategories": subcategories,
    }


def _build_eid_subtypes(type_obj: dict, entries: list):
    """Populate EID subtypes."""
    buckets: dict = {
        "core": [], "signin": [], "applications": [], "ca": [],
        "rolemanagement": [], "policy": [], "org": [], "identity": [],
        "risk": [], "security": [], "reports": [], "sp": [], "users": [],
    }
    RISK_SEGS = {"riskdetections", "spriskdetections", "riskyusers", "riskysp",
                 "riskysphistory", "riskyuserhistory"}
    SECURITY_SEGS = {"securityalerts", "securescores"}

    for e in entries:
        st = e["sourcetype"]
        parts = st.split(":")
        if len(parts) < 3:
            continue
        seg = parts[2]
        if seg in buckets:
            buckets[seg].append(e)
        elif seg in RISK_SEGS:
            buckets["risk"].append(e)
        elif seg in SECURITY_SEGS:
            buckets["security"].append(e)
        else:
            buckets["core"].append(e)

    for subtype_id, sub_entries in buckets.items():
        if not sub_entries:
            continue
        meta = SUBTYPE_META.get(f"eid:{subtype_id}", {
            "display_name": subtype_id.title(), "description": "",
        })
        sourcetypes: dict = {}
        for e in sub_entries:
            st = e["sourcetype"]
            key = ":".join(st.split(":")[2:])
            sourcetypes[key] = _make_sourcetype_entry(st, e["monitor"])
        type_obj["subtypes"][subtype_id] = {
            "display_name": meta["display_name"],
            "description": meta["description"],
            "sourcetypes": sourcetypes,
        }


def _build_mde_subtypes(type_obj: dict, entries: list):
    """Populate MDE subtypes: api (REST API) and hunting (advanced hunting tables)."""
    API_TYPES = {
        "alerts", "indicators", "cloudappactivity", "incidents",
        "investigations", "machines", "recommendations", "software", "vulnerabilities",
    }
    api_entries: list = []
    hunting_entries: list = []

    for e in entries:
        st = e["sourcetype"]
        parts = st.split(":")
        if len(parts) < 3:
            continue
        detail = parts[2]
        if detail in API_TYPES:
            api_entries.append(e)
        else:
            hunting_entries.append(e)

    for subtype_id, sub_entries in [("api", api_entries), ("hunting", hunting_entries)]:
        if not sub_entries:
            continue
        meta = SUBTYPE_META.get(f"mde:{subtype_id}", {
            "display_name": subtype_id.title(), "description": "",
        })
        sourcetypes: dict = {}
        for e in sub_entries:
            st = e["sourcetype"]
            key = ":".join(st.split(":")[2:])
            sourcetypes[key] = _make_sourcetype_entry(st, e["monitor"])
        type_obj["subtypes"][subtype_id] = {
            "display_name": meta["display_name"],
            "description": meta["description"],
            "sourcetypes": sourcetypes,
        }


def _build_m365_subtypes(type_obj: dict, entries: list):
    """Populate M365 subtypes: core (UAL, users) and exchange."""
    EXCHANGE_PREFIX = "ugt:m365:exchange:"
    core_entries: list = []
    exchange_entries: list = []

    for e in entries:
        st = e["sourcetype"]
        if st.startswith(EXCHANGE_PREFIX):
            exchange_entries.append(e)
        else:
            core_entries.append(e)

    for subtype_id, sub_entries in [("core", core_entries), ("exchange", exchange_entries)]:
        if not sub_entries:
            continue
        meta = SUBTYPE_META.get(f"m365:{subtype_id}", {
            "display_name": subtype_id.title(), "description": "",
        })
        sourcetypes: dict = {}
        for e in sub_entries:
            st = e["sourcetype"]
            key = ":".join(st.split(":")[2:])
            sourcetypes[key] = _make_sourcetype_entry(st, e["monitor"])
        type_obj["subtypes"][subtype_id] = {
            "display_name": meta["display_name"],
            "description": meta["description"],
            "sourcetypes": sourcetypes,
        }


def count_sourcetypes(data: dict) -> int:
    """Count total sourcetype entries in the JSON structure."""
    count = 0
    for type_obj in data["types"].values():
        for subtype_obj in type_obj["subtypes"].values():
            if "sourcetypes" in subtype_obj:
                count += len(subtype_obj["sourcetypes"])
            if "subcategories" in subtype_obj:
                for subcat in subtype_obj["subcategories"].values():
                    count += len(subcat.get("sourcetypes", {}))
    return count


def main():
    """Entry point: parse arguments, run generation, write output."""
    parser = argparse.ArgumentParser(
        description="Generate goosey/data/sourcetypes.json from conf/inputs.conf"
    )
    parser.add_argument(
        "--inputs", default="conf/inputs.conf",
        help="Path to Splunk inputs.conf (default: conf/inputs.conf)",
    )
    parser.add_argument(
        "--output", default="goosey/data/sourcetypes.json",
        help="Output path (default: goosey/data/sourcetypes.json)",
    )
    args = parser.parse_args()

    if not os.path.exists(args.inputs):
        print(f"ERROR: inputs.conf not found at {args.inputs}", file=sys.stderr)
        sys.exit(1)

    print(f"Parsing {args.inputs}...")
    entries = parse_inputs_conf(args.inputs)
    print(f"  Parsed {len(entries)} monitor/sourcetype pairs")

    print("Building sourcetypes.json structure...")
    data = build_sourcetypes_json(entries)

    total = count_sourcetypes(data)
    print(f"  Total sourcetypes in output JSON: {total}")

    os.makedirs(os.path.dirname(args.output), exist_ok=True)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"Written to {args.output}")

    if total != len(entries):
        print(
            f"WARNING: Count mismatch -- {len(entries)} input entries but {total} in output JSON",
            file=sys.stderr,
        )
        sys.exit(1)

    print("Done.")


if __name__ == "__main__":
    main()

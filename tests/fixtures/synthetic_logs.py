"""Synthetic (fake) telemetry builders for the CyberFire lab regression tests.

Everything here is fabricated: GUIDs are obviously fake (00000000-...-aa),
IPs come from the RFC 5737 documentation ranges, and users are example.com.
The only real values are the well-known public Microsoft application and
resource IDs that the detections key on.

@decision DEC-HQL-010
@title Build fixtures programmatically with documented shapes
@status accepted
@rationale A ROADrecon burst is thousands of near-identical rows; generating
  them keeps the repository free of collected output while still exercising
  realistic volume, and makes every field of the shape explicit in one place.
"""

import json
import os

AZURE_CLI_APP_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"   # public: Microsoft Azure CLI
AAD_GRAPH_RESOURCE_ID = "00000002-0000-0000-c000-000000000000"  # public: Windows Azure Active Directory
MS_GRAPH_RESOURCE_ID = "00000003-0000-0000-c000-000000000000"   # public: Microsoft Graph

FAKE_USER_ID = "00000000-0000-0000-0000-0000000000aa"
FAKE_UPN = "victim@example.com"
FAKE_IP = "203.0.113.10"
OTHER_IP = "198.51.100.20"
ROAD_UA = "Python/3.11 aiohttp/3.14.5"
GRAPH_BASE = "https://graph.windows.net/00000000-0000-0000-0000-0000000000bb"


def write_ndjson(path, rows):
    """Write rows as NDJSON, creating parent dirs; an empty list gives a 0-byte file."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    return path


def roadrecon_burst_rows(n=150):
    """AADGraphActivityLogs rows: one actor, many distinct URIs within ~11 seconds."""
    rows = []
    for i in range(n):
        rows.append({
            "TimeGenerated": "2026-11-02T10:04:%02d.000Z" % (i % 60),
            "TimeRequested": "2026-11-02T10:00:%02d.000Z" % (i % 11),
            "UserId": FAKE_USER_ID,
            "CallerIpAddress": FAKE_IP,
            "AppId": AZURE_CLI_APP_ID,
            "UserAgent": ROAD_UA,
            "RequestMethod": "GET",
            "RequestUri": GRAPH_BASE + "/users/obj-%04d?api-version=1.61-internal" % i,
            "ResponseStatusCode": 200,
        })
    return rows


def first_party_policy_rows(n=6):
    """Low-volume Microsoft first-party style traffic: other app, UA, IP, few URIs."""
    return [{
        "TimeGenerated": "2026-11-02T11:00:%02d.000Z" % i,
        "TimeRequested": "2026-11-02T10:56:%02d.000Z" % i,
        "UserId": "00000000-0000-0000-0000-0000000000cc",
        "CallerIpAddress": OTHER_IP,
        "AppId": "00000000-0000-0000-0000-0000000000dd",
        "UserAgent": "Microsoft.OData.Client/7.0",
        "RequestMethod": "GET",
        "RequestUri": GRAPH_BASE + "/policies/p%d" % (i % 2),
        "ResponseStatusCode": 200,
    } for i in range(n)]


def graph_signin(resource_id, error_code=0, user_agent="python-requests/2.31.0",
                 app_id=AZURE_CLI_APP_ID, suffix="1"):
    """One raw Graph beta signIn object (nested status/deviceDetail/location)."""
    return {
        "id": "00000000-0000-0000-0000-00000000e%03d" % int(suffix),
        "createdDateTime": "2026-11-02T10:00:00Z",
        "userDisplayName": "Victim",
        "userPrincipalName": FAKE_UPN,
        "userId": FAKE_USER_ID,
        "appId": app_id,
        "appDisplayName": "Microsoft Azure CLI",
        "ipAddress": FAKE_IP,
        "clientAppUsed": "Mobile Apps and Desktop clients",
        "resourceDisplayName": ("Windows Azure Active Directory"
                                if resource_id == AAD_GRAPH_RESOURCE_ID else "Microsoft Graph"),
        "resourceId": resource_id,
        "userAgent": user_agent,
        "correlationId": "00000000-0000-0000-0000-00000000c%03d" % int(suffix),
        "conditionalAccessStatus": "notApplied",
        "status": {"errorCode": error_code,
                   "failureReason": "Other." if error_code else "",
                   "additionalDetails": None},
        "deviceDetail": {"deviceId": "", "displayName": "", "operatingSystem": "Linux",
                         "browser": "", "isCompliant": False, "isManaged": False,
                         "trustType": ""},
        "location": {"city": "Exampleville", "state": "", "countryOrRegion": "US",
                     "geoCoordinates": {"latitude": 0.0, "longitude": 0.0}},
    }

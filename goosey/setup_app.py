#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Untitled Goose Tool: Azure App Registration Setup

Creates or deletes the Azure AD app registration, service principal, API permissions,
subscription IAM roles, and Exchange Online service principal needed by Goosey.

This is the Python equivalent of scripts/Create_SP.ps1 — no PowerShell required.

Usage:
    goosey setup --app_name GooseApp --create
    goosey setup --app_name GooseApp --delete
    goosey setup --app_name GooseApp --create --gcc_high
    goosey setup --app_name GooseApp --create --no_subscriptions
    goosey setup --app_name GooseApp --create --force
"""

import getpass
import json
import msal
import requests
import sys
import time

from azure.identity import InteractiveBrowserCredential, DeviceCodeCredential
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.authorization import AuthorizationManagementClient

from goosey.utils import write_auth

# API permissions to assign to the service principal (application permissions).
# Keys are the display names of resource applications (as registered in Entra ID).
PERMISSIONS = {
    "Log Analytics API": [
        "Data.Read",
    ],
    "Microsoft Threat Protection": [
        "AdvancedHunting.Read.All",
    ],
    "WindowsDefenderATP": [
        "AdvancedQuery.Read.All",
        "Alert.Read.All",
        "Library.Manage",
        "Machine.Read.All",
        "SecurityRecommendation.Read.All",
        "Software.Read.All",
        "Ti.ReadWrite",
        "Vulnerability.Read.All",
    ],
    "Office 365 Exchange Online": [
        "Exchange.ManageAsApp",
    ],
    "Microsoft Graph": [
        "AdministrativeUnit.Read.All",
        "APIConnectors.Read.All",
        "AuditLog.Read.All",
        "AuditLogsQuery.Read.All",
        "ConsentRequest.Read.All",
        "Directory.Read.All",
        "Domain.Read.All",
        "ExternalUserProfile.Read.All",
        "Group.Read.All",
        "IdentityProvider.Read.All",
        "IdentityRiskEvent.Read.All",
        "IdentityRiskyServicePrincipal.Read.All",
        "IdentityRiskyUser.Read.All",
        "MailboxSettings.Read",
        "PendingExternalUserProfile.Read.All",
        "Policy.Read.All",
        "Policy.Read.PermissionGrant",
        "Reports.Read.All",
        "ResourceSpecificPermissionGrant.ReadForUser.All",
        "RoleManagement.Read.All",
        "SecurityActions.Read.All",
        "SecurityAlert.Read.All",
        "SecurityEvents.Read.All",
        "Team.ReadBasic.All",
        "TeamsAppInstallation.ReadForUser.All",
        "ThreatHunting.Read.All",
        "User.Read.All",
        "UserAuthenticationMethod.Read.All",
    ],
}

# Azure subscription-level IAM roles to assign to the service principal
APP_ROLES = [
    "Reader",
    "Storage Blob Data Reader",
    "Storage Queue Data Reader",
]

# Exchange Online roles for the app's role group
EXCHANGE_ROLES = [
    "View-Only Audit Logs",
    "View-Only Configuration",
    "View-Only Recipients",
    "User Options",
]

# Well-known app IDs for MSAL interactive auth
# Microsoft Graph PowerShell SDK client ID — pre-authorized for Graph API
GRAPH_POWERSHELL_CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
# Azure PowerShell client ID — used for Exchange Online auth
AZ_POWERSHELL_CLIENT_ID = "1950a258-227b-4e31-a9cf-717495945fc2"


def get_env_config(gcc_high=False):
    """Return environment-specific URLs and cloud names."""
    if gcc_high:
        return {
            "graph_url": "https://graph.microsoft.us",
            "graph_scope": "https://graph.microsoft.us/.default",
            "authority": "https://login.microsoftonline.us",
            "arm_url": "https://management.usgovcloudapi.net",
            "arm_scope": "https://management.usgovcloudapi.net/.default",
            "exo_url": "https://outlook.office365.us",
            "exo_scope": "https://outlook.office365.us/.default",
            "azure_cloud": "AzureUSGovernment",
        }
    return {
        "graph_url": "https://graph.microsoft.com",
        "graph_scope": "https://graph.microsoft.com/.default",
        "authority": "https://login.microsoftonline.com",
        "arm_url": "https://management.azure.com",
        "arm_scope": "https://management.azure.com/.default",
        "exo_url": "https://outlook.office365.com",
        "exo_scope": "https://outlook.office365.com/.default",
        "azure_cloud": "AzureCloud",
    }


def acquire_graph_token(env, tenant_id=None):
    """Acquire a delegated Microsoft Graph token via interactive browser login.

    Uses MSAL PublicClientApplication with the Azure PowerShell well-known client ID.
    Scopes request broad directory and app management permissions needed for setup.
    """
    authority = env["authority"]
    if tenant_id:
        authority = f"{env['authority']}/{tenant_id}"
    else:
        authority = f"{env['authority']}/common"

    app = msal.PublicClientApplication(
        client_id=GRAPH_POWERSHELL_CLIENT_ID,
        authority=authority,
    )

    scopes = [
        "Application.ReadWrite.All",
        "AppRoleAssignment.ReadWrite.All",
        "Directory.ReadWrite.All",
    ]

    result = app.acquire_token_interactive(scopes=scopes)
    if "error" in result:
        print(f"Error acquiring Graph token: {result.get('error_description', result['error'])}")
        sys.exit(1)

    return result["access_token"], result.get("id_token_claims", {}).get("tid")


def acquire_exo_token(env, tenant_id):
    """Acquire a delegated Exchange Online token via interactive browser login."""
    authority = f"{env['authority']}/{tenant_id}"

    app = msal.PublicClientApplication(
        client_id=AZ_POWERSHELL_CLIENT_ID,
        authority=authority,
    )

    # Exchange Online management scope
    exo_base = env["exo_url"]
    scopes = [f"{exo_base}/.default"]

    result = app.acquire_token_interactive(scopes=scopes)
    if "error" in result:
        print(f"Error acquiring Exchange token: {result.get('error_description', result['error'])}")
        sys.exit(1)

    return result["access_token"]


class GraphClient:
    """Thin wrapper around Microsoft Graph REST API calls."""

    def __init__(self, token, base_url="https://graph.microsoft.com"):
        self.token = token
        self.base_url = base_url
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

    def get(self, path, params=None):
        r = requests.get(f"{self.base_url}/v1.0{path}", headers=self.headers, params=params)
        r.raise_for_status()
        return r.json()

    def post(self, path, body=None):
        r = requests.post(f"{self.base_url}/v1.0{path}", headers=self.headers, json=body)
        r.raise_for_status()
        return r.json()

    def delete(self, path):
        r = requests.delete(f"{self.base_url}/v1.0{path}", headers=self.headers)
        r.raise_for_status()

    def get_app_by_name(self, name):
        result = self.get("/applications", params={"$filter": f"displayName eq '{name}'"})
        apps = result.get("value", [])
        return apps[0] if apps else None

    def get_sp_by_name(self, name):
        result = self.get("/servicePrincipals", params={"$filter": f"displayName eq '{name}'"})
        sps = result.get("value", [])
        return sps[0] if sps else None

    def get_sp_by_appid(self, app_id):
        result = self.get("/servicePrincipals", params={"$filter": f"appId eq '{app_id}'"})
        sps = result.get("value", [])
        return sps[0] if sps else None


class ExchangeClient:
    """Executes Exchange Online PowerShell cmdlets via the AdminAPI REST endpoint."""

    def __init__(self, token, base_url, tenant_id):
        self.token = token
        self.base_url = base_url
        self.tenant_id = tenant_id

    def run_cmdlet(self, cmdlet, parameters=None):
        if parameters is None:
            parameters = {}

        url = f"{self.base_url}/adminapi/beta/{self.tenant_id}/InvokeCommand"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-ResponseFormat": "json",
            "X-CmdletName": cmdlet,
            "X-ClientApplication": "ExoManagementModule",
        }
        payload = {
            "CmdletInput": {
                "CmdletName": cmdlet,
                "Parameters": parameters,
            }
        }

        r = requests.post(url, headers=headers, json=payload, timeout=120)
        result = r.json()

        if r.status_code != 200:
            error_msg = result.get("error", {}).get("message", r.text)
            raise RuntimeError(f"EXO cmdlet {cmdlet} failed ({r.status_code}): {error_msg}")

        return result


def create_app(graph, app_name, subscriptions_used, env, gcc_high=False):
    """Create the Entra ID app registration, service principal, permissions, and roles."""
    # 1. Create or get app registration
    app = graph.get_app_by_name(app_name)
    if not app:
        print(f"Creating application '{app_name}'...")
        app = graph.post("/applications", {"displayName": app_name})
    else:
        print(f"Application '{app_name}' already exists.")
    app_id = app["appId"]
    app_object_id = app["id"]

    # 2. Create or get service principal
    sp = graph.get_sp_by_name(app_name)
    if not sp:
        print(f"Creating service principal for '{app_name}'...")
        sp = graph.post("/servicePrincipals", {"appId": app_id})
    else:
        print(f"Service principal for '{app_name}' already exists.")
    sp_id = sp["id"]

    # 3. Assign API permissions
    # Get existing assignments to avoid duplicates
    existing_assignments = graph.get(f"/servicePrincipals/{sp_id}/appRoleAssignments")
    existing_role_ids = {a["appRoleId"] for a in existing_assignments.get("value", [])}

    for scope_name, perms in PERMISSIONS.items():
        print(f"Assigning permissions for {scope_name}...")
        resource_sp = graph.get_sp_by_name(scope_name)
        if not resource_sp:
            print(f"  WARNING: Resource application '{scope_name}' not found. Skipping.")
            continue

        resource_id = resource_sp["id"]
        app_roles = {role["value"]: role["id"] for role in resource_sp.get("appRoles", [])}

        for perm in perms:
            role_id = app_roles.get(perm)
            if not role_id:
                print(f"  WARNING: Permission '{perm}' not found in '{scope_name}'. Skipping.")
                continue
            if role_id in existing_role_ids:
                print(f"  Permission '{perm}' already assigned.")
                continue

            body = {
                "principalId": sp_id,
                "resourceId": resource_id,
                "appRoleId": role_id,
            }
            try:
                graph.post(f"/servicePrincipals/{sp_id}/appRoleAssignments", body)
                print(f"  Assigned '{perm}'.")
            except requests.exceptions.HTTPError as e:
                print(f"  ERROR assigning '{perm}': {e}")

    # 4. Assign Azure subscription IAM roles
    if subscriptions_used:
        credential = InteractiveBrowserCredential()
        sub_client = SubscriptionClient(credential)
        all_subs = list(sub_client.subscriptions.list())

        for sub in all_subs:
            sub_id = sub.subscription_id
            if "all" not in subscriptions_used and sub_id not in subscriptions_used:
                continue

            print(f"Assigning IAM roles on subscription '{sub.display_name}' ({sub_id})...")
            auth_client = AuthorizationManagementClient(credential, sub_id)

            # Get role definitions
            scope = f"/subscriptions/{sub_id}"
            role_defs = list(auth_client.role_definitions.list(scope, filter=None))
            role_def_map = {rd.role_name: rd.id for rd in role_defs}

            # Get existing assignments for this SP
            existing = list(auth_client.role_assignments.list_for_scope(
                scope, filter=f"principalId eq '{sp_id}'"
            ))
            existing_def_ids = {a.role_definition_id for a in existing}

            import uuid
            for role_name in APP_ROLES:
                role_def_id = role_def_map.get(role_name)
                if not role_def_id:
                    print(f"  WARNING: Role '{role_name}' not found. Skipping.")
                    continue
                if role_def_id in existing_def_ids:
                    print(f"  Role '{role_name}' already assigned.")
                    continue

                try:
                    auth_client.role_assignments.create(
                        scope,
                        str(uuid.uuid4()),
                        {
                            "role_definition_id": role_def_id,
                            "principal_id": sp_id,
                            "principal_type": "ServicePrincipal",
                        },
                    )
                    print(f"  Assigned role '{role_name}'.")
                except Exception as e:
                    print(f"  ERROR assigning role '{role_name}': {e}")

    # 5. Generate client secret
    print("Generating client secret...")
    secret_result = graph.post(f"/servicePrincipals/{sp_id}/addPassword", {
        "passwordCredential": {"displayName": f"{app_name} secret"}
    })
    client_secret = secret_result["secretText"]

    return app_id, sp_id, client_secret


def create_exchange_sp(exo, graph, app_name):
    """Create the Exchange Online service principal and role group."""
    app = graph.get_app_by_name(app_name)
    sp = graph.get_sp_by_name(app_name)
    if not app or not sp:
        print("ERROR: App registration or service principal not found. Run create first.")
        return

    app_id = app["appId"]
    object_id = sp["id"]

    # Create role group
    print(f"Creating Exchange role group '{app_name}'...")
    try:
        result = exo.run_cmdlet("Get-RoleGroup", {"Identity": app_name})
        if result.get("value"):
            print(f"  Role group '{app_name}' already exists.")
        else:
            raise RuntimeError("not found")
    except Exception:
        try:
            exo.run_cmdlet("New-RoleGroup", {"Name": app_name, "Roles": ",".join(EXCHANGE_ROLES)})
            print(f"  Role group '{app_name}' created.")
        except Exception as e:
            print(f"  ERROR creating role group: {e}")
            return

    # Create Exchange service principal
    print(f"Creating Exchange service principal...")
    try:
        exo.run_cmdlet("New-ServicePrincipal", {
            "AppId": app_id,
            "ObjectId": object_id,
            "DisplayName": app_name,
        })
        print(f"  Exchange service principal created.")
    except Exception as e:
        # May already exist
        if "already exists" in str(e).lower() or "ManagementObjectAlreadyExists" in str(e):
            print(f"  Exchange service principal already exists.")
        else:
            print(f"  ERROR creating Exchange service principal: {e}")
            return

    # Add to role group
    print(f"Adding service principal to role group...")
    try:
        exo.run_cmdlet("Add-RoleGroupMember", {
            "Identity": app_name,
            "Member": object_id,
        })
        print(f"  Added to role group.")
    except Exception as e:
        if "already a member" in str(e).lower():
            print(f"  Already a member of the role group.")
        else:
            print(f"  ERROR adding to role group: {e}")


def delete_app(graph, app_name, force=False):
    """Delete the Entra ID app registration, service principal, and subscription roles."""
    if not force:
        confirm = input(f"Are you sure you want to delete '{app_name}'? (y/n): ").strip().lower()
        if confirm != "y":
            print("Deletion cancelled.")
            return

    # Remove subscription role assignments
    sp = graph.get_sp_by_name(app_name)
    if sp:
        sp_id = sp["id"]
        print(f"Removing subscription IAM roles...")
        try:
            credential = InteractiveBrowserCredential()
            sub_client = SubscriptionClient(credential)
            for sub in sub_client.subscriptions.list():
                sub_id = sub.subscription_id
                auth_client = AuthorizationManagementClient(credential, sub_id)
                scope = f"/subscriptions/{sub_id}"
                assignments = list(auth_client.role_assignments.list_for_scope(
                    scope, filter=f"principalId eq '{sp_id}'"
                ))
                for assignment in assignments:
                    auth_client.role_assignments.delete_by_id(assignment.id)
                    print(f"  Removed role assignment from {sub.display_name}.")
        except Exception as e:
            print(f"  ERROR removing role assignments: {e}")

        # Delete service principal
        print(f"Deleting service principal '{app_name}'...")
        try:
            graph.delete(f"/servicePrincipals/{sp_id}")
            print(f"  Service principal deleted.")
        except Exception as e:
            print(f"  ERROR: {e}")
    else:
        print(f"Service principal '{app_name}' not found.")

    # Delete app registration
    app = graph.get_app_by_name(app_name)
    if app:
        print(f"Deleting application '{app_name}'...")
        try:
            graph.delete(f"/applications/{app['id']}")
            print(f"  Application deleted.")
        except Exception as e:
            print(f"  ERROR: {e}")
    else:
        print(f"Application '{app_name}' not found.")


def delete_exchange_sp(exo, graph, app_name, force=False):
    """Delete the Exchange Online service principal and role group."""
    sp = graph.get_sp_by_name(app_name)
    if not sp:
        print(f"Service principal '{app_name}' not found. Skipping Exchange cleanup.")
        return

    object_id = sp["id"]

    try:
        print(f"Removing Exchange role group member...")
        params = {"Identity": app_name, "Member": object_id}
        if force:
            params["Confirm"] = "False"
        exo.run_cmdlet("Remove-RoleGroupMember", params)
    except Exception as e:
        print(f"  WARNING: {e}")

    try:
        print(f"Removing Exchange service principal...")
        params = {"Identity": object_id}
        if force:
            params["Confirm"] = "False"
        exo.run_cmdlet("Remove-ServicePrincipal", params)
    except Exception as e:
        print(f"  WARNING: {e}")

    try:
        print(f"Removing Exchange role group...")
        params = {"Identity": app_name}
        if force:
            params["Confirm"] = "False"
        exo.run_cmdlet("Remove-RoleGroup", params)
    except Exception as e:
        print(f"  WARNING: {e}")


def choose_subscriptions(force=False):
    """Prompt user to select which subscriptions to assign IAM roles on."""
    credential = InteractiveBrowserCredential()
    sub_client = SubscriptionClient(credential)
    subscriptions = list(sub_client.subscriptions.list())

    if not subscriptions:
        print("No Azure subscriptions found.")
        return []

    selected = []
    all_selected = True
    for sub in subscriptions:
        if force:
            selected.append(sub.subscription_id)
        else:
            choice = input(f"Assign roles for subscription '{sub.display_name}' ({sub.subscription_id})? (y/n): ").strip().lower()
            if choice == "y":
                selected.append(sub.subscription_id)
            else:
                all_selected = False

    if all_selected and selected:
        return ["all"]
    return selected


def setup(app_name=None,
          create=False,
          delete=False,
          force=False,
          no_subscriptions=False,
          gcc_high=False,
          insecure=False,
          outpath_auth=".auth",
          debug=False):
    """Create or delete the Azure app registration and service principal for Goosey.

    This replaces the PowerShell script scripts/Create_SP.ps1 with a pure Python
    implementation. It creates the Entra ID app, assigns API permissions, sets up
    Azure subscription IAM roles, configures the Exchange Online service principal,
    and generates a client secret. Automatically writes a .auth file (encrypted by
    default) so you can proceed directly to goosey auth.

    Args:
        app_name: Display name for the Azure application
        create: Create the application and service principal
        delete: Delete the application and service principal
        force: Skip confirmation prompts
        no_subscriptions: Skip Azure subscription role assignments
        gcc_high: Configure for GCC High environment
        insecure: Write .auth as plaintext instead of encrypted .auth.aes
        outpath_auth: Path for the auth config file (default: .auth)
        debug: Enable debug output
    """
    if not app_name:
        app_name = input("Enter the application name: ").strip()
        if not app_name:
            print("Application name is required.")
            sys.exit(1)

    if not create and not delete:
        choice = input("Create or delete the goose app? (c/d): ").strip().lower()
        create = choice == "c"
        delete = choice == "d"
        if not create and not delete:
            print("Invalid choice. Exiting.")
            sys.exit(1)
    elif create and delete:
        choice = input("Both --create and --delete specified. Create or delete? (c/d): ").strip().lower()
        create = choice == "c"
        delete = choice == "d"

    env = get_env_config(gcc_high)

    # Authenticate to Microsoft Graph
    print("Authenticating to Microsoft Graph...")
    graph_token, tenant_id = acquire_graph_token(env)
    graph = GraphClient(graph_token, env["graph_url"])

    if not tenant_id:
        # Fall back to fetching tenant from the organization endpoint
        org = graph.get("/organization")
        tenant_id = org["value"][0]["id"]

    print(f"Tenant ID: {tenant_id}")

    if create:
        # Choose subscriptions
        subscriptions_used = []
        if not no_subscriptions:
            subscriptions_used = choose_subscriptions(force)

        # Create Entra ID app + service principal + permissions + roles
        app_id, sp_id, client_secret = create_app(
            graph, app_name, subscriptions_used, env, gcc_high
        )

        # Create Exchange Online service principal
        print("\nAuthenticating to Exchange Online...")
        exo_token = acquire_exo_token(env, tenant_id)
        exo = ExchangeClient(exo_token, env["exo_url"], tenant_id)
        create_exchange_sp(exo, graph, app_name)

        # Write .auth file
        auth_s = "[auth]\n"
        auth_s += f"appid={app_id}\n"
        auth_s += f"clientsecret={client_secret}\n"
        auth_s += "ests_cookie=\n"
        auth_s += "portal_refresh_token=\n"

        encryption_pw = None
        if not insecure:
            encryption_pw = getpass.getpass("Create a password for .auth file encryption: ")
            confirm_pw = getpass.getpass("Confirm encryption password: ")
            if encryption_pw != confirm_pw:
                print("Passwords do not match. Writing unencrypted .auth file instead.")
                encryption_pw = None

        write_auth(outpath_auth, auth_s, encryption_pw=encryption_pw, insecure=(encryption_pw is None))

        if encryption_pw:
            print(f"\nAuth file written to {outpath_auth}.aes (encrypted)")
        else:
            print(f"\nAuth file written to {outpath_auth} (plaintext)")

        # Output next steps
        sub_ids = ",".join(subscriptions_used) if subscriptions_used else "All"
        print("\n" + "=" * 70)
        print("Setup complete! Generate your Goosey configuration with:\n")
        print(f"  goosey conf --config_tenant={tenant_id} --config_subscriptionid={sub_ids} --auth_appid={app_id}")
        print(f"\nThe client secret has been saved to your .auth file.")
        print(f"You can skip the client secret prompt during goosey conf.")
        print("=" * 70)

    elif delete:
        # Delete Exchange Online service principal first
        print("\nAuthenticating to Exchange Online...")
        try:
            exo_token = acquire_exo_token(env, tenant_id)
            exo = ExchangeClient(exo_token, env["exo_url"], tenant_id)
            delete_exchange_sp(exo, graph, app_name, force)
        except Exception as e:
            print(f"WARNING: Could not clean up Exchange components: {e}")

        # Delete Entra ID app + service principal + roles
        delete_app(graph, app_name, force)

        print("\nDeletion complete.")


if __name__ == "__main__":
    import fire
    fire.Fire(setup)

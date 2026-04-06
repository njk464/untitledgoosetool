#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Untitled Goose Tool: Auth!
This module handles authentication to Entra ID, Azure, M365, and D4IoT environments.
"""

import argparse
import atexit
import configparser
import copy
import getpass
import io
import json
import msal
import os
import re
import requests
import sys
import time

from collections import namedtuple
from goosey.utils import *

green = "\x1b[1;32m"

class Authentication():
    """Handles OAuth authentication for all supported Microsoft cloud platforms.

    Supports two auth paths:
    - Standard (MSAL): Client credential flow for Graph, O365, ARM, Security Center, Log Analytics.
      Tokens are stored in the .ugt_auth file as JSON keyed by endpoint name.
    - D4IoT: Cookie-based auth via CSRF token + session cookie, stored in .d4iot_auth.

    Auth credentials (app ID, client secret, or D4IoT username/password) are read from
    the .auth file (optionally AES-encrypted) or prompted interactively.
    """
    def __init__(self, debug=False):
        self.tokendata = {}
        self.logger = None
        self.d4iot = False
        self.encryption_pw = None

    def get_authority_url(self):
        """
        Returns the authority URL for the commercial or government tenant specified,
        or the common one if no tenant was specified.
        """
        endpoint = self.endpoints_dict["authority_api"]
        tenant = "common"
        if self.tenant:
            tenant = self.tenant
        return f'{endpoint}/{tenant}'

    def get_d4iot_sensor_uri(self):
        """
        Returns the d4iot sensor URI.
        """
        return "https://" + self.d4iot_sensor_ip

    def get_app_resource_uri(self):
        """
        Returns the application resource URI for a commercial or government tenant.
        """
        app_resource_uris = {}
        for key in self.endpoints_dict.keys():
            if key in ["blob_api", "authority_api"]:
                continue
            if key == "cloudapp_defender":
                app_resource_uris[key] = "05a65629-4c1b-48c1-a78b-804c4abdd4af/.default"
            else:
                app_resource_uris[key] = self.endpoints_dict[key] + "/.default"
        return app_resource_uris

    def authenticate_as_app(self, resource_uri):
        """Acquire an OAuth token using the client credentials (app ID + secret) flow.

        Uses MSAL's ConfidentialClientApplication to get a token for the given resource.
        Adds an absolute 'expires_on' timestamp (epoch seconds) to the token dict so
        downstream code (TokenManager) can check expiry without parsing relative times.

        Args:
            resource_uri: The scope/resource URI to authenticate against (e.g. "https://graph.microsoft.com/.default").

        Returns:
            dict: The token data including access_token, token_type, expires_on, etc.
        """
        authority_uri = self.get_authority_url()
        self.logger.debug(f"App Authentication authority uri: {str(authority_uri)}")
        self.logger.debug(f"App authentication resource uri: {str(resource_uri)}")
        context = msal.ConfidentialClientApplication(client_id=self.app_client_id, client_credential=self.client_secret, authority=authority_uri)
        self.tokendata = context.acquire_token_for_client(scopes=[resource_uri])
        if 'error' in self.tokendata:
            if self.tokendata['error'] == 'invalid_client':
                self.logger.error("There was an issue with your application auth: " + self.tokendata['error_description'])
                sys.exit(1)
            else:
                self.logger.error("There was an issue with your application auth: " + self.tokendata['error_description'])
        if 'expires_in' in self.tokendata:
            # Convert relative expiry (seconds from now) to absolute epoch timestamp
            expiration_time = time.time() + self.tokendata['expires_in']
            self.tokendata['expires_on'] = expiration_time
        return self.tokendata

    def parse_config(self, configfile):
        """Parse the .conf file to load tenant settings, cloud type (GCC/GCC High), and endpoint URLs."""
        config = configparser.ConfigParser()
        config.read(configfile)
        if not self.d4iot:
            self.tenant = config_get(config, 'config', 'tenant', self.logger)
            self.gcc = config_get(config, 'config', 'gcc', self.logger).lower() == "true"
            self.gcc_high = config_get(config, 'config', 'gcc_high', self.logger).lower() == "true"
            self.subscriptions = config_get(config, 'config', 'subscriptionid', self.logger)
            self.endpoints_dict = get_endpoints(gcc=self.gcc, gcc_high=self.gcc_high)
        else:
            self.d4iot_sensor_ip = config_get(config, 'config', 'd4iot_sensor_ip', self.logger)
            self.d4iot_mgmt_ip = config_get(config, 'config', 'd4iot_mgmt_ip', self.logger)

        return config

    def parse_auth(self, authstr=None):
        """Parse the .auth credentials file or prompt the user for credentials interactively.

        For standard auth: reads appid and clientsecret.
        For D4IoT: reads username, password, sensor token, and management console token.
        Missing values are prompted via getpass (hidden input).
        """
        self.authconfig = configparser.ConfigParser()
        auth_dict = {}
        if authstr:
            self.authconfig.read_string(authstr)
        self.username = ""
        if self.d4iot:
            if config_get(self.authconfig, 'auth', 'username', self.logger):
                self.username = config_get(self.authconfig, 'auth', 'username', self.logger)
            else:
                self.username = getpass.getpass("Please type your username: ")
        auth_dict["username"] = self.username
        self.password = ""
        if self.d4iot:
            if config_get(self.authconfig, 'auth', 'password', self.logger):
                self.password = config_get(self.authconfig, 'auth', 'password', self.logger)
            else:
                self.password = getpass.getpass("Please type your password: ")
        auth_dict["password"] = self.password
        if self.d4iot:
            if config_get(self.authconfig, 'auth', 'd4iot_sensor_token', self.logger):
                self.d4iot_sensor_token = config_get(self.authconfig, 'auth', 'd4iot_sensor_token', self.logger)
            else:
                self.d4iot_sensor_token = getpass.getpass("Please type your D4IOT sensor token: ")
            auth_dict["d4iot_sensor_token"] = self.d4iot_sensor_token
            if config_get(self.authconfig, 'auth', 'd4iot_mgmt_token', self.logger):
                self.d4iot_mgmt_token = config_get(self.authconfig, 'auth', 'd4iot_mgmt_token', self.logger)
            else:
                self.d4iot_mgmt_token = getpass.getpass("Please type your D4IOT management console token: ")
            auth_dict["d4iot_mgmt_token"] = self.d4iot_mgmt_token
        else:
            if config_get(self.authconfig, 'auth', 'appid', self.logger):
                self.app_client_id = config_get(self.authconfig, 'auth', 'appid', self.logger)
            else:
                self.app_client_id = getpass.getpass("Please type your application client id: ")
            auth_dict["appid"] = self.app_client_id
            if config_get(self.authconfig, 'auth', 'clientsecret', self.logger):
                self.client_secret = config_get(self.authconfig, 'auth', 'clientsecret', self.logger)
            else:
                self.client_secret = getpass.getpass("Please type your client secret: ")
            auth_dict["clientsecret"] = self.client_secret

            # Optional ESTS cookie for MDE portal timeline APIs
            self.ests_cookie = ""
            if config_get(self.authconfig, 'auth', 'ests_cookie', self.logger):
                self.ests_cookie = config_get(self.authconfig, 'auth', 'ests_cookie', self.logger)
            auth_dict["ests_cookie"] = self.ests_cookie

            # Optional OAuth refresh token for portal access (alternative to ESTS cookie)
            self.portal_refresh_token = ""
            if config_get(self.authconfig, 'auth', 'portal_refresh_token', self.logger):
                self.portal_refresh_token = config_get(self.authconfig, 'auth', 'portal_refresh_token', self.logger)
            auth_dict["portal_refresh_token"] = self.portal_refresh_token
        self.authconfig["auth"] = auth_dict

    def _read_current_tokens(self, filepath: str):
        tokens = {}
        tokens_str = read_auth(filepath, logger=self.logger, encryption_pw=self.encryption_pw)
        if tokens_str:
            tokens = json.loads(tokens_str)
        return tokens

    def _write_current_tokens(self, filepath: str, tokens: dict):
        writestr = json.dumps(tokens, indent=2, sort_keys=True)
        write_auth(filepath, writestr, logger=self.logger, encryption_pw=self.encryption_pw, insecure=self.insecure)

    def d4iot_auth(self):
        """Authenticate to a Defender for IoT sensor using cookie-based auth.

        The flow is:
        1. GET the sensor URL to obtain an initial CSRF token from cookies.
        2. POST username/password to /api/authentication/login with the CSRF token.
        3. Extract the session cookie (csrftoken + sessionid) from the response.
        4. Store cookies in the D4IoT auth file for use by DefenderIoTDumper.
        """
        custom_auth_dict = self._read_current_tokens(self.d4iot_authfile)

        if 'sensor' not in custom_auth_dict:
            custom_auth_dict['sensor'] = {}

        url = self.get_d4iot_sensor_uri()

        self.logger.info("Authenticating to Defender for IoT sensor at %s" % (url))
        if self.d4iot:
            headers = {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5'
                }
            response = requests.request("GET", url, headers=headers, verify=False)
            mid_csrf = response.cookies['csrftoken']

            url2 = url + "/api/authentication/login"

            headers2 = {
            'Accept': 'application/json, text/plain, */*',
            'Cookie': 'csrftoken=' + mid_csrf,
            'Origin': url,
            'Referrer': url + '/login',
            'X-CSRFToken': mid_csrf
            }

            payload ={
            "username": self.username,
            "password": self.password
            }

            response2 = requests.post(url2, headers=headers2, json=payload, verify=False)

            self.tokendata['csrftoken'] = response2.cookies['csrftoken']
            self.tokendata['sessionId'] = response2.cookies['sessionid']
            self.logger.info('Obtained d4iot cookies.')

            if self.tokendata:
                custom_auth_dict['sensor'] = copy.copy(self.tokendata)

            self.logger.info(green + "Authentication complete." + green)
            self._write_current_tokens(self.d4iot_authfile, custom_auth_dict)

    def portal_auth(self):
        """Bootstrap a portal session for M365 Defender timeline APIs.

        Supports two authentication methods:
        1. OAuth refresh token (preferred): Uses a refresh token to obtain a Bearer
           access token for the M365 Security Center. More reliable for long-running
           collections since tokens auto-refresh. Set portal_refresh_token in .auth.
        2. ESTS cookie (fallback): Uses an ESTSAUTHPERSISTENT cookie from the user's
           browser to obtain sccauth and xsrf-token session cookies.

        Stores portal_auth dict in .ugt_auth with auth credentials for portal API access.
        """
        if not self.ests_cookie and not self.portal_refresh_token:
            self.logger.info("No portal credentials provided. Skipping portal auth "
                             "(timeline collection will be unavailable). "
                             "Set ests_cookie or portal_refresh_token in .auth.")
            return

        portal_url = "https://security.microsoft.com"

        # Prefer refresh token auth over ESTS cookie (more reliable for long runs)
        if self.portal_refresh_token:
            self._portal_auth_refresh_token(portal_url)
        else:
            self._portal_auth_ests_cookie(portal_url)

    def _portal_auth_refresh_token(self, portal_url):
        """Authenticate to the M365 Security portal using an OAuth refresh token.

        Uses the Microsoft Teams first-party client ID to exchange a refresh token
        for an access token scoped to the M365 Security Center resource. The resulting
        Bearer token is sent directly in the Authorization header, bypassing the need
        for sccauth/xsrf cookies entirely.

        The refresh token is updated on each exchange (rolling refresh tokens).
        """
        self.logger.info("Authenticating to M365 Security portal via OAuth refresh token...")

        # Microsoft Teams client ID (first-party app with portal access)
        client_id = "1fec8e78-bce4-4aaf-ab1b-5451cc387264"
        # M365 Security Center resource ID
        scope = "80ccca67-54bd-44ab-8625-4b79c4dc7775/.default offline_access"
        token_url = f"https://login.microsoftonline.com/{self.tenant}/oauth2/v2.0/token"

        try:
            resp = requests.post(token_url, data={
                'client_id': client_id,
                'scope': scope,
                'grant_type': 'refresh_token',
                'refresh_token': self.portal_refresh_token,
            }, timeout=30)

            if resp.status_code != 200:
                self.logger.error(f"Portal refresh token auth failed (HTTP {resp.status_code}): {resp.text[:500]}")
                # Fall back to ESTS cookie if available
                if self.ests_cookie:
                    self.logger.info("Falling back to ESTS cookie auth...")
                    self._portal_auth_ests_cookie(portal_url)
                return

            token_data = resp.json()
            access_token = token_data.get('access_token')
            new_refresh_token = token_data.get('refresh_token')
            expires_in = token_data.get('expires_in', 3600)

            if not access_token:
                self.logger.error("Portal refresh token auth returned no access token.")
                return

            portal_auth_data = {
                'access_token': access_token,
                'token_type': 'Bearer',
                'expires_in': expires_in,
                'portal_url': portal_url,
                'tenant_id': self.tenant,
                'auth_method': 'refresh_token',
            }

            # Update stored refresh token if a new one was issued (rolling tokens)
            custom_auth_dict = self._read_current_tokens(self.authfile)
            if new_refresh_token and new_refresh_token != self.portal_refresh_token:
                self.portal_refresh_token = new_refresh_token
                if 'auth' not in custom_auth_dict:
                    custom_auth_dict['auth'] = {}
                custom_auth_dict['auth']['portal_refresh_token'] = new_refresh_token

            custom_auth_dict['portal_auth'] = portal_auth_data
            self._write_current_tokens(self.authfile, custom_auth_dict)

            self.logger.info(green + "Portal authentication complete (refresh token)." + green)

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Portal refresh token auth failed: {e}")

    def _portal_auth_ests_cookie(self, portal_url):
        """Authenticate to the M365 Security portal using an ESTS cookie.

        Uses an ESTSAUTHPERSISTENT cookie (from the user's browser at
        security.microsoft.com) to obtain sccauth and xsrf-token session cookies.
        """
        self.logger.info("Bootstrapping M365 Defender portal session via ESTS cookie...")

        try:
            # Hit the portal with the ESTS cookie to get sccauth + xsrf-token
            session = requests.Session()
            session.cookies.set('ESTSAUTHPERSISTENT', self.ests_cookie, domain='.microsoft.com')
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            })

            resp = session.get(portal_url, allow_redirects=True, timeout=60)
            resp.raise_for_status()

            # Extract sccauth cookie
            sccauth = session.cookies.get('sccauth', domain='security.microsoft.com')
            if not sccauth:
                # Try without domain filter
                for cookie in session.cookies:
                    if cookie.name == 'sccauth':
                        sccauth = cookie.value
                        break

            if not sccauth:
                self.logger.error("Failed to obtain sccauth cookie from portal. "
                                  "ESTS cookie may be expired or invalid.")
                return

            # Extract XSRF token from response body or cookies
            xsrf_token = ""
            # Check cookies first
            for cookie in session.cookies:
                if cookie.name.lower() in ('xsrf-token', 'xsrf_token'):
                    xsrf_token = cookie.value
                    break

            # Fall back to parsing from response body
            if not xsrf_token:
                match = re.search(r'"xsrfToken"\s*:\s*"([^"]+)"', resp.text)
                if match:
                    xsrf_token = match.group(1)

            if not xsrf_token:
                self.logger.warning("Could not extract XSRF token. Portal API calls may fail.")

            portal_auth_data = {
                'sccauth': sccauth,
                'xsrf_token': xsrf_token,
                'portal_url': portal_url,
                'ests_cookie': self.ests_cookie,
                'tenant_id': self.tenant,
                'auth_method': 'ests_cookie',
            }

            # Store in auth file
            custom_auth_dict = self._read_current_tokens(self.authfile)
            custom_auth_dict['portal_auth'] = portal_auth_data
            self._write_current_tokens(self.authfile, custom_auth_dict)

            self.logger.info(green + "Portal authentication complete (ESTS cookie)." + green)

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Portal auth failed: {e}")

    def ugt_auth(self):
        """Authenticate to all Microsoft cloud endpoints using client credentials.

        Iterates over each endpoint (Graph, O365, ARM, Security Center, Log Analytics, etc.)
        and acquires a token for each one. All tokens are stored in a single .ugt_auth JSON file
        under 'app_auth', keyed by endpoint name (e.g. 'graph_api', 'securitycenter_api').

        Also stores SDK credentials (tenant_id, app_id, client_secret) under 'sdk_auth'
        so TokenManager can refresh tokens mid-run without re-prompting.
        """
        custom_auth_dict = self._read_current_tokens(self.authfile)

        self._write_current_tokens(self.authfile, custom_auth_dict)

        if 'mfa' not in custom_auth_dict:
            custom_auth_dict['mfa'] = {}
        if 'app_auth' not in custom_auth_dict:
            custom_auth_dict['app_auth'] = {}
        if 'sdk_auth' not in custom_auth_dict:
            custom_auth_dict['sdk_auth'] = {}

        # Store credentials so TokenManager can re-authenticate during long runs
        custom_auth_dict['sdk_auth']['tenant_id'] = self.tenant
        custom_auth_dict['sdk_auth']['app_id'] = self.app_client_id
        custom_auth_dict['sdk_auth']['client_secret'] = self.client_secret
        custom_auth_dict['sdk_auth']['subscriptionid'] = self.subscriptions

        resource_uri = self.get_app_resource_uri()
        # Acquire a token for each Microsoft API endpoint
        for key, uri in resource_uri.items():
            try:
                if self.client_secret and self.app_client_id:
                    self.authenticate_as_app(uri)
            except Exception as e:
                self.logger.error(f"Error authenticating as app: {str(e)}")

            if self.tokendata:
                custom_auth_dict['app_auth'][key] = copy.copy(self.tokendata)
                custom_auth_dict['app_auth'][key]['tenantId'] = self.tenant
                if 'expiresOn' in custom_auth_dict['app_auth'][key]:
                    expiretime = time.mktime(time.strptime(custom_auth_dict['app_auth'][key]['expiresOn'].split('.')[0], '%Y-%m-%d %H:%M:%S'))
                    custom_auth_dict['app_auth'][key]['expireTime'] = expiretime
        self._write_current_tokens(self.authfile, custom_auth_dict)

        # Bootstrap portal session if ESTS cookie is available (for MDE timeline APIs)
        self.portal_auth()

    def parse_args(self, args):
        """Initialize from CLI args: set up logger, read/decrypt config and auth files, prompt if needed."""
        self.debug = args.debug
        self.logger = setup_logger(__name__, self.debug)
        self.authfile = args.authfile
        self.auth = args.auth
        self.insecure = args.insecure
        self.encryption_pw = args.encryption_pw
        if args.d4iot:
            self.d4iot = True
            self.config = args.d4iot_config
            self.d4iot_authfile = args.d4iot_authfile
            self.auth = args.d4iot_auth
        else:
            self.config = args.config

        if not self.insecure:
            if self.encryption_pw is None:
                self.encryption_pw = getpass.getpass("Please type the password for file encryption: ")
        auth_config_str = read_auth(self.auth, logger=self.logger, encryption_pw=self.encryption_pw)

        # Read in authconfig or prompt for user info
        self.parse_auth(auth_config_str)

        authio = io.StringIO()
        self.authconfig.write(authio)
        authio.seek(0)
        auth_config_str = authio.getvalue()

        write_auth(self.auth, auth_config_str, logger=self.logger, encryption_pw=self.encryption_pw, insecure=self.insecure)

        self.parse_config(self.config)

class TokenManager:
    """Manages token lifecycle for all datadumpers.

    Refreshes tokens proactively (before expiry) by mutating auth dicts in-place,
    so all holders of references to those dicts automatically see new tokens.
    """
    _REFRESH_MARGIN_SECONDS = 300  # Refresh 5 minutes before expiry

    def __init__(self, auth_dict, endpoints_dict, logger):
        """
        Args:
            auth_dict: The full auth dictionary (same object shared by all dumpers).
                       Contains 'app_auth' (tokens per endpoint) and 'sdk_auth' (credentials).
            endpoints_dict: Maps endpoint keys to base URLs for scope construction.
            logger: Logger instance for refresh status messages.
        """
        self._auth_dict = auth_dict
        self._endpoints_dict = endpoints_dict
        self._logger = logger
        self._msal_app = None  # Lazy-initialized MSAL app (created on first refresh)

        # Extract credentials stored by ugt_auth() for re-authentication
        sdk = auth_dict.get('sdk_auth', {})
        self._tenant_id = sdk.get('tenant_id')
        self._app_id = sdk.get('app_id')
        self._client_secret = sdk.get('client_secret')

    def _get_msal_app(self):
        """Lazy-initialize the MSAL ConfidentialClientApplication (reused across refreshes)."""
        if self._msal_app is None:
            authority = f"{self._endpoints_dict['authority_api']}/{self._tenant_id}"
            self._msal_app = msal.ConfidentialClientApplication(
                client_id=self._app_id,
                client_credential=self._client_secret,
                authority=authority,
            )
        return self._msal_app

    def ensure_valid_token(self, endpoint_key):
        """Check if the token for endpoint_key is near expiry and refresh if needed.

        Mutates auth_dict['app_auth'][endpoint_key] in place so all holders see the update.
        """
        if not endpoint_key:
            return
        app_auth = self._auth_dict.get('app_auth', {})
        token_data = app_auth.get(endpoint_key)
        if not token_data:
            return

        expires_on = token_data.get('expires_on', 0)
        if time.time() < expires_on - self._REFRESH_MARGIN_SECONDS:
            return  # Token still valid

        self._logger.info(f"Token for {endpoint_key} refreshing...")
        scope_url = self._endpoints_dict.get(endpoint_key)
        if not scope_url:
            self._logger.warning(f"No endpoint URL for {endpoint_key}, cannot refresh.")
            return

        scope = scope_url + "/.default"
        try:
            app = self._get_msal_app()
            result = app.acquire_token_for_client(scopes=[scope])
            if 'error' in result:
                self._logger.error(f"Token refresh failed for {endpoint_key}: {result.get('error_description', result['error'])}")
                return
            if 'expires_in' in result:
                result['expires_on'] = time.time() + result['expires_in']
            # IMPORTANT: Mutate in-place (dict.update) rather than reassigning.
            # All dumpers hold references to the same token dict, so in-place
            # mutation ensures every holder sees the refreshed token immediately.
            token_data.update(result)
            self._logger.info(f"Token for {endpoint_key} refreshed successfully.")
        except Exception as e:
            self._logger.error(f"Exception refreshing token for {endpoint_key}: {e}")

def auth(authfile=".ugt_auth",
         d4iot_authfile=".d4iot_auth",
         config=".conf",
         auth=".auth",
         d4iot_auth=".auth_d4iot",
         d4iot_config=".d4iot_conf",
         debug=False,
         d4iot=False,
         insecure=False,
         encryption_pw=None):
    """
    Untitled Goose Tool Authentication

    Args:
        authfile: File to store the authentication tokens and cookies
        d4iot_authfile: File to store the authentication cookies for D4IoT
        config: Path to config file
        auth: File to store the credentials used for authentication
        d4iot_auth: File to store the D4IoT credentials used for authentication
        debug: Enable debug logging
        d4iot: Run the authentication portion for d4iot
        insecure: Disable secure authentication handling (file encryption)
        encryption_pw: password used for auth file encryption. SHOULD ONLY BE USED WITH AUTOHONK
    """
    args = dict2obj(locals())
    auth = Authentication(debug=debug)
    auth.parse_args(args)
    if args.d4iot:
        auth.d4iot_auth()
    else:
        auth.ugt_auth()

if __name__ == '__main__':
    main()

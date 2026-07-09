#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Untitled Goose Tool: ediscovery_datadumper!
This module collects Microsoft Purview eDiscovery telemetry via the Microsoft Graph API.

eDiscovery is Microsoft's litigation/investigation surface for collecting content from the
Microsoft 365 live services (Exchange, SharePoint, OneDrive, Teams, and Copilot interactions).
The Graph eDiscovery API lives under the microsoft.graph.security namespace at
    /security/cases/ediscoveryCases
and is GA in the Graph v1.0 endpoint.

The module supports two modes of collection:

- Snapshot (read-only): enumerate the eDiscovery objects that already exist in the tenant
  (cases, settings, custodians, noncustodial data sources, searches, legal holds, review sets,
  tags, and case operations). This is a non-invasive forensic inventory. See Phase 1 methods.

- Export (read/write): create/reuse an UntitledGooseTool-* case, run searches with per-content-type
  filters (email, Teams messages, Copilot interactions, SharePoint/OneDrive), add the results to a
  review set, and export/download the package. This WRITES objects into the tenant, so it is gated
  behind explicit toggles and honors --dry-run. See Phase 2 methods.

Licensing / auth notes:
- Standard operations (cases, searches, holds) work on E3 with delegated (user) auth.
- Review sets, tagging, analytics, and app-only auth require E5 (or an eDiscovery add-on).
- Export on E3 requires pay-as-you-go billing.
- Graph permission scopes: eDiscovery.Read.All (snapshot) / eDiscovery.ReadWrite.All (export).
"""

import os

from goosey.datadumper import DataDumper
from goosey.utils import *

class EdiscoveryDataDumper(DataDumper):
    """Collects Microsoft Purview eDiscovery data via the Microsoft Graph API.

    Uses the graph_api token (same as the Entra ID and M365-Graph dumpers). eDiscovery
    endpoints are GA under the Graph v1.0 endpoint, so this dumper targets v1.0 rather
    than beta (Phase 2 export/estimate operations that are beta-only override the base
    per call).
    """

    def __init__(self, output_dir, reports_dir, app_auth, session, config, debug, token_manager=None, force_repull=False):
        super().__init__(f'{output_dir}{os.path.sep}ediscovery', reports_dir, app_auth, session, debug, token_manager=token_manager, endpoint_key="graph_api", force_repull=force_repull)
        self.logger = setup_logger(__name__, debug)
        self.gcc = config_get(config, 'config', 'gcc', self.logger).lower() == "true"
        self.gcc_high = config_get(config, 'config', 'gcc_high', self.logger).lower() == "true"
        endpoints = get_endpoints(gcc=self.gcc, gcc_high=self.gcc_high)
        self.graph_url = endpoints["graph_api"]
        self.failurefile = os.path.join(reports_dir, '_no_results.json')

        self.call_object = [self.get_url(), self.app_auth, self.logger, self.output_dir, self.get_session()]

    def get_url(self):
        # The eDiscovery API is generally available under the Graph v1.0 endpoint.
        return self.graph_url + "/v1.0/"

    @requires_auth
    async def dump_ediscovery_cases(self):
        """List all eDiscovery cases in the tenant.

        This is the foundation for the per-case snapshot pulls (custodians, searches,
        holds, review sets, etc.), each of which enumerates cases before fetching the
        case-scoped children.

        API Reference:
        https://learn.microsoft.com/en-us/graph/api/security-casesroot-list-ediscoverycases?view=graph-rest-1.0
        """
        await helper_single_object("security/cases/ediscoveryCases", self.call_object, self.failurefile, caller="ediscovery")

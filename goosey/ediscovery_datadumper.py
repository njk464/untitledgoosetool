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
  review set queries, tags, and case operations). This is a non-invasive forensic inventory.
  See the Phase 1 dump_* methods.

- Export (read/write): create/reuse an UntitledGooseTool-* case, run searches with per-content-type
  filters (email, Teams messages, Copilot interactions, SharePoint/OneDrive), add the results to a
  review set, and export/download the package. This WRITES objects into the tenant, so it is gated
  behind explicit toggles and honors --dry-run. See the Phase 2 dump_* methods.

Licensing / auth notes:
- Standard operations (cases, searches, holds) work on E3 with delegated (user) auth.
- Review sets, tagging, analytics, and app-only auth require E5 (or an eDiscovery add-on).
- Export on E3 requires pay-as-you-go billing.
- Because Goosey authenticates to Graph app-only (client credentials), eDiscovery collection
  through Goosey effectively requires E5 / an eDiscovery add-on subscription.
- Graph permission scopes: eDiscovery.Read.All (snapshot) / eDiscovery.ReadWrite.All (export).

Snapshot output: every dump_* method writes an ediscovery_<object>.json JSONL file to
output/ediscovery/. Case-scoped records are enriched with caseId / caseDisplayName so the
flattened files remain traceable back to their parent case.
"""

import json
import os

from datetime import datetime
from goosey.datadumper import DataDumper
from goosey.utils import *

# Base path for the eDiscovery API under the Graph v1.0 endpoint.
EDISCOVERY_CASES_PATH = "security/cases/ediscoveryCases"

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
        self.date_range, self.date_start, self.date_end = get_date_range(config, self.logger)

        self.call_object = [self.get_url(), self.app_auth, self.logger, self.output_dir, self.get_session()]

    def get_url(self):
        # The eDiscovery API is generally available under the Graph v1.0 endpoint.
        return self.graph_url + "/v1.0/"

    def _auth_header(self):
        return {'Authorization': '%s %s' % (self.app_auth['token_type'], self.app_auth['access_token'])}

    async def _get_json(self, url, params=None, timeout=600):
        """GET a Graph URL and return the parsed JSON (or None on transport error)."""
        try:
            async with self.ahsession.get(url, headers=self._auth_header(), params=params, timeout=timeout) as r:
                return await r.json()
        except Exception as e:
            self.logger.error('eDiscovery request failed for %s: %s' % (url, str(e)))
            return None

    async def _get_collection(self, url, params=None):
        """Fetch a Graph collection, following @odata.nextLink, and return all 'value' entries.

        `params` (e.g. an OData $filter) is applied to the first request only; subsequent
        pages use the @odata.nextLink URL which already carries the encoded query.
        """
        entries = []
        while url:
            result = await self._get_json(url, params=params)
            params = None
            if result is None:
                break
            if 'value' not in result:
                if 'error' in result:
                    self.logger.debug('eDiscovery error on %s: %s' % (url, result['error'].get('message', result['error'])))
                break
            entries.extend(result['value'])
            nexturl = result.get('@odata.nextLink')
            # Guard against a nextLink that points back at the current page.
            url = nexturl if nexturl and nexturl != url else None
        return entries

    async def _list_cases(self):
        """Return all eDiscovery cases in the tenant (paginated)."""
        return await self._get_collection(self.get_url() + EDISCOVERY_CASES_PATH)

    def _write_records(self, name, records):
        """Write JSONL output for a snapshot object, or note an empty result in the failure file."""
        outfile = os.path.join(self.output_dir, name + '.json')
        if records:
            with open(outfile, 'w', encoding='utf-8') as f:
                for entry in records:
                    f.write(json.dumps(entry, sort_keys=True) + '\n')
            self.logger.info('Finished dumping %s (%d records).' % (name, len(records)))
        else:
            with open(self.failurefile, 'a+', encoding='utf-8') as f:
                f.write('No output file: ' + name + ' - ' + str(datetime.now()) + '\n')
            self.logger.debug('%s has no information. No output file.' % (name))

    async def _dump_case_children(self, child, name, single=False):
        """Enumerate cases, then fetch a case-scoped child object for each case.

        Args:
            child: The case child path segment (e.g. 'custodians', 'searches', 'settings').
            name: Output basename (ediscovery_<name>.json).
            single: True for endpoints that return a single object rather than a collection
                    (e.g. the case 'settings' resource).
        """
        cases = await self._list_cases()
        if not cases:
            self.logger.info('No eDiscovery cases found; skipping %s.' % name)
            self._write_records(name, [])
            return

        self.logger.info('Dumping eDiscovery %s across %d case(s)...' % (child, len(cases)))
        records = []
        for case in cases:
            case_id = case.get('id')
            case_ref = {'caseId': case_id, 'caseDisplayName': case.get('displayName')}
            url = '%s%s/%s/%s' % (self.get_url(), EDISCOVERY_CASES_PATH, case_id, child)
            if single:
                result = await self._get_json(url)
                if result is None or 'error' in result:
                    if result is not None and 'error' in result:
                        self.logger.debug('eDiscovery %s error for case %s: %s' % (child, case_id, result['error'].get('message', result['error'])))
                    continue
                result.pop('@odata.context', None)
                result.pop('@odata.type', None)
                result.update(case_ref)
                records.append(result)
            else:
                for entry in await self._get_collection(url):
                    entry.pop('@odata.type', None)
                    entry.update(case_ref)
                    records.append(entry)
        self._write_records(name, records)

    @requires_auth
    async def dump_ediscovery_cases(self):
        """List all eDiscovery cases in the tenant.

        This is the foundation for the per-case snapshot pulls (custodians, searches,
        holds, review sets, etc.), each of which enumerates cases before fetching the
        case-scoped children.

        API Reference:
        https://learn.microsoft.com/en-us/graph/api/security-casesroot-list-ediscoverycases?view=graph-rest-1.0
        """
        self.logger.info('Dumping eDiscovery cases...')
        self._write_records('ediscovery_cases', await self._list_cases())

    @requires_auth
    async def dump_ediscovery_case_settings(self):
        """Dump the settings object for each eDiscovery case (redaction, topic modeling, OCR, etc.)."""
        await self._dump_case_children('settings', 'ediscovery_case_settings', single=True)

    @requires_auth
    async def dump_ediscovery_custodians(self):
        """Dump custodians (people whose data is under administrative control) per case."""
        await self._dump_case_children('custodians', 'ediscovery_custodians')

    @requires_auth
    async def dump_ediscovery_noncustodial_sources(self):
        """Dump noncustodial data sources (data added to a case without a custodian) per case."""
        await self._dump_case_children('noncustodialDataSources', 'ediscovery_noncustodial_sources')

    @requires_auth
    async def dump_ediscovery_searches(self):
        """Dump collection searches (query, data source scopes, statistics) per case."""
        await self._dump_case_children('searches', 'ediscovery_searches')

    @requires_auth
    async def dump_ediscovery_holds(self):
        """Dump legal holds (content preserved for litigation) per case."""
        await self._dump_case_children('legalHolds', 'ediscovery_holds')

    @requires_auth
    async def dump_ediscovery_review_sets(self):
        """Dump review sets (static sets of collected content) per case."""
        await self._dump_case_children('reviewSets', 'ediscovery_review_sets')

    @requires_auth
    async def dump_ediscovery_tags(self):
        """Dump review tags used to cull/classify content per case."""
        await self._dump_case_children('tags', 'ediscovery_tags')

    @requires_auth
    async def dump_ediscovery_operations(self):
        """Dump case operations (add-to-review-set, tag, export, estimate, etc.) per case."""
        await self._dump_case_children('operations', 'ediscovery_operations')

    @requires_auth
    async def dump_copilot_interactions(self):
        """Dump Microsoft 365 Copilot interactions (user prompts + AI responses) per user.

        Uses the dedicated Graph aiInteractionHistory:getAllEnterpriseInteractions API
        (read-only, application permission AiEnterpriseInteraction.Read.All) rather than
        the eDiscovery export pipeline. This is a non-invasive way to pull Copilot content:
        each record is a userPrompt or aiResponse with the prompt/response body, app class
        (Teams, BizChat, etc.), timestamps, and referenced resources.

        The endpoint is per-user, so this enumerates users first, then fetches each user's
        interaction history (optionally bounded by the configured date range via a
        createdDateTime $filter). Records are enriched with userId / userPrincipalName.

        Requires a Copilot license and is available in the Global cloud only (not GCC/GCC High).

        API Reference:
        https://learn.microsoft.com/en-us/microsoft-365-copilot/extensibility/api/ai-services/interaction-export/aiinteractionhistory-getallenterpriseinteractions
        """
        if self.gcc or self.gcc_high:
            self.logger.warning('Copilot interaction export (aiInteractionHistory) is Global-cloud only; skipping for GCC/GCC High.')
            self._write_records('copilot_interactions', [])
            return

        users = await self._get_collection(self.get_url() + 'users?$select=id,userPrincipalName')
        if not users:
            self.logger.info('No users found; skipping copilot_interactions.')
            self._write_records('copilot_interactions', [])
            return

        params = None
        if self.date_range:
            params = {'$filter': 'createdDateTime gt %sT00:00:00Z and createdDateTime lt %sT00:00:00Z' % (self.date_start, self.date_end)}

        self.logger.info('Dumping Copilot interactions across %d user(s)...' % len(users))
        records = []
        for user in users:
            uid = user.get('id')
            upn = user.get('userPrincipalName')
            url = '%scopilot/users/%s/interactionHistory/getAllEnterpriseInteractions' % (self.get_url(), uid)
            for entry in await self._get_collection(url, params=params):
                entry.pop('@odata.type', None)
                entry['userId'] = uid
                entry['userPrincipalName'] = upn
                records.append(entry)
        self._write_records('copilot_interactions', records)

    @requires_auth
    async def dump_ediscovery_review_set_queries(self):
        """Dump review set queries per review set (grandchildren of cases).

        Path: /security/cases/ediscoveryCases/{caseId}/reviewSets/{reviewSetId}/queries
        Each query is enriched with caseId / caseDisplayName / reviewSetId for traceability.
        """
        cases = await self._list_cases()
        if not cases:
            self.logger.info('No eDiscovery cases found; skipping ediscovery_review_set_queries.')
            self._write_records('ediscovery_review_set_queries', [])
            return

        self.logger.info('Dumping eDiscovery review set queries across %d case(s)...' % len(cases))
        records = []
        for case in cases:
            case_id = case.get('id')
            case_ref = {'caseId': case_id, 'caseDisplayName': case.get('displayName')}
            review_sets_url = '%s%s/%s/reviewSets' % (self.get_url(), EDISCOVERY_CASES_PATH, case_id)
            for review_set in await self._get_collection(review_sets_url):
                rs_id = review_set.get('id')
                queries_url = '%s/%s/queries' % (review_sets_url, rs_id)
                for entry in await self._get_collection(queries_url):
                    entry.pop('@odata.type', None)
                    entry.update(case_ref)
                    entry['reviewSetId'] = rs_id
                    records.append(entry)
        self._write_records('ediscovery_review_set_queries', records)

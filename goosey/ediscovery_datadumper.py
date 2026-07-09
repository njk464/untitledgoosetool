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

import asyncio
import json
import os

from datetime import datetime
from goosey.datadumper import DataDumper
from goosey.utils import *

# Base path for the eDiscovery API under the Graph v1.0 endpoint.
EDISCOVERY_CASES_PATH = "security/cases/ediscoveryCases"

# Phase 2 export: default KQL content query and data-source scope per content type.
# Scopes are the tenant-wide defaults; when targets are supplied they are replaced with
# allCaseCustodians (mailbox targets). See dump_ediscovery_export.
EXPORT_CONTENT_TYPES = {
    # content type -> (default contentQuery KQL, tenant-wide dataSourceScope)
    "email":      ("kind:email", "allTenantMailboxes"),
    "teams":      ("kind:im", "allTenantMailboxes"),
    # Copilot interactions are message-class items in mailboxes; the precise item-class
    # filter is best-effort (see untitledgoosetool-oz3.4.1). dump_copilot_interactions
    # (aiInteractionHistory) is the reliable Copilot path.
    "copilot":    ("kind:im", "allTenantMailboxes"),
    "sharepoint": ("", "allTenantSites"),
}

# Poll cadence for long-running case operations (estimate/export).
EXPORT_POLL_INTERVAL_SECONDS = 30
EXPORT_POLL_MAX_ATTEMPTS = 240  # ~2 hours at 30s


def _operation_id_from(payload, location):
    """Extract a case-operation id from a 202/200 response payload or its Location header.

    estimateStatistics/exportResult return the operation id either as `id` in the JSON body
    or embedded in the Location header (.../operations/{operationId}).
    """
    if isinstance(payload, dict) and payload.get('id'):
        return payload['id']
    if location and '/operations/' in location:
        tail = location.split('/operations/', 1)[1]
        return tail.split('?', 1)[0].strip('/')
    return None

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

        # Phase 2 export options (live in [variables], like ual_*/mde_*). Read quietly:
        # these are usually absent and config_get would warn on every run.
        def _var(key, default=""):
            if config.has_option('variables', key):
                val = config.get('variables', key)
                return val if val is not None else default
            return default

        # ediscovery_export_confirm is a HARD safety gate: the export orchestrator creates
        # objects in the tenant and is a no-op unless this is explicitly set to true.
        self.export_confirm = _var('ediscovery_export_confirm').lower() == "true"
        self.export_content_types = [c.strip().lower() for c in _var('ediscovery_export_content_types', 'email,teams,copilot,sharepoint').split(',') if c.strip()]
        self.export_targets = [t.strip() for t in _var('ediscovery_export_targets').split(',') if t.strip()]
        self.export_case_name = _var('ediscovery_case_name', 'UntitledGooseTool')
        self.export_format = _var('ediscovery_export_format', 'pst').lower()
        self.export_download = _var('ediscovery_export_download', 'true').lower() == "true"
        self.export_content_query = _var('ediscovery_content_query')

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

    # ------------------------------------------------------------------
    # Phase 2: content export orchestration (WRITES objects to the tenant)
    # ------------------------------------------------------------------

    async def _post_json(self, url, body):
        """POST JSON to a Graph URL. Returns (status, parsed_json_or_None, location_header)."""
        headers = self._auth_header()
        headers['Content-Type'] = 'application/json'
        try:
            async with self.ahsession.post(url, headers=headers, data=json.dumps(body), timeout=600) as r:
                location = r.headers.get('Location')
                try:
                    payload = await r.json()
                except Exception:
                    payload = None
                return r.status, payload, location
        except Exception as e:
            self.logger.error('eDiscovery POST failed for %s: %s' % (url, str(e)))
            return None, None, None

    def _export_statefile(self):
        return os.path.join(self.output_dir, '.ediscovery_export.savestate')

    def _load_export_state(self):
        path = self._export_statefile()
        if os.path.isfile(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _save_export_state(self, state):
        with open(self._export_statefile(), 'w', encoding='utf-8') as f:
            json.dump(state, f, indent=2)

    async def _poll_operation(self, case_id, operation_id, label):
        """Poll a case operation until it reaches a terminal state. Returns the final operation dict."""
        url = '%s%s/%s/operations/%s' % (self.get_url(), EDISCOVERY_CASES_PATH, case_id, operation_id)
        for attempt in range(EXPORT_POLL_MAX_ATTEMPTS):
            self.ensure_token()
            op = await self._get_json(url)
            status = (op or {}).get('status', 'unknown')
            self.logger.info('eDiscovery %s operation %s: %s (%d/%d)' % (label, operation_id, status, attempt + 1, EXPORT_POLL_MAX_ATTEMPTS))
            if status in ('succeeded', 'failed', 'partiallySucceeded'):
                return op
            await asyncio.sleep(EXPORT_POLL_INTERVAL_SECONDS)
        self.logger.warning('eDiscovery %s operation %s did not complete within the polling window.' % (label, operation_id))
        return await self._get_json(url)

    async def _create_or_reuse_case(self, state):
        """Create a new UntitledGooseTool export case, or reuse one recorded in save state."""
        if state.get('caseId') and not self.force_repull:
            self.logger.info('Reusing eDiscovery export case %s from save state.' % state['caseId'])
            return state['caseId']
        display_name = '%s-%s' % (self.export_case_name, datetime.now().strftime('%Y%m%dT%H%M%SZ'))
        status, payload, _ = await self._post_json(
            self.get_url() + EDISCOVERY_CASES_PATH,
            {'displayName': display_name, 'description': 'Automated export created by Untitled Goose Tool.'})
        if payload and payload.get('id'):
            self.logger.info('Created eDiscovery export case %s (%s).' % (display_name, payload['id']))
            state['caseId'] = payload['id']
            state['caseDisplayName'] = display_name
            self._save_export_state(state)
            return payload['id']
        self.logger.error('Failed to create eDiscovery export case (status=%s): %s' % (status, payload))
        return None

    async def _add_custodians(self, case_id, state):
        """Add custodians for each configured target UPN. Returns True if custodians exist."""
        if state.get('custodiansAdded'):
            return True
        ok = False
        for upn in self.export_targets:
            status, payload, _ = await self._post_json(
                '%s%s/%s/custodians' % (self.get_url(), EDISCOVERY_CASES_PATH, case_id),
                {'email': upn, 'applyHoldToSources': False})
            if payload and payload.get('id'):
                self.logger.info('Added custodian %s to export case.' % upn)
                ok = True
            else:
                self.logger.error('Failed to add custodian %s (status=%s): %s' % (upn, status, payload))
        state['custodiansAdded'] = ok
        self._save_export_state(state)
        return ok

    def _content_query_and_scope(self, content_type):
        """Resolve the KQL content query and dataSourceScope for a content type, honoring targets/overrides."""
        default_query, tenant_scope = EXPORT_CONTENT_TYPES[content_type]
        query = self.export_content_query or default_query
        # Targeted mailbox scoping via custodians; SharePoint site targeting is a follow-up (oz3.4.2).
        if self.export_targets and content_type != 'sharepoint':
            scope = 'allCaseCustodians'
        else:
            scope = tenant_scope
        return query, scope

    async def _download_export(self, operation, content_type):
        """Download an export package's files (exportFileMetadata[].downloadUrl) to disk."""
        files = (operation or {}).get('exportFileMetadata') or []
        if not files:
            self.logger.info('No exportFileMetadata download URLs for %s export.' % content_type)
            return []
        dest_dir = os.path.join(self.output_dir, 'export', content_type)
        os.makedirs(dest_dir, exist_ok=True)
        downloaded = []
        for meta in files:
            file_name = meta.get('fileName') or 'export.bin'
            download_url = meta.get('downloadUrl')
            if not download_url:
                continue
            out_path = os.path.join(dest_dir, file_name)
            try:
                # Download URLs are pre-authenticated (SAS); no auth header needed.
                async with self.ahsession.get(download_url, timeout=3600) as r:
                    with open(out_path, 'wb') as f:
                        async for chunk in r.content.iter_chunked(1 << 20):
                            f.write(chunk)
                self.logger.info('Downloaded %s export file to %s' % (content_type, out_path))
                downloaded.append(out_path)
            except Exception as e:
                self.logger.error('Failed to download %s export file %s: %s' % (content_type, file_name, str(e)))
        return downloaded

    async def _export_one_content_type(self, case_id, content_type, state):
        """Create a search, estimate it, export it, poll, and (optionally) download for one content type."""
        searches = state.setdefault('searches', {})
        entry = searches.setdefault(content_type, {})

        query, scope = self._content_query_and_scope(content_type)

        # 1. Create the search (skip if already recorded in save state).
        if not entry.get('searchId'):
            body = {
                'displayName': 'UGT-%s-%s' % (content_type, datetime.now().strftime('%Y%m%dT%H%M%SZ')),
                'description': 'Untitled Goose Tool %s export.' % content_type,
                'dataSourceScopes': scope,
            }
            if query:
                body['contentQuery'] = query
            status, payload, _ = await self._post_json(
                '%s%s/%s/searches' % (self.get_url(), EDISCOVERY_CASES_PATH, case_id), body)
            if not (payload and payload.get('id')):
                self.logger.error('Failed to create %s search (status=%s): %s' % (content_type, status, payload))
                return entry
            entry['searchId'] = payload['id']
            self._save_export_state(state)
            self.logger.info('Created %s search %s (scope=%s, query=%r).' % (content_type, entry['searchId'], scope, query))

        search_base = '%s%s/%s/searches/%s' % (self.get_url(), EDISCOVERY_CASES_PATH, case_id, entry['searchId'])

        # 2. Estimate statistics (exportResult exports from an estimated search).
        if not entry.get('estimated'):
            status, payload, location = await self._post_json(search_base + '/estimateStatistics', {})
            op_id = _operation_id_from(payload, location)
            if op_id:
                op = await self._poll_operation(case_id, op_id, '%s estimate' % content_type)
                entry['estimated'] = (op or {}).get('status') in ('succeeded', 'partiallySucceeded')
            else:
                self.logger.error('Failed to start %s estimate (status=%s): %s' % (content_type, status, payload))
            self._save_export_state(state)

        # 3. Export the search results.
        if not entry.get('exportOperationId'):
            body = {
                'displayName': 'UGT-%s-export' % content_type,
                'exportCriteria': 'searchHits',
                'additionalOptions': 'none',
                'exportFormat': self.export_format,
            }
            status, payload, location = await self._post_json(search_base + '/exportResult', body)
            op_id = _operation_id_from(payload, location)
            if not op_id:
                self.logger.error('Failed to start %s export (status=%s): %s' % (content_type, status, payload))
                return entry
            entry['exportOperationId'] = op_id
            self._save_export_state(state)

        # 4. Poll the export operation and optionally download the package.
        op = await self._poll_operation(case_id, entry['exportOperationId'], '%s export' % content_type)
        entry['exportStatus'] = (op or {}).get('status')
        if self.export_download and entry['exportStatus'] in ('succeeded', 'partiallySucceeded'):
            entry['downloadedFiles'] = await self._download_export(op, content_type)
        self._save_export_state(state)
        return entry

    async def dump_ediscovery_export(self):
        """Orchestrate an eDiscovery content export (WRITES objects to the tenant).

        Pipeline: create (or reuse) an UntitledGooseTool-<timestamp> case -> optionally add
        custodians for targeted UPNs -> for each configured content type create a search,
        estimate it, export the results, poll to completion, and download the package(s) to
        output/ediscovery/export/<content_type>/. Progress is checkpointed to a save-state
        file so an interrupted run resumes.

        HARD SAFETY GATE: because this creates cases/searches/exports in the tenant, it is a
        no-op unless [variables] ediscovery_export_confirm=true. Under --dry-run this method
        is never invoked (honk substitutes the dry-run dumper).

        Options (in [variables]): ediscovery_export_confirm, ediscovery_export_content_types,
        ediscovery_export_targets, ediscovery_case_name, ediscovery_export_format,
        ediscovery_export_download, ediscovery_content_query.

        API Reference:
        https://learn.microsoft.com/en-us/graph/api/security-ediscoverysearch-exportresult?view=graph-rest-1.0
        """
        if 'token_type' not in self.app_auth or 'access_token' not in self.app_auth:
            self.logger.error('Missing token from auth. Skipping dump_ediscovery_export.')
            return
        self.ensure_token()

        if not self.export_confirm:
            self.logger.warning('eDiscovery export is a tenant-WRITING operation and is disabled. '
                                'Set [variables] ediscovery_export_confirm=true to enable it. Skipping.')
            return

        unknown = [c for c in self.export_content_types if c not in EXPORT_CONTENT_TYPES]
        if unknown:
            self.logger.warning('Ignoring unknown eDiscovery export content types: %s' % ', '.join(unknown))
        content_types = [c for c in self.export_content_types if c in EXPORT_CONTENT_TYPES]
        if not content_types:
            self.logger.error('No valid eDiscovery export content types configured. Skipping.')
            return

        state = self._load_export_state()
        case_id = await self._create_or_reuse_case(state)
        if not case_id:
            return

        if self.export_targets:
            self.logger.info('eDiscovery export targeting custodians: %s' % ', '.join(self.export_targets))
            await self._add_custodians(case_id, state)
        else:
            self.logger.info('eDiscovery export scope: tenant-wide (no targets configured).')

        for content_type in content_types:
            self.logger.info('Starting eDiscovery export for content type: %s' % content_type)
            await self._export_one_content_type(case_id, content_type, state)

        # Write a manifest summarizing the export for the collection output.
        self._write_records('ediscovery_export_manifest', [state])
        self.logger.info('Finished eDiscovery export orchestration for case %s.' % case_id)

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

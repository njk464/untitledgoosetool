#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Untitled Goose Tool: Web UI

Browser-based interface for configuring and running Goosey data collection.

Usage:
    goosey web                    # Start on http://127.0.0.1:8000
    goosey web --port 9000        # Custom port
    goosey web --host 0.0.0.0     # Listen on all interfaces
"""

import configparser
import datetime
import glob as glob_module
import json
import os
import queue
import re
import select
import subprocess
import sys
import threading
import uuid

try:
    from flask import Flask, render_template, request, jsonify, Response
except ImportError:
    def web(**kwargs):
        print("Flask is required for the web UI. Install with: pip install flask")
        sys.exit(1)
    raise SystemExit

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), 'templates'),
)

# Module-level storage for in-progress device code flows.
# Keyed by flow_id (uuid4 hex); values are dicts with 'flow' and 'msal_app'.
_device_flows = {}  # flow_id -> {flow, msal_app}


# ---------------------------------------------------------------------------
# Command runner: executes goosey CLI commands as subprocesses and streams output
# ---------------------------------------------------------------------------

class CommandRunner:
    def __init__(self):
        self.tasks = {}

    def start(self, cmd_args, cwd=None):
        task_id = uuid.uuid4().hex[:8]
        q = queue.Queue()
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"

        # Use os.setsid to detach from controlling terminal so getpass
        # falls back to reading from stdin instead of /dev/tty.
        # Binary mode (no text=True, no bufsize=1) is required so that
        # select.select() on the raw fd works correctly and partial lines
        # (prompts without trailing newlines) are not buffered indefinitely.
        proc = subprocess.Popen(
            cmd_args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=cwd,
            env=env,
            preexec_fn=os.setsid,
        )

        def reader():
            """
            @decision DEC-WEB-001
            @title select-based chunk reader for interactive subprocess prompts
            @status accepted
            @rationale Python's input() and getpass.getpass() write prompts without
              trailing newlines. Iterating over proc.stdout line-by-line blocks until
              a newline arrives, so the prompt never reaches the UI and the subprocess
              hangs. Using select.select() with a 0.2-second timeout lets us detect
              partial lines sitting in the buffer and forward them as prompts
              immediately, while still batching complete newline-terminated lines
              efficiently.
            """
            try:
                fd = proc.stdout.fileno()
                buf = b""
                while True:
                    ready, _, _ = select.select([fd], [], [], 0.2)
                    if ready:
                        chunk = os.read(fd, 4096)
                        if not chunk:
                            # EOF — emit remaining buffer (incomplete final line)
                            if buf:
                                q.put(buf.decode('utf-8', errors='replace').rstrip('\r'))
                            break
                        buf += chunk
                        # Flush complete newline-terminated lines immediately
                        while b'\n' in buf:
                            line, buf = buf.split(b'\n', 1)
                            q.put(line.decode('utf-8', errors='replace').rstrip('\r'))
                    else:
                        # Timeout with no new data: partial content is likely a prompt
                        if buf:
                            q.put(buf.decode('utf-8', errors='replace').rstrip('\r'))
                            buf = b""
                proc.wait()
            except Exception as e:  # @defprog-exempt: error forwarded to UI via queue
                q.put(f"[ERROR] {e}")
            q.put(None)  # sentinel

        t = threading.Thread(target=reader, daemon=True)
        t.start()

        self.tasks[task_id] = {
            "process": proc,
            "queue": q,
            "thread": t,
            "status": "running",
            "cmd": " ".join(cmd_args),
        }
        return task_id

    def send_input(self, task_id, text):
        """Write text to a running task's stdin."""
        task = self.tasks.get(task_id)
        if not task or task["process"].poll() is not None:
            return False
        try:
            task["process"].stdin.write((text + "\n").encode())
            task["process"].stdin.flush()
            return True
        except (OSError, BrokenPipeError):
            return False

    def stream(self, task_id):
        task = self.tasks.get(task_id)
        if not task:
            yield "data: [ERROR] Task not found\n\n"
            return
        while True:
            try:
                line = task["queue"].get(timeout=30)
                if line is None:
                    rc = task["process"].returncode
                    task["status"] = "completed" if rc == 0 else "failed"
                    yield f"data: [DONE] exit code {rc}\n\n"
                    return
                yield f"data: {line}\n\n"
            except queue.Empty:
                yield ": keepalive\n\n"

    def stop(self, task_id):
        task = self.tasks.get(task_id)
        if task and task["process"].poll() is None:
            task["process"].terminate()
            task["status"] = "stopped"
            return True
        return False


runner = CommandRunner()


# ---------------------------------------------------------------------------
# Config file helpers
# ---------------------------------------------------------------------------

def get_working_dir():
    return app.config.get("WORKING_DIR", os.getcwd())


def read_conf(conf_path=".conf"):
    path = os.path.join(get_working_dir(), conf_path)
    config = configparser.ConfigParser()
    if os.path.isfile(path):
        config.read(path)
    return {s: dict(config[s]) for s in config.sections()}


def write_conf(data, conf_path=".conf"):
    path = os.path.join(get_working_dir(), conf_path)
    config = configparser.ConfigParser()
    for section, values in data.items():
        config[section] = values
    with open(path, "w") as f:
        config.write(f)


def read_auth(auth_path=".auth"):
    path = os.path.join(get_working_dir(), auth_path)
    if not os.path.isfile(path):
        return {}
    config = configparser.ConfigParser()
    config.read(path)
    return {s: dict(config[s]) for s in config.sections()}


# ---------------------------------------------------------------------------
# Dump method discovery — introspect dumper classes for available methods
# ---------------------------------------------------------------------------

def get_dump_methods():
    """Return available dump methods per platform by introspecting dumper classes."""
    methods = {}
    try:
        from goosey.m365_datadumper import M365DataDumper
        from goosey.entra_id_datadumper import EntraIdDataDumper
        from goosey.azure_dumper import AzureDataDumper
        from goosey.mde_datadumper import MDEDataDumper

        for name, cls in [("m365", M365DataDumper), ("entraid", EntraIdDataDumper),
                          ("azure", AzureDataDumper), ("mde", MDEDataDumper)]:
            methods[name] = []
            for attr in sorted(dir(cls)):
                if attr.startswith("dump_"):
                    key = attr[5:]  # strip dump_ prefix
                    doc = ""
                    try:
                        doc = getattr(cls, attr).__doc__ or ""
                        doc = doc.strip().split("\n")[0]
                    except Exception:
                        pass
                    methods[name].append({"key": key, "doc": doc})
    except Exception:
        pass
    return methods


# ---------------------------------------------------------------------------
# Browse Data: helpers and API endpoints
#
# @decision DEC-BROWSE-002
# @title Server-side directory scan, client-side tree rendering
# @status accepted
# @rationale Security (no raw file paths exposed in initial tree response),
#   responsive filtering without re-requesting, and fast initial render since
#   the tree endpoint only aggregates counts rather than sending file lists.
#
# @decision DEC-BROWSE-003
# @title Three API endpoints (tree / files / preview)
# @status accepted
# @rationale Separation of concerns: tree gives hierarchy with counts (fast),
#   files gives per-sourcetype file listing (lazy-loaded on demand), preview
#   gives paginated content for a single file. Keeps initial page render fast.
# ---------------------------------------------------------------------------

# Module-level cache: populated on first call to load_sourcetypes()
_sourcetypes_cache = None

# Module-level cache: populated on first call to load_hunting_queries()
_hunting_queries_cache = None


def load_sourcetypes():
    """Load and cache the sourcetypes registry from goosey/data/sourcetypes.json.

    The registry is loaded once at first call and stored in a module-level
    variable. Subsequent calls return the cached object without re-reading disk.

    Returns:
        dict: Parsed sourcetypes.json data with 'version' and 'types' keys.
    """
    global _sourcetypes_cache
    if _sourcetypes_cache is None:
        data_dir = os.path.join(os.path.dirname(__file__), 'data')
        path = os.path.join(data_dir, 'sourcetypes.json')
        with open(path, 'r', encoding='utf-8') as f:
            _sourcetypes_cache = json.load(f)
    return _sourcetypes_cache


def load_hunting_queries():
    """Load and cache the hunting query catalog from goosey/data/hunting_queries.json.

    The catalog is loaded once at first call and stored in a module-level
    variable.  Subsequent calls return the cached object without re-reading disk.

    Returns:
        dict: Parsed hunting_queries.json data with 'version' and 'queries' keys.
    """
    global _hunting_queries_cache
    if _hunting_queries_cache is None:
        data_dir = os.path.join(os.path.dirname(__file__), 'data')
        path = os.path.join(data_dir, 'hunting_queries.json')
        with open(path, 'r', encoding='utf-8') as f:
            _hunting_queries_cache = json.load(f)
    return _hunting_queries_cache


def resolve_target_files(target_globs, output_dir):
    """Resolve a list of glob patterns against the output directory.

    Handles the ``{sub_id}`` placeholder by substituting each known Azure
    subscription ID discovered under ``output_dir/azure/``.  Duplicate paths
    (from overlapping patterns) are deduplicated.

    PATH SECURITY: all resolved paths are verified with ``os.path.realpath()``
    to be strictly inside ``output_dir``.  Any path that resolves outside the
    output directory is silently discarded.

    @decision DEC-HUNT-002
    @title Mirror _expand_glob_patterns for hunting query file resolution
    @status accepted
    @rationale Reuses the same {sub_id} substitution and hidden-file filtering
      logic already proven in the browse API.  Keeps the two subsystems
      consistent without duplicating the expansion algorithm into a shared
      helper (that refactor can happen later if a third consumer appears).

    Args:
        target_globs: List of glob patterns relative to output_dir (from a
                      hunting query's ``target_files`` field).
        output_dir: Absolute path to the root output directory.

    Returns:
        list[dict]: Sorted list of ``{"path": rel, "size": int, "modified": str}``
                    dicts for every resolved file, ordered by relative path.
    """
    if not target_globs or not os.path.isdir(output_dir):
        return []

    resolved_base = os.path.realpath(output_dir)

    # Discover Azure subscription IDs (same logic as scan_output_dir)
    azure_dir = os.path.join(output_dir, 'azure')
    azure_sub_ids = []
    if os.path.isdir(azure_dir):
        for entry in os.scandir(azure_dir):
            if entry.is_dir() and not entry.name.startswith('.') and entry.name != '.savestate':
                azure_sub_ids.append(entry.name)

    seen = set()
    results = []

    for file_glob in target_globs:
        matches = _expand_glob_patterns(output_dir, file_glob, azure_sub_ids)
        for abs_path in matches:
            # Deduplicate
            real_path = os.path.realpath(abs_path)
            if real_path in seen:
                continue

            # Path traversal protection: must be strictly inside output_dir
            if not real_path.startswith(resolved_base + os.sep) and real_path != resolved_base:
                continue

            seen.add(real_path)

            try:
                stat = os.stat(abs_path)
            except OSError:
                continue

            rel_path = os.path.relpath(abs_path, output_dir)
            mtime = datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(timespec='seconds')
            results.append({
                'path': rel_path,
                'size': stat.st_size,
                'modified': mtime,
            })

    results.sort(key=lambda x: x['path'])
    return results


def _size_human(nbytes):
    """Format a byte count as a human-readable string (e.g. '1.0 MB')."""
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if nbytes < 1024.0:
            return f"{nbytes:.1f} {unit}"
        nbytes /= 1024.0
    return f"{nbytes:.1f} PB"


def _count_lines(filepath):
    """Count lines in a file efficiently.

    For files < 10 MB: count newlines directly.
    For files >= 10 MB: estimate from file size using the average line length
    sampled from the first 100 lines.

    Args:
        filepath: Absolute path to the file.

    Returns:
        int: Estimated line count (>= 0).
    """
    size = os.path.getsize(filepath)
    if size == 0:
        return 0
    ten_mb = 10 * 1024 * 1024
    if size < ten_mb:
        with open(filepath, 'rb') as f:
            return sum(1 for _ in f)
    # Large file: sample first 100 lines to estimate average line length
    sample_lines = 0
    sample_bytes = 0
    with open(filepath, 'rb') as f:
        for line in f:
            sample_lines += 1
            sample_bytes += len(line)
            if sample_lines >= 100:
                break
    if sample_bytes == 0:
        return 0
    avg_line_len = sample_bytes / sample_lines
    return int(size / avg_line_len)


def _iter_all_sourcetypes(sourcetypes_data):
    """Yield (sourcetype_id, sourcetype_dict) for every leaf sourcetype in the registry.

    Traverses the full types → subtypes → [subcategories →] sourcetypes hierarchy.

    Args:
        sourcetypes_data: Parsed sourcetypes.json dict.

    Yields:
        tuple: (sourcetype_id: str, sourcetype_dict: dict)
    """
    for _type_id, type_data in sourcetypes_data.get('types', {}).items():
        # Top-level direct sourcetypes (unusual but handle it)
        for st_id, st_data in type_data.get('sourcetypes', {}).items():
            yield st_id, st_data
        for _subtype_id, subtype_data in type_data.get('subtypes', {}).items():
            for st_id, st_data in subtype_data.get('sourcetypes', {}).items():
                yield st_id, st_data
            for _cat_id, cat_data in subtype_data.get('subcategories', {}).items():
                for st_id, st_data in cat_data.get('sourcetypes', {}).items():
                    yield st_id, st_data


def _expand_glob_patterns(output_dir, file_glob, azure_sub_ids):
    """Expand a file_glob pattern against the output directory.

    Handles the {sub_id} placeholder by substituting each known Azure
    subscription ID (discovered by listing the azure/ subdirectory).
    LAW globs that already use '*' work without substitution.

    Args:
        output_dir: Absolute path to the root output directory.
        file_glob: Glob pattern string from sourcetypes.json (relative to output_dir).
        azure_sub_ids: List of subscription ID directory names found under output/azure/.

    Returns:
        list[str]: Absolute file paths matching the pattern (no hidden files, no .savestate).
    """
    matches = []
    if '{sub_id}' in file_glob:
        # Substitute each known subscription ID
        for sub_id in azure_sub_ids:
            pattern = os.path.join(output_dir, file_glob.replace('{sub_id}', sub_id))
            matches.extend(glob_module.glob(pattern))
    else:
        pattern = os.path.join(output_dir, file_glob)
        matches.extend(glob_module.glob(pattern))

    # Filter hidden files (basename starts with '.') and .savestate directories
    filtered = []
    for p in matches:
        parts = p.replace(output_dir, '').split(os.sep)
        if any(part.startswith('.') or part == '.savestate' for part in parts if part):
            continue
        filtered.append(p)
    return filtered


def scan_output_dir(output_dir, sourcetypes_data):
    """Walk the output directory and match files against sourcetype file_glob patterns.

    Args:
        output_dir: Path to the output directory (may not exist).
        sourcetypes_data: Parsed sourcetypes.json dict.

    Returns:
        dict: Maps sourcetype_id (str) → list of matching absolute file paths.
              All known sourcetype IDs are always present as keys; non-matching
              IDs map to [].
    """
    result = {}

    if not os.path.isdir(output_dir):
        # Return empty lists for all known sourcetypes
        for st_id, _ in _iter_all_sourcetypes(sourcetypes_data):
            result[st_id] = []
        return result

    # Discover Azure subscription IDs by listing the azure/ subdirectory
    azure_dir = os.path.join(output_dir, 'azure')
    azure_sub_ids = []
    if os.path.isdir(azure_dir):
        for entry in os.scandir(azure_dir):
            if entry.is_dir() and not entry.name.startswith('.') and entry.name != '.savestate':
                azure_sub_ids.append(entry.name)

    for st_id, st_data in _iter_all_sourcetypes(sourcetypes_data):
        file_glob = st_data.get('file_glob', '')
        if not file_glob:
            result[st_id] = []
            continue
        result[st_id] = _expand_glob_patterns(output_dir, file_glob, azure_sub_ids)

    return result


def build_tree(sourcetypes_data, file_map):
    """Build the browse tree response, including only nodes with matching files.

    File counts are aggregated upward through the hierarchy so that each
    container (type, subtype, subcategory) carries the total count of all
    files beneath it.

    Args:
        sourcetypes_data: Parsed sourcetypes.json dict.
        file_map: Dict mapping sourcetype_id → list of matching file paths,
                  as returned by scan_output_dir().

    Returns:
        dict: {'types': [list of type nodes]} where each node has:
              id, display_name, description, file_count, subtypes.
    """
    type_nodes = []

    for type_id, type_data in sourcetypes_data.get('types', {}).items():
        subtype_nodes = []

        for subtype_id, subtype_data in type_data.get('subtypes', {}).items():
            # Build sourcetypes list directly on the subtype (non-LAW pattern)
            st_list = []
            for st_id, st_data in subtype_data.get('sourcetypes', {}).items():
                count = len(file_map.get(st_id, []))
                if count > 0:
                    st_list.append({
                        'id': st_id,
                        'display_name': st_data.get('display_name', st_id),
                        'description': st_data.get('description', ''),
                        'file_count': count,
                    })

            # Build subcategories list (LAW pattern)
            subcat_nodes = []
            for cat_id, cat_data in subtype_data.get('subcategories', {}).items():
                cat_st_list = []
                for st_id, st_data in cat_data.get('sourcetypes', {}).items():
                    count = len(file_map.get(st_id, []))
                    if count > 0:
                        cat_st_list.append({
                            'id': st_id,
                            'display_name': st_data.get('display_name', st_id),
                            'description': st_data.get('description', ''),
                            'file_count': count,
                        })
                if cat_st_list:
                    cat_count = sum(s['file_count'] for s in cat_st_list)
                    subcat_nodes.append({
                        'id': cat_id,
                        'display_name': cat_data.get('display_name', cat_id),
                        'file_count': cat_count,
                        'sourcetypes': cat_st_list,
                    })

            subtype_total = (
                sum(s['file_count'] for s in st_list) +
                sum(c['file_count'] for c in subcat_nodes)
            )
            if subtype_total > 0:
                subtype_nodes.append({
                    'id': subtype_id,
                    'display_name': subtype_data.get('display_name', subtype_id),
                    'description': subtype_data.get('description', ''),
                    'file_count': subtype_total,
                    'sourcetypes': st_list,
                    'subcategories': subcat_nodes,
                })

        type_total = sum(s['file_count'] for s in subtype_nodes)
        if type_total > 0:
            type_nodes.append({
                'id': type_id,
                'display_name': type_data.get('display_name', type_id),
                'description': type_data.get('description', ''),
                'file_count': type_total,
                'subtypes': subtype_nodes,
            })

    return {'types': type_nodes}


def _get_output_dir():
    """Return the output directory: query param > app config > CWD/output."""
    output_dir_param = request.args.get('output_dir')
    if output_dir_param:
        return os.path.abspath(output_dir_param)
    configured = app.config.get('OUTPUT_DIR')
    if configured:
        return os.path.abspath(configured)
    return os.path.join(get_working_dir(), 'output')


def _lookup_sourcetype(sourcetypes_data, sourcetype_id):
    """Find a sourcetype dict by ID in the registry.

    Args:
        sourcetypes_data: Parsed sourcetypes.json dict.
        sourcetype_id: The sourcetype identifier string.

    Returns:
        dict or None: The sourcetype dict (with display_name, file_glob, …)
                      or None if not found.
    """
    for st_id, st_data in _iter_all_sourcetypes(sourcetypes_data):
        if st_id == sourcetype_id:
            return st_data
    return None


@app.route('/api/browse/tree')
def api_browse_tree():
    """Return the sourcetype hierarchy filtered to nodes with actual output files.

    Query params:
        output_dir (optional): Path to output directory; defaults to CWD/output.

    Returns:
        200 JSON: {'types': [...]} tree with file_count at every node.
    """
    output_dir = _get_output_dir()
    sourcetypes_data = load_sourcetypes()
    file_map = scan_output_dir(output_dir, sourcetypes_data)
    tree = build_tree(sourcetypes_data, file_map)
    return jsonify(tree)


@app.route('/api/browse/folder-tree')
def api_browse_folder_tree():
    """Return the output directory as a folder tree with file metadata.

    Walks the output directory recursively, skipping hidden files/dirs
    (starting with '.') and __pycache__. Returns a nested structure.

    Returns:
        200 JSON: {'name': 'output', 'children': [...], 'file_count': N}
        Each node is either:
        - directory: {name, children, file_count, type: 'dir'}
        - file: {name, path (relative), size, size_human, modified, lines, type: 'file'}
    """
    output_dir = _get_output_dir()
    if not os.path.isdir(output_dir):
        return jsonify({'name': os.path.basename(output_dir), 'children': [], 'file_count': 0, 'type': 'dir'})

    def walk_dir(dirpath, rel_prefix=''):
        children = []
        file_count = 0
        try:
            entries = sorted(os.scandir(dirpath), key=lambda e: (not e.is_dir(), e.name.lower()))
        except PermissionError:
            return {'name': os.path.basename(dirpath), 'children': [], 'file_count': 0, 'type': 'dir'}

        for entry in entries:
            if entry.name.startswith('.') or entry.name == '__pycache__':
                continue
            rel_path = os.path.join(rel_prefix, entry.name) if rel_prefix else entry.name
            if entry.is_dir(follow_symlinks=False):
                child = walk_dir(entry.path, rel_path)
                if child['file_count'] > 0:  # Only include non-empty dirs
                    children.append(child)
                    file_count += child['file_count']
            elif entry.is_file(follow_symlinks=False):
                try:
                    stat = entry.stat()
                except OSError:
                    continue
                mtime = datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(timespec='seconds')
                children.append({
                    'name': entry.name,
                    'path': rel_path,
                    'size': stat.st_size,
                    'size_human': _size_human(stat.st_size),
                    'modified': mtime,
                    'lines': _count_lines(entry.path),
                    'type': 'file',
                })
                file_count += 1

        return {
            'name': os.path.basename(dirpath),
            'children': children,
            'file_count': file_count,
            'type': 'dir',
        }

    tree = walk_dir(output_dir)
    return jsonify(tree)


@app.route('/api/browse/files')
def api_browse_files():
    """Return the list of files for a specific sourcetype with metadata.

    Query params:
        type (required): Top-level type ID (e.g. 'azure', 'eid').
        subtype (required): Subtype ID (e.g. 'core', 'law').
        subcategory (optional): Subcategory ID for LAW types.
        sourcetype (required): Sourcetype ID (e.g. 'aadmanagedidentitysigninlogs').
        output_dir (optional): Path to output directory.

    Returns:
        200 JSON: {'sourcetype': id, 'display_name': ..., 'files': [...]}
        400 JSON: Missing required parameters.
        404 JSON: Sourcetype not found in registry.
    """
    sourcetype_id = request.args.get('sourcetype')
    type_id = request.args.get('type')
    subtype_id = request.args.get('subtype')

    if not sourcetype_id or not type_id or not subtype_id:
        return jsonify({'error': 'Required parameters: type, subtype, sourcetype'}), 400

    output_dir = _get_output_dir()
    sourcetypes_data = load_sourcetypes()
    st_data = _lookup_sourcetype(sourcetypes_data, sourcetype_id)

    if st_data is None:
        return jsonify({'error': f'Sourcetype not found: {sourcetype_id}'}), 404

    # Discover Azure subscription IDs
    azure_dir = os.path.join(output_dir, 'azure')
    azure_sub_ids = []
    if os.path.isdir(azure_dir):
        for entry in os.scandir(azure_dir):
            if entry.is_dir() and not entry.name.startswith('.') and entry.name != '.savestate':
                azure_sub_ids.append(entry.name)

    file_glob = st_data.get('file_glob', '')
    matching = _expand_glob_patterns(output_dir, file_glob, azure_sub_ids)

    files = []
    for abs_path in sorted(matching):
        try:
            stat = os.stat(abs_path)
        except OSError:
            continue
        rel_path = os.path.relpath(abs_path, output_dir)
        mtime = datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(timespec='seconds')
        lines = _count_lines(abs_path)
        files.append({
            'path': rel_path,
            'size': stat.st_size,
            'size_human': _size_human(stat.st_size),
            'modified': mtime,
            'lines': lines,
        })

    return jsonify({
        'sourcetype': sourcetype_id,
        'display_name': st_data.get('display_name', sourcetype_id),
        'files': files,
    })


@app.route('/api/browse/query', methods=['POST'])
def api_browse_query():
    """Execute an HQL query against collected data files.

    Accepts a JSON body with:
        query      (str, required): HQL query string.  May or may not include
                   the ``database("goose").file(...)`` prefix.
        file       (str, optional): Relative path within output_dir.  Required
                   when ``query`` does not start with ``database(``.
        page       (int, optional): 1-based result page (default 1).
        page_size  (int, optional): Rows per page, max 1000 (default 100).

    Returns:
        200 JSON: {columns, rows, total, page, pages, query}
        400 JSON: {error} for user-recoverable query failures or bad parameters.
        500 JSON: {error} for unexpected server-side errors.
    """
    data = request.get_json(silent=True) or {}
    query = (data.get('query') or '').strip()
    file_path = (data.get('file') or '').strip()
    try:
        page = max(1, int(data.get('page', 1)))
    except (TypeError, ValueError):
        page = 1
    try:
        page_size = min(max(1, int(data.get('page_size', 100))), 1000)
    except (TypeError, ValueError):
        page_size = 100

    if not query:
        return jsonify({'error': 'Required field: query'}), 400

    output_dir = _get_output_dir()

    try:
        from goosey.hql_compat import run_hql_query
        result = run_hql_query(
            query,
            output_dir,
            file_path=file_path or None,
            page=page,
            page_size=page_size,
        )
        return jsonify(result)
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except ImportError as exc:
        return jsonify({'error': str(exc)}), 400
    except Exception as exc:
        return jsonify({'error': f'Query failed: {exc}'}), 500


@app.route('/api/browse/preview')
def api_browse_preview():
    """Return the first N lines of a data file with optional offset for pagination.

    PATH TRAVERSAL PROTECTION: the requested path is resolved with realpath()
    and must be a child of the resolved output_dir. Any path containing '..'
    or an absolute path is rejected immediately with 403.

    Query params:
        path (required): Relative path within output_dir.
        lines (optional): Number of lines to return (default 50, max 500).
        offset (optional): Starting line index (0-based, default 0).
        output_dir (optional): Path to output directory.

    Returns:
        200 JSON: {'path', 'lines', 'offset', 'total_lines', 'has_more'}
        400 JSON: Missing required parameters.
        403 JSON: Path traversal attempt detected.
        404 JSON: File not found.
    """
    rel_path = request.args.get('path')
    if not rel_path:
        return jsonify({'error': 'Required parameter: path'}), 400

    # Reject absolute paths and obvious traversal attempts immediately
    if os.path.isabs(rel_path) or '..' in rel_path.split(os.sep) or '..' in rel_path.split('/'):
        return jsonify({'error': 'Path traversal attempt rejected'}), 403

    output_dir = _get_output_dir()
    resolved_base = os.path.realpath(output_dir)
    candidate = os.path.realpath(os.path.join(output_dir, rel_path))

    # Canonical prefix check: must be strictly inside the output directory
    if not candidate.startswith(resolved_base + os.sep) and candidate != resolved_base:
        return jsonify({'error': 'Path traversal attempt rejected'}), 403

    if not os.path.isfile(candidate):
        return jsonify({'error': f'File not found: {rel_path}'}), 404

    try:
        n_lines = min(int(request.args.get('lines', 50)), 500)
    except (ValueError, TypeError):
        n_lines = 50
    try:
        offset = max(int(request.args.get('offset', 0)), 0)
    except (ValueError, TypeError):
        offset = 0

    total_lines = _count_lines(candidate)

    # Read the requested slice
    result_lines = []
    with open(candidate, 'r', encoding='utf-8', errors='replace') as f:
        for i, line in enumerate(f):
            if i < offset:
                continue
            if len(result_lines) >= n_lines:
                break
            result_lines.append(line.rstrip('\n').rstrip('\r'))

    has_more = (offset + len(result_lines)) < total_lines

    return jsonify({
        'path': rel_path,
        'lines': result_lines,
        'offset': offset,
        'total_lines': total_lines,
        'has_more': has_more,
    })


# ---------------------------------------------------------------------------
# Hunting Queries API
#
# @decision DEC-HUNT-002
# @title Hunting query catalog endpoints: list+filter and per-ID lookup
# @status accepted
# @rationale Provides the browser UI with structured access to the curated
#   HQL query catalog (hunting_queries.json) without coupling to the browse
#   API.  File-target resolution reuses _expand_glob_patterns() so {sub_id}
#   substitution and hidden-file filtering behave identically to browse/files.
# ---------------------------------------------------------------------------


def _build_hunting_index(queries):
    """Build sorted unique lists of categories and MITRE IDs from query list.

    Args:
        queries: List of query dicts from hunting_queries.json.

    Returns:
        tuple: (categories: list[str], mitre_ids: list[str]) both sorted.
    """
    categories = sorted({q.get('category', '') for q in queries if q.get('category')})
    mitre_ids_set = set()
    for q in queries:
        for m in q.get('mitre_ids', []):
            mitre_ids_set.add(m)
    return categories, sorted(mitre_ids_set)


@app.route('/api/hunting/queries')
def api_hunting_queries():
    """Return the hunting query catalog with optional filters.

    Query params:
        category (optional):    Filter to queries matching this category exactly.
        subcategory (optional): Filter to queries matching this subcategory exactly.
        mitre_id (optional):    Filter to queries where any mitre_ids entry starts
                                with this prefix (e.g. 'T1110' matches 'T1110.003').
        search (optional):      Case-insensitive substring match against name and
                                description.
        severity (optional):    Filter to queries matching this severity exactly.

    Returns:
        200 JSON: {
            "queries": [...],
            "total": N,
            "categories": [unique categories],
            "mitre_ids": [unique MITRE IDs]
        }
    """
    catalog = load_hunting_queries()
    queries = list(catalog.get('queries', []))

    category = request.args.get('category', '').strip()
    subcategory = request.args.get('subcategory', '').strip()
    mitre_id = request.args.get('mitre_id', '').strip()
    search = request.args.get('search', '').strip().lower()
    severity = request.args.get('severity', '').strip()

    if category:
        queries = [q for q in queries if q.get('category') == category]
    if subcategory:
        queries = [q for q in queries if q.get('subcategory') == subcategory]
    if severity:
        queries = [q for q in queries if q.get('severity') == severity]
    if mitre_id:
        queries = [
            q for q in queries
            if any(m.startswith(mitre_id) for m in q.get('mitre_ids', []))
        ]
    if search:
        queries = [
            q for q in queries
            if search in q.get('name', '').lower() or search in q.get('description', '').lower()
        ]

    categories, mitre_ids = _build_hunting_index(queries)

    return jsonify({
        'queries': queries,
        'total': len(queries),
        'categories': categories,
        'mitre_ids': mitre_ids,
    })


@app.route('/api/hunting/queries/<query_id>')
def api_hunting_query_by_id(query_id):
    """Return a single hunting query by its ID.

    Args:
        query_id: The query identifier (e.g. 'hunt-signin-001').

    Returns:
        200 JSON: The full query dict.
        404 JSON: {"error": "..."} if the ID is not found.
    """
    catalog = load_hunting_queries()
    for q in catalog.get('queries', []):
        if q.get('id') == query_id:
            return jsonify(q)
    return jsonify({'error': f'Query not found: {query_id}'}), 404


@app.route('/api/hunting/resolve')
def api_hunting_resolve():
    """Resolve a hunting query's target_files globs against the output directory.

    Query params:
        id (required): The query ID to resolve (e.g. 'hunt-signin-001').
        output_dir (optional): Override the output directory (defaults to app config).

    Returns:
        200 JSON: {"query_id": "...", "files": [...], "count": N}
        400 JSON: {"error": "..."} when 'id' is missing.
        404 JSON: {"error": "..."} when the query ID is not found.
    """
    query_id = request.args.get('id', '').strip()
    if not query_id:
        return jsonify({'error': 'Required parameter: id'}), 400

    catalog = load_hunting_queries()
    query = None
    for q in catalog.get('queries', []):
        if q.get('id') == query_id:
            query = q
            break

    if query is None:
        return jsonify({'error': f'Query not found: {query_id}'}), 404

    output_dir = _get_output_dir()
    target_globs = query.get('target_files', [])
    files = resolve_target_files(target_globs, output_dir)

    return jsonify({
        'query_id': query_id,
        'files': files,
        'count': len(files),
    })


# ---------------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/conf", methods=["GET"])
def api_get_conf():
    conf = read_conf()
    auth = read_auth()
    # Mask secrets
    if "auth" in auth:
        for key in ("clientsecret", "ests_cookie", "portal_refresh_token"):
            if key in auth["auth"] and auth["auth"][key]:
                auth["auth"][key] = "********"
    return jsonify({"conf": conf, "auth": auth, "dump_methods": get_dump_methods()})


@app.route("/api/conf", methods=["POST"])
def api_save_conf():
    """Save configuration from the web UI.

    Calls genconf() to produce a properly structured .conf file with comments
    and correct key names (without the dump_ prefix that DataDumper.data_dump()
    strips when resolving method names). After genconf writes the file, individual
    dump method selections are patched in from the submitted form data.

    @decision DEC-WEBCONF-001
    @title Use genconf() for .conf writes to ensure correct key structure
    @status accepted
    @rationale The frontend sends dump method keys without the dump_ prefix
      (e.g. ual=true), matching what honk.py/parse_config expects. Using
      genconf() guarantees the file is fully structured with comments and all
      required sections, then we patch individual dump selections afterward.
    """
    # Imported inside the function to avoid circular imports at module load time
    from goosey.conf import genconf

    data = request.json
    conf_data = data.get("conf", {})
    auth_data = data.get("auth", {})

    # --- Auth: restore masked values from the existing .auth file ---
    existing_auth = read_auth()
    for section, values in auth_data.items():
        for k, v in values.items():
            if v == "********" and section in existing_auth and k in existing_auth[section]:
                auth_data[section][k] = existing_auth[section][k]

    # Write the (unmasked) .auth file so genconf sees it and skips interactive prompts
    auth_path = os.path.join(get_working_dir(), ".auth")
    auth_cfg = configparser.ConfigParser()
    for section, values in auth_data.items():
        auth_cfg[section] = values
    with open(auth_path, "w") as f:
        auth_cfg.write(f)

    # --- Build genconf keyword arguments from submitted conf sections ---
    auth_section = auth_data.get("auth", {})
    config_section = conf_data.get("config", {})
    filters_section = conf_data.get("filters", {})
    variables_section = conf_data.get("variables", {})

    # Collect dump method selections per platform (keys WITHOUT dump_ prefix)
    platform_sections = ("azure", "entraid", "m365", "mde")
    dict_config = {}
    for platform in platform_sections:
        if platform in conf_data:
            dict_config[platform] = {
                k: (v.lower() == "true" if isinstance(v, str) else bool(v))
                for k, v in conf_data[platform].items()
            }

    # Determine which platforms have at least one method enabled (for genconf flags)
    def _any_enabled(platform):
        return any(dict_config.get(platform, {}).values())

    def _str_or_none(val):
        return val if val not in (None, "") else None

    def _int_or_default(val, default):
        try:
            return int(val)
        except (TypeError, ValueError):
            return default

    genconf_kwargs = dict(
        outpath_auth=auth_path,
        outpath_conf=os.path.join(get_working_dir(), ".conf"),
        auth_appid=_str_or_none(auth_section.get("appid")),
        auth_clientsecret=_str_or_none(auth_section.get("clientsecret")),
        auth_ests_cookie=_str_or_none(auth_section.get("ests_cookie")),
        auth_portal_refresh_token=_str_or_none(auth_section.get("portal_refresh_token")),
        config_tenant=_str_or_none(config_section.get("tenant")),
        config_gcc=(config_section.get("gcc", "false").lower() == "true"),
        config_gcc_high=(config_section.get("gcc_high", "false").lower() == "true"),
        config_subscriptionid=config_section.get("subscriptionid", "All") or "All",
        filters_date_start=_str_or_none(filters_section.get("date_start")),
        filters_date_end=_str_or_none(filters_section.get("date_end")),
        variable_ual_threshold=_int_or_default(variables_section.get("ual_threshold"), 5000),
        variable_max_ual_tasks=_int_or_default(variables_section.get("max_ual_tasks"), 5),
        variable_ual_extra_start=_str_or_none(variables_section.get("ual_extra_start")),
        variable_ual_extra_end=_str_or_none(variables_section.get("ual_extra_end")),
        variable_ual_record_type=_str_or_none(variables_section.get("ual_record_type")),
        variable_ual_operations=_str_or_none(variables_section.get("ual_operations")),
        variable_ual_user_ids=_str_or_none(variables_section.get("ual_user_ids")),
        variable_ual_free_text=_str_or_none(variables_section.get("ual_free_text")),
        variable_ual_ip_addresses=_str_or_none(variables_section.get("ual_ip_addresses")),
        variable_ual_object_ids=_str_or_none(variables_section.get("ual_object_ids")),
        variable_mde_threshold=_int_or_default(variables_section.get("mde_threshold"), 10000),
        variable_mde_query_mode=variables_section.get("mde_query_mode", "table") or "table",
        azure=_any_enabled("azure"),
        entraid=_any_enabled("entraid"),
        m365=_any_enabled("m365"),
        mde=_any_enabled("mde"),
        dict_config=dict_config,
        new=True,
        insecure=True,
    )

    try:
        genconf(**genconf_kwargs)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

    # --- Patch individual dump method selections into the written .conf ---
    # genconf sets all methods for a platform to True/False based on the platform
    # flag.  We now overwrite each key with the per-method selection the user chose.
    conf_path = os.path.join(get_working_dir(), ".conf")
    if dict_config:
        with open(conf_path, "r") as f:
            conf_text = f.read()
        for platform, methods in dict_config.items():
            for key, enabled in methods.items():
                target_value = "True" if enabled else "False"
                # Replace "key=True" or "key=False" (case-insensitive value) within
                # the appropriate section.  Simple line-by-line replacement is safe
                # because genconf writes one key per line.
                conf_text = re.sub(
                    r'(?i)^(' + re.escape(key) + r'\s*=\s*)(?:true|false)',
                    r'\g<1>' + target_value,
                    conf_text,
                    flags=re.MULTILINE,
                )
        with open(conf_path, "w") as f:
            f.write(conf_text)

    return jsonify({"status": "ok"})


@app.route("/api/progress")
def api_progress():
    """Return the current progress state from .progress.json in the output directory.

    Query params:
        output_dir (optional): Output directory name, relative to working dir.
                               Defaults to "output".

    Returns:
        200 JSON: Dict of task_name -> {current, total, status, unit} objects,
                  or {} if the file does not exist or cannot be parsed.
    """
    output_dir = request.args.get("output_dir", "output")
    path = os.path.join(get_working_dir(), output_dir, ".progress.json")
    if not os.path.isfile(path):
        return jsonify({})
    try:
        with open(path) as f:
            return jsonify(json.load(f))
    except (json.JSONDecodeError, IOError):
        return jsonify({})


@app.route("/api/portal-cookie", methods=["POST"])
def api_portal_cookie():
    """Save and validate an ESTS cookie for MDE portal auth.

    Writes the cookie to the .auth file, then validates it by hitting
    security.microsoft.com and checking for an sccauth cookie in the response.
    """
    import requests as req_lib

    data = request.json
    ests_cookie = data.get("ests_cookie", "").strip()
    if not ests_cookie:
        return jsonify({"saved": False, "valid": False, "error": "No cookie provided"})

    # Save to .auth file
    auth_path = os.path.join(get_working_dir(), ".auth")
    auth_cfg = configparser.ConfigParser()
    if os.path.isfile(auth_path):
        auth_cfg.read(auth_path)
    if not auth_cfg.has_section("auth"):
        auth_cfg.add_section("auth")
    auth_cfg.set("auth", "ests_cookie", ests_cookie)
    with open(auth_path, "w") as f:
        auth_cfg.write(f)

    # Validate by hitting the portal
    try:
        session = req_lib.Session()
        session.cookies.set('ESTSAUTHPERSISTENT', ests_cookie, domain='.microsoft.com')
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        resp = session.get('https://security.microsoft.com', allow_redirects=True, timeout=30)
        sccauth = session.cookies.get('sccauth', domain='security.microsoft.com')
        if not sccauth:
            for cookie in session.cookies:
                if cookie.name == 'sccauth':
                    sccauth = cookie.value
                    break
        if sccauth:
            return jsonify({"saved": True, "valid": True})
        else:
            return jsonify({"saved": True, "valid": False,
                          "error": "Cookie saved but could not obtain portal session. Cookie may be expired."})
    except Exception as e:
        return jsonify({"saved": True, "valid": False, "error": str(e)})


@app.route("/api/portal-device-code/start", methods=["POST"])
def api_portal_device_code_start():
    """Initiate an MDE portal device-code OAuth flow.

    Starts a device-code flow using MSAL for the Microsoft Security portal
    (client_id 1fec8e78-bce4-4aaf-ab1b-5451cc387264) targeting the
    WindowsDefenderATP scope. The returned user_code and verification_uri
    are shown to the user who must complete login in their browser.

    Request JSON:
        tenant_id (str): Azure AD tenant ID or domain.

    Returns:
        200 JSON: {flow_id, user_code, verification_uri, expires_in, message}
        400 JSON: {error} on missing/invalid input or MSAL failure.
    """
    import msal

    data = request.json or {}
    tenant_id = (data.get("tenant_id") or "").strip()
    if not tenant_id:
        return jsonify({"error": "tenant_id is required"}), 400

    authority = f"https://login.microsoftonline.com/{tenant_id}"
    # Client ID for the Microsoft Security portal public app registration
    client_id = "1fec8e78-bce4-4aaf-ab1b-5451cc387264"
    scopes = ["80ccca67-54bd-44ab-8625-4b79c4dc7775/.default", "offline_access"]

    try:
        msal_app = msal.PublicClientApplication(client_id, authority=authority)
        flow = msal_app.initiate_device_flow(scopes=scopes)
        if "user_code" not in flow:
            error_msg = flow.get("error_description", flow.get("error", "Failed to initiate device flow"))
            return jsonify({"error": error_msg}), 400

        flow_id = uuid.uuid4().hex
        _device_flows[flow_id] = {"flow": flow, "msal_app": msal_app}

        return jsonify({
            "flow_id": flow_id,
            "user_code": flow["user_code"],
            "verification_uri": flow["verification_uri"],
            "expires_in": flow.get("expires_in", 900),
            "message": flow.get("message", ""),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/portal-device-code/poll", methods=["POST"])
def api_portal_device_code_poll():
    """Poll for completion of an MDE portal device-code flow.

    Calls MSAL's acquire_token_by_device_flow which returns immediately
    with 'authorization_pending' if the user has not yet completed login.
    On success, writes the refresh_token to the .auth file so the MDE
    portal auth module can use it for subsequent requests.

    Request JSON:
        flow_id (str): Flow ID returned by /api/portal-device-code/start.

    Returns:
        200 JSON: {status} where status is one of:
            "complete"  — user finished login; refresh_token saved to .auth
            "pending"   — user hasn't completed login yet; poll again
            "expired"   — device code expired; start a new flow
            "error"     — unexpected error; {error} field contains description
    """
    data = request.json or {}
    flow_id = (data.get("flow_id") or "").strip()
    if not flow_id or flow_id not in _device_flows:
        return jsonify({"status": "error", "error": "Unknown or expired flow_id"}), 400

    entry = _device_flows[flow_id]
    flow = entry["flow"]
    msal_app = entry["msal_app"]

    try:
        result = msal_app.acquire_token_by_device_flow(flow)
    except Exception as e:
        _device_flows.pop(flow_id, None)
        return jsonify({"status": "error", "error": str(e)})

    if "access_token" in result:
        # Success — persist the refresh token to .auth
        refresh_token = result.get("refresh_token", "")
        auth_path = os.path.join(get_working_dir(), ".auth")
        auth_cfg = configparser.ConfigParser()
        if os.path.isfile(auth_path):
            auth_cfg.read(auth_path)
        if not auth_cfg.has_section("auth"):
            auth_cfg.add_section("auth")
        if refresh_token:
            auth_cfg.set("auth", "portal_refresh_token", refresh_token)
        with open(auth_path, "w") as f:
            auth_cfg.write(f)
        _device_flows.pop(flow_id, None)
        return jsonify({"status": "complete"})

    error_code = result.get("error", "")
    if error_code == "authorization_pending":
        return jsonify({"status": "pending"})
    elif error_code in ("expired_token", "code_expired"):
        _device_flows.pop(flow_id, None)
        return jsonify({"status": "expired"})
    else:
        error_desc = result.get("error_description", error_code)
        _device_flows.pop(flow_id, None)
        return jsonify({"status": "error", "error": error_desc})


@app.route("/api/run", methods=["POST"])
def api_run():
    data = request.json
    command = data.get("command", "")
    args = data.get("args", [])

    # Build the goosey CLI command
    cmd = [sys.executable, "-m", "goosey.main", command] + args
    task_id = runner.start(cmd, cwd=get_working_dir())
    return jsonify({"task_id": task_id, "cmd": " ".join(cmd)})


@app.route("/api/stream/<task_id>")
def api_stream(task_id):
    return Response(
        runner.stream(task_id),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/input/<task_id>", methods=["POST"])
def api_input(task_id):
    data = request.json
    text = data.get("text", "")
    ok = runner.send_input(task_id, text)
    return jsonify({"sent": ok})


@app.route("/api/stop/<task_id>", methods=["POST"])
def api_stop(task_id):
    ok = runner.stop(task_id)
    return jsonify({"stopped": ok})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def web(host="127.0.0.1", port=8000, debug=False, working_dir=None):
    """Launch the Goosey web UI in a browser.

    Args:
        host: Host to bind to (default: 127.0.0.1, use 0.0.0.0 for all interfaces)
        port: Port to listen on
        debug: Enable Flask debug mode
        working_dir: Working directory for config files and output (default: current directory)
    """
    if working_dir:
        app.config["WORKING_DIR"] = os.path.abspath(working_dir)
    else:
        app.config["WORKING_DIR"] = os.getcwd()

    print(f"Starting Goosey Web UI at http://{host}:{port}")
    print(f"Working directory: {app.config['WORKING_DIR']}")
    app.run(host=host, port=port, debug=debug)

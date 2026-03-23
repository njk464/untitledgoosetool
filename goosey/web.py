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
    data = request.json
    if "conf" in data:
        write_conf(data["conf"])
    if "auth" in data:
        # Only save auth if values aren't masked
        auth_data = data["auth"]
        existing = read_auth()
        for section, values in auth_data.items():
            for k, v in values.items():
                if v == "********" and section in existing and k in existing[section]:
                    auth_data[section][k] = existing[section][k]
        path = os.path.join(get_working_dir(), ".auth")
        config = configparser.ConfigParser()
        for section, values in auth_data.items():
            config[section] = values
        with open(path, "w") as f:
            config.write(f)
    return jsonify({"status": "ok"})


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

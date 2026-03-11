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

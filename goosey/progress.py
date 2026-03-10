#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Untitled Goose Tool: Progress bar management for clean console output."""

import json
import os
import threading
import time
from tqdm import tqdm

# ANSI color codes
_GREEN = "\033[92m"
_RED = "\033[91m"
_RESET = "\033[0m"

_progress_manager = None

def init_progress_manager(enabled=True, progress_file=None):
    """Initialize the global progress manager.

    Args:
        enabled: Whether tqdm bars are shown in the terminal.
        progress_file: Optional path to write a JSON progress file on each update.
                       Useful for non-TTY consumers (e.g. Claude Code skill).
    """
    global _progress_manager
    _progress_manager = ProgressManager(enabled=enabled, progress_file=progress_file)
    return _progress_manager

def get_progress_manager():
    """Get the global progress manager, or None if not initialized."""
    return _progress_manager


class ProgressManager:
    """Manages tqdm progress bars for async task tracking."""

    def __init__(self, enabled=True, progress_file=None):
        self.enabled = enabled
        self.progress_file = progress_file
        self._bars = {}
        self._task_status = {}  # task_name -> {status, current, total, unit, elapsed}
        self._position_counter = 0
        self._lock = threading.Lock()
        self._start_times = {}

    def _write_progress_file(self):
        """Write current progress state to a JSON file for external consumers."""
        if not self.progress_file:
            return
        try:
            now = time.time()
            snapshot = {}
            with self._lock:
                for name, info in self._task_status.items():
                    snapshot[name] = {
                        'status': info['status'],
                        'current': info.get('current', 0),
                        'total': info.get('total', 0),
                        'unit': info.get('unit', ''),
                        'start_time': info.get('start_time', now),
                    }
            # Atomic write via temp file
            tmp = self.progress_file + '.tmp'
            with open(tmp, 'w') as f:
                json.dump(snapshot, f)
            os.replace(tmp, self.progress_file)
        except Exception:
            pass

    def start_task(self, task_name):
        """Create a spinner-style progress bar for a task."""
        with self._lock:
            self._task_status[task_name] = {
                'status': 'running', 'current': 0, 'total': 1,
                'unit': 'task', 'start_time': time.time(),
            }
        self._write_progress_file()
        if not self.enabled:
            return
        with self._lock:
            pos = self._position_counter
            self._position_counter += 1
        bar = tqdm(
            total=1,
            bar_format=f"{{desc}} |{{bar}}| elapsed {{elapsed}} | {{postfix}}",
            desc=f"{task_name:<35}",
            postfix="running",
            position=pos,
            leave=True,
            dynamic_ncols=True,
            colour="cyan",
        )
        self._bars[task_name] = bar

    def complete_task(self, task_name, error=None):
        """Mark a task as done or failed, fill its bar, and colorize it."""
        with self._lock:
            if task_name in self._task_status:
                self._task_status[task_name]['status'] = 'FAILED' if error else 'done'
                self._task_status[task_name]['current'] = self._task_status[task_name].get('total', 1)
        self._write_progress_file()
        if not self.enabled:
            return
        bar = self._bars.get(task_name)
        if bar is None:
            return
        # Mark as completed to prevent auto-green from patched update
        bar._completed = getattr(bar, '_completed', False) or True
        # Fill bar to 100%
        remaining = (bar.total or 1) - bar.n
        if remaining > 0:
            bar.update(remaining)
        if error:
            bar.set_postfix_str(f"{_RED}FAILED{_RESET}")
            bar.colour = "red"
        else:
            bar.set_postfix_str(f"{_GREEN}done{_RESET}")
            bar.colour = "green"
        bar.refresh()

    def create_custom_bar(self, task_name, **kwargs):
        """Create a custom tqdm bar (e.g. for UAL) at a managed position."""
        with self._lock:
            self._task_status[task_name] = {
                'status': 'running', 'current': 0,
                'total': kwargs.get('total', 0),
                'unit': 'item', 'start_time': time.time(),
            }
        self._write_progress_file()
        if not self.enabled:
            return None
        with self._lock:
            pos = self._position_counter
            self._position_counter += 1
        kwargs.setdefault("position", pos)
        kwargs.setdefault("leave", True)
        kwargs.setdefault("dynamic_ncols", True)
        bar = tqdm(**kwargs)
        self._bars[task_name] = bar
        return bar

    def create_time_bar(self, task_name, total_days, desc=None, unit='day'):
        """Create a progress bar for time-based collection showing day progress.

        Shows: desc |████████░░░░| 45% | day 13/29 | elapsed 00:05
        """
        with self._lock:
            self._task_status[task_name] = {
                'status': 'running', 'current': 0, 'total': total_days,
                'unit': unit, 'start_time': time.time(),
            }
        self._write_progress_file()
        if not self.enabled:
            return _FileOnlyBar(self, task_name)
        with self._lock:
            pos = self._position_counter
            self._position_counter += 1
        bar = tqdm(
            total=total_days,
            bar_format=f"{{desc}} |{{bar}}| {{percentage:3.0f}}% | {unit} {{n_fmt}}/{{total_fmt}} | elapsed {{elapsed}}",
            desc=f"{(desc or task_name):<35}",
            position=pos,
            leave=True,
            dynamic_ncols=True,
            colour="cyan",
        )
        bar._pm = self
        bar._pm_name = task_name
        bar._completed = False
        original_update = bar.update
        def _patched_update(n=1):
            original_update(n)
            with self._lock:
                if task_name in self._task_status:
                    self._task_status[task_name]['current'] = bar.n
            self._write_progress_file()
            # Auto-colorize green when bar reaches 100%
            if not bar._completed and bar.n >= bar.total:
                bar._completed = True
                bar.colour = "green"
                bar.refresh()
        bar.update = _patched_update
        self._bars[task_name] = bar
        return bar

    def close_all(self):
        """Close all managed progress bars."""
        if not self.enabled:
            return
        for bar in self._bars.values():
            try:
                bar.close()
            except Exception:
                pass
        self._bars.clear()


class _FileOnlyBar:
    """Lightweight bar that only updates the progress file (no tqdm)."""

    def __init__(self, pm, task_name):
        self._pm = pm
        self._name = task_name
        self.n = 0
        self.bar_format = None  # allow callers to set without error

    def update(self, n=1):
        self.n += n
        with self._pm._lock:
            if self._name in self._pm._task_status:
                self._pm._task_status[self._name]['current'] = self.n
        self._pm._write_progress_file()

    def close(self):
        pass

    def refresh(self):
        pass

    def set_postfix_str(self, s):
        with self._pm._lock:
            if self._name in self._pm._task_status:
                self._pm._task_status[self._name]['status'] = s
        self._pm._write_progress_file()

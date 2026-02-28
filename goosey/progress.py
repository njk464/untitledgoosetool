#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Untitled Goose Tool: Progress bar management for clean console output."""

import threading
from tqdm import tqdm

_progress_manager = None

def init_progress_manager(enabled=True):
    """Initialize the global progress manager."""
    global _progress_manager
    _progress_manager = ProgressManager(enabled=enabled)
    return _progress_manager

def get_progress_manager():
    """Get the global progress manager, or None if not initialized."""
    return _progress_manager


class ProgressManager:
    """Manages tqdm progress bars for async task tracking."""

    def __init__(self, enabled=True):
        self.enabled = enabled
        self._bars = {}
        self._position_counter = 0
        self._lock = threading.Lock()

    def start_task(self, task_name):
        """Create a spinner-style progress bar for a task."""
        if not self.enabled:
            return
        with self._lock:
            pos = self._position_counter
            self._position_counter += 1
        bar = tqdm(
            total=1,
            bar_format="{desc} | elapsed {elapsed} | {postfix}",
            desc=f"{task_name:<35}",
            postfix="running",
            position=pos,
            leave=True,
            dynamic_ncols=True,
        )
        self._bars[task_name] = bar

    def complete_task(self, task_name, error=None):
        """Mark a task as done or failed and fill its bar."""
        if not self.enabled:
            return
        bar = self._bars.get(task_name)
        if bar is None:
            return
        if error:
            bar.set_postfix_str("FAILED")
        else:
            bar.set_postfix_str("done")
        bar.update(1)
        bar.refresh()

    def create_custom_bar(self, task_name, **kwargs):
        """Create a custom tqdm bar (e.g. for UAL) at a managed position."""
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

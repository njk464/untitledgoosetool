#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Abstract base class for all data collection dumpers.

DataDumper provides the task scheduling framework that all platform-specific dumpers
(M365, Entra ID, Azure, MDE, D4IoT) inherit from. It handles:
- Auto-discovery of dump_* methods via getattr in data_dump()
- Wrapping each dump method as an isolated asyncio task with error handling
- Token refresh before each task via TokenManager
- Progress bar integration for task status tracking
"""

from goosey.utils import *
from goosey.progress import get_progress_manager

class DataDumper(object):
    """Base class for all platform-specific data dumpers.

    Args:
        output_dir: Directory where collected data files are written.
        reports_dir: Directory for debugging/informational report files.
        app_auth: Token dict for the primary API endpoint. This is a mutable dict
                  shared with TokenManager so token refreshes propagate automatically.
        session: aiohttp.ClientSession shared across all dumpers for connection pooling.
        debug: Whether to enable debug-level logging.
        token_manager: Optional TokenManager for automatic token refresh mid-run.
        endpoint_key: The default endpoint key (e.g. 'graph_api') used for token refresh.
        force_repull: If True, ignore save states for non-time-based (snapshot) dumpers
                      and re-pull all data even if it was previously collected.
    """
    def __init__(self, output_dir: str, reports_dir: str, app_auth: dict, session, debug, token_manager=None, endpoint_key=None, force_repull=False):
        self.output_dir = output_dir
        self.reports_dir = reports_dir
        self.ahsession = session
        self.app_auth = app_auth
        self.logger = setup_logger(type(self).__module__, debug)
        self.token_manager = token_manager
        self.endpoint_key = endpoint_key
        self.force_repull = force_repull

    def check_savestate(self, name):
        """Check if a non-time-based dump has already been collected.

        Returns True (should skip) if a save state exists and force_repull is False.
        """
        if self.force_repull:
            return False
        statefile = os.path.join(self.output_dir, f'.{name}.savestate')
        if os.path.isfile(statefile):
            with open(statefile, 'r') as f:
                saved_date = f.read().strip()
            self.logger.info(f"{name} already collected on {saved_date}, skipping. Use --force_repull to override.")
            return True
        return False

    def write_savestate(self, name):
        """Record that a non-time-based dump completed successfully."""
        statefile = os.path.join(self.output_dir, f'.{name}.savestate')
        with open(statefile, 'w') as f:
            f.write(datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"))

    def get_session(self):
        return self.ahsession

    def ensure_token(self, endpoint_key=None):
        """Ensure the token for the given endpoint (or the default) is still valid.

        Delegates to TokenManager.ensure_valid_token() which checks expiry and
        refreshes the token in-place if it's within 5 minutes of expiring.
        """
        if self.token_manager is None:
            return
        key = endpoint_key or self.endpoint_key
        if key:
            self.token_manager.ensure_valid_token(key)

    def data_dump(self, calls, dumper_name) -> list:
        """Auto-discover and schedule dump_* methods as async tasks.

        For each key in `calls`, looks up `self.dump_<key>` via getattr. If found,
        wraps it in func_wrapper() and creates an asyncio task. This is the core
        mechanism that maps .conf file options to actual data collection methods.

        Args:
            calls: Dict of method name suffixes to schedule (e.g. {'ual': True, 'exo_mailbox': True}).
            dumper_name: Prefix for task names (e.g. 'm365', 'entraid') used in logging/progress.

        Returns:
            List of asyncio.Task objects ready for asyncio.gather().
        """
        tasks = []
        self.logger.debug("Called data_dump in DataDumper")
        for key in calls:
            try:
                func = getattr(self, 'dump_' + key)

            except Exception as e:
                self.logger.debug("Did not find %s in dumper" % (key))
                continue
            self.logger.debug("Calling %s" % (func))
            task_name = f"{dumper_name}_{key}"
            tasks.append(asyncio.create_task(self.func_wrapper(func, task_name=task_name), name=task_name))
        return tasks

    async def func_wrapper(self, func, task_name=None):
        """Execute a single dump method with error isolation and progress tracking.

        Each dump_* method runs inside this wrapper so that:
        1. Tokens are refreshed before execution (ensure_token)
        2. Exceptions are caught and returned rather than crashing other tasks
        3. Progress bar is updated on start/completion
        4. Methods with _manages_own_progress=True (e.g. dump_ual) skip auto-progress

        Returns:
            Tuple of (class_name, func_name, error_or_None) for the results summary.
        """
        error = None
        pm = get_progress_manager()
        manages_own_progress = getattr(func, '_manages_own_progress', False)
        if pm and task_name and not manages_own_progress:
            pm.start_task(task_name)
        try:
            self.ensure_token()
            error = await func()
        except Exception as e:
            self.logger.debug(f"{func.__name__} Failed with error {e}", exc_info=1)
            error = e
        if pm and task_name and not manages_own_progress:
            pm.complete_task(task_name, error=error)
        return self.__class__.__name__, func.__name__, error

    def __getattr__(self, attr):
        """Fallback for missing dump_* methods: logs a dry-run message instead of crashing.

        This enables --dry-run mode where DataDumper itself is used as the dumper,
        and any missing methods are handled gracefully with a log message.
        """
        self.logger.info("[DRY RUN] Calling %s" % (attr))
        async def default(*args, **kwargs):
            return attr
        return default

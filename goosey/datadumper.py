#!/usr/bin/env python
# -*- coding: utf-8 -*-

from goosey.utils import *
from goosey.progress import get_progress_manager

class DataDumper(object):
    def __init__(self, output_dir: str, reports_dir: str, app_auth: dict, session, debug, token_manager=None, endpoint_key=None):
        self.output_dir = output_dir
        self.reports_dir = reports_dir
        self.ahsession = session
        self.app_auth = app_auth
        self.logger = setup_logger(type(self).__module__, debug)
        self.token_manager = token_manager
        self.endpoint_key = endpoint_key

    def get_session(self):
        return self.ahsession

    def ensure_token(self, endpoint_key=None):
        """Ensure the token for the given endpoint (or the default) is still valid."""
        if self.token_manager is None:
            return
        key = endpoint_key or self.endpoint_key
        if key:
            self.token_manager.ensure_valid_token(key)

    def data_dump(self, calls, dumper_name) -> list:
        """

        :param calls: function calls to make mapped to params
        :type calls: dict
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
        self.logger.info("[DRY RUN] Calling %s" % (attr))
        async def default(*args, **kwargs):
            return attr
        return default

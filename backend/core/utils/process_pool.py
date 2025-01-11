import asyncio
import importlib
import inspect
import multiprocessing
import os
from concurrent.futures import ProcessPoolExecutor
from contextlib import asynccontextmanager

from core.utils import logger


def _import_and_run(module_name: str, func_name: str, *args, **kwargs):
    """Import and run a function in the subprocess"""
    module = importlib.import_module(module_name)
    func = getattr(module, func_name)

    # If the function is async, run it in a new event loop
    if inspect.iscoroutinefunction(func):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(func(*args, **kwargs))
        finally:
            loop.close()
    else:
        return func(*args, **kwargs)


class ProcessPoolManager:
    _instance = None
    _executor = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        if self._executor is None:
            # Both production and development use (cpu_count - 1) workers
            workers = max(1, multiprocessing.cpu_count() - 1)

            env_type = "production" if os.environ.get("GUNICORN_WORKER") else "development"
            logger.info(
                f"Initializing ProcessPoolExecutor with {workers} workers in {env_type} mode"
            )
            self._executor = ProcessPoolExecutor(max_workers=workers)

    @property
    def executor(self):
        return self._executor

    async def run_in_process(self, func, *args, **kwargs):
        """Run a function in the process pool"""
        loop = asyncio.get_event_loop()

        # Get the module path and function name
        module_name = func.__module__
        func_name = func.__name__

        # Run the function in the process pool
        return await loop.run_in_executor(
            self._executor, _import_and_run, module_name, func_name, *args, **kwargs
        )

    def shutdown(self):
        """Shutdown the process pool"""
        if self._executor:
            self._executor.shutdown(wait=True)
            self._executor = None


@asynccontextmanager
async def get_process_pool():
    """Context manager for process pool to ensure proper cleanup"""
    pool = ProcessPoolManager.get_instance()
    try:
        yield pool
    finally:
        # Don't shutdown on context exit - pool is managed by the singleton
        pass

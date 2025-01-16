import asyncio
import importlib
import inspect
import os
from concurrent.futures import ProcessPoolExecutor
from contextlib import asynccontextmanager

from fastapi import HTTPException

from core.utils.logger import logger


def _import_and_run(module_name: str, func_name: str, *args, **kwargs):
    """Import and run a function in the subprocess."""
    try:
        # Handle nested modules
        module_parts = module_name.split(".")
        module = importlib.import_module(module_parts[0])
        for part in module_parts[1:]:
            module = getattr(module, part)

        # Get the function from the module
        func = getattr(module, func_name)

        # If the function is async, run it in a new event loop
        if inspect.iscoroutinefunction(func):
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(func(*args, **kwargs))
                return result
            finally:
                loop.close()
        else:
            return func(*args, **kwargs)
    except Exception as e:
        logger.error(
            f"[ProcessPool] Error executing {func_name} in subprocess: {str(e)}", exc_info=True
        )
        return None  # Fail silently


class ProcessPoolManager:
    _instance = None
    _executor = None

    @classmethod
    def get_instance(cls):
        """Get the singleton instance of ProcessPoolManager."""
        if not cls._instance:
            cls._instance = ProcessPoolManager()
        return cls._instance

    def __init__(self):
        """Initialize the manager but not the executor yet."""
        pass

    def initialize(self):
        """Initialize the process pool executor."""
        if self._executor is None:
            try:
                # Keep 2 workers for CPU-intensive tasks (context scans, setup)
                workers = 2
                env_type = "production" if os.environ.get("GUNICORN_WORKER") else "development"
                logger.info(
                    f"Initializing ProcessPool with {workers} workers for CPU tasks in {env_type} mode"
                )
                self._executor = ProcessPoolExecutor(max_workers=workers)
            except Exception as e:
                logger.error(f"Failed to initialize ProcessPool: {str(e)}")
                # Don't raise, let it fail silently
                self._executor = None

    @property
    def executor(self):
        """Get the process pool executor, initialize if needed."""
        if self._executor is None:
            self.initialize()
        return self._executor

    async def run_in_process(self, func, *args, **kwargs):
        """Run a CPU-intensive function in the process pool."""
        if not self.executor:
            logger.error("ProcessPool is not initialized, running in main process")
            return None

        try:
            loop = asyncio.get_event_loop()
            logger.info(f"[ProcessPool] Delegating {func.__name__} to worker")
            result = await loop.run_in_executor(
                self.executor, _import_and_run, func.__module__, func.__name__, *args, **kwargs
            )
            logger.info(f"[ProcessPool] Worker completed {func.__name__}")
            return result
        except Exception as e:
            logger.error(
                f"[ProcessPool] Failed to execute function in process pool: {str(e)}", exc_info=True
            )
            return None

    def shutdown(self):
        """Shutdown the process pool."""
        if self._executor:
            try:
                self._executor.shutdown(wait=True)
            except Exception as e:
                logger.error(f"[ProcessPool] Failed to shutdown process pool: {str(e)}")
            finally:
                self._executor = None


@asynccontextmanager
async def get_process_pool():
    """
    Context manager for process pool to ensure proper cleanup.

    Yields:
        ProcessPoolManager: The process pool manager instance
    """
    try:
        pool = ProcessPoolManager.get_instance()
        yield pool
    except Exception as e:
        logger.error(f"[ProcessPool] Error in process pool context: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal Server Error") from e
    finally:
        # Don't shutdown on context exit - pool is managed by the singleton
        pass

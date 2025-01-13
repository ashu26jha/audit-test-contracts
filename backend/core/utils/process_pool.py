import asyncio
import importlib
import inspect
import multiprocessing
import os
from concurrent.futures import ProcessPoolExecutor
from contextlib import asynccontextmanager

from fastapi import HTTPException

from core.utils.logger import logger


def _import_and_run(module_name: str, func_name: str, *args, **kwargs):
    """Import and run a function in the subprocess."""
    try:
        module = importlib.import_module(module_name)
        func = getattr(module, func_name)

        # If the function is async, run it in a new event loop
        if inspect.iscoroutinefunction(func):
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(func(*args, **kwargs))
                return result
            except Exception as e:
                logger.error(
                    f"[ProcessPool] Error executing {func_name} in event loop: {str(e)}",
                    exc_info=True,
                )
                raise
            finally:
                loop.close()
        else:
            return func(*args, **kwargs)
    except Exception as e:
        logger.error(
            f"[ProcessPool] Unexpected error in subprocess for {func_name}: {str(e)}", exc_info=True
        )
        raise HTTPException(status_code=500, detail="Internal Server Error") from e


class ProcessPoolManager:
    _instance = None
    _executor = None

    @classmethod
    def get_instance(cls):
        """Get the singleton instance of ProcessPoolManager."""

        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        """Initialize the process pool."""
        if self._executor is None:
            try:
                # Both production and development use (cpu_count - 1) workers
                workers = max(1, multiprocessing.cpu_count() - 1)

                env_type = "production" if os.environ.get("GUNICORN_WORKER") else "development"
                logger.info(
                    f"Initializing ProcessPoolExecutor with {workers} workers in {env_type} mode"
                )
                self._executor = ProcessPoolExecutor(max_workers=workers)
            except Exception as e:
                raise HTTPException(status_code=500, detail="Internal Server Error") from e

    @property
    def executor(self):
        """Get the process pool executor."""
        return self._executor

    async def run_in_process(self, func, *args, **kwargs):
        """
        Run a function in the process pool.

        Args:
            func: The function to run
            *args: Positional arguments for the function
            **kwargs: Keyword arguments for the function

        Returns:
            The result of the function
        """
        if not self._executor:
            raise EnvironmentError(
                message="Process pool is not initialized", details={"state": "shutdown"}
            )

        try:
            loop = asyncio.get_event_loop()

            # Get the module path and function name
            module_name = func.__module__
            func_name = func.__name__

            # Run the function in the process pool
            return await loop.run_in_executor(
                self._executor, _import_and_run, module_name, func_name, *args, **kwargs
            )
        except Exception as e:
            logger.error(
                f"[ProcessPool] Failed to execute function in process pool: {str(e)}", exc_info=True
            )
            raise HTTPException(status_code=500, detail="Internal Server Error") from e

    def shutdown(self):
        """Shutdown the process pool."""
        if self._executor:
            try:
                self._executor.shutdown(wait=True)
                self._executor = None
            except Exception as e:
                logger.error(
                    f"[ProcessPool] Failed to shutdown process pool: {str(e)}", exc_info=True
                )
                raise HTTPException(status_code=500, detail="Internal Server Error") from e


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

import asyncio
import subprocess
from typing import Dict, List, Tuple

from common import logger


async def run_command(
    command: List[str], cwd: str, env: Dict[str, str] = None
) -> Tuple[int, str, str]:
    """
    Executes a command asynchronously and captures its output.

    Args:
        command (List[str]): The command and its arguments to execute.
        cwd (str): The working directory to run the command in.
        env (Dict[str, str], optional): Environment variables to set for the command.

    Returns:
        Tuple[int, str, str]: A tuple containing the return code, stdout, and stderr.
    """
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            cwd=cwd,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        return process.returncode, stdout.decode(), stderr.decode()
    except Exception as e:
        logger.exception(
            f"Exception occurred while running command '{' '.join(command)}': {str(e)}"
        )
        raise


def run_command_sync(
    command: List[str], cwd: str, env: Dict[str, str] = None
) -> Tuple[int, str, str]:
    """
    Executes a command synchronously and captures its output.

    Args:
        command (List[str]): The command and its arguments to execute.
        cwd (str): The working directory to run the command in.
        env (Dict[str, str], optional): Environment variables to set for the command.

    Returns:
        Tuple[int, str, str]: A tuple containing the return code, stdout, and stderr.
    """
    try:
        with subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True
        ) as process:
            stdout, stderr = process.communicate(timeout=10)
            return_code = process.returncode
            return return_code, stdout, stderr
    except Exception as e:
        logger.exception(
            f"Exception occurred while running command '{' '.join(command)}' synchronously: {str(e)}"
        )
        raise

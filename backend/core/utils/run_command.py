import asyncio
import shutil
from typing import Dict, List, Tuple

from core.utils.errors import DependencyError, EnvironmentError
from core.utils.logger import logger


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

    Raises:
        DependencyError: If the required command is not found in PATH
        EnvironmentError: If there's an error executing the command
    """
    try:
        # Check if command exists in PATH
        if command[0] in ["npm", "forge", "git"]:
            executable = shutil.which(command[0])
            if not executable:
                raise DependencyError(
                    message=f"{command[0]} not found in PATH",
                    details={"command": command[0], "path": shutil.get_exec_path()},
                )
            command[0] = executable

        process = await asyncio.create_subprocess_exec(
            *command,
            cwd=cwd,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        return process.returncode, stdout.decode(), stderr.decode()
    except DependencyError:
        raise
    except Exception as e:
        logger.exception(
            f"Exception occurred while running command '{' '.join(command)}': {str(e)}"
        )
        raise EnvironmentError(
            message="Failed to execute command",
            details={"command": " ".join(command), "cwd": cwd, "error": str(e)},
        ) from e

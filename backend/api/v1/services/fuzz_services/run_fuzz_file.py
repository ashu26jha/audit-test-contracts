import asyncio

from common import logger  # Ensure logger is imported


async def run_fuzz_file(project_dir: str) -> str:
    """
    Runs the fuzz test using Foundry in the specified project directory.

    Args:
        project_dir (str): The directory where the Foundry project is located.

    Returns:
        str: The output of the fuzz test or an error message.
    """
    try:
        process = await asyncio.create_subprocess_exec(
            "forge",
            "test",
            "-vvvv",
            cwd=project_dir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

        output = stdout.decode() if stdout else ""
        error = stderr.decode() if stderr else ""

        return output if output else error
    except Exception as e:
        logger.error(f"Error running fuzz test: {str(e)}")
        return str(e)

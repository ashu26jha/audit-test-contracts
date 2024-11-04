from api.v1.helpers.run_command import run_command
from common import logger
from config.solidity import FORGE_TEST_COMMAND


async def run_fuzz_file(project_dir: str) -> str:
    """
    Executes the fuzz test using Foundry in the specified project directory.
    The function constructs the command to run the fuzz tests and captures
    the output, including any errors that may occur during execution.

    Args:
        project_dir (str): The directory where the Foundry project is located.

    Returns:
        str: The output of the fuzz test execution, which may include success messages
             or error details if the execution fails.
    """
    logger.info("Running fuzz tests...")

    try:
        returncode, stdout, stderr = await run_command(FORGE_TEST_COMMAND, cwd=project_dir)

        # Combine stdout and stderr for full output
        full_output = stdout + stderr

        if returncode != 0:
            logger.warning(f"Forge test completed with non-zero exit code: {returncode}")
            logger.warning(full_output)
            return full_output

        logger.info("Fuzz test completed successfully")
        return full_output

    except Exception as e:
        # logger.error(f"Error running fuzz test: {str(e)}")
        logger.exception("Error running fuzz test")
        return str(e)

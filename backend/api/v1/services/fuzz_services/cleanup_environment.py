import asyncio
import shutil


async def cleanup_environment(project_dir: str) -> None:
    """
    Cleans up the environment by deleting the temporary project directory.

    Args:
        project_dir (str): The directory of the project to be deleted.
    """
    try:
        await asyncio.to_thread(shutil.rmtree, project_dir)
        print(f"Cleaned up temporary environment: {project_dir}")
    except Exception as e:
        print(f"Error cleaning up environment: {str(e)}")

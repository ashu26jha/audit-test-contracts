from fastapi import HTTPException
from common.logger import logger
def handle_exception(e: Exception):
    logger.error(f"An error occurred: {str(e)}")
    raise HTTPException(status_code=500, detail="Internal server error")
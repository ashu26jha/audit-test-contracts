from uuid import UUID

from config.settings import ELIZA_CALLBACK_URL
from core.utils import logger
from core.utils.http_client import get_http_client


async def send_callback_status(scan_id: UUID, user_name: str, success: bool, message: str):
    """Send callback status to the requesting service."""

    try:
        async with get_http_client() as client:
            payload = {
                "scan_id": str(scan_id),
                "user_name": user_name,
                "success": success,
                "message": message,
            }
            response = await client.post(ELIZA_CALLBACK_URL, json=payload)
            response.raise_for_status()
            logger.info(f"[Agentic] Callback sent successfully for scan {scan_id}")
    except Exception as e:
        logger.error(f"[Agentic] Failed to send callback for scan {scan_id}: {str(e)}")
        # We don't want to raise the error here as this is a non-critical operation

from uuid import UUID

import httpx

from core.utils import logger

# TODO: Replace with actual callback URL from config/settings
CALLBACK_URL = "http://localhost:3000/api/scan-callback"


async def send_callback_status(scan_id: UUID, success: bool, message: str):
    """Send callback status to the requesting service."""

    try:
        async with httpx.AsyncClient() as client:
            payload = {"scan_id": str(scan_id), "success": success, "message": message}
            response = await client.post(CALLBACK_URL, json=payload)
            response.raise_for_status()
            logger.info(f"[Agentic] Callback sent successfully for scan {scan_id}")
    except Exception as e:
        logger.error(f"[Agentic] Failed to send callback for scan {scan_id}: {str(e)}")
        # We don't want to raise the error here as this is a non-critical operation

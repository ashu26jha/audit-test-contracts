from uuid import UUID

from config.settings import ELIZA_CALLBACK_URL
from core.db.repositories.scan import ScanRepository
from core.utils.http_client import get_http_client
from core.utils.logger import logger


async def send_callback_status(scan_id: UUID, user_name: str | None, success: bool, message: str):
    """
    Send callback to the requesting service.
    - Only send the scan status if the user name is provided (send the PDF report to the user directly)
    - Otherwise, send the scan results to the requesting service as JSON
    """
    payload = {}

    if user_name:
        payload = {
            "scan_id": str(scan_id),
            "user_name": user_name,
            "success": success,
            "message": message,
        }
    else:
        scan_results_json = await ScanRepository.get_scan_result(scan_id)
        payload = {
            "scan_id": str(scan_id),
            "results": scan_results_json.findings,
            "success": success,
            "message": message,
        }

    try:
        async with get_http_client() as client:
            response = await client.post(ELIZA_CALLBACK_URL, json=payload)
            response.raise_for_status()

        logger.info(f"[Agentic] Callback sent successfully for scan {scan_id}")

    except Exception as e:
        logger.error(f"[Agentic] Failed to send callback for scan {scan_id}: {str(e)}")
        # We don't want to raise the error here as this is a non-critical operation

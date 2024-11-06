from datetime import datetime, timezone
from uuid import UUID

from api.v1.services import scan_history_service
from common import logger
from common.email_utils import send_error_email


async def update_scan_failure(email: str, scan_id: UUID, message: str) -> None:
    """Update scan and scan result with failure status and message."""
    try:
        await scan_history_service.update_scan_status(scan_id, "failed")

        scan_result = await scan_history_service.get_scan_result(scan_id)
        scan_result.info_message = message
        scan_result.completedAt = datetime.now(timezone.utc)
        await scan_result.save()

        # Send an email to the user with the error message
        await send_error_email(email, scan_id, scan_result.scan_number)

        logger.error(f"Scan {scan_id} failed: {message}")
    except Exception as e:
        logger.exception(f"Error updating scan failure: {str(e)}")

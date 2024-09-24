
from typing import List


from common import logger
from fastapi import HTTPException

from scan_history_service import get_scan, get_full_scan_result


async def generate_pdf(scan_id: str):
    """
    Generate a PDF from the scan data.
    """
    scan = await get_scan(scan_id)
    full_result = await get_full_scan_result(scan_id)

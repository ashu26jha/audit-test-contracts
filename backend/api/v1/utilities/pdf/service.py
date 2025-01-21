import asyncio
from pathlib import Path
from uuid import UUID

from fastapi import HTTPException

from api.v1.utilities.pdf.helpers.pdf_assembly import combine_pdfs
from api.v1.utilities.pdf.helpers.pdf_generation import cleanup_temp_file, generate_pdf_from_html
from api.v1.utilities.pdf.helpers.template_helpers import (
    create_report_html_unified,
    extract_organization_name,
)
from core.db.repositories.scan import ScanRepository
from core.models.scan import Scan, ScanResult
from core.models.user import User
from core.utils.email_utils import send_pdf_email
from core.utils.logger import logger
from core.utils.process_pool import get_process_pool
from core.utils.validate import validate_user_scan_access


# Entry points for regular scans (require User)
async def generate_pdf_from_scan(user: User, scan_id: UUID) -> Path:
    """
    Generate a PDF report from a regular scan.
    Requires a User object for validation.

    Args:
        user: User object for validation
        scan_id: The ID of the scan to generate PDF for

    Returns:
        Path to the generated PDF file

    Raises:
        HTTPException: If validation fails or PDF generation fails
    """
    try:
        await validate_user_scan_access(scan_id, user)
        scan = await ScanRepository.get_scan(scan_id)
        scan_result = await ScanRepository.get_scan_result(scan_id)
        return await _generate_pdf_report_internal(scan, scan_result, agentic=False)
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error during PDF generation: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to generate PDF report") from e


async def generate_and_send_pdf_from_scan(user: User, scan_id: UUID) -> None:
    """
    Generate and send a PDF report from a regular scan.
    Requires a User object for validation and email delivery.

    Args:
        user: User object for validation and email
        scan_id: The ID of the scan to generate PDF for

    Raises:
        HTTPException: If validation fails
    """
    try:
        await validate_user_scan_access(scan_id, user)
        scan = await ScanRepository.get_scan(scan_id)
        scan_result = await ScanRepository.get_scan_result(scan_id)

        async with get_process_pool() as pool:
            task = pool.run_in_process(
                _generate_and_send_pdf,
                scan_result,
                scan.repositoryName,
                scan.branchName,
                scan.commitHash,
                scan.repositoryURL,
                scan.contractFiles,
                scan.linesOfCode.total_lines if scan.linesOfCode else 0,
                scan.scan_number,
                str(scan_id),  # Convert UUID to string for process pool
                user.email,
                False,  # agentic flag
            )
            success = await asyncio.wait_for(task, timeout=300)  # 5 minutes timeout

            if not success:
                raise HTTPException(
                    status_code=500, detail="Failed to generate and send PDF report"
                )

    except HTTPException:
        raise
    except asyncio.TimeoutError as e:
        logger.error(f"PDF generation and email sending timed out for scan ID: {scan_id}")
        raise HTTPException(status_code=500, detail="Operation timed out") from e
    except Exception as e:
        logger.exception(f"Error during PDF generation and email sending: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to generate and send PDF report") from e


# Entry points for agentic scans (require email)
async def generate_agentic_pdf(scan_id: UUID) -> Path:
    """
    Generate a PDF report from an agentic scan.
    Requires an email address.

    Args:
        scan_id: The ID of the scan to generate PDF for
        email: Email address for the report

    Returns:
        Path to the generated PDF file

    Raises:
        HTTPException: If PDF generation fails
    """
    try:
        scan = await ScanRepository.get_scan(scan_id)
        scan_result = await ScanRepository.get_scan_result(scan_id)
        return await _generate_pdf_report_internal(scan, scan_result, agentic=True)
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error during PDF generation: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to generate PDF report") from e


async def generate_and_send_agentic_pdf(scan_id: UUID, email: str) -> None:
    """
    Generate and send a PDF report from an agentic scan.

    Args:
        scan_id: The ID of the scan to generate PDF for
        email: Email address to send the report to

    Raises:
        HTTPException: If generation or sending fails
    """
    try:
        scan = await ScanRepository.get_scan(scan_id)
        scan_result = await ScanRepository.get_scan_result(scan_id)

        async with get_process_pool() as pool:
            task = pool.run_in_process(
                _generate_and_send_pdf,
                scan_result,
                scan.repositoryName,
                scan.branchName,
                scan.commitHash,
                scan.repositoryURL,
                scan.contractFiles,
                scan.linesOfCode.total_lines if scan.linesOfCode else 0,
                scan.scan_number,
                str(scan_id),  # Convert UUID to string for process pool
                email,
                True,  # agentic flag
                scan.contract_address,
                scan.chain_id,
            )
            success = await asyncio.wait_for(task, timeout=300)  # 5 minutes timeout

            if not success:
                raise HTTPException(
                    status_code=500, detail="Failed to generate and send PDF report"
                )

    except HTTPException:
        raise
    except asyncio.TimeoutError as e:
        logger.error(f"PDF generation and email sending timed out for scan ID: {scan_id}")
        raise HTTPException(status_code=500, detail="Operation timed out") from e
    except Exception as e:
        logger.exception(f"Error during PDF generation and email sending: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to generate and send PDF report") from e


# Internal helper functions
async def _generate_and_send_pdf(
    scan_result: ScanResult,
    repository_name: str,
    branch_name: str,
    commit_hash: str,
    repository_url: str,
    contract_files: list,
    lines_of_code: int,
    scan_number: int,
    scan_id: str,
    email: str,
    agentic: bool,
    contract_address: str = None,
    chain_id: str = None,
) -> bool:
    """Generate PDF and send email in one worker process."""
    try:
        # Create report data directly with only what we need
        report_data = {
            "summary": scan_result.summary,
            "total_vulnerabilities": scan_result.total_findings,
            "total_lines_of_code": lines_of_code,
            "contract_files": contract_files,
            "findings": scan_result.findings,
            "scan_id": scan_id,
            "scan_number": scan_number,
        }

        if agentic:
            report_data.update(
                {
                    "chain": chain_id,
                    "ethereum_address": contract_address,
                    "date": scan_result.completedAt.isoformat() if scan_result.completedAt else "",
                }
            )
        else:
            report_data.update(
                {
                    "organization": extract_organization_name(repository_url or ""),
                    "repository_name": repository_name,
                    "branch_name": branch_name,
                    "commit_hash": commit_hash,
                }
            )

        html_content = await create_report_html_unified(report_data, agentic=agentic)
        pdf_filename = f"audit_agent_report_{scan_number}.pdf"
        report_pdf_path = await generate_pdf_from_html(html_content, pdf_filename)
        final_pdf_path = combine_pdfs(report_pdf_path)

        try:
            await send_pdf_email(email, str(final_pdf_path), scan_id)
            return True
        finally:
            # Clean up all temporary files after sending email
            cleanup_temp_file(report_pdf_path)
            cleanup_temp_file(final_pdf_path)
    except Exception as e:
        logger.exception(f"Error during PDF generation and email sending: {str(e)}")
        return False


async def _generate_pdf_report_internal(
    scan: Scan,
    scan_result: ScanResult,
    agentic: bool,
) -> Path:
    """Internal function to generate PDF report from scan data."""
    try:
        report_data = {
            "summary": scan_result.summary,
            "total_vulnerabilities": scan_result.total_findings,
            "total_lines_of_code": scan.linesOfCode.total_lines or 0,
            "contract_files": scan.contractFiles,
            "findings": scan_result.findings,
            "scan_id": scan.scan_id,
            "scan_number": scan.scan_number,
        }

        if agentic:
            report_data.update(
                {
                    "chain": scan.chain_id,
                    "ethereum_address": scan.contract_address,
                    "date": scan.completedAt.isoformat() if scan.completedAt else "",
                }
            )
        else:
            report_data.update(
                {
                    "organization": extract_organization_name(scan.repositoryURL or ""),
                    "repository_name": scan.repositoryName,
                    "branch_name": scan.branchName,
                    "commit_hash": scan.commitHash,
                }
            )

        html_content = await create_report_html_unified(report_data, agentic=agentic)
        pdf_filename = f"audit_agent_report_{scan.scan_number}.pdf"
        report_pdf_path = await generate_pdf_from_html(html_content, pdf_filename)
        final_pdf_path = combine_pdfs(report_pdf_path)
        logger.info(f"PDF generated successfully for scan ID: {scan.scan_id}")

        # Clean up intermediate PDF
        cleanup_temp_file(report_pdf_path)

        return final_pdf_path
    except Exception:
        # Clean up any files that might have been created
        if "report_pdf_path" in locals():
            cleanup_temp_file(report_pdf_path)
        if "final_pdf_path" in locals():
            cleanup_temp_file(final_pdf_path)
        raise

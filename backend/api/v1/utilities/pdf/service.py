from uuid import UUID

from fastapi import HTTPException

from api.v1.utilities.pdf.helpers.pdf_assembly import combine_pdfs
from api.v1.utilities.pdf.helpers.pdf_generation import cleanup_temp_file, generate_pdf_from_html
from api.v1.utilities.pdf.helpers.template_helpers import (
    create_report_html_unified,
    extract_organization_name,
)
from core.db.repositories.scan import ScanRepository
from core.models.scan import ScanResult
from core.models.user import User
from core.utils.email_utils import send_pdf_email
from core.utils.logger import logger
from core.utils.validate import validate_user_scan_access


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

        # Run directly in the current process
        success = await _generate_and_send_pdf(
            scan_result,
            scan.repositoryName,
            scan.branchName,
            scan.commitHash,
            scan.repositoryURL,
            scan.contractFiles,
            scan.linesOfCode.total_lines if scan.linesOfCode else 0,
            scan.scan_number,
            str(scan_id),
            user.email,
            False,  # agentic flag
        )

        if not success:
            raise HTTPException(status_code=500, detail="Failed to generate and send PDF report")

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error during PDF generation and email sending: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to generate and send PDF report") from e


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

        # Run directly in the current process
        success = await _generate_and_send_pdf(
            scan_result,
            scan.repositoryName,
            scan.branchName,
            scan.commitHash,
            scan.repositoryURL,
            scan.contractFiles,
            scan.linesOfCode.total_lines if scan.linesOfCode else 0,
            scan.scan_number,
            str(scan_id),
            email,
            True,  # agentic flag
            scan.contract_address,
            scan.chain_id,
        )

        if not success:
            raise HTTPException(status_code=500, detail="Failed to generate and send PDF report")

    except HTTPException:
        raise
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

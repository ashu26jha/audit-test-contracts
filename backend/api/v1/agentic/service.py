from uuid import UUID

from fastapi import BackgroundTasks, HTTPException
from langfuse.decorators import langfuse_context, observe

from api.v1.agentic.helpers.result_processor import ResultProcessor
from api.v1.agentic.helpers.scan_initializer import AgenticScanInitializer
from api.v1.agentic.helpers.task_manager import TaskManager
from api.v1.agentic.schema import AgenticScanContext, PerAddressAgenticRequest
from core.db.repositories.scan import ScanRepository
from core.models.scan import Scan
from core.utils.email_utils import send_error_email
from core.utils.logger import logger

TWITTER_BOT_EMAIL = "auditagent@nethermind.io"


class AgenticService:
    @staticmethod
    async def create_scan_per_address(
        scan_id: UUID,
        request: PerAddressAgenticRequest,
        background_tasks: BackgroundTasks,
    ):

        # TODO: Add logic to fetch contract code from address
        # TODO: Add logic to remove libraries from contract code
        initializer = AgenticScanInitializer(request, scan_id)

        try:
            # Create scan record
            scan_number = await Scan.get_next_agentic_scan_number(request.contractAddress)
            await initializer.create_agentic_scan_record(scan_number or 1)

            # Create agentic scan context
            context = AgenticScanContext(
                scan_id=scan_id,
                contract_address=request.contractAddress,
                chain_id=request.chainID,
                contract_files=request.contractFiles,
                flattened_contracts="flattened_contracts",
            )

            # Start initialization in background
            background_tasks.add_task(
                AgenticService._perform_audit_agent_background,
                context,
            )

        except HTTPException:
            raise
        except Exception as e:
            logger.exception(f"Unexpected error during scan initiation: {str(e)}")
            await ScanRepository.update_scan_failure(scan_id, "Failed to initiate audit scan")
            await send_error_email(TWITTER_BOT_EMAIL, scan_id)
            raise HTTPException(status_code=500, detail="Failed to initiate audit scan") from e

    @staticmethod
    @observe(name="agentic_background_scan")
    async def _perform_audit_agent_background(
        context: AgenticScanContext,
    ):
        logger.info(f"Starting agentic background audit scan with ID: {context.scan_id}")

        try:
            # Initialize TaskManager
            task_manager = TaskManager(
                context=context,
            )

            # Initialize scan and detectors
            await task_manager.initialize_scan()

            # Start tasks (will skip Slither if setup_result is None)
            await task_manager.start_tasks()

            # Gather and process results
            results = await task_manager.gather_results()

            combined_findings = results["combined_findings"]
            summary_result = results["summary_result"]
            detected_type = results["detected_type"]

            # Process results using ResultProcessor
            result_processor = ResultProcessor(
                context=context,
                combined_findings=combined_findings,
                flattened_contracts=context.flattened_contracts,
                summary_result=summary_result,
                detected_type=detected_type,
            )
            await result_processor.process_results()
            total_findings_after_dedup = result_processor.get_total_findings()

            langfuse_context.update_current_trace(session_id=str(context.scan_id))

            # Update scan status to 'completed' and include total_findings
            await ScanRepository.update_scan_status(
                context.scan_id, "completed", total_findings_after_dedup
            )

            # TODO: Generate PDF and send back to ELIZA BOT

            logger.info(f"Completed agentic audit scan with ID: {context.scan_id}")
        except HTTPException as e:
            error_msg = f"Error in agentic audit scan {context.scan_id}: {str(e)}"
            logger.exception(error_msg)
            await ScanRepository.update_scan_failure(context.scan_id, e.detail)
            await send_error_email(TWITTER_BOT_EMAIL, context.scan_id)
            raise

        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"
            logger.exception(error_msg)
            await ScanRepository.update_scan_failure(context.scan_id, error_msg)
            await send_error_email(TWITTER_BOT_EMAIL, context.scan_id)
            raise HTTPException(status_code=500, detail=error_msg) from e

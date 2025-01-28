from uuid import UUID

from fastapi import HTTPException
from langfuse.decorators import langfuse_context, observe

from api.v1.agentic.helpers.eliza_callback import send_callback_status
from api.v1.agentic.helpers.scan_initializer import AgenticScanInitializer
from api.v1.agentic.helpers.task_manager import TaskManager
from api.v1.agentic.schema import AgenticScanContext, PerAddressAgenticRequest
from api.v1.common.result_processor import ResultProcessor
from api.v1.utilities.etherscan.service import EtherscanService
from api.v1.utilities.pdf.service import generate_and_send_agentic_pdf
from core.db.connection import close_database, huey, init_database
from core.db.repositories.scan import ScanRepository
from core.models.scan import Scan
from core.utils.logger import logger


class AgenticService:
    @staticmethod
    async def create_scan_per_address(scan_id: UUID, request: PerAddressAgenticRequest):
        try:
            # Fetch and validate contract source code from Etherscan
            contracts_dict = await EtherscanService.get_contract_source(
                request.contractAddress, request.chainId
            )

            if not contracts_dict:
                raise HTTPException(
                    status_code=400,
                    detail=f"Could not fetch source code for contract {request.contractAddress} on chain {request.chainId}. Contract might not be verified.",
                )

            flattened_contracts = ""
            for _, contract in contracts_dict.items():
                flattened_contracts += contract.content

            if not flattened_contracts.strip():
                raise HTTPException(
                    status_code=400,
                    detail=f"No source code content found for contract {request.contractAddress}",
                )

            initializer = AgenticScanInitializer(request, scan_id)

            try:
                # Create scan record
                scan_number = await Scan.get_next_agentic_scan_number(request.contractAddress)
                scan_number = scan_number or 1

                # Get contract files from the contracts dictionary
                contract_files = list(contracts_dict.keys())

                # Correctly call the instance method with contract_files
                await initializer.create_agentic_scan_record(scan_number, contract_files)
                await initializer.count_lines_of_code(flattened_contracts)

                # Create agentic scan context
                context = AgenticScanContext(
                    scan_id=scan_id,
                    user_email=request.userEmail,
                    user_name=request.userName,
                    contract_address=request.contractAddress,
                    chain_id=request.chainId,
                    contract_files=contract_files,
                    flattened_contracts=flattened_contracts,
                )

                # Queue scan for background processing in Huey worker
                perform_agentic_background(context)

            except HTTPException:
                raise
            except Exception as e:
                logger.exception(f"[Agentic] Unexpected error during scan initiation: {str(e)}")
                error_msg = f"Failed to initiate agentic scan for scan ID: {str(scan_id)}"
                await ScanRepository.update_scan_failure(scan_id, error_msg)
                await send_callback_status(
                    scan_id=scan_id,
                    user_name=request.userName,
                    success=False,
                    message=error_msg,
                )
                raise HTTPException(status_code=500, detail=error_msg) from e

        except HTTPException:
            raise
        except Exception as e:
            logger.exception(
                f"[Agentic] Error processing contract {request.contractAddress}: {str(e)}"
            )
            raise HTTPException(
                status_code=500, detail=f"Failed to process contract {request.contractAddress}"
            ) from e


@huey.task(retries=2, retry_delay=10, priority=6)
def perform_agentic_background(context: AgenticScanContext):
    """
    Background task to perform the agentic scan.

    Runs in a separate Huey worker process with database connection management.
    Handles the complete scan lifecycle including summary generation, context scans,
    and result processing.

    Args:
        context (AgenticScanContext): Complete context for the scan including
            contract information and configuration.
    """
    logger.info(f"[Agentic] Starting agentic background audit scan with ID: {context.scan_id}")

    import asyncio
    import os

    os.environ["HUEY_WORKER"] = "1"

    @observe(name="agentic_background_scan")
    async def _async_perform_scan():
        try:
            # Initialize database first
            await init_database()

            # Initialize TaskManager
            task_manager = TaskManager(context)

            # Initialize scan and detectors
            await task_manager.initialize_scan()

            # Start tasks
            await task_manager.start_tasks()

            # Gather and process results
            results = await task_manager.gather_results()

            combined_findings = results["combined_findings"]
            summary_result = results["summary_result"]
            detected_type = results["detected_type"]

            # Process results using ResultProcessor
            result_processor = ResultProcessor(
                scan_id=context.scan_id,
                user_id=None,
                contract_files=context.contract_files,
                combined_findings=combined_findings,
                flattened_contracts=context.flattened_contracts,
                summary_result=summary_result,
                detected_type=detected_type,
            )

            # Process results and update final scan status
            await result_processor.process_results()
            total_findings_after_dedup = result_processor.get_total_findings()

            langfuse_context.update_current_trace(session_id=str(context.scan_id))

            # Update scan status to 'completed' and include total_findings
            await ScanRepository.update_scan_status(
                context.scan_id, "completed", total_findings_after_dedup
            )

            # Send success callback
            await send_callback_status(
                scan_id=context.scan_id,
                user_name=context.user_name,
                success=True,
                message=f"Scan completed successfully with {total_findings_after_dedup} findings",
            )

            # Generate PDF without blocking scan completion
            if context.user_email:
                await generate_and_send_agentic_pdf(context.scan_id, context.user_email)
            else:
                logger.warning("[Agentic] User email not configured, skipping PDF generation.")

            logger.info(f"[Agentic] Completed agentic audit scan with ID: {context.scan_id}")

        except HTTPException as e:
            error_msg = f"[Agentic] Error in agentic audit scan {context.scan_id}: {str(e)}"
            logger.exception(error_msg)
            await ScanRepository.update_scan_failure(context.scan_id, e.detail)
            await send_callback_status(
                scan_id=context.scan_id,
                user_name=context.user_name,
                success=False,
                message=e.detail,
            )
            raise

        except Exception as e:
            error_msg = f"[Agentic] Unexpected error: {str(e)}"
            logger.exception(error_msg)
            await ScanRepository.update_scan_failure(context.scan_id, error_msg)
            await send_callback_status(
                scan_id=context.scan_id,
                user_name=context.user_name,
                success=False,
                message=error_msg,
            )
            raise HTTPException(status_code=500, detail=error_msg) from e

        finally:
            await close_database()

    try:
        # Revert to basic asyncio.run instead of manual loop
        asyncio.run(_async_perform_scan())
    except Exception as e:
        logger.exception(f"[Agentic] Error in Huey task: {str(e)}")
        raise

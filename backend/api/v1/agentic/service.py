from uuid import UUID

from fastapi import BackgroundTasks, HTTPException
from langfuse.decorators import langfuse_context, observe

from api.v1.agentic.helpers.eliza_callback import send_callback_status
from api.v1.agentic.helpers.scan_initializer import AgenticScanInitializer
from api.v1.agentic.helpers.task_manager import TaskManager
from api.v1.agentic.schema import AgenticScanContext, PerAddressAgenticRequest
from api.v1.common.result_processor import ResultProcessor
from api.v1.utilities.etherscan.service import EtherscanService
from api.v1.utilities.pdf.service import generate_and_send_agentic_pdf
from core.db.repositories.scan import ScanRepository
from core.models.scan import Scan
from core.utils.logger import logger


class AgenticService:
    @staticmethod
    async def create_scan_per_address(
        scan_id: UUID,
        request: PerAddressAgenticRequest,
        background_tasks: BackgroundTasks,
    ):
        try:
            # fetch contract code from address
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
                    contract_address=request.contractAddress,
                    chain_id=request.chainId,
                    contract_files=contract_files,
                    flattened_contracts=flattened_contracts,
                )

                # Start initialization in background
                background_tasks.add_task(
                    AgenticService._perform_audit_agent_background,
                    context,
                )

            except HTTPException:
                raise
            except Exception as e:
                logger.exception(f"[Agentic] Unexpected error during scan initiation: {str(e)}")
                await ScanRepository.update_scan_failure(scan_id, "Failed to initiate audit scan")
                await send_callback_status(
                    scan_id,
                    success=False,
                    message=f"Failed to initiate audit scan for scan ID: {str(scan_id)}",
                )
                raise HTTPException(status_code=500, detail="Failed to initiate audit scan") from e

        except HTTPException:
            raise
        except Exception as e:
            logger.exception(
                f"[Agentic] Error processing contract {request.contractAddress}: {str(e)}"
            )
            raise HTTPException(
                status_code=500, detail=f"Failed to process contract {request.contractAddress}"
            ) from e

    @staticmethod
    @observe(name="agentic_background_scan")
    async def _perform_audit_agent_background(
        context: AgenticScanContext,
    ):
        logger.info(f"[Agentic] Starting agentic background audit scan with ID: {context.scan_id}")

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
                scan_id=context.scan_id,
                user_id=None,
                contract_files=context.contract_files,
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

            # Send success callback
            await send_callback_status(
                context.scan_id,
                success=True,
                message=f"Scan completed successfully with {total_findings_after_dedup} findings",
            )

            # Generate PDF without blocking scan completion
            if context.user_email:
                await generate_and_send_agentic_pdf(context.scan_id, context.user_email)
            else:
                logger.warning("User email not configured, skipping PDF generation.")

            logger.info(f"[Agentic] Completed agentic audit scan with ID: {context.scan_id}")
        except HTTPException as e:
            error_msg = f"[Agentic] Error in agentic audit scan {context.scan_id}: {str(e)}"
            logger.exception(error_msg)
            await ScanRepository.update_scan_failure(context.scan_id, e.detail)
            await send_callback_status(context.scan_id, success=False, message=e.detail)
            raise

        except Exception as e:
            error_msg = f"[Agentic] Unexpected error: {str(e)}"
            logger.exception(error_msg)
            await ScanRepository.update_scan_failure(context.scan_id, error_msg)
            await send_callback_status(context.scan_id, success=False, message=error_msg)
            raise HTTPException(status_code=500, detail=error_msg) from e

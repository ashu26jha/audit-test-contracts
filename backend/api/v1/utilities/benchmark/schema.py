from dataclasses import dataclass
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator

from config.settings import SUPPORTED_MODELS
from core.schemas.context_protocols import (
    BenchmarkContext,
    CompilationContext,
    GitHubContext,
    UserContext,
)
from core.schemas.scan_schema import BaseScanContext, ModeType, ScanType, SetupResult, TypeOfScan


class BenchmarkScanRequest(BaseModel):
    """
    Schema for benchmark scan requests.
    Similar to AuditAgentRequest but without user validation and with additional benchmark-specific fields.
    """

    repositoryURL: str = Field(..., description="URL of the GitHub repository to scan")
    contractFiles: List[str] = Field(
        ...,
        description="Array of relative file paths within the repository (e.g., contracts/MyContract.sol)",
    )
    branchName: str = Field(
        "main", description="Name of the branch to scan. Defaults to 'main' if not provided."
    )
    typeOfScan: TypeOfScan = Field(
        default=TypeOfScan.AUDIT_AGENT,
        description="Type of scan to benchmark: 'auditagent' for full scan or 'model' for LLM-only scan",
    )
    model: Optional[str] = Field(
        None,
        description="LLM model to use for the scan. Required if typeOfScan is 'model'",
    )
    mode: Optional[ModeType] = Field(
        None,
        description="Mode to use for the scan. Defaults to 'few_shots' if not provided.",
    )

    @field_validator("typeOfScan", mode="before")
    @classmethod
    def validate_type_of_scan(cls, v: str) -> TypeOfScan:
        if isinstance(v, TypeOfScan):
            return v
        try:
            return TypeOfScan(v.upper())
        except ValueError as e:
            raise ValueError(
                f"Invalid scan type. Must be one of: {[t.value for t in TypeOfScan]}"
            ) from e

    @field_validator("model")
    @classmethod
    def validate_model(cls, v: Optional[str], info: ValidationInfo) -> Optional[str]:
        type_of_scan = info.data.get("typeOfScan")
        if type_of_scan == TypeOfScan.MODEL and not v:
            raise ValueError("Model is required for model-only scans")

        if v:
            # Check if model exists in any of the supported providers
            supported = any(v in models for models in SUPPORTED_MODELS.values())
            if not supported:
                raise ValueError(
                    f"Model {v} is not supported. Must be one of the supported models."
                )

        return v

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: Optional[ModeType]) -> Optional[ModeType]:
        if v is None:
            return ModeType.FEW_SHOTS  # Set default here
        return v

    model_config = ConfigDict(use_enum_values=True)  # This will serialize enums to their values


@dataclass(kw_only=True)
class BenchmarkScanContext(BaseScanContext):
    """Context for Benchmark scans with GitHub capabilities."""

    repository_url: str
    branch_name: str
    user_id: str = "benchmark"
    user_access_token: str = "test_access_token"
    user_email: Optional[str] = None
    user_name: Optional[str] = "benchmark"
    scan_number: int = 1
    scan_type: ScanType = ScanType.BENCHMARK
    type_of_scan: TypeOfScan = TypeOfScan.AUDIT_AGENT
    mode: Optional[ModeType] = ModeType.FEW_SHOTS

    # Optional fields (with defaults)
    model: Optional[str] = None
    repository_name: Optional[str] = None
    repo_dir: Optional[str] = None
    temp_dir: Optional[str] = None
    setup_result: Optional[SetupResult] = None
    commit_hash: Optional[str] = None
    formatted_docs: Optional[str] = None

    model_config = ConfigDict(arbitrary_types_allowed=True)
    _supports = (GitHubContext, CompilationContext, UserContext, BenchmarkContext)

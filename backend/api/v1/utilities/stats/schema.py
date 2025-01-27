from pydantic import BaseModel


class TotalPaidScansBreakdown(BaseModel):
    total: int
    regular_paid: int
    discounted: int
    free: int


class ScanStatusCounts(BaseModel):
    pending: int
    in_progress: int
    completed: int
    failed: int


class GlobalStatsResponse(BaseModel):
    total_scans: int
    total_users: int
    returning_users: int
    total_paid_scans: TotalPaidScansBreakdown
    total_unpaid_scans: int
    total_failed_scans: int
    total_findings: int
    total_lines_of_code: int
    scan_statuses: ScanStatusCounts
    pro_scans: int
    free_scans: int
    enterprise_scans: int


class TwentyFourHStatsResponse(BaseModel):
    lines_of_code: int
    total_scans_24h: int
    vulnerabilities_found: int
    paid_scans_24h: int
    free_scans: int
    pro_scans: int
    enterprise_scans: int
    new_users: int

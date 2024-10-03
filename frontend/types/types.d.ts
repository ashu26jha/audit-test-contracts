interface ScanHistoryItem {
  branchName: string;
  commitHash: string;
  completedAt: string | null;
  contractFiles: string[];
  linesOfCode: {
    total_lines: number;
    code_lines: number;
    comment_lines: number;
    empty_lines: number;
  } | null;
  logo: string | null;
  paid_status: boolean;
  repositoryName: string;
  repositoryURL: string;
  scan_id: string;
  scan_number: string;
  startedAt: string;
  name: string;
  status: ScanStatus;
  total_findings: number;
}

type ScanStatus = "pending" | "in_progress" | "completed" | "failed";

interface Finding {
  Issue: string;
  Description: string;
  Severity: string;
  Contracts: string[];
  Recommendation: string;
}

type ScanType = "default" | "defi" | "nft" | "dao" | "utility" | "identity";

interface ScanResult {
  completedAt: string | null;
  createdAt: string;
  findings: Finding[];
  scan: ScanHistoryItem;
  scan_id: string;
  scan_number: number;
  summary: string;
  total_findings: number;
  type: ScanType;
}

interface Owner {
  login: string;
  type: "user" | "organization";
}

interface Repository {
  name: string;
  updatedAt: string;
}

interface File {
  name: string;
  path: string;
  type: string;
  download_url: string;
  lineCount: number;
  token: number;
}

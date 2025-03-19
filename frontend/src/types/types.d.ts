interface User {
  id: string;
  githubId: string;
  name: string;
  username: string;
  email: string;
  avatarUrl: string;
  subscription: Subscription;
}

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
  progress: number;
}

type ScanStatus = "pending" | "in_progress" | "completed" | "failed";
type FilterKey = (typeof filters)[number]["key"];

interface Finding {
  Issue: string;
  Description: string;
  Severity: string;
  Contracts: string[];
  Recommendation: string;
}

interface Invariant {
  condition: string;
  description: string;
  function: string;
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
  progress: number;
  invariants: Invariant[] | null;
}

interface RepositoriesData {
  repositoryName: string;
  repositoryURL: string;
  scans: ScanHistoryItem[];
  logo?: string | null;
  latestScan?: ScanHistoryItem;
  totalScans: number;
  hasUnpaidScans: boolean;
  hasActiveScans: boolean;
}

interface Subscription {
  isActive: boolean;
  type: SubscriptionType;
  credits: number;
  monthlyCredits: number;
  expiresAt: Date;
  lastRenewalAt: Date;
  cancelAtPeriodEnd: boolean;
}

type SubscriptionType = "free" | "pro" | "enterprise";

interface StripeCheckoutResponse {
  data: {
    url: string;
  };
}

interface DocsResponse {
  docs: RepoDocs;
}

interface InitiateScanRequest {
  repositoryURL: string;
  contractFiles: string[];
  branchName: string;
  docs: {
    readme: string[];
    qa: Record<string, string>;
  };
  file_type: ScanLanguage;
}

interface FolderStructure {
  name: string;
  type: "folder" | "file";
  path: string;
  children?: FolderStructure[];
  fileInfo?: any;
}

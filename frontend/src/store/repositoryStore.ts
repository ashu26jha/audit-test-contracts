import { create } from "zustand";

interface RepositoryStore {
  repositories: Map<string, RepositoriesData>;
  setScans: (scans: ScanHistoryItem[]) => void;
  getRepositoryScans: (repoName: string) => ScanHistoryItem[];
  getAllRepositories: () => RepositoriesData[];
  clear: () => void;
}

export const useRepositoryStore = create<RepositoryStore>((set, get) => ({
  repositories: new Map(),

  setScans: (scans) => {
    const repoMap = new Map<string, RepositoriesData>();

    // First pass: Group scans by repository
    scans.forEach((scan) => {
      const existing = repoMap.get(scan.repositoryName);
      if (existing) {
        existing.scans.push(scan);
      } else {
        repoMap.set(scan.repositoryName, {
          repositoryName: scan.repositoryName,
          repositoryURL: scan.repositoryURL,
          logo: scan.logo,
          scans: [scan],
          totalScans: 1,
          hasUnpaidScans: false,
          hasActiveScans: false,
          latestScan: scan,
        });
      }
    });

    repoMap.forEach((repo) => {
      // Sort scans by date (newest first)
      repo.scans.sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime());

      // Update computed fields
      repo.totalScans = repo.scans.length;
      repo.latestScan = repo.scans[0]; // After sorting, first scan is the latest

      // Check for unpaid completed scans
      repo.hasUnpaidScans = repo.scans.some((scan) => !scan.paid_status && scan.status === "completed");

      // Check for active scans
      repo.hasActiveScans = repo.scans.some((scan) => scan.status === "in_progress" || scan.status === "pending");
    });

    set({ repositories: repoMap });
  },

  getRepositoryScans: (repoName) => {
    return get().repositories.get(repoName)?.scans || [];
  },

  getAllRepositories: () => {
    return Array.from(get().repositories.values());
  },

  clear: () => {
    set({ repositories: new Map() });
  },
}));

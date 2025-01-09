import { useState, useEffect } from "react";

import { useQuery } from "@tanstack/react-query";

import { useAuth } from "@/contexts/AuthContext";
import { getScanHistory } from "@/services/api";
import { useRepositoryStore } from "@/store/repositoryStore";

export const useFetchScanHistory = (pollingInterval = 5000) => {
  const { user } = useAuth();
  const { setScans, getRepositoryScans, getAllRepositories } = useRepositoryStore();
  const [hasActiveScans, setHasActiveScans] = useState<boolean>(false);

  const {
    data: scanHistory,
    isLoading,
    error,
    refetch,
  } = useQuery({
    queryKey: ["scanHistory"],
    queryFn: async () => {
      if (!user) {
        throw new Error("No user found");
      }
      const data = await getScanHistory();
      setScans(data);
      return data;
    },
    enabled: !!user,
    refetchInterval: hasActiveScans ? pollingInterval : false,
    refetchIntervalInBackground: hasActiveScans,
  });

  useEffect(() => {
    if (scanHistory) {
      // Check for active scans (only in_progress or pending)
      const activeScans = scanHistory.some(
        (scan: ScanHistoryItem) => scan.status === "in_progress" || scan.status === "pending",
      );
      setHasActiveScans(activeScans);
    }
  }, [scanHistory]);

  return {
    scanHistory,
    isLoading,
    error,
    refetch,
    repositories: getAllRepositories(),
    getRepositoryScans,
  };
};

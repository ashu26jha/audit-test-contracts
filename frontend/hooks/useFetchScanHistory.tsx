import { useState, useEffect } from "react";

import { useQuery } from "@tanstack/react-query";

import { useAuth } from "@/contexts/AuthContext";
import { getScanHistory } from "@/services/api";

export const useFetchScanHistory = (pollingInterval = 5000) => {
  const { token } = useAuth();
  const [scanable, setScanable] = useState<boolean>(false);
  const [hasActiveScans, setHasActiveScans] = useState<boolean>(false);

  const {
    data: scanHistory,
    isLoading,
    error,
    refetch,
  } = useQuery({
    queryKey: ["scanHistory"],
    queryFn: async () => {
      if (!token) {
        throw new Error("No token found");
      }
      return await getScanHistory(token);
    },
    enabled: !!token,
    refetchInterval: hasActiveScans ? pollingInterval : false,
    refetchIntervalInBackground: hasActiveScans,
  });

  useEffect(() => {
    if (scanHistory) {
      const unpaidHistory = scanHistory.filter((scan: ScanHistoryItem) => !scan.paid_status);
      setScanable(unpaidHistory.length === 0);

      const activeScans = scanHistory.some((scan: ScanHistoryItem) => !scan.paid_status && scan.status !== "completed");
      setHasActiveScans(activeScans);
    }
  }, [scanHistory]);

  return { scanHistory, isLoading, error, scanable, refetch };
};

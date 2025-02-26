import { useEffect } from "react";

import { useQuery } from "@tanstack/react-query";
import toast from "react-hot-toast";

import ScanProgressToast from "@/components/common/ScanProgressToast";
import { useAuth } from "@/contexts/AuthContext";
import { getScanResults } from "@/services/api";
import { usePaymentStore } from "@/store/paymentStore";

export type PaymentType = "single" | "subscription";

export const useScanResult = (scanId: string, pollingInterval = 5000) => {
  const { user } = useAuth();
  const {
    isProcessing,
    error,
    shouldPoll,
    isScanLoading,
    setError,
    setShouldPoll,
    toastStarted,
    setToastStarted,
    setIsScanLoading,
  } = usePaymentStore();

  const {
    data: scanData,
    isLoading,
    refetch,
  } = useQuery({
    queryKey: ["scanResults", scanId],
    queryFn: async () => {
      if (!user || !scanId) throw new Error("User or scanId not available");

      setIsScanLoading(true);
      const result = await getScanResults(scanId);

      return result;
    },
    enabled: !!user && !!scanId,
    refetchInterval: shouldPoll ? pollingInterval : false,
    refetchIntervalInBackground: shouldPoll,
    retry: 3,
  });

  useEffect(() => {
    setError(null);
    if (scanData) {
      const isCompleted = scanData.scan.status === "completed" || scanData.scan.status === "failed";
      setShouldPoll(!isCompleted);
      if (isCompleted) {
        setIsScanLoading(false);
      }
    }

    return () => {
      // Cleanup when unmounting
      setError(null);
    };
  }, [scanData, setError, setShouldPoll, setIsScanLoading]);

  useEffect(() => {
    if (shouldPoll && scanData && !toastStarted) {
      toast.custom((t) => <ScanProgressToast t={t} scanId={scanId} />, {
        duration: Infinity,
        position: "bottom-right",
      });
      setToastStarted(true);
    }
  }, [shouldPoll, scanData, scanId, toastStarted, setToastStarted]);

  return {
    scanData,
    isProcessing,
    isScanLoading,
    error,
    isLoading,
    refetchScanResults: refetch,
  };
};

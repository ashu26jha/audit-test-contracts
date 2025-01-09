import { useCallback, useEffect } from "react";

import { useQuery } from "@tanstack/react-query";

import { useAuth } from "@/contexts/AuthContext";
import { createSubscriptionSession, getScanResults } from "@/services/api";
import { usePaymentStore } from "@/store/paymentStore";

export type PaymentType = "single" | "subscription";

export const usePaymentProcessing = (scanId: string, pollingInterval = 5000) => {
  const { user } = useAuth();
  const { isProcessing, error, shouldPoll, setIsProcessing, setError, setShouldPoll } = usePaymentStore();

  const {
    data: scanData,
    isLoading,
    refetch,
  } = useQuery({
    queryKey: ["scanResults", scanId],
    queryFn: async () => {
      if (!user || !scanId) throw new Error("User or scanId not available");

      const result = await getScanResults(scanId);

      return result;
    },
    enabled: !!user && !!scanId && shouldPoll,
    refetchInterval: shouldPoll ? pollingInterval : false,
    refetchIntervalInBackground: shouldPoll,
    retry: 3,
  });

  useEffect(() => {
    setError(null);
    if (scanData) {
      const isCompleted = scanData.scan.status === "completed" || scanData.scan.status === "failed";
      setShouldPoll(!isCompleted);
    }

    return () => {
      // Cleanup when unmounting
      setError(null);
      setShouldPoll(true);
    };
  }, [scanData, setError, setShouldPoll]);

  const handlePayment = useCallback(
    async (paymentType: PaymentType = "single") => {
      if (!user || !scanId) return;

      try {
        setIsProcessing(true);
        setError(null);

        // TODO: Handle the subscription type dynamically if needed
        const res = await createSubscriptionSession("pro");

        setIsProcessing(false);
        window.location.assign(res.data.url);
      } catch (err) {
        console.error("Error creating checkout session:", err);
        setError(`Failed to initiate ${paymentType} payment. Please try again.`);
        setIsProcessing(false);
      }
    },
    [user, scanId, setError, setIsProcessing],
  );

  return {
    scanData,
    isProcessing,
    error,
    isLoading,
    handlePayment,
    refetchScanResults: refetch,
  };
};

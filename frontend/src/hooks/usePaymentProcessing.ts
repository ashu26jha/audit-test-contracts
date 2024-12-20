import { useCallback, useEffect } from "react";

import { useQuery } from "@tanstack/react-query";

import { useAuth } from "@/contexts/AuthContext";
import {
  createCheckoutSession,
  createSubscriptionSession,
  getPartialScanResults,
  getFullScanResults,
} from "@/services/api";
import { usePaymentStore } from "@/store/paymentStore";

export type PaymentType = "single" | "subscription";

export const usePaymentProcessing = (scanId: string, pollingInterval = 5000) => {
  const { user } = useAuth();
  const { isProcessing, error, shouldPoll, isPaid, setIsProcessing, setError, setShouldPoll, setIsPaid } =
    usePaymentStore();

  const {
    data: scanData,
    isLoading,
    refetch,
  } = useQuery({
    queryKey: ["scanResults", scanId],
    queryFn: async () => {
      if (!user || !scanId) throw new Error("User or scanId not available");

      let result;
      if (isPaid) {
        result = await getFullScanResults(scanId);
      } else {
        result = await getPartialScanResults(scanId);
        if (result.scan.paid_status) {
          // If the scan is now paid, immediately fetch full results
          result = await getFullScanResults(scanId);
          setIsPaid(true);
        }
      }
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
      setIsPaid(scanData.scan.paid_status);
    }

    return () => {
      // Cleanup when unmounting
      setError(null);
      setShouldPoll(true);
      setIsPaid(false);
    };
  }, [scanData, setError, setShouldPoll, setIsPaid]);

  const handlePayment = useCallback(
    async (paymentType: PaymentType = "single") => {
      if (!user || !scanId) return;

      try {
        setIsProcessing(true);
        setError(null);

        const res =
          paymentType === "subscription"
            ? await createSubscriptionSession(scanId)
            : await createCheckoutSession(scanId);

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
    isPaid,
    handlePayment,
    refetchScanResults: refetch,
  };
};

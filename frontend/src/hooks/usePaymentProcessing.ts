import { useState, useCallback, useEffect } from "react";

import { useQuery } from "@tanstack/react-query";

import { useAuth } from "@/contexts/AuthContext";
import { createCheckoutSession, getPartialScanResults, getFullScanResults } from "@/services/api";

export const usePaymentProcessing = (scanId: string, pollingInterval = 5000) => {
  const { user } = useAuth();
  const [isProcessing, setIsProcessing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [shouldPoll, setShouldPoll] = useState(true);
  const [isPaid, setIsPaid] = useState(false);

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
    if (scanData) {
      const isCompleted = scanData.scan.status === "completed" || scanData.scan.status === "failed";
      setShouldPoll(!isCompleted);
      setIsPaid(scanData.scan.paid_status);
    }
  }, [scanData]);

  const handlePayment = useCallback(async () => {
    if (!user || !scanId) return;

    setIsProcessing(true);
    setError(null);

    try {
      const res = await createCheckoutSession(scanId);
      const { URL } = res.data;

      // Redirect to Stripe Checkout
      window.location.href = URL;
    } catch (err) {
      console.error("Error creating checkout session:", err);
      setError("Failed to initiate payment. Please try again.");
      setIsProcessing(false);
    }
  }, [user, scanId]);

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

import { useState, useCallback, useEffect } from "react";

import { useQuery } from "@tanstack/react-query";

import { useAuth } from "@/contexts/AuthContext";
import { createCheckoutSession, getPartialScanResults, getFullScanResults } from "@/services/api";

export const usePaymentProcessing = (scanId: string, pollingInterval = 5000) => {
  const { token } = useAuth();
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
      if (!token || !scanId) throw new Error("Token or scanId not available");
      let result;
      if (isPaid) {
        result = await getFullScanResults(token, scanId);
      } else {
        result = await getPartialScanResults(token, scanId);
        if (result.scan.paid_status) {
          // If the scan is now paid, immediately fetch full results
          result = await getFullScanResults(token, scanId);
          setIsPaid(true);
        }
      }
      return result;
    },
    enabled: !!token && !!scanId && shouldPoll,
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
    if (!token || !scanId) return;

    setIsProcessing(true);
    setError(null);

    try {
      const res = await createCheckoutSession(token, scanId);
      const { URL } = res.data;

      // Redirect to Stripe Checkout
      window.location.href = URL;
    } catch (err) {
      console.error("Error creating checkout session:", err);
      setError("Failed to initiate payment. Please try again.");
      setIsProcessing(false);
    }
  }, [token, scanId]);

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

import { useState, useCallback, useEffect } from "react";

import { useQuery } from "@tanstack/react-query";

import { useAuth } from "@/contexts/AuthContext";
import { createCheckoutSession, getPartialScanResults } from "@/services/api";

export const usePaymentProcessing = (scanId: string, pollingInterval = 5000) => {
  const { token } = useAuth();
  const [isProcessing, setIsProcessing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [shouldPoll, setShouldPoll] = useState(true);

  const {
    data: scanData,
    isLoading,
    refetch,
  } = useQuery({
    queryKey: ["scanResults", scanId],
    queryFn: async () => {
      if (!token || !scanId) throw new Error("Token or scanId not available");
      return await getPartialScanResults(token, scanId);
    },
    enabled: !!token && !!scanId && shouldPoll,
    refetchInterval: shouldPoll ? pollingInterval : false,
    refetchIntervalInBackground: shouldPoll,
  });

  useEffect(() => {
    if (scanData) {
      const isCompleted = scanData.scan.status === "completed";
      const isPaid = scanData.scan.paid_status;
      setShouldPoll(!isCompleted || !isPaid);
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
    handlePayment,
    refetchScanResults: refetch,
  };
};

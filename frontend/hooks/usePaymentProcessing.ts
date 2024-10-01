import { useState, useCallback } from "react";

import { useAuth } from "@/contexts/AuthContext";
import { createCheckoutSession, getPartialScanResults } from "@/services/api";

export const usePaymentProcessing = (scanId: string) => {
  const { token } = useAuth();
  const [isProcessing, setIsProcessing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [scanData, setScanData] = useState<ScanResult | null>(null);

  const fetchScanResults = useCallback(async () => {
    if (!token || !scanId) return;

    try {
      const data = await getPartialScanResults(token, scanId);
      setScanData(data);
    } catch (err) {
      console.error("Error fetching scan results:", err);
      setError("Failed to fetch scan results. Please try again.");
    }
  }, [token, scanId]);

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
    handlePayment,
    fetchScanResults,
  };
};

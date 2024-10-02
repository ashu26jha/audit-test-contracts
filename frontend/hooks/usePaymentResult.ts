import { useEffect, useState, useCallback, useRef } from "react";

import { useSearchParams } from "next/navigation";

import { useAuth } from "@/contexts/AuthContext";
import { sendPdfReport } from "@/services/api";

type PaymentStatus = "success" | "failed" | "processing" | null;

export const usePaymentResult = () => {
  const { token, loading } = useAuth();
  const searchParams = useSearchParams();
  const [status, setStatus] = useState<PaymentStatus>(null);
  const [isProcessing, setIsProcessing] = useState(false);
  const isPdfReportSentRef = useRef(false);

  const handlePaymentResult = useCallback(async () => {
    if (isProcessing || isPdfReportSentRef.current || loading) return;

    const scanId = searchParams.get("scan_id");
    const urlStatus = searchParams.get("status");

    if (scanId && urlStatus === "success" && token) {
      setStatus("processing");
      setIsProcessing(true);
      isPdfReportSentRef.current = true;

      try {
        sendPdfReport(token, scanId);
        setStatus("success");
      } catch (error) {
        console.error("Error in report generation:", error);
        setStatus("failed");
      } finally {
        setIsProcessing(false);
      }
    } else if (urlStatus === "error") {
      setStatus("failed");
    } else {
      // If the status is neither success nor error, set it to failed
      setStatus("failed");
    }
  }, [searchParams, token, isProcessing, loading]);

  useEffect(() => {
    handlePaymentResult();
  }, [handlePaymentResult]);

  return {
    status,
    isProcessing,
  };
};

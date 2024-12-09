import { useEffect, useState, useCallback, useRef } from "react";

import { useSearchParams } from "next/navigation";

import { useAuth } from "@/contexts/AuthContext";
import { sendPdfReport } from "@/services/api";

import { useFetchScanHistory } from "./useFetchScanHistory";

type PaymentStatus = "success" | "failed" | "processing" | null;

export const usePaymentResult = () => {
  const { user, loading } = useAuth();
  const searchParams = useSearchParams();
  const { refetch } = useFetchScanHistory();
  const [status, setStatus] = useState<PaymentStatus>(null);
  const [isProcessing, setIsProcessing] = useState(false);
  const isPdfReportSentRef = useRef(false);

  const handlePaymentResult = useCallback(async () => {
    if (isProcessing || isPdfReportSentRef.current || loading) return;

    const scanId = searchParams.get("scan_id");
    const urlStatus = searchParams.get("status");

    if (scanId && urlStatus === "success" && user) {
      setStatus("processing");
      setIsProcessing(true);
      isPdfReportSentRef.current = true;

      try {
        refetch();
        sendPdfReport(scanId);
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
  }, [searchParams, user, isProcessing, loading, refetch]);

  useEffect(() => {
    handlePaymentResult();
  }, [handlePaymentResult]);

  return {
    status,
    isProcessing,
  };
};

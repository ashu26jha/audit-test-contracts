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

  const scanId = searchParams.get("scan_id");
  const urlStatus = searchParams.get("status");

  const handlePaymentResult = useCallback(async () => {
    if (isProcessing || isPdfReportSentRef.current || loading) return;

    if (urlStatus === "success" && user) {
      setStatus("processing");
      setIsProcessing(true);
      isPdfReportSentRef.current = true;

      try {
        if (scanId) {
          await Promise.all([refetch(), sendPdfReport(scanId)]);
        }
        setStatus("success");
      } catch (error) {
        console.error("Error in payment processing:", error);
        setStatus("failed");
      } finally {
        setIsProcessing(false);
      }
    } else if (urlStatus === "error") {
      setStatus("failed");
    } else if (urlStatus === "success") {
      setStatus("success");
    } else {
      setStatus("failed");
    }
  }, [scanId, urlStatus, user, isProcessing, loading, refetch]);

  useEffect(() => {
    handlePaymentResult();
  }, [handlePaymentResult]);

  return {
    status,
    isProcessing,
    scanId,
  };
};

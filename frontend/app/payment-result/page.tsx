"use client";

import { useEffect, useState, useCallback } from "react";

import { useSearchParams, useRouter } from "next/navigation";

import { Loading } from "@/components/Loading";
import Payment from "@/components/payment";
import { useAuth } from "@/contexts/AuthContext";
import { paymentSuccess } from "@/services/api";

const PaymentResultPage = () => {
  const searchParams = useSearchParams();
  const router = useRouter();
  const [status, setStatus] = useState<"success" | "failed" | "processing" | null>(null);
  const { user, token, loading } = useAuth();
  const [isProcessing, setIsProcessing] = useState(false);

  const handlePaymentResult = useCallback(async () => {
    if (isProcessing) return;
    setIsProcessing(true);

    const session_id = searchParams.get("session_id");
    const urlStatus = searchParams.get("status");

    if (session_id && urlStatus === "success" && token) {
      setStatus("processing");
      try {
        const result = await paymentSuccess(token, session_id);
        if (result.data === "Payment processed successfully" || result.data === "Payment already processed") {
          setStatus("success");
        } else {
          setStatus("processing");
        }
      } catch (error) {
        console.error("Error in report generation:", error);
        setStatus("failed");
      }
    } else if (urlStatus === "error") {
      setStatus("failed");
    }

    setIsProcessing(false);
  }, [searchParams, token, isProcessing]);

  useEffect(() => {
    if (!loading && status === null) {
      handlePaymentResult();
    }
  }, [loading, handlePaymentResult, status]);

  const handleRetry = () => {
    router.push("/dashboard");
  };

  if (loading || status === null || status === "processing") {
    return <Loading />;
  }

  if (!user) {
    return <div>Please log in to view payment results.</div>;
  }

  return <Payment status={status} onRetry={handleRetry} />;
};

export default PaymentResultPage;

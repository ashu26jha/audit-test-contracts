"use client";

import { useRouter } from "next/navigation";

import { Loading } from "@/components/Loading";
import Payment from "@/components/payment";
import { useAuth } from "@/contexts/AuthContext";
import { usePaymentResult } from "@/hooks/usePaymentResult";

const PaymentResultPage = () => {
  const router = useRouter();
  const { user, loading } = useAuth();
  const { status, isProcessing } = usePaymentResult();

  const handleRetry = () => {
    router.push("/dashboard");
  };

  if (loading || isProcessing || status === null || status === "processing") {
    return <Loading />;
  }

  if (!user) {
    return <div>Please log in to view payment results.</div>;
  }

  return <Payment status={status} onRetry={handleRetry} />;
};

export default PaymentResultPage;

"use client";

import { useRouter } from "next/navigation";

import { Loading } from "@/components/Loading";
import Payment from "@/components/payment";
import { usePaymentResult } from "@/hooks/usePaymentResult";

const PaymentResultPage = () => {
  const router = useRouter();
  const { status, isProcessing } = usePaymentResult();

  const handleRetry = () => {
    router.push("/dashboard");
  };

  if (isProcessing || status === null || status === "processing") {
    return <Loading />;
  }

  return <Payment status={status} onRetry={handleRetry} />;
};

export default PaymentResultPage;

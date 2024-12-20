"use client";

import { type FC } from "react";

import { useRouter } from "next/navigation";

import { CONTACT } from "@/config/constants";
import { useAuth } from "@/contexts/AuthContext";
import { usePaymentResult } from "@/hooks";

import { Loading } from "../layout";
import { SuccessPayment, FailedPayment } from "../payment";

const PaymentView: FC = () => {
  const router = useRouter();
  const { user } = useAuth();
  const { status, isProcessing, scanId } = usePaymentResult();

  if (isProcessing || status === null || status === "processing") {
    return <Loading />;
  }

  const redirectUrl = scanId ? `/scan-results/${scanId}` : "/dashboard";

  return (
    <div className="h-full bg-black text-white flex flex-col items-center justify-center">
      {status === "success" ? (
        <SuccessPayment scanId={scanId} userEmail={user?.email} onBack={() => router.push(redirectUrl)} />
      ) : (
        <FailedPayment onRetry={() => router.back()} onBack={() => router.push(redirectUrl)} />
      )}
      <p className="text-gray-500 mt-8 text-sm">Need help? Reach out to us at {CONTACT.EMAIL}</p>
    </div>
  );
};

export default PaymentView;

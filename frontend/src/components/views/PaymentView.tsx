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
  const { status, isProcessing } = usePaymentResult();

  // Fetch scanId from url
  const url = window.location.href;
  const scanId = url.split("scan_id=")[1];

  if (isProcessing || status === null || status === "processing") {
    return <Loading />;
  }

  return (
    <div className="h-full bg-black text-white flex flex-col items-center justify-center">
      {status === "success" ? (
        <SuccessPayment scanId={scanId} userEmail={user?.email} />
      ) : (
        <FailedPayment onRetry={() => router.push("/dashboard")} onBack={() => router.back()} />
      )}
      <p className="text-gray-500 mt-8 text-sm">Need help? Reach out to us at {CONTACT.EMAIL}</p>
    </div>
  );
};

export default PaymentView;

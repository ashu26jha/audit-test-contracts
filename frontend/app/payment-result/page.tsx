"use client";

import { useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import Payment from "../../components/payment";
import { useRouter } from "next/navigation";
import { useAuth } from "../../contexts/AuthContext";

const PaymentResultPage = () => {
  const searchParams = useSearchParams();
  const router = useRouter();
  const [status, setStatus] = useState<"success" | "failed" | null>(null);
  const { user, loading } = useAuth();

  useEffect(() => {
    const session_id = searchParams.get("session_id");
    const urlStatus = searchParams.get("status");

    // TODO: Check if session_id is valid
    if (session_id && urlStatus === "success") {
      setStatus("success");
    } else {
      setStatus("failed");
    }
  }, [searchParams]);

  const handleRetry = () => {
    // Implement retry logic here
    router.push("/dashboard");
  };

  if (loading) {
    return <div>Loading...</div>;
  }

  if (!user) {
    // If the user is not authenticated, you might want to handle this case
    // For example, redirect to login or show a message
    return <div>Please log in to view payment results.</div>;
  }

  if (status === null) {
    return <div>Processing payment result...</div>;
  }

  return <Payment status={status} onRetry={handleRetry} />;
};

export default PaymentResultPage;

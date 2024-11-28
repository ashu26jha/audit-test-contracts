"use client";

import { useEffect, useState } from "react";

import { useRouter } from "next/navigation";

import Dashboard from "@/components/dashboard";
import { Loading } from "@/components/Loading";

import ScanStepper from "../../components/scan-stepper";
import ScanInfoModal from "../../components/ScanInfoModal";
import { useAuth } from "../../contexts/AuthContext";
import { useFetchScanHistory } from "../../hooks/useFetchScanHistory";

const DashboardPage = () => {
  const { user } = useAuth();
  const router = useRouter();

  const [showStepper, setShowStepper] = useState(false);
  const { scanHistory, isLoading, scanable, refetch } = useFetchScanHistory();

  useEffect(() => {
    if (!user) {
      router.push("/login");
    }
  }, [user, router]);

  if (!user || isLoading) {
    return <Loading />;
  }

  return (
    <>
      <ScanInfoModal />
      <div className="container mx-auto max-w-10xl h-full">
        {showStepper ? (
          <ScanStepper setShowStepper={setShowStepper} />
        ) : (
          <Dashboard scanHistory={scanHistory} scanable={scanable} refetch={refetch} setShowStepper={setShowStepper} />
        )}
      </div>
    </>
  );
};

export default DashboardPage;

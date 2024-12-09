"use client";

import { type FC, useState } from "react";

import Dashboard from "@/components/dashboard";
import { Loading } from "@/components/Loading";
import ScanStepper from "@/components/scan-stepper";
import ScanInfoModal from "@/components/ScanInfoModal";
import { ProtectedRoute, useAuth } from "@/contexts/AuthContext";
import { useFetchScanHistory } from "@/hooks";

const DashboardPage: FC = () => {
  const { user, loading } = useAuth();
  const { scanHistory, isLoading, scanable, refetch } = useFetchScanHistory();
  const [showStepper, setShowStepper] = useState(false);

  if (loading || isLoading || !user) {
    return <Loading text="Loading data" subText="Please wait..." />;
  }

  return (
    <ProtectedRoute>
      <ScanInfoModal />
      <div className="container mx-auto max-w-10xl h-full">
        {showStepper ? (
          <ScanStepper setShowStepper={setShowStepper} />
        ) : (
          <Dashboard scanHistory={scanHistory} scanable={scanable} refetch={refetch} setShowStepper={setShowStepper} />
        )}
      </div>
    </ProtectedRoute>
  );
};

export default DashboardPage;

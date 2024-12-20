"use client";

import { useEffect, type FC } from "react";

import { AlertTriangle } from "lucide-react";

import { Loading, ProtectedRoute, StateMessage } from "@/components/layout";
import { ScanFullResultsView, ScanResultsView } from "@/components/views";
import { useAuth } from "@/contexts/AuthContext";
import { usePaymentProcessing } from "@/hooks";

interface ScanResultsPageProps {
  params: {
    scanId: string;
  };
}

const ScanResultsPage: FC<ScanResultsPageProps> = ({ params }) => {
  const { scanId } = params;
  const { user, loading, refetchUser } = useAuth();
  const { scanData, isProcessing, error, isLoading } = usePaymentProcessing(scanId);

  useEffect(() => {
    refetchUser(); // To updte credits in case of refund
  }, [scanData, refetchUser]);

  if (!user) return null;

  if (loading) {
    return <Loading />;
  }

  if (isLoading) {
    return <Loading text="Loading scan results" />;
  }

  if (isProcessing) {
    return <Loading text="Creating payment session" />;
  }

  if (error) {
    return <StateMessage icon={<AlertTriangle size={40} className="text-red-500" />} message={`Error: ${error}`} />;
  }

  if (!scanData) {
    return <StateMessage icon={<AlertTriangle size={40} className="text-red-500" />} message="No scan data found" />;
  }

  return (
    <ProtectedRoute>
      {scanData.scan.status === "completed" && scanData.scan.paid_status && scanData.findings.length > 0 ? (
        <ScanFullResultsView scanData={scanData} />
      ) : (
        <ScanResultsView scanData={scanData} />
      )}
    </ProtectedRoute>
  );
};

export default ScanResultsPage;

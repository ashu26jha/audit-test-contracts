"use client";

import { useEffect } from "react";

import { Loading } from "@/components/Loading";
import ScanResults from "@/components/scan-results";
import { usePaymentProcessing } from "@/hooks/usePaymentProcessing";

interface ScanResultsPageProps {
  params: {
    scanId: string;
  };
}

const ScanResultsPage: React.FC<ScanResultsPageProps> = ({ params }) => {
  const { scanId } = params;
  const { scanData, isProcessing, error, handlePayment, fetchScanResults } = usePaymentProcessing(scanId);

  useEffect(() => {
    fetchScanResults();
  }, [fetchScanResults]);

  if (isProcessing) {
    return <Loading />;
  }

  if (error) {
    return <div>Error: {error}</div>;
  }

  if (!scanData) {
    return <div>No scan data found</div>;
  }

  return <ScanResults scanData={scanData} handlePayment={handlePayment} />;
};

export default ScanResultsPage;

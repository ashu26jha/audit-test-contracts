"use client";

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
  const { scanData, isProcessing, error, isLoading, handlePayment } = usePaymentProcessing(scanId);

  if (isProcessing || isLoading) {
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

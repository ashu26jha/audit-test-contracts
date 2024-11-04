"use client";

import { Loading } from "@/components/Loading";
import ScanFullResults from "@/components/scan-full-results";
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
    return <div className="container mx-auto max-w-10xl h-full">Error: {error}</div>;
  }

  if (!scanData) {
    return <div className="container mx-auto max-w-10xl h-full">No scan data found</div>;
  }

  if (scanData.scan.paid_status && scanData.findings.length > 1) {
    return <ScanFullResults scanData={scanData} handlePayment={handlePayment} />;
  } else {
    return <ScanResults scanData={scanData} handlePayment={handlePayment} />;
  }
};

export default ScanResultsPage;

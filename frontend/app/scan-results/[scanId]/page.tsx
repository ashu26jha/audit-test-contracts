"use client";

import { Loading } from "@/components/Loading";
import ScanFullResults from "@/components/scan-full-results";
import ScanResults from "@/components/scan-results";
import { useAuth } from "@/contexts/AuthContext";
import { usePaymentProcessing } from "@/hooks/usePaymentProcessing";

interface ScanResultsPageProps {
  params: {
    scanId: string;
  };
}

interface CenteredMessageProps {
  message: string;
}

const CenteredMessage: React.FC<CenteredMessageProps> = ({ message }) => (
  <div className="container mx-auto max-w-10xl h-[100%] flex items-center justify-center">
    <p className="text-lg">{message}</p>
  </div>
);

const ScanResultsPage: React.FC<ScanResultsPageProps> = ({ params }) => {
  const { loading } = useAuth();
  const { scanId } = params;
  const { scanData, isProcessing, error, isLoading, handlePayment } = usePaymentProcessing(scanId);

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
    return <CenteredMessage message={`Error: ${error}`} />;
  }

  if (!scanData) {
    return <CenteredMessage message="No scan data found" />;
  }

  if (scanData.scan.paid_status && scanData.findings.length > 1) {
    return <ScanFullResults scanData={scanData} handlePayment={handlePayment} />;
  } else {
    return <ScanResults scanData={scanData} handlePayment={handlePayment} />;
  }
};

export default ScanResultsPage;

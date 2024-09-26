"use client";

import { useEffect, useState } from "react";
import { useAuth } from "../../../contexts/AuthContext";
import { getPartialScanResults, createCheckoutSession } from "../../../services/api";
import ScanResults from "../../../components/scan-results";

interface ScanResultsPageProps {
  params: {
    scanId: string;
  };
}

const ScanResultsPage: React.FC<ScanResultsPageProps> = ({ params }) => {
  const { scanId } = params;
  const { token } = useAuth();
  const [scanData, setScanData] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchScanResults = async () => {
      if (!token || !scanId) return;

      try {
        const data = await getPartialScanResults(token, scanId);
        setScanData(data);
      } catch (err) {
        console.error("Error fetching scan results:", err);
        setError("Failed to fetch scan results. Please try again.");
      } finally {
        setIsLoading(false);
      }
    };

    fetchScanResults();
  }, [token, scanId]);

  const handlePayment = async () => {
    if (!token || !scanId) return;

    try {
      const { session_id, URL } = await createCheckoutSession(token, scanId);
      console.log(URL);
      console.log(session_id);
      // Redirect to Stripe Checkout
      window.location.href = URL;
    } catch (err) {
      console.error("Error creating checkout session:", err);
      setError("Failed to initiate payment. Please try again.");
    }
  };

  if (isLoading) {
    return <div>Loading...</div>;
  }

  if (error) {
    return <div>Error: {error}</div>;
  }

  return (
    <div className="h-full">
      <ScanResults scanData={scanData} handlePayment={handlePayment} />
    </div>
  );
};

export default ScanResultsPage;

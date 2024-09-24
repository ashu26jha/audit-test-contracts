"use client";

import { useEffect, useState } from "react";
import { useAuth } from "../../../contexts/AuthContext";
import { getPartialScanResults } from "../../../services/api";
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

  if (isLoading) {
    return <div>Loading...</div>;
  }

  if (error) {
    return <div>Error: {error}</div>;
  }

  return <ScanResults scanData={scanData} />;
};

export default ScanResultsPage;

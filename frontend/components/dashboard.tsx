"use client";

import React from "react";

import { Button, Divider, Card, CardBody, CardHeader } from "@nextui-org/react";
import Image from "next/image";
import { useRouter } from "next/navigation";

import ScanCard from "@/components/ScanCard";
import { useToast } from "@/hooks/useToast";

interface DashboardProps {
  scanHistory: ScanHistoryItem[];
  scanable: boolean;
  refetch: () => void;
  setShowStepper: (show: boolean) => void;
}

const Dashboard: React.FC<DashboardProps> = ({ scanHistory, scanable, refetch, setShowStepper }) => {
  const { toast } = useToast();
  const router = useRouter();

  const handleScanClick = (scanId: string) => {
    router.push(`/scan-results/${scanId}`);
  };

  const handleScan = () => {
    if (scanable) {
      if (typeof window !== "undefined" && window._mtm != undefined) {
        window._mtm.push({ event: "repository-selection" });
      }
      setShowStepper(true);
      // Trigger a refetch when starting a new scan
      refetch();
    } else {
      toast({
        title: "You must pay for previous scans to continue",
        status: "error",
        duration: 3000,
      });
    }
  };

  return (
    <Card className="h-full">
      {/* Header */}
      <CardHeader>
        <div className="flex justify-between items-center mb-1 ml-4 mr-4 w-full">
          <h2 className="text-l font-light">Dashboard</h2>
          <Button
            color="secondary"
            className="bg-[#8B5CF6] text-white"
            onClick={handleScan}
            startContent={<Image src="/scan-icon.svg" alt="Scan" width={20} height={20} />}
          >
            Scan Code
          </Button>
        </div>
      </CardHeader>
      <Divider />

      {/* Main content */}
      <CardBody className="overflow-y-auto">
        {scanHistory.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {scanHistory.map((scan: ScanHistoryItem, index: number) => (
              <ScanCard key={index} scan={scan} onClick={handleScanClick} />
            ))}
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center h-[60vh]">
            <Image src="/empty-dashboard.svg" alt="No Code Scanned" width={100} height={100} />
            <h3 className="text-xl my-4">No Code Scanned</h3>
            <p className="text-gray-400 text-center">
              You haven&apos;t scanned any code yet.
              <br />
              Click on the Scan Code button to get started.
            </p>
          </div>
        )}
      </CardBody>
    </Card>
  );
};

export default Dashboard;

"use client";

import { type FC } from "react";

import { Button, Divider, Card, CardBody, CardHeader } from "@nextui-org/react";
import Image from "next/image";
import { useRouter } from "next/navigation";

import ScanCard from "@/components/ScanCard";
import { SERVICES } from "@/config/constants";
import { useFetchScanHistory, useGithubApp, useToast } from "@/hooks";
import { useScanStepperStore } from "@/store/scanStepperStore";

import { Loading } from "../layout";

const DashboardView: FC = () => {
  const router = useRouter();
  const { setShowStepper } = useScanStepperStore();
  const { scanHistory, isLoading, scanable, refetch } = useFetchScanHistory();
  const { hasGithubApp } = useGithubApp();
  const { toast } = useToast();

  if (isLoading) return <Loading text="Loading data" subText="Please wait..." />;

  const handleScanClick = (scanId: string) => {
    router.push(`/scan-results/${scanId}`);
  };

  const handleScan = async () => {
    if (scanable) {
      // prettier-ignore
      if (typeof window !== "undefined" && window._mtm != undefined) {
        window._mtm.push({ "event": "repository-selection" });
      }

      if (!hasGithubApp) {
        window.location.href = SERVICES.GITHUB_APP_URL;
        return;
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
            isLoading={hasGithubApp === null}
            startContent={<Image src="/svg/scan-icon.svg" alt="Scan" width={20} height={20} />}
          >
            Scan Code
          </Button>
        </div>
      </CardHeader>
      <Divider />

      {/* Main content */}
      <CardBody className="overflow-y-auto">
        {scanHistory?.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {scanHistory.map((scan: ScanHistoryItem, index: number) => (
              <ScanCard key={index} scan={scan} onClick={handleScanClick} />
            ))}
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center h-[60vh]">
            <Image src="/svg/empty-dashboard.svg" alt="No Code Scanned" width={100} height={100} />
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

export default DashboardView;

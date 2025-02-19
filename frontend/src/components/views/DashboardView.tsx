"use client";

import { useEffect, useState, type FC } from "react";

import { Button } from "@nextui-org/react";
import Image from "next/image";
import { useRouter } from "next/navigation";

import { Container, Loading } from "@/components/layout";
import ScanCard from "@/components/ScanCard";
import { SERVICES } from "@/config/constants";
import { useFetchScanHistory, useGithubApp, useScanResult } from "@/hooks";
import { checkInProgressScan } from "@/utils/helpers";

const DashboardView: FC = () => {
  const router = useRouter();
  const { repositories, scanHistory, isLoading, refetch } = useFetchScanHistory();
  const { hasGithubApp } = useGithubApp();
  const [inProgressScan, setInProgressScan] = useState<string | null>(null);
  const { isScanLoading } = useScanResult(inProgressScan ?? "");

  useEffect(() => {
    if (repositories.length > 0) {
      const scanId = checkInProgressScan(repositories);
      setInProgressScan(scanId);
    }
  }, [repositories]);

  if (isLoading) return <Loading text="Loading data" subText="Please wait..." />;

  const handleScan = async () => {
    // prettier-ignore
    if (typeof window !== "undefined" && window._mtm != undefined) {
        window._mtm.push({ "event": "repository-selection" });
      }

    if (!hasGithubApp) {
      window.location.href = SERVICES.GITHUB_APP_URL;
      return;
    }
    // Trigger a refetch when starting a new scan
    refetch();

    router.push("/dashboard?tab=scan");
  };

  return (
    <Container
      breadcrumbItems={[{ label: "Dashboard", href: "/dashboard" }]}
      buttons={
        <Button
          color="secondary"
          className="bg-[#8B5CF6] text-white"
          onPress={handleScan}
          isLoading={hasGithubApp === null}
          isDisabled={isScanLoading || inProgressScan !== null}
          startContent={<Image src="/svg/scan-code.svg" alt="Scan" width={20} height={20} />}
        >
          Scan Code
        </Button>
      }
    >
      {scanHistory.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {repositories.map((repository: RepositoriesData) => (
            <ScanCard
              key={repository.repositoryName}
              repository={repository}
              onClick={() => router.push(`/repository/${repository.repositoryName}`)}
            />
          ))}
        </div>
      )}

      {scanHistory.length === 0 && <EmptyScans />}
    </Container>
  );
};

export default DashboardView;

const EmptyScans = () => {
  return (
    <div className="flex flex-col items-center justify-center h-[60vh]">
      <Image src="/svg/empty-dashboard.svg" alt="No Code Scanned" width={100} height={100} />
      <h3 className="text-xl my-4">No Code Scanned</h3>
      <p className="text-gray-400 text-center">
        You haven&apos;t scanned any code yet.
        <br />
        Click on the Scan Code button to get started.
      </p>
    </div>
  );
};

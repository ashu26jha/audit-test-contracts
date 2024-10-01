"use client";

import { useEffect, useState } from "react";
import React from "react";

import { Button, Divider, Card, CardBody, CardHeader, Chip } from "@nextui-org/react";
import { Hash, Calendar, AlertTriangle, FileText } from "lucide-react";
import Image from "next/image";
import { useRouter } from "next/navigation";

import { Loading } from "@/components/Loading";

import ScanStepper from "../../components/scan-stepper";
import { useAuth } from "../../contexts/AuthContext";
import { useToast } from "../../hooks/useToast";
import { getScanHistory } from "../../services/api";

const DashboardPage = () => {
  const { user, token } = useAuth();
  const router = useRouter();
  const { toast } = useToast();
  const [showStepper, setShowStepper] = useState(false);
  const [scanHistory, setScanHistory] = useState<ScanHistoryItem[]>([]);
  const [scanable, setScanable] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    if (!user) {
      router.push("/login");
    }
  }, [user, router]);

  useEffect(() => {
    const fetchScanHistory = async () => {
      if (token) {
        try {
          setIsLoading(true);
          const history = await getScanHistory(token);
          console.log("history", history);
          // To scan repository all history must be paid
          const unpaidHistory = history.filter((scan: ScanHistoryItem) => !scan.paid_status);
          if (unpaidHistory.length > 0) {
            setScanable(false);
          } else {
            setScanable(true);
          }
          setScanHistory(history);
        } catch (error) {
          console.error("Error fetching scan history:", error);
        } finally {
          setIsLoading(false);
        }
      }
    };

    fetchScanHistory();
  }, [token]);

  if (!user || isLoading) {
    return <Loading />;
  }

  const handleScanClick = (scanId: string) => {
    console.log("handleScanClick called with scanId:", scanId);
    router.push(`/scan-results/${scanId}`);
  };

  const handleScan = () => {
    if (scanable) {
      setShowStepper(true);
    } else {
      toast({
        title: "You must pay for previous scans to continue",
        status: "error",
        duration: 3000,
      });
    }
  };

  return (
    <>
      {showStepper ? (
        <ScanStepper />
      ) : (
        <Card className="h-full">
          {/* Main content */}
          <CardHeader>
            <div className="flex justify-between items-center mb-1 ml-4 mr-4 w-full">
              <h2 className="text-l font-light">Dashboard</h2>
              <Button
                color="secondary"
                className="bg-[#8B5CF6] text-white"
                onClick={() => handleScan()}
                startContent={<Image src="/scan-icon.svg" alt="Scan" width={20} height={20}></Image>}
              >
                Scan Code
              </Button>
            </div>
          </CardHeader>
          <Divider />

          <CardBody className="overflow-y-auto">
            {scanHistory.length > 0 ? (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {scanHistory.map((scan, index) => (
                  <Card
                    key={index}
                    isPressable
                    className="bg-[#222222] cursor-pointer hover:bg-[#333333] transition-colors duration-300"
                    onClick={() => handleScanClick(scan.scan_id)}
                  >
                    <CardBody>
                      <div className="flex items-center justify-between mb-4">
                        <div className="flex items-center">
                          <div className="w-10 h-10 mr-3 bg-gray-700 rounded-full flex items-center justify-center">
                            <Image src={scan.logo ?? "/github.svg"} alt="logo" width={24} height={24} />
                          </div>
                          <span className="font-semibold">{scan.repositoryName ?? "Repo Name"}</span>
                        </div>
                        <Chip
                          color={scan.paid_status ? "success" : scan.status === "completed" ? "warning" : "primary"}
                          size="sm"
                        >
                          {scan.paid_status ? "paid" : scan.status === "completed" ? "unpaid" : scan.status}
                        </Chip>
                      </div>
                      <div className="space-y-2">
                        <div className="flex items-center">
                          <Hash size={16} className="mr-2 text-gray-400" />
                          <span className="text-sm">Scan ID: {scan.scan_number}</span>
                        </div>
                        <div className="flex items-center">
                          <Calendar size={16} className="mr-2 text-gray-400" />
                          <span className="text-sm">Scanned Date: {new Date(scan.startedAt).toLocaleString()}</span>
                        </div>
                        <div className="flex items-center">
                          <AlertTriangle size={16} className="mr-2 text-gray-400" />
                          <span className="text-sm">Vulnerabilities Found: {scan.total_findings ?? 1}</span>
                        </div>
                        <div className="flex items-center">
                          <FileText size={16} className="mr-2 text-gray-400" />
                          <span className="text-sm">Contracts Scanned: {scan.contractFiles.length}</span>
                        </div>
                      </div>
                    </CardBody>
                  </Card>
                ))}
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center h-[60vh]">
                <Image src="/empty-dashboard.svg" alt="No Code Scanned" width={100} height={100} />
                <h3 className="text-xl my-4">No Code Scanned</h3>
                <p className="text-gray-400 text-center">
                  You haven&apos;t scanned any code yet.
                  <br />
                  Please select a code file to scan.
                </p>
              </div>
            )}
          </CardBody>
        </Card>
      )}
    </>
  );
};

export default DashboardPage;

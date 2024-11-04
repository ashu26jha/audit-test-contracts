import React, { useState, useRef, useEffect } from "react";

import { Card, CardBody, CardHeader, Button, Tooltip, Divider, Spinner } from "@nextui-org/react";
import { AlertTriangle, FileText, Code, Hash, Info, CheckCircle } from "lucide-react";
import { Dot } from "lucide-react";
import Image from "next/image";

import { useAuth } from "@/contexts/AuthContext";
import { useToast } from "@/hooks/useToast";
import { sendPdfReport } from "@/services/api";

import CodeSummary from "./CodeSummary";
import FindingsMenu from "./FindingsMenu";
import ScanInfo from "./scan-info";

interface ScanFullResultsProps {
  scanData: ScanResult;
  handlePayment: () => void;
}

const ScanFullResults: React.FC<ScanFullResultsProps> = ({ scanData }) => {
  const { toast } = useToast();
  const { token } = useAuth();
  const [isInfoModalOpen, setIsInfoModalOpen] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  // Add isCollapsed state
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [isSticky, setIsSticky] = useState(false);

  // Add ref for findings container
  const findingsRefs = useRef<{ [key: string]: HTMLDivElement | null }>({});

  // Add scroll handler
  const scrollToFinding = (finding: Finding) => {
    const findingElement = findingsRefs.current[finding.Issue];
    if (findingElement) {
      findingElement.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  };

  const isCompleted = scanData.scan.status === "completed";
  const isFailed = scanData.scan.status === "failed";
  const isPaid = isCompleted && scanData.scan.paid_status;
  const isNoFinding = isCompleted && scanData.total_findings === 0;

  const handleSendReportAgain = async () => {
    if (!token) {
      console.error("No token found");
      return;
    }
    const res = await sendPdfReport(token, scanData.scan_id);
    if (res.success) {
      toast({
        title: "Report sent",
        status: "success",
      });
    } else {
      toast({
        title: res.message,
        status: "error",
      });
    }
  };

  const scanStats = [
    {
      icon: <Image src="/vulnerability-icon.svg" alt="Error" width={16} height={16} />,
      label: "Vulnerabilities Found",
      value: scanData.total_findings ?? 0,
    },
    {
      icon: <FileText size={16} />,
      label: "Contracts Scanned",
      value: scanData.scan.contractFiles?.length.toString() || "0",
    },
    {
      icon: <Code size={16} />,
      label: "Lines of Code",
      value: scanData.scan.linesOfCode?.total_lines.toString() || "N/A",
    },
    { icon: <Hash size={16} />, label: "Scan ID", value: scanData.scan_number },
  ];

  const getSeverityChip = (severity: string) => {
    switch (severity) {
      case "Critical":
        return <Image src="/critical-chip.svg" alt="Critical" width={73} height={28} />;
      case "High":
        return <Image src="/high-risk-chip.svg" alt="High" width={86} height={28} />;
      case "Medium":
        return <Image src="/medium-risk-chip.svg" alt="Medium" width={106} height={28} />;
      case "Low":
        return <Image src="/low-risk-chip.svg" alt="Low" width={83} height={28} />;
      case "Info":
        return <Image src="/info-chip.svg" alt="Info" width={58} height={28} />;
      case "Best Practices":
        return <Image src="/best-practices-chip.svg" alt="Best Practice" width={119} height={28} />;
    }
  };

  const renderFailed = () => (
    <ScanStateMessage icon={<AlertTriangle size={40} className="text-red-500" />} message="Scan failed" />
  );

  const renderInProgress = () => (
    <ScanStateMessage
      icon={<Spinner size="lg" color="secondary" />}
      message="Please wait a few minutes while your scan is being processed. You can close this page."
    />
  );

  const renderNoFindings = () => (
    <ScanStateMessage
      icon={<CheckCircle size={40} className="text-green-500" />}
      message="Congratulations! No vulnerabilities found."
    />
  );

  const renderFindings = () => (
    <div>
      {scanData.findings.map((finding: Finding, index: number) => (
        <Card
          key={index}
          className="bg-[#222222] mb-6 border-2 border-[#18181B]"
          ref={(el) => {
            findingsRefs.current[finding.Issue] = el;
          }}
        >
          <CardHeader className="flex flex-row justify-between bg-[#18181B] border-1 border-[#18181B] font-inter font-normal text-sm text-[#B8B8B8]">
            <div className="flex items-center space-x-2">
              <Image src="/vulnerability-icon.svg" alt="Error" width={15} height={14} className="mr-1" />
              <span className="text-sm">
                {index + 1} of {scanData.total_findings ?? 1} Vulnerability
              </span>
              <Dot size={25} />
              <Image src="/file-icon.svg" alt="Error" width={14} height={14} className="mr-1" />
              <div className="text-sm">{finding.Contracts.join(", ")}</div>
            </div>
          </CardHeader>
          <CardBody className="px-0 bg-black">
            <div className="flex justify-between items-center mb-2">
              <div className="flex items-center space-x-2 border-b-2 border-[#18181B] pb-2 w-full px-3">
                <p className="text-sm font-medium text-white">{finding.Issue}</p>
                {getSeverityChip(finding.Severity)}
              </div>
            </div>
            <p className="text-sm font-normal text-[#D4D4D8] mb-2 px-3">{finding.Description}</p>
          </CardBody>
        </Card>
      ))}
    </div>
  );

  useEffect(() => {
    const mainElement = document.querySelector("main");
    if (!mainElement) return;

    const handleScroll = () => {
      const scrollPosition = mainElement.scrollTop;
      setIsSticky(scrollPosition > 50);
    };

    mainElement.addEventListener("scroll", handleScroll);
    return () => mainElement.removeEventListener("scroll", handleScroll);
  }, []);

  return (
    <div className="h-full relative flex flex-col lg:flex-row">
      <div className="w-full">
        <div className="flex justify-between items-center mb-1 ml-4 mr-4 w-full p-4">
          <div className="text-sm text-gray-400 flex">
            Dashboard <div className="mx-2">/</div> <div className="text-white">Results</div>
          </div>
          <div className="flex space-x-2">
            <Tooltip content="More information">
              <Button
                size="sm"
                className="font-inter text-sm font-normal bg-[#18181B] hover:bg-[#27272A] border-1 border-[#3F3F46]"
                startContent={<Info size={20} />}
                onPress={() => setIsInfoModalOpen(true)}
              >
                Info
              </Button>
            </Tooltip>
            {isPaid && (
              <Tooltip content="Send to email">
                <Button
                  size="sm"
                  className="bg-[#8B5CF6] hover:bg-[#7C3AED]"
                  startContent={<Image src="/mail.svg" width={20} height={20} alt="Send Email" />}
                  onPress={handleSendReportAgain}
                >
                  Resend Report
                </Button>
              </Tooltip>
            )}
          </div>
        </div>
        <Divider className="my-2" />
        <div className="relative flex flex-col lg:flex-row lg:justify-center">
          {!isNoFinding && (
            <div
              className={`transition-all duration-300 mt-3 
              ${isCollapsed ? "w-[50px]" : "w-full lg:w-1/5"}`}
            >
              <div className={`${isSticky ? "lg:sticky lg:top-[15px]" : ""} transition-all duration-300`}>
                <FindingsMenu
                  findings={scanData.findings}
                  onSelectFinding={(finding) => {
                    setSelectedFinding(finding);
                    scrollToFinding(finding);
                  }}
                  isCollapsed={isCollapsed}
                  setIsCollapsed={setIsCollapsed}
                  selectedFinding={selectedFinding}
                />
              </div>
            </div>
          )}

          <div
            className={`transition-all duration-300 flex justify-center
              ${isCollapsed ? "w-full lg:w-[calc(100%-50px)]" : "w-full lg:w-3/4"}`}
          >
            <div
              className={`transition-all duration-300 px-4 lg:px-8 pb-8 pt-4 
              ${isCollapsed ? "w-full lg:w-[80%]" : "w-full"}`}
            >
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
                {scanStats.map((stat, index) => (
                  <Card key={index} className="bg-[#0F0F0F] border-2 border-[#18181B]">
                    <CardBody className="flex flex-row items-center space-x-3">
                      <div className="bg-[#18181B] p-2 rounded-xl">{stat.icon}</div>
                      <div>
                        <p className="text-sm font-inter font-normal text-[#A1A1AA]">{stat.label}</p>
                        <p className="text-sm font-medium">{stat.value}</p>
                      </div>
                    </CardBody>
                  </Card>
                ))}
              </div>

              <CodeSummary summary={scanData.summary} />

              {isFailed && renderFailed()}
              {!isCompleted && !isFailed && renderInProgress()}
              {isNoFinding && renderNoFindings()}
              {!isNoFinding && renderFindings()}
            </div>
          </div>
        </div>
      </div>

      <ScanInfo isOpen={isInfoModalOpen} onClose={() => setIsInfoModalOpen(false)} scanData={scanData} />
    </div>
  );
};

export default ScanFullResults;

interface ScanStateMessageProps {
  icon: React.ReactNode;
  message: string;
}

const ScanStateMessage: React.FC<ScanStateMessageProps> = ({ icon, message }) => (
  <div className="h-[calc(100%-6rem)]">
    <div className="flex flex-col items-center justify-center h-full">
      {icon}
      <p className="mt-4 text-lg">{message}</p>
    </div>
  </div>
);

"use client";

import { type FC, useEffect, useState } from "react";

import { Card, CardBody, Button, Tooltip, Skeleton } from "@nextui-org/react";
import { AlertTriangle, FileText, Code, Hash, Info, ThumbsUp } from "lucide-react";

import { Container, StateMessage } from "@/components/layout";
import { ScanProgress } from "@/components/scan-stepper/ScanProgress";
import ScanInfo from "@/components/ScanInfo";

import { CodeSummary, FindingsMenu } from "../scan-results";

interface ScanLoadingStateViewProps {
  scanData: ScanResult;
}

const ScanLoadingStateView: FC<ScanLoadingStateViewProps> = ({ scanData }) => {
  const [isInfoModalOpen, setIsInfoModalOpen] = useState(false);
  const [isCollapsed, setIsCollapsed] = useState(false);

  const isCompleted = scanData.scan.status === "completed";
  const inProgress = scanData.scan.status === "in_progress";
  const isFailed = scanData.scan.status === "failed";
  const isNoFinding = isCompleted && scanData.total_findings === 0;

  const scanStats = [
    {
      icon: <AlertTriangle size={22} />,
      label: "Vulnerabilities Found",
      value: isFailed ? "N/A" : (scanData.total_findings ?? 0),
    },
    {
      icon: <FileText size={22} />,
      label: "Contracts Scanned",
      value: scanData.scan.contractFiles?.length.toString() || "0",
    },
    {
      icon: <Code size={22} />,
      label: "Lines of Code",
      value: scanData.scan.linesOfCode?.total_lines.toString() || "N/A",
    },
    { icon: <Hash size={22} />, label: "Scan ID", value: scanData.scan_number },
  ];

  const renderFailed = () => (
    <div className="relative h-[calc(100%-6rem)]">
      <StateMessage icon={<AlertTriangle size={40} className="text-red-500" />} message="Scan failed" />
    </div>
  );

  const renderInProgress = () => (
    <div className="h-[calc(100%-6rem)] flex flex-col items-center justify-center space-y-8">
      <ScanProgress progress={scanData.scan.progress ?? 0} />
    </div>
  );

  const renderNoFindings = () => (
    <div className="h-64 flex flex-col items-center justify-center space-y-8">
      <div className="flex flex-col items-center space-y-4 w-56">
        <Card className="p-4">
          <ThumbsUp size={40} className="text-secondary" />
        </Card>

        <p className="font-medium">No Vulnerabilities Found</p>
        <p className="text-foreground-500 text-center text-sm">Your code has no vulnerabilities. Great work!</p>
      </div>
    </div>
  );

  useEffect(() => {
    if (isCompleted || isFailed || inProgress) {
      setIsCollapsed(true);
    } else {
      setIsCollapsed(false);
    }
  }, [isCompleted, isFailed, inProgress]);

  return (
    <Container
      breadcrumbItems={[
        { label: "Dashboard", href: "/dashboard" },
        { label: scanData.scan.repositoryName ?? "", href: `/repository/${scanData.scan.repositoryName}` },
        { label: scanData.scan_number.toString(), href: `/scan-results/${scanData.scan_number}` },
      ]}
      buttons={
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
      }
    >
      <div className="w-full min-h-[65vh] flex flex-col lg:flex-row lg:justify-center">
        {/* Findings Menu */}
        <div className={`h-full transition-all duration-300 ${isCollapsed ? "w-[50px] flex-none" : "w-full lg:w-1/5"}`}>
          <div className="sticky top-0 h-full overflow-y-auto w-full flex justify-center pt-4">
            <div className={`w-full ${isCollapsed ? "flex justify-center" : ""}`}>
              <FindingsMenu
                findings={scanData.findings}
                onSelectFinding={() => {}}
                isCollapsed={isCollapsed}
                setIsCollapsed={setIsCollapsed}
                selectedFinding={null}
                isLoading
                isButtonDisabled
              />
            </div>
          </div>
        </div>

        <div
          className={`transition-all duration-300 flex-1 overflow-y-auto flex justify-center ${
            isCollapsed ? "lg:w-[calc(100%-50px)]" : "lg:w-3/4"
          }`}
        >
          <div className={`transition-all duration-300 w-full lg:w-[95%] px-4 lg:px-8 pb-8 pt-4`}>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
              {scanStats.map((stat, index) => (
                <Card key={index} className="bg-[#0F0F0F] border-2 border-[#18181B]">
                  <CardBody className="flex flex-row items-center space-x-3">
                    <div className="bg-[#18181B] p-2 rounded-xl">{stat.icon}</div>
                    <div>
                      <p className="text-sm font-inter font-normal text-[#A1A1AA]">{stat.label}</p>
                      {index === 0 && inProgress ? (
                        <Skeleton className="h-4 w-12 rounded-md" />
                      ) : (
                        <p className="text-sm font-medium">{stat.value}</p>
                      )}
                    </div>
                  </CardBody>
                </Card>
              ))}
            </div>

            {isNoFinding && <CodeSummary summary={scanData.summary} />}

            {isFailed && renderFailed()}

            {!isFailed && !isCompleted && renderInProgress()}

            {isNoFinding && renderNoFindings()}
          </div>
        </div>
      </div>

      <ScanInfo isOpen={isInfoModalOpen} onClose={() => setIsInfoModalOpen(false)} scanData={scanData} />
    </Container>
  );
};

export default ScanLoadingStateView;

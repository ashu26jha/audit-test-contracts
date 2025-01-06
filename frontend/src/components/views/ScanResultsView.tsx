"use client";

import { type FC, useState } from "react";

import { Card, CardBody, Button, Tooltip } from "@nextui-org/react";
import { AlertTriangle, FileText, Code, Hash, Info, CheckCircle } from "lucide-react";

import { Container, StateMessage, BottomBanner } from "@/components/layout";
import PaymentsModal from "@/components/Modals/PaymentsModal";
import { BluredFindings, Finding } from "@/components/scan-results";
import { ScanProgress } from "@/components/scan-stepper/ScanProgress";
import ScanInfo from "@/components/ScanInfo";

interface ScanResultsViewProps {
  scanData: ScanResult;
}

const ScanResultsView: FC<ScanResultsViewProps> = ({ scanData }) => {
  const [isInfoModalOpen, setIsInfoModalOpen] = useState(false);
  const [isSubscriptionModalOpen, setIsSubscriptionModalOpen] = useState(false);

  const isCompleted = scanData.scan.status === "completed";
  const isFailed = scanData.scan.status === "failed";
  const isPaid = isCompleted && scanData.scan.paid_status;
  const isNoFinding = isCompleted && scanData.total_findings === 0;

  const scanStats = [
    {
      icon: <AlertTriangle size={22} />,
      label: "Vulnerabilities Found",
      value: scanData.total_findings ?? 0,
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
    <StateMessage icon={<AlertTriangle size={40} className="text-red-500" />} message="Scan failed" />
  );

  const renderInProgress = () => (
    <div className="h-full flex flex-col items-center justify-center space-y-8">
      <ScanProgress progress={scanData.scan.progress ?? 0} />
      <p className="text-lg">You can close this page. You&apos;ll receive an email when the scan is complete.</p>
    </div>
  );

  const renderNoFindings = () => (
    <StateMessage
      icon={<CheckCircle size={40} className="text-green-500" />}
      message="Congratulations! No vulnerabilities found."
    />
  );

  const renderFindings = () => (
    <>
      {scanData.findings.length > 0 && (
        <Finding finding={scanData.findings[0]} index={0} totalFindings={scanData.total_findings ?? 1} />
      )}
    </>
  );

  return (
    <Container
      breadcrumbItems={["Dashboard", scanData.scan.repositoryName, scanData.scan_number.toString()]}
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
      <div className="overflow-hidden h-full">
        <div className="flex-1 min-h-0 flex flex-col">
          <div className="h-full w-full lg:w-[80%] mx-auto flex flex-col pt-4">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
              {scanStats.map((stat, index) => (
                <Card key={index} className="bg-[#0F0F0F] border-2 border-[#18181B]">
                  <CardBody className="flex flex-row items-center space-x-3">
                    <div className="bg-[#18181B] p-2 rounded-lg">{stat.icon}</div>
                    <div>
                      <p className="text-sm font-inter font-normal text-[#A1A1AA]">{stat.label}</p>
                      <p className="text-sm font-medium">{stat.value}</p>
                    </div>
                  </CardBody>
                </Card>
              ))}
            </div>

            <div className="flex-1 min-h-[60vh] overflow-hidden flex flex-col justify-center items-center">
              {/* Failed scans */}
              {isFailed && renderFailed()}

              {/* In progress scans */}
              {!isFailed && !isCompleted && renderInProgress()}

              {/* No findings scans */}
              {isNoFinding && renderNoFindings()}

              {/* Findings scans */}
              {isCompleted && !isNoFinding && renderFindings()}

              {/* Blured finding when not paid */}
              {isCompleted && !isPaid && !isNoFinding && <BluredFindings />}
            </div>
          </div>
        </div>

        <ScanInfo isOpen={isInfoModalOpen} onClose={() => setIsInfoModalOpen(false)} scanData={scanData} />
        <PaymentsModal
          isOpen={isSubscriptionModalOpen}
          setIsOpen={setIsSubscriptionModalOpen}
          scanId={scanData.scan_id}
        />

        {isCompleted && !isPaid && !isNoFinding && (
          <BottomBanner
            title="Only one finding is free."
            description={`Unlock full access to a detailed report of ${scanData.total_findings} vulnerabilities.`}
            buttonText="Pay & Get Full Report"
            action={() => setIsSubscriptionModalOpen(true)}
            cardBgColor="bg-[#F2EAFA]"
            titleColor="text-black"
            descriptionColor="text-black"
            buttonClassName="bg-secondary text-white"
          />
        )}
      </div>
    </Container>
  );
};

export default ScanResultsView;

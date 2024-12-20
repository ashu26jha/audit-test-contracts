"use client";

import { type FC, useState } from "react";

import { Card, CardBody, Button, Tooltip, Divider } from "@nextui-org/react";
import { AlertTriangle, FileText, Code, Hash, Info, CheckCircle } from "lucide-react";

import { Breadcrumb, StateMessage } from "@/components/layout";

import PaymentsModal from "../Modals/PaymentsModal";
import { BluredFindings, Finding } from "../scan-results";
import { ScanProgress } from "../scan-stepper/ScanProgress";
import ScanInfo from "../ScanInfo";

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

  const renderPaymentCard = () => (
    <div className="bg-transparent sticky flex justify-center items-end bottom-0 left-0 right-0 bg-gradient-to-t from-[#3B175F] to-[#18181B00] rounded-b-xl h-[8rem]">
      <Card className="lg:w-[80%]  bg-[#F2EAFA] bottom-6 flex justify-between items-center p-2">
        <CardBody className="flex flex-row justify-between items-center space-x-2">
          <div className="flex flex-col pl-5">
            <strong className="text-sm text-black">Only one finding is free.</strong>
            <p className="text-sm text-black">
              Unlock full access to a detailed report of {scanData.total_findings} vulnerabilities.
            </p>
          </div>

          <Button color="secondary" className="bg-secondary" onPress={() => setIsSubscriptionModalOpen(true)}>
            Pay & Get Full Report
          </Button>
        </CardBody>
      </Card>
    </div>
  );

  return (
    <div className="h-full flex flex-col">
      <div className="w-full flex flex-raw justify-between items-center pb-4 px-4">
        <Breadcrumb base="Dashboard" current={scanData.scan.repositoryName} />
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
      </div>

      <Divider className="my-2" />

      <div className="flex-1 flex justify-center min-h-0">
        <div className="w-full lg:w-[80%] flex flex-col pt-4">
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

          <div className="flex-1 relative min-h-0">
            <div className="absolute inset-0 overflow-hidden">
              {/* Failed scans */}
              {isFailed && renderFailed()}

              {/* In progress scans */}
              {!isFailed && !isCompleted && renderInProgress()}

              {/* No findings scans */}
              {isNoFinding && renderNoFindings()}

              {/* Findings scans */}
              {!isNoFinding && renderFindings()}

              {/* Blured finding when not paid */}
              {isCompleted && !isPaid && !isNoFinding && <BluredFindings />}
            </div>
          </div>
        </div>
      </div>

      {isCompleted && !isPaid && !isNoFinding && renderPaymentCard()}

      <ScanInfo isOpen={isInfoModalOpen} onClose={() => setIsInfoModalOpen(false)} scanData={scanData} />
      <PaymentsModal
        isOpen={isSubscriptionModalOpen}
        setIsOpen={setIsSubscriptionModalOpen}
        scanId={scanData.scan_id}
      />
    </div>
  );
};

export default ScanResultsView;

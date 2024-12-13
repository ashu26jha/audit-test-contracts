"use client";

import { type FC, useState } from "react";

import { Card, CardBody, Button, Tooltip, Divider, CardHeader } from "@nextui-org/react";
import { AlertTriangle, FileText, Code, Hash, Info, CheckCircle, Dot } from "lucide-react";
import Image from "next/image";

import { Breadcrumb, MarkdownWithCode, StateMessage } from "@/components/layout";
import { openFeedbackEmail } from "@/utils/email";

import SubscriptionPlansModal from "../Modals/SubscriptionPlansModal";
import { BluredFindings } from "../scan-results";
import { ScanProgress } from "../scan-stepper/ScanProgress";
import ScanInfo from "../ScanInfo";

interface ScanResultsViewProps {
  scanData: ScanResult;
  handlePayment: () => void;
}

const ScanResultsView: FC<ScanResultsViewProps> = ({ scanData }) => {
  const [isInfoModalOpen, setIsInfoModalOpen] = useState(false);
  const [isSubscriptionModalOpen, setIsSubscriptionModalOpen] = useState(false);

  const isCompleted = scanData.scan.status === "completed";
  const isFailed = scanData.scan.status === "failed";
  const isPaid = isCompleted && scanData.scan.paid_status;
  const isNoFinding = isCompleted && scanData.total_findings === 0;
  const hasFindings = isCompleted && scanData.total_findings > 1;

  const handleSendFeedback = () => {
    const subject = `Feedback for Scan ${scanData.scan_number}`;
    const body = `Dear Support Team,

I would like to provide feedback for my recent scan (ID: ${scanData.scan_number}).

[Please enter your feedback here]

Thank you,
[Your Name]`;

    openFeedbackEmail(subject, body);
  };

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

  const getSeverityChip = (severity: string) => {
    switch (severity) {
      case "Critical":
        return <Image src="/svg/critical-chip.svg" alt="Critical" width={73} height={28} />;
      case "High":
        return <Image src="/svg/high-risk-chip.svg" alt="High" width={86} height={28} />;
      case "Medium":
        return <Image src="/svg/medium-risk-chip.svg" alt="Medium" width={106} height={28} />;
      case "Low":
        return <Image src="/svg/low-risk-chip.svg" alt="Low" width={83} height={28} />;
      case "Info":
        return <Image src="/svg/info-chip.svg" alt="Info" width={58} height={28} />;
      case "Best Practices":
        return <Image src="/svg/best-practices-chip.svg" alt="Best Practice" width={119} height={28} />;
    }
  };

  const renderFailed = () => (
    <StateMessage icon={<AlertTriangle size={40} className="text-red-500" />} message="Scan failed" />
  );

  const renderInProgress = () => (
    <div className="h-[calc(100%-6rem)]">
      <div className="flex flex-col items-center justify-center h-full space-y-8">
        <ScanProgress progress={scanData.scan.progress ?? 0} />
        <p className="text-lg">You can close this page. You&apos;ll receive an email when the scan is complete.</p>
      </div>
    </div>
  );

  const renderNoFindings = () => (
    <StateMessage
      icon={<CheckCircle size={40} className="text-green-500" />}
      message="Congratulations! No vulnerabilities found."
    />
  );

  const renderFindings = () => (
    <div>
      {scanData.findings.map((finding: Finding, index: number) => (
        <Card key={index} className="bg-[#222222] mb-6 border-2 border-[#18181B]">
          <CardHeader className="flex flex-row justify-between bg-[#18181B] border-1 border-[#18181B] font-inter font-normal text-sm text-[#B8B8B8]">
            <div className="flex items-center space-x-2">
              <Image src="/svg/vulnerability-icon.svg" alt="Error" width={15} height={14} className="mr-1" />
              <span className="text-sm">
                {index + 1} of {scanData.total_findings ?? 1} Vulnerability
              </span>
              <Dot size={25} />
              <Image src="/svg/file-icon.svg" alt="Error" width={14} height={14} className="mr-1" />
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
            <MarkdownWithCode content={finding.Description} />
          </CardBody>
        </Card>
      ))}
    </div>
  );

  const renderPaymentCard = () => (
    <div className="sticky flex justify-center items-end bottom-0 left-0 right-0 bg-gradient-to-t from-[#3B175F] to-[#18181B00] rounded-b-xl h-40">
      <Card className="lg:w-[80%]  bg-[#F2EAFA] bottom-5 flex justify-between items-center p-2">
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

  const alreadyPaidMessage = () => {
    if (hasFindings) {
      return `You've already paid for this contract report.`;
    } else if (isNoFinding) {
      return `This scan was free because we found ${scanData.total_findings} vulnerability.`;
    } else {
      return `This scan was free because we only found ${scanData.total_findings} vulnerability.`;
    }
  };

  const checkEmailMessage = () => {
    if (hasFindings) {
      return `Please check your email for the detailed report of ${scanData.total_findings} vulnerabilities.`;
    } else {
      return "Please check your email for the detailed report.";
    }
  };

  const renderAlreadyPaid = () => (
    <Card className="absolute bottom-5 left-8 right-8 flex justify-between items-center p-2 bg-[#222222]">
      <CardBody className="flex flex-row justify-between items-center space-x-2">
        <div className="flex flex-col pl-5">
          <strong className="text-sm">{alreadyPaidMessage()}</strong>
          <p className="text-sm">{checkEmailMessage()}</p>
        </div>

        <Button
          endContent={<Image src="/svg/feedback.svg" width={20} height={20} alt="feedback" />}
          onPress={handleSendFeedback}
        >
          Send Feedback
        </Button>
      </CardBody>
    </Card>
  );

  return (
    <div className="h-full relative flex flex-col lg:flex-row">
      <div className="w-full">
        <div className="flex justify-between items-center mb-1 ml-4 mr-4 w-full p-4">
          <Breadcrumb base="Dashboard" current={scanData.scan.repositoryName} />
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
          </div>
        </div>
        <Divider className="my-2" />

        <div className="flex justify-center w-full lg:w-[calc(100%-50px)]">
          <div className="px-4 lg:px-8 pb-8 pt-4 w-full lg:w-[80%]">
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

            {isFailed && renderFailed()}
            {!isCompleted && !isFailed && renderInProgress()}
            {isNoFinding && renderNoFindings()}
            {!isNoFinding && renderFindings()}

            {isPaid && renderAlreadyPaid()}
          </div>
        </div>
        {!isPaid && hasFindings && (
          <>
            <BluredFindings />
            {renderPaymentCard()}
          </>
        )}
      </div>

      <ScanInfo isOpen={isInfoModalOpen} onClose={() => setIsInfoModalOpen(false)} scanData={scanData} />
      <SubscriptionPlansModal isOpen={isSubscriptionModalOpen} setIsOpen={setIsSubscriptionModalOpen} />
    </div>
  );
};

export default ScanResultsView;

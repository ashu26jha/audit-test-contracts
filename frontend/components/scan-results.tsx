import React, { useState } from "react";

import { Card, CardBody, CardHeader, Button, Tooltip, Divider, Spinner } from "@nextui-org/react";
import { AlertTriangle, FileText, Code, Hash, Info, CheckCircle } from "lucide-react";
import Image from "next/image";

import { useAuth } from "@/contexts/AuthContext";
import { useToast } from "@/hooks/useToast";
import { sendPdfReport } from "@/services/api";

import BluredFindings from "./blured-findings";
import ScanInfo from "./scan-info";
import { openFeedbackEmail } from "../utils/email";

interface ScanResultsProps {
  scanData: ScanResult;
  handlePayment: () => void;
}

const ScanResults: React.FC<ScanResultsProps> = ({ scanData, handlePayment }) => {
  const { toast } = useToast();
  const { token } = useAuth();
  const [isInfoModalOpen, setIsInfoModalOpen] = useState(false);

  const isCompleted = scanData.scan.status === "completed";
  const isFailed = scanData.scan.status === "failed";
  const isPaid = isCompleted && scanData.scan.paid_status;
  const isNoFinding = isCompleted && scanData.total_findings === 0;
  const hasFindings = isCompleted && scanData.total_findings > 1;

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
        <Card key={index} className="bg-[#222222] mb-6">
          <CardBody>
            <div className="flex justify-between items-center mb-2">
              <div className="flex items-center space-x-2">
                <AlertTriangle size={16} className="text-red-500" />
                <span className="text-sm">
                  Finding {index + 1} of {scanData.total_findings ?? 1}
                </span>
              </div>
              <div className="text-sm text-gray-400">{finding.Contracts.join(", ")}</div>
            </div>
            <h3 className="text-lg font-semibold mb-2">{finding.Issue}</h3>
            <p className="text-sm text-gray-300 mb-2">{finding.Description}</p>
          </CardBody>
        </Card>
      ))}
    </div>
  );

  const renderPaymentCard = () => (
    <Card className="absolute bottom-5 left-0 right-0 bg-[#F2EAFA] flex justify-between items-center p-2">
      <CardBody className="flex flex-row justify-between items-center space-x-2">
        <div className="flex flex-col pl-5">
          <strong className="text-sm text-black">Only partial findings are shown.</strong>
          <p className="text-sm text-black">
            Unlock full access to a detailed report of {scanData.total_findings} vulnerabilities.
          </p>
        </div>

        <Button color="secondary" className="bg-[#8B5CF6] hover:bg-[#7C3AED]" onPress={handlePayment}>
          Pay $20 via Stripe
        </Button>
      </CardBody>
    </Card>
  );

  const renderAlreadyPaid = () => (
    <Card className="absolute bottom-5 left-8 right-8 flex justify-between items-center p-2 bg-[#222222]">
      <CardBody className="flex flex-row justify-between items-center space-x-2">
        <div className="flex flex-col pl-5">
          <strong className="text-sm">You&apos;ve already paid for this contract report.</strong>
          <p className="text-sm">
            Please check your email for the detailed report of {scanData.total_findings} vulnerabilities.
          </p>
        </div>

        <Button
          endContent={<Image src="/feedback.svg" width={20} height={20} alt="feedback" />}
          onPress={handleSendFeedback}
        >
          Send Feedback
        </Button>
      </CardBody>
    </Card>
  );

  return (
    <Card className="h-full relative">
      <CardHeader>
        <div className="flex justify-between items-center mb-1 ml-4 mr-4 w-full">
          <div className="text-sm text-gray-400 flex">
            Dashboard <div className="mx-2">/</div> <div className="text-white">Results</div>
          </div>
          <div className="flex space-x-2">
            <Tooltip content="More information">
              <Button size="sm" startContent={<Info size={20} />} onPress={() => setIsInfoModalOpen(true)}>
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
                  Send Report Again
                </Button>
              </Tooltip>
            )}
          </div>
        </div>
      </CardHeader>
      <Divider />

      <main className="h-full p-8">
        <div className="grid grid-cols-4 gap-4 mb-6">
          {scanStats.map((stat, index) => (
            <Card key={index} className="bg-[#222222]">
              <CardBody className="flex flex-row items-center space-x-3">
                {stat.icon}
                <div>
                  <p className="text-sm text-gray-400">{stat.label}</p>
                  <p className="text-lg font-semibold">{stat.value}</p>
                </div>
              </CardBody>
            </Card>
          ))}
        </div>

        {isFailed && renderFailed()}
        {!isCompleted && !isFailed && renderInProgress()}
        {isNoFinding && renderNoFindings()}
        {!isNoFinding && renderFindings()}
        {!isPaid && hasFindings && (
          <>
            <BluredFindings />
            {renderPaymentCard()}
          </>
        )}
        {isPaid && renderAlreadyPaid()}
      </main>

      <ScanInfo isOpen={isInfoModalOpen} onClose={() => setIsInfoModalOpen(false)} scanData={scanData} />
    </Card>
  );
};

export default ScanResults;

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

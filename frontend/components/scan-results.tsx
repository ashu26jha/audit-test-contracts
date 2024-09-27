import React, { useState } from "react";
import {
  Card,
  CardBody,
  CardHeader,
  Button,
  Tooltip,
  Modal,
  ModalContent,
  ModalHeader,
  ModalBody,
  ModalFooter,
  Divider,
} from "@nextui-org/react";
import { AlertTriangle, FileText, Code, Hash, Info, Home, GitBranch, FileCode, LockIcon } from "lucide-react";
import BluredFindings from "./blured-findings";
import Image from "next/image";
import { sendReportAgain } from "../services/api";
import { useAuth } from "../contexts/AuthContext";
import { useToast } from "@/hooks/useToast";

interface ScanResultsProps {
  scanData: any;
  handlePayment: () => void;
}

const ScanResults: React.FC<ScanResultsProps> = ({ scanData, handlePayment }) => {
  const { toast } = useToast();
  console.log("scanData", scanData);
  const [isInfoModalOpen, setIsInfoModalOpen] = useState(false);
  const { token } = useAuth();
  const isPaid = scanData.scan.paid_status;
  console.log("isPaid", isPaid);

  const handleSendReportAgain = () => {
    console.log("send report again");
    if (!token) {
      console.error("No token found");
      return;
    }
    sendReportAgain(token, scanData.scan_id);
    toast({
      title: "Report sent",
      status: "success",
    });
  };

  const scanStats = [
    {
      icon: <AlertTriangle size={22} />,
      label: "Vulnerabilities Found",
      value: scanData.total_findings ?? 1,
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

  return (
    <Card className="h-full relative">
      {/* <div className="min-h-screen bg-black text-white flex flex-col"> */}
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
                  startContent={<Image src="/mail.svg" width={20} height={20} alt="mail" />}
                  onPress={() => handleSendReportAgain()}
                >
                  Send Report Again
                </Button>
              </Tooltip>
            )}
          </div>
        </div>
      </CardHeader>
      <Divider />

      <main className="flex-grow p-8">
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

        {scanData.findings.map((finding: any, index: any) => (
          <Card key={index} className="bg-[#222222] mb-6">
            <CardBody>
              <div className="flex justify-between items-center mb-2">
                <div className="flex items-center space-x-2">
                  <AlertTriangle size={16} className="text-red-500" />
                  <span className="text-sm">
                    Finding {index + 1} of {scanData.total_findings ?? scanData.findings.length}
                  </span>
                </div>
                <div className="text-sm text-gray-400">{finding.Contracts.join(", ")}</div>
              </div>
              <h3 className="text-lg font-semibold mb-2">{finding.Issue}</h3>
              <p className="text-sm text-gray-300 mb-2">{finding.Description}</p>
              <p className="text-sm text-gray-300 mb-2">
                <strong>Recommendation:</strong> {finding.Recommendation}
              </p>
            </CardBody>
          </Card>
        ))}

        {/* If it is not paid show the blured findings */}
        {!isPaid && <BluredFindings />}

        {!isPaid && (
          <Card className="absolute bottom-5 left-0 right-0 bg-[#F2EAFA] flex justify-between items-center p-2">
            <CardBody className="flex flex-row justify-between items-center space-x-2">
              <div className="flex flex-col pl-5">
                <strong className="text-sm text-black">Only partial findings are shown.</strong>
                <p className="text-sm text-black">
                  Unlock full access to detailed report of {scanData.total_findings} vulnerabilities.
                </p>
              </div>

              <Button color="secondary" className="bg-[#8B5CF6] hover:bg-[#7C3AED]" onPress={handlePayment}>
                Pay $20 via stripe
              </Button>
            </CardBody>
          </Card>
        )}

        {isPaid && (
          <Card className="absolute bottom-5 left-8 right-8 flex justify-between items-center p-2 bg-[#222222]">
            <CardBody className="flex flex-row justify-between items-center space-x-2">
              <div className="flex flex-col pl-5">
                <strong className="text-sm">You&apos;ve already paid for this contract report.</strong>
                <p className="text-sm">
                  Please check your email for the detailed report of {scanData.total_findings} vulnerabilities.
                </p>
              </div>

              <Button endContent={<Image src="/feedback.svg" width={20} height={20} alt="feedback" />}>
                Send Feedback
              </Button>
            </CardBody>
          </Card>
        )}
      </main>

      {/* Info Modal (you may need to update this based on the actual data structure) */}
      <Modal isOpen={isInfoModalOpen} onClose={() => setIsInfoModalOpen(false)} className="bg-[#222222] text-white">
        <ModalContent>
          <ModalHeader className="flex flex-col gap-1">Scanned Code Info</ModalHeader>
          <ModalBody>
            {/* {infoModalContent.map((section, index) => (
              <Card key={index} className="bg-[#333333] mb-4">
                <CardBody>
                  <div className="flex items-center gap-2 mb-2">
                    {section.icon}
                    <h3 className="text-sm font-semibold">{section.title}</h3>
                  </div>
                  {section.content.map((item, itemIndex) => (
                    <div
                      key={itemIndex}
                      className="flex justify-between text-sm"
                    >
                      <span className="text-gray-400">{item.label}</span>
                      <span>{item.value}</span>
                    </div>
                  ))}
                </CardBody>
              </Card>
            ))} */}
          </ModalBody>
          <ModalFooter>
            <Button color="danger" variant="light" onPress={() => setIsInfoModalOpen(false)}>
              Close
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
    </Card>
  );
};

export default ScanResults;

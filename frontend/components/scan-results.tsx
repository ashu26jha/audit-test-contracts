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
import { AlertTriangle, FileText, Code, Hash, Info, Home, GitBranch, FileCode } from "lucide-react";
import Payment from "./payment";

interface ScanResultsProps {
  scanData: any; // Replace 'any' with a more specific type based on your API response
}

const ScanResults: React.FC<ScanResultsProps> = ({ scanData }) => {
  console.log("scanData", scanData);
  const [isInfoModalOpen, setIsInfoModalOpen] = useState(false);
  const [paymentStatus, setPaymentStatus] = useState<"success" | "failed" | null>(null);

  const handlePayment = () => {
    // Simulate payment process
    setTimeout(() => {
      // Randomly set payment status for demonstration
      setPaymentStatus(Math.random() > 0.5 ? "success" : "failed");
    }, 2000);
  };

  const handleRetryPayment = () => {
    setPaymentStatus(null);
    handlePayment();
  };

  if (paymentStatus) {
    return <Payment status={paymentStatus} onRetry={handleRetryPayment} />;
  }

  const scanStats = [
    {
      icon: <AlertTriangle size={20} />,
      label: "Vulnerabilities Found",
      value: scanData.total_findings ?? 1,
    },
    {
      icon: <FileText size={20} />,
      label: "Contracts Scanned",
      value: scanData.scan.contractFiles?.length.toString() || "0",
    },
    {
      icon: <Code size={20} />,
      label: "Lines of Code",
      value: scanData.scan.linesOfCode?.total_lines.toString() || "N/A",
    },
    { icon: <Hash size={20} />, label: "Scan ID", value: scanData.scan_id },
  ];

  return (
    <Card className="min-h-screen">
      {/* <div className="min-h-screen bg-black text-white flex flex-col"> */}
      <CardHeader>
        <div className="flex justify-between items-center mb-1 ml-4 mr-4 w-full">
          <div className="text-sm text-gray-400 flex">
            Dashboard <div className="mx-2">/</div> <div className="text-white">Results</div>
          </div>
          <Tooltip content="More information">
            <Button
              size="sm"
              startContent={<Info size={20} />}
              onPress={() => setIsInfoModalOpen(true)}
            >
              Info
            </Button>
          </Tooltip>
        </div>
      </CardHeader>
      <Divider />

      <main className="flex-grow p-8">
        <div className="grid grid-cols-4 gap-4 mb-6">
          {scanStats.map((stat, index) => (
            <Card key={index} className="bg-[#222222]">
              <CardBody className="flex flex-row items-center space-x-2">
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

        <Card className="">
          <CardBody className="flex flex-row justify-between items-center">
            <p className="text-sm">
              Only partial findings are shown. Unlock full access to detailed report of all
              vulnerabilities.
            </p>
            <Button color="secondary" className="bg-[#8B5CF6]" onPress={handlePayment}>
              Pay $10 via stripe
            </Button>
          </CardBody>
        </Card>
      </main>

      {/* Info Modal (you may need to update this based on the actual data structure) */}
      <Modal
        isOpen={isInfoModalOpen}
        onClose={() => setIsInfoModalOpen(false)}
        className="bg-[#222222] text-white"
      >
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

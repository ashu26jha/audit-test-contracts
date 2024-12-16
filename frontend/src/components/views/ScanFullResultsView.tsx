"use client";

import { type FC, useState, useRef } from "react";

import { Card, CardBody, Button, Tooltip, Divider } from "@nextui-org/react";
import { FileText, Code, Hash, Info } from "lucide-react";
import Image from "next/image";

import { useSendReport } from "@/hooks";

import { Breadcrumb } from "../layout";
import { CodeSummary, FindingsMenu, Finding, SendFeedback } from "../scan-results";
import ScanInfo from "../ScanInfo";

interface ScanFullResultsViewProps {
  scanData: ScanResult;
}

const ScanFullResultsView: FC<ScanFullResultsViewProps> = ({ scanData }) => {
  const { sendReportAgain, isLoading } = useSendReport();
  const [isInfoModalOpen, setIsInfoModalOpen] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [isCollapsed, setIsCollapsed] = useState(false);

  // Add ref for findings container
  const findingsRefs = useRef<{ [key: string]: HTMLDivElement | null }>({});

  // Add scroll handler
  const scrollToFinding = (finding: Finding) => {
    const findingElement = findingsRefs.current[finding.Issue];
    if (findingElement) {
      findingElement.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  };

  const scanStats = [
    {
      icon: <Image src="/svg/vulnerability-icon.svg" alt="Error" width={16} height={16} />,
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

  return (
    <div className="flex flex-col h-full">
      <div className="w-full flex flex-raw justify-between items-center pb-4 px-4">
        <Breadcrumb base="Dashboard" current="Results" />
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

          <Tooltip content="Send to email">
            <Button
              size="sm"
              className="bg-[#8B5CF6] hover:bg-[#7C3AED]"
              startContent={<Image src="/svg/mail.svg" width={20} height={20} alt="Send Email" />}
              onPress={() => sendReportAgain(scanData.scan_id)}
              isLoading={isLoading}
            >
              Resend Report
            </Button>
          </Tooltip>
        </div>
      </div>

      <Divider className="my-2" />

      <div className="w-full flex-1 flex flex-col lg:flex-row lg:justify-center min-h-0 ">
        <div
          className={`transition-all duration-300 lg:h-full ${isCollapsed ? "w-[50px] flex-none" : "w-full lg:w-1/5"}`}
        >
          <div className="lg:sticky lg:top-0 h-full overflow-y-auto w-full flex justify-center pt-4 overflow-y-hidden">
            <div className={`w-full ${isCollapsed ? "flex justify-center" : ""}`}>
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
                      <p className="text-sm font-medium">{stat.value}</p>
                    </div>
                  </CardBody>
                </Card>
              ))}
            </div>

            <CodeSummary summary={scanData.summary} />

            {scanData.findings.map((finding: Finding, index: number) => (
              <Finding
                key={index}
                finding={finding}
                index={index}
                totalFindings={scanData.total_findings ?? 1}
                ref={(el) => {
                  findingsRefs.current[finding.Issue] = el;
                }}
              />
            ))}
            <SendFeedback scanData={scanData} />
          </div>
        </div>
      </div>

      <ScanInfo isOpen={isInfoModalOpen} onClose={() => setIsInfoModalOpen(false)} scanData={scanData} />
    </div>
  );
};

export default ScanFullResultsView;

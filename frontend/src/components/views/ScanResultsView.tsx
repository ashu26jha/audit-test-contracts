"use client";

import { type FC, useState, useRef, useEffect } from "react";

import { Card, CardBody, Button, Tooltip } from "@nextui-org/react";
import { Hash, Info, Text } from "lucide-react";
import Image from "next/image";

import { Container } from "@/components/layout";
import { CodeSummary, FindingsMenu, Finding, SendFeedback } from "@/components/scan-results";
import Invariants from "@/components/scan-results/Invariants";
import ScanInfo from "@/components/ScanInfo";
import { useSendReport } from "@/hooks";

interface ScanResultsViewProps {
  scanData: ScanResult;
}

const ScanResultsView: FC<ScanResultsViewProps> = ({ scanData }) => {
  const { sendReportAgain, isLoading } = useSendReport();
  const [isInfoModalOpen, setIsInfoModalOpen] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [hasScrolled, setHasScrolled] = useState(false);

  // Add ref for findings container
  const findingsRefs = useRef<{ [key: string]: HTMLDivElement | null }>({});

  // Add scroll event listener
  useEffect(() => {
    const handleScroll = () => {
      setHasScrolled(window.scrollY > 0);
    };

    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  // Add scroll handler
  const scrollToFinding = (finding: Finding) => {
    const findingElement = findingsRefs.current[finding.Issue];
    if (findingElement) {
      findingElement.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  };

  const scanStats = [
    {
      icon: (
        <Image
          src="/svg/vulnerability-icon.svg"
          alt="Error"
          width={16}
          height={14}
          className="min-w-[16px] aspect-[16/14]"
        />
      ),
      label: "Vulnerabilities Found",
      value: scanData.total_findings ?? 0,
    },
    {
      icon: <Image src="/svg/contracts-scanned.svg" alt="Error" width={16} height={16} />,
      label: "Contracts Scanned",
      value: scanData.scan.contractFiles?.length.toString() || "0",
    },
    {
      icon: <Text size={16} />,
      label: "Lines of Code",
      value: scanData.scan.linesOfCode?.total_lines.toString() || "N/A",
    },
    { icon: <Hash size={16} />, label: "Scan ID", value: scanData.scan_number },
  ];

  return (
    <>
      <Container
        breadcrumbItems={[
          { label: "Dashboard", href: "/dashboard" },
          { label: scanData.scan.repositoryName ?? "", href: `/repository/${scanData.scan.repositoryName}` },
          { label: scanData.scan_number.toString(), href: `/scan-results/${scanData.scan_number}` },
        ]}
        buttons={
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
        }
      >
        <div className="w-full h-full flex flex-col lg:flex-row lg:justify-center">
          {/* Findings Menu */}
          <div
            className={`hidden lg:block h-full transition-all duration-300 ${isCollapsed ? "w-[50px] flex-none" : "lg:w-1/5"}`}
          >
            <div
              className={`fixed h-[70vh] transform ${hasScrolled ? "-translate-y-20" : "translate-y-0"} transition-all duration-300 ease-in-out overflow-y-auto flex justify-center pt-4 ${isCollapsed ? "w-[50px]" : "lg:w-1/5"}`}
            >
              <div className={`w-[90%] sm:w-full ${isCollapsed ? "flex justify-center" : ""}`}>
                {/* For desktop view */}
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

              {/* For mobile view */}
              <div className="lg:hidden">
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

              {scanData.invariants && <Invariants invariants={scanData.invariants} />}

              <SendFeedback scanData={scanData} />
            </div>
          </div>
        </div>
      </Container>

      <ScanInfo isOpen={isInfoModalOpen} onClose={() => setIsInfoModalOpen(false)} scanData={scanData} />
    </>
  );
};

export default ScanResultsView;

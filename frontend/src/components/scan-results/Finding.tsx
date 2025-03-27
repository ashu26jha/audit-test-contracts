import { forwardRef } from "react";

import { Card, CardBody, CardHeader } from "@nextui-org/react";
import { Dot } from "lucide-react";
import Image from "next/image";

import { MarkdownWithCode } from "../layout";

interface FindingProps {
  finding: Finding;
  index?: number;
  totalFindings?: number;
  isBlurred?: boolean;
}

const Finding = forwardRef<HTMLDivElement, FindingProps>(
  ({ finding, index = 0, totalFindings = 1, isBlurred = false }, ref) => {
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

    return (
      <Card
        ref={ref}
        className={`bg-[#222222] mb-6 border-2 border-[#18181B] ${isBlurred ? "blur-sm select-none cursor-default" : ""}`}
      >
        <CardHeader className="flex flex-row justify-center sm:justify-between bg-[#18181B] border-1 border-[#18181B] font-inter font-normal text-sm text-[#B8B8B8]">
          <div className="flex flex-col sm:flex-row items-center space-x-2">
            <div className="flex items-center space-x-2">
              <Image
                src="/svg/vulnerability-icon.svg"
                alt="Error"
                width={15}
                height={14}
                className="min-w-[15px] aspect-[15/14] mr-1"
              />
              <span className="text-sm">
                {index + 1} of {totalFindings} Vulnerability
              </span>
            </div>
            <Dot size={25} />
            <div className="flex items-center space-x-2">
              <Image src="/svg/file-icon.svg" alt="Error" width={14} height={14} className="mr-1" />
              <div className="text-sm">{finding.Contracts.join(", ")}</div>
            </div>
          </div>
        </CardHeader>

        <CardBody className={`px-0 bg-black ${isBlurred ? "select-none cursor-default" : ""}`}>
          <div className="flex justify-between items-center mb-2">
            <div className="h-full flex flex-col sm:flex-row justify-between items-center border-b-2 border-[#18181B] pb-2 w-full px-3">
              <div className="pt-4 order-2 sm:order-1">
                <MarkdownWithCode content={finding.Issue} />
              </div>
              <div className="order-1 sm:order-2">{getSeverityChip(finding.Severity)}</div>
            </div>
          </div>
          <div className="pt-3 px-3 overflow-hidden">
            <MarkdownWithCode content={finding.Description} />
          </div>
        </CardBody>
      </Card>
    );
  },
);

Finding.displayName = "Finding";

export default Finding;

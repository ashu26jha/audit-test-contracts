import { useState, type FC } from "react";

import { Accordion, AccordionItem, Card, CardHeader, Divider, Button, Skeleton } from "@nextui-org/react";
import { ChevronUp, ChevronDown, Dot } from "lucide-react";
import Image from "next/image";

import { MarkdownWithCode } from "../layout";

interface FindingsMenuProps {
  findings: Finding[];
  onSelectFinding: (finding: Finding) => void;
  isCollapsed: boolean;
  setIsCollapsed: (collapsed: boolean) => void;
  selectedFinding: Finding | null;
  isLoading?: boolean;
  isButtonDisabled?: boolean;
}

const FindingsMenu: FC<FindingsMenuProps> = ({
  findings,
  onSelectFinding,
  isCollapsed,
  setIsCollapsed,
  selectedFinding,
  isLoading,
  isButtonDisabled,
}) => {
  const severityColor = (severity: Finding["Severity"]) => {
    switch (severity) {
      case "Critical":
        return "text-[#F871A0]";
      case "High":
        return "text-[#F5A524]";
      case "Medium":
        return "text-[#D9D626]";
      case "Low":
        return "text-[#3F3F46]";
      case "Info":
        return "text-[#99C7FB]";
      case "Best Practices":
        return "text-[#12F3D8]";
    }
  };

  const groupedFindings = findings.reduce(
    (acc, finding) => {
      if (!acc[finding.Severity]) acc[finding.Severity] = [];
      acc[finding.Severity].push(finding);
      return acc;
    },
    {} as Record<Finding["Severity"], Finding[]>,
  );

  const [isExpanded, setIsExpanded] = useState(isCollapsed);

  const toggleExpand = () => {
    setIsExpanded(!isExpanded);
  };

  const handleKeyDown = (event: React.KeyboardEvent) => {
    if (event.key === "Enter" || event.key === " ") {
      toggleExpand();
    }
  };

  const severityKeys = Object.keys(groupedFindings);

  let globalIndex = 1; // Initialize a global index

  return (
    <Card
      className={`border-2 border-content-2 bg-content-1 transition-all duration-300 mb-4 lg:mb-0 
        ${isCollapsed ? "sm:w-[50px] h-fit" : "w-full lg:h-full"}`}
    >
      {!isCollapsed && isLoading && (
        <div className="flex flex-col h-full">
          <CardHeader className="mb-0 flex items-center justify-between">
            <p className="text-sm font-inter font-medium">Findings</p>

            <Button
              isDisabled={isButtonDisabled}
              isIconOnly
              className="bg-[#18181B] hover:bg-[#27272A]"
              size="sm"
              onPress={() => setIsCollapsed(!isCollapsed)}
            >
              <Image src="/svg/findings-icon.svg" width={14} height={14} alt="Findings Icon" />
            </Button>
          </CardHeader>
          <Divider className="my-2" />
          <div className="flex flex-col p-3 gap-y-4">
            <Skeleton className="h-6 w-full rounded-lg" />
            <Skeleton className="h-6 w-3/4 rounded-lg" />
            <Skeleton className="h-6 w-2/4 rounded-lg" />
            <Skeleton className="h-6 w-1/4 rounded-lg" />
            <Skeleton className="h-6 w-full rounded-lg" />
          </div>
        </div>
      )}

      {!isCollapsed && !isLoading && (
        <div className="flex flex-col h-full">
          {/* Desktop */}
          <CardHeader className="hidden lg:flex mb-0 items-center justify-between">
            <p className="text-sm font-inter font-medium">Findings</p>

            <Button
              isDisabled={isButtonDisabled}
              isIconOnly
              className="bg-[#18181B] hover:bg-[#27272A]"
              size="sm"
              onPress={() => setIsCollapsed(!isCollapsed)}
            >
              <div className="hidden lg:block">
                <Image src="/svg/findings-icon.svg" width={14} height={14} alt="Findings Icon" />
              </div>
              <div className="block lg:hidden">
                <ChevronUp size={16} />
              </div>
            </Button>
          </CardHeader>
          {/* Mobile */}
          <div className="lg:hidden bg-[#18181B] text-white rounded-lg border-2 border-[#18181B] shadow-[0_1px_2px_0px_rgba(0,0,0,0.1),0_1px_3px_0px_rgba(0,0,0,0.1)]">
            <div
              role="button"
              tabIndex={0}
              className="flex justify-between items-center cursor-pointer border-1 border-[#18181B] p-4"
              onClick={() => setIsCollapsed(!isCollapsed)}
              onKeyDown={handleKeyDown}
            >
              <h2 className="text-sm font-normal text-[#B8B8B8]">Findings</h2>
              <ChevronUp size={16} />
            </div>
          </div>
          <Divider className="my-2" />
          <div className="overflow-y-auto flex-1 custom-scrollbar">
            <Accordion className="px-0" isCompact={false} defaultExpandedKeys={severityKeys} selectionMode="multiple">
              {Object.entries(groupedFindings).map(([severity, severityFindings]) => (
                <AccordionItem
                  key={severity}
                  aria-label={severity}
                  className="pr-2"
                  title={
                    <div className="flex items-center">
                      <Dot size={25} className={`ml-2 ${severityColor(severity)}`} />
                      <span className="text-sm font-inter font-medium text-[#B8B8B8]">{severity}</span>
                    </div>
                  }
                >
                  <div className="space-y-2">
                    {severityFindings.map((finding) => (
                      <div
                        key={globalIndex}
                        role="button"
                        tabIndex={0}
                        onClick={() => onSelectFinding(finding)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter" || e.key === " ") {
                            onSelectFinding(finding);
                          }
                        }}
                        className={`flex items-center cursor-pointer pl-4  hover:bg-gray-700 relative
                          ${
                            selectedFinding?.Issue === finding.Issue
                              ? "text-white bg-[#18181B] before:absolute before:left-0 before:top-0 before:h-full before:w-[1px] before:bg-white"
                              : "text-[#B8B8B8]"
                          } hover:text-white rounded`}
                      >
                        <div className="flex items-center justify-center min-w-[24px] h-6 bg-[#3F3F4666] rounded-lg">
                          <span className="text-sm tabular-nums">{globalIndex++}</span>
                        </div>
                        <span className="text-sm mt-4 ml-1">
                          <MarkdownWithCode content={finding.Issue} />
                        </span>
                      </div>
                    ))}
                  </div>
                </AccordionItem>
              ))}
            </Accordion>
          </div>
        </div>
      )}
      {isCollapsed && (
        <>
          {/* Desktop */}
          <div className="hidden lg:flex lg:flex-col lg:items-center lg:py-2 lg:px-2">
            <Button
              isDisabled={isButtonDisabled}
              isIconOnly
              className="bg-[#18181B] hover:bg-[#27272A]"
              size="sm"
              onPress={() => setIsCollapsed(!isCollapsed)}
            >
              <Image src="/svg/findings-icon.svg" width={14} height={14} alt="Findings Icon" />
            </Button>
          </div>
          {/* Mobile */}
          <div className="lg:hidden bg-[#18181B] text-white rounded-lg border-2 border-[#18181B] shadow-[0_1px_2px_0px_rgba(0,0,0,0.1),0_1px_3px_0px_rgba(0,0,0,0.1)]">
            <div
              role="button"
              tabIndex={0}
              className="flex justify-between items-center cursor-pointer border-1 border-[#18181B] p-4"
              onClick={() => setIsCollapsed(!isCollapsed)}
              onKeyDown={handleKeyDown}
            >
              <h2 className="text-sm font-normal text-[#B8B8B8]">Findings</h2>
              <ChevronDown size={16} />
            </div>
          </div>
        </>
      )}
    </Card>
  );
};

export default FindingsMenu;

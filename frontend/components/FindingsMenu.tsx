import React from "react";

import { Accordion, AccordionItem, Card, CardHeader, Divider, Button } from "@nextui-org/react";
import { Dot } from "lucide-react";
import Image from "next/image";

interface FindingsMenuProps {
  findings: Finding[];
  onSelectFinding: (finding: Finding) => void;
  isCollapsed: boolean;
  setIsCollapsed: (collapsed: boolean) => void;
  selectedFinding: Finding | null;
}

const FindingsMenu: React.FC<FindingsMenuProps> = ({
  findings,
  onSelectFinding,
  isCollapsed,
  setIsCollapsed,
  selectedFinding,
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

  const severityKeys = Object.keys(groupedFindings);

  let globalIndex = 1; // Initialize a global index

  return (
    <Card
      className={`border-2 border-[#27272A] bg-[#18181B] transition-all duration-300 mb-4 lg:mb-0 
        ${isCollapsed ? "w-[50px]" : "w-full lg:h-[calc(100vh-270px)]"}`}
    >
      {!isCollapsed && (
        <div className="flex flex-col h-full">
          <CardHeader className="mt-2 mb-0 flex items-center justify-between">
            <p className="text-sm font-inter font-medium">Findings</p>

            <Button
              isIconOnly
              className="bg-[#18181B] hover:bg-[#27272A]"
              size="sm"
              onClick={() => setIsCollapsed(!isCollapsed)}
            >
              <Image src="/findings-icon.svg" width={14} height={14} alt="Findings Icon" />
            </Button>
          </CardHeader>
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
                        className={`flex items-center cursor-pointer pl-6  hover:bg-gray-700 relative
                          ${
                            selectedFinding?.Issue === finding.Issue
                              ? "text-white bg-[#18181B] before:absolute before:left-0 before:top-0 before:h-full before:w-[1px] before:bg-white"
                              : "text-[#B8B8B8]"
                          } hover:text-white p-1 rounded`}
                      >
                        <div className="flex items-center justify-center w-6 h-6 bg-[#3F3F4666] rounded-md">
                          <p className="text-sm">{globalIndex++}</p>
                        </div>
                        <span className="text-sm ml-2">{finding.Issue}</span>
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
        <div className="flex flex-col items-center py-2 px-2">
          <Button
            isIconOnly
            className="bg-[#18181B] hover:bg-[#27272A]"
            size="sm"
            onClick={() => setIsCollapsed(!isCollapsed)}
          >
            <Image src="/findings-icon.svg" width={14} height={14} alt="Findings Icon" />
          </Button>
        </div>
      )}
    </Card>
  );
};

export default FindingsMenu;

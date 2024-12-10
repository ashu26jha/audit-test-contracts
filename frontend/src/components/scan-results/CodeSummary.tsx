import { useState, useRef, useEffect, type FC } from "react";

import { ChevronUp, ChevronDown } from "lucide-react";

import { MarkdownWithCode } from "../layout";

interface CodeSummaryProps {
  summary: string;
}

const CodeSummary: FC<CodeSummaryProps> = ({ summary }) => {
  const [isExpanded, setIsExpanded] = useState(true);
  const contentRef = useRef<HTMLDivElement>(null);

  const toggleExpand = () => {
    setIsExpanded(!isExpanded);
  };

  const handleKeyDown = (event: React.KeyboardEvent) => {
    if (event.key === "Enter" || event.key === " ") {
      toggleExpand();
    }
  };

  useEffect(() => {
    if (contentRef.current) {
      contentRef.current.style.maxHeight = isExpanded ? `${contentRef.current.scrollHeight}px` : "0px";
    }
  }, [isExpanded]);

  return (
    <div className="bg-[#18181B] text-white rounded-lg border-2 border-[#18181B] mb-4 shadow-[0_1px_2px_0px_rgba(0,0,0,0.1),0_1px_3px_0px_rgba(0,0,0,0.1)]">
      <div
        role="button"
        tabIndex={0}
        className="flex justify-between items-center cursor-pointer border-1 border-[#18181B] p-4"
        onClick={toggleExpand}
        onKeyDown={handleKeyDown}
      >
        <h2 className="text-sm font-normal text-[#B8B8B8]">Code Summary</h2>
        {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
      </div>

      <div
        ref={contentRef}
        className={`text-sm font-inter font-normal text-[#D4D4D8] leading-relaxed bg-black overflow-hidden transition-all duration-300 ease-in-out`}
        style={{ maxHeight: "0px" }}
      >
        <div className="p-4">
          <MarkdownWithCode content={summary} />
        </div>
      </div>
    </div>
  );
};

export default CodeSummary;

import { useEffect, useRef, useState } from "react";

import { ChevronDown, ChevronUp } from "lucide-react";

import { MarkdownWithCode } from "../layout";

const Invariants = ({ invariants }: { invariants: Invariant[] }) => {
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
      <button
        tabIndex={0}
        className=" w-full flex justify-between items-center cursor-pointer border-1 border-[#18181B] p-4"
        onClick={toggleExpand}
        onKeyDown={handleKeyDown}
      >
        <h2 className="text-sm font-normal text-[#B8B8B8]">Invariants</h2>
        {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
      </button>

      <div
        ref={contentRef}
        className="text-sm font-inter font-normal text-[#D4D4D8] leading-relaxed bg-black overflow-hidden transition-all duration-300 ease-in-out"
        style={{ maxHeight: "0px" }}
      >
        {invariants.length === 0 && (
          <div className="p-8 flex items-center justify-center">
            <div className="text-center">
              <p className="text-base">No invariants found</p>
            </div>
          </div>
        )}
        {invariants.length > 0 && (
          <div className="p-4 space-y-6">
            {invariants.map((invariant) => (
              <div key={invariant.description} className="border-b border-[#27272A] last:border-b-0 pb-6 last:pb-0">
                <div className="mb-3">
                  <h3 className="text-white text-base font-medium">Function</h3>
                  <p className="text-[#D4D4D8]">{invariant.function}</p>
                </div>
                <div className="mb-3">
                  <h3 className="text-white text-base font-medium">Description</h3>
                  <p className="text-[#D4D4D8]">{invariant.description}</p>
                </div>
                <div>
                  <h3 className="text-white text-base font-medium">Condition</h3>

                  <MarkdownWithCode content={invariant.condition} />
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default Invariants;

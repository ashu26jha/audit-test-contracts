import React, { useEffect } from "react";
import { Progress, Divider } from "@nextui-org/react";
import { useScanStepperStore } from "../../store/scanStepperStore";
import Image from "next/image";

export const HelpGuide: React.FC<{
  selectedLines: number;
  totalLines: number;
  selectedFiles: number;
  totalFiles: number;
}> = ({ selectedLines, totalLines, selectedFiles, totalFiles }) => {
  const { setIsLineExceeded, setIsFileLimitExceeded } = useScanStepperStore();
  const isLineExceeded = selectedLines > totalLines;
  const isFileLimitExceeded = selectedFiles > totalFiles;

  useEffect(() => {
    setIsLineExceeded(isLineExceeded);
    setIsFileLimitExceeded(isFileLimitExceeded);
  }, [isLineExceeded, isFileLimitExceeded, setIsLineExceeded, setIsFileLimitExceeded]);

  return (
    <div className="flex-initial w-auto ">
      <h3 className="text-base font-normal mb-2 font-inter leading-6">Help Guide</h3>
      <div className=" rounded-xl border-2 border-[#27272A] pb-4 pt-4 space-y-2">
        <p className="text-sm text-[#A1A1AA] mb-2 ml-4 mr-4">Consider the following</p>
        <Divider className="my-4 bg-[#27272A] h-0.5" />
        <ul className="list-disc pl-5 text-gray-300 space-y-2 ml-4 mr-4 text-xs leading-5">
          <li>
            Only select files that are highly relevant and crucial for gaining insight into the protocol&apos;s context.
          </li>
          <li>Avoid selecting mock contracts, test contracts, and interface contracts.</li>
          <li>Narrowing the scope of the scan leads to more accurate results.</li>
        </ul>
        <Divider className="my-4 bg-[#27272A] h-0.5" />
        <div className="px-4 space-y-2">
          <div className="flex justify-between">
            <p className={`text-xs leading-5 ${isLineExceeded ? "text-[#F871A0]" : "text-gray-300"}`}>
              {selectedLines}/{totalLines} Lines of Code
            </p>

            <p className={`text-xs leading-5 ${isFileLimitExceeded ? "text-[#F871A0]" : "text-gray-300"}`}>
              {selectedFiles}/{totalFiles} Files
            </p>
          </div>
          <Progress
            size="md"
            radius="sm"
            classNames={{
              base: "max-w-md",
              track: "drop-shadow-md border border-default",
              indicator: isLineExceeded ? "bg-[#920B3A]" : "bg-[#52525B]",
            }}
            value={(selectedLines / totalLines) * 100}
          />
          {isLineExceeded ? (
            <div className="flex items-center">
              <Image src="/error.svg" alt="Error" width={20} height={20} className="mr-1" />
              <p className="text-[#E4E4E7] text-xs mb-2">
                The total lines of code is too large; please reduce the lines of code.
              </p>
            </div>
          ) : (
            <>
              {isFileLimitExceeded && (
                <div className="flex items-center">
                  <Image src="/error.svg" alt="Error" width={20} height={20} className="mr-1" />
                  <p className="text-[#E4E4E7] text-xs mb-2">
                    You&apos;ve exceeded the maximum number of files. Please remove some files to continue.
                  </p>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
};

"use client";

import { type FC, useEffect } from "react";

import { Progress, Divider, Card, CardHeader, CardBody } from "@nextui-org/react";
import Image from "next/image";

import { useScanStepperStore } from "@/store/scanStepperStore";

export const HelpGuide: FC<{
  selectedLines: number;
  totalLines: number;
  selectedFiles: number;
  totalFiles: number;
  description: string[];
  variant: "contract" | "readme";
}> = ({ selectedLines, totalLines, selectedFiles, totalFiles, description, variant }) => {
  const { setIsLineExceeded, setIsFileLimitExceeded } = useScanStepperStore();
  const isLineExceeded = selectedLines > totalLines;
  const isFileLimitExceeded = selectedFiles > totalFiles;

  useEffect(() => {
    setIsLineExceeded(isLineExceeded);
    setIsFileLimitExceeded(isFileLimitExceeded);
  }, [isLineExceeded, isFileLimitExceeded, setIsLineExceeded, setIsFileLimitExceeded]);

  return (
    <div className="flex flex-col items-center sm:items-start">
      <h3 className="text-sm text-default-600 font-normal mb-2 font-inter leading-6">Help Guide</h3>
      <Card classNames={{ base: "min-h-[23.85rem] bg-content-1 border-2 border-default-100 w-[90%]" }}>
        <CardHeader className="flex flex-col gap-y-2">
          <div className="w-full flex justify-between">
            <p className={`text-xs leading-5 ${isLineExceeded ? "text-[#F871A0]" : "text-gray-300"}`}>
              {selectedLines}/{totalLines} {variant === "contract" ? "Lines of Code" : "Characters"}
            </p>

            <p className={`text-xs leading-5 ${isFileLimitExceeded ? "text-[#F871A0]" : "text-gray-300"}`}>
              {selectedFiles}/{totalFiles} Files
            </p>
          </div>
          <Progress
            size="md"
            radius="sm"
            aria-label="Selection Progress"
            classNames={{
              base: "max-w-md",
              track: "drop-shadow-md border border-default",
              indicator: isLineExceeded ? "bg-[#920B3A]" : "bg-[#52525B]",
            }}
            value={(selectedLines / totalLines) * 100}
          />
          {isLineExceeded && (
            <div className="flex items-start gap-x-2" role="alert">
              <Image src="/svg/error.svg" alt="Error" width={20} height={20} className="mr-1 mt-1" />
              <p className="text-[#E4E4E7] text-xs mb-2">
                {variant === "contract"
                  ? "The total lines of code is too large; please reduce the lines of code."
                  : "Too many characters in selected files; please reduce characters."}
              </p>
            </div>
          )}

          {isFileLimitExceeded && (
            <div className="flex items-center gap-x-2" role="alert">
              <Image src="/svg/error.svg" alt="Error" width={20} height={20} className="mr-1" />
              <p className="text-[#E4E4E7] text-xs mb-2">
                You&apos;ve exceeded the maximum number of files. Please remove some files to continue.
              </p>
            </div>
          )}
        </CardHeader>
        <Divider className="bg-default-100 h-[2px]" />
        <p className="text-sm text-default-600 mt-4 ml-4">Consider the following</p>

        <CardBody>
          <ul className="list-disc pl-4 text-gray-300 space-y-2 text-xs leading-5">
            {description.map((desc, key) => (
              <li key={key}>{desc}</li>
            ))}
          </ul>
        </CardBody>
      </Card>
    </div>
  );
};

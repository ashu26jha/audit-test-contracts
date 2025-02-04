"use client";
import { type FC, useCallback, useEffect, useMemo } from "react";

import { Input, Accordion, AccordionItem, Divider } from "@nextui-org/react";
import { Search, Sparkles } from "lucide-react";
import { useRouter } from "next/navigation";

import { BottomBanner } from "@/components/layout";
import { ENTERPRISE_PLAN_DETAILS } from "@/config/constants";
import { HELP_DESCRIPTION } from "@/config/helpDescription";
import { useAuth } from "@/contexts/AuthContext";
import { useScanStepper } from "@/hooks";
import { useScanStepperStore } from "@/store/scanStepperStore";
import { organizeFilesByFolder } from "@/utils/helpers";

import { HelpGuide } from "./HelpGuide";
import { QnABox } from "./QnABox";
import { FolderStructureView } from "../common/FolderStructureView";

export const DocsSelection: FC = () => {
  const {
    readmeFiles,
    repoDocs,
    contractSearch,
    setContractSearch,
    setRepoDocs,
    selectedOwner,
    selectedRepo,
    selectedBranch,
    isLoading,
    isFileLimitExceeded,
  } = useScanStepperStore();

  const { user } = useAuth();
  const router = useRouter();
  const { fetchReadmeFiles, fetchPreviousDocs } = useScanStepper();

  const filteredReadmeFiles = useMemo(() => {
    const searchLower = contractSearch.toLowerCase();
    return readmeFiles.filter((file) => file.path.toLowerCase().includes(searchLower));
  }, [readmeFiles, contractSearch]);

  const calculateTotalSelectedChars = useCallback(() => {
    const fileMap = new Map(readmeFiles.map((file) => [file.path, file.character_count]));
    return repoDocs.readme.reduce((acc, path) => {
      return acc + (fileMap.get(path) || 0);
    }, 0);
  }, [readmeFiles, repoDocs]);

  const totalSelectedChars = calculateTotalSelectedChars();

  const handleSelectionChange = useCallback(
    (path: string) => {
      if (repoDocs.readme.includes(path)) {
        setRepoDocs({ readme: repoDocs.readme.filter((p) => p !== path) });
      } else {
        setRepoDocs({ readme: [...repoDocs.readme, path] });
      }
    },
    [repoDocs.readme, setRepoDocs],
  );

  // Fetch previous docs if user is a subscriber
  useEffect(() => {
    if (user?.subscription.isActive && selectedOwner && selectedRepo) {
      fetchPreviousDocs(selectedOwner.login, selectedRepo.name);
    }
  }, [selectedOwner, selectedRepo, user?.subscription.isActive, fetchPreviousDocs]);

  // Fetch readme files when owner/repo/branch changes
  useEffect(() => {
    if (selectedOwner && selectedRepo && selectedBranch) {
      fetchReadmeFiles(selectedOwner, selectedRepo, selectedBranch);
    }
  }, [fetchReadmeFiles, selectedOwner, selectedRepo, selectedBranch]);

  const isBlurred = user?.subscription.type !== "enterprise";

  return (
    <div className="h-full w-full flex flex-col overflow-y-hidden">
      <section
        className={`flex-1 min-h-0 flex justify-center ${isBlurred ? "blur-sm select-none cursor-default" : ""}`}
      >
        <div className="w-3/4">
          <Accordion defaultExpandedKeys={["1", "2"]} selectionMode="multiple">
            <AccordionItem
              classNames={{
                title: "text-base font-normal text-default-600 font-inter leading-6",
              }}
              key="1"
              aria-label="Select Readme files (Optional)"
              title="1. Select Readme files (Optional)"
            >
              <div className="flex gap-8">
                <div className="flex-1 max-w-[70%]">
                  <h3 className="text-sm font-normal mb-2 text-default-600 font-inter leading-6"> Readme files </h3>

                  <div className="border-2 bg-content-1 border-default-100 rounded-xl max-h-[22rem] overflow-auto">
                    <Input
                      classNames={{
                        inputWrapper: "bg-content-1",
                      }}
                      radius="none"
                      aria-label="Search files"
                      isClearable={true}
                      placeholder="Search files..."
                      value={contractSearch}
                      onValueChange={setContractSearch}
                      startContent={<Search size={18} />}
                    />
                    <Divider className="bg-default-100 h-[2px] mb-3" />
                    <FolderStructureView
                      items={organizeFilesByFolder(filteredReadmeFiles)}
                      onSelect={handleSelectionChange}
                      selectedPaths={repoDocs.readme}
                      isDisabled={isFileLimitExceeded}
                      isLoading={isLoading}
                      variant="readme"
                    />
                  </div>
                </div>
                <div className="w-[30%]">
                  <HelpGuide
                    selectedLines={totalSelectedChars}
                    totalLines={ENTERPRISE_PLAN_DETAILS.MAX_DOCS_CHARS}
                    selectedFiles={repoDocs.readme.length}
                    totalFiles={ENTERPRISE_PLAN_DETAILS.MAX_DOCS_FILES}
                    description={HELP_DESCRIPTION.readme}
                    variant="readme"
                  />
                </div>
              </div>
            </AccordionItem>

            <AccordionItem
              classNames={{
                title: "text-base font-normal text-default-600 font-inter leading-6",
              }}
              key="2"
              aria-label="Additional Q&A (Optional)"
              title="2. Additional Q&A (Optional)"
            >
              <QnABox />
            </AccordionItem>
          </Accordion>
        </div>
      </section>

      {user?.subscription.type !== "enterprise" && (
        <BottomBanner
          title="Context docs are only available for enterprise users"
          description="Please subscribe to enterprise plan to access the docs and Q&A."
          buttonText="Subscribe Now"
          buttonIcon={<Sparkles size={14} />}
          action={() => router.push("/profile?tab=subscription")}
        />
      )}
    </div>
  );
};

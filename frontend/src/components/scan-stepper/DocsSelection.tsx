"use client";
import { type FC, useCallback, useEffect, useMemo, useState } from "react";

import { Input, Divider, Checkbox, Textarea } from "@nextui-org/react";
import { Search } from "lucide-react";

import { ENTERPRISE_PLAN_DETAILS } from "@/config/constants";
import { HELP_DESCRIPTION } from "@/config/helpDescription";
import { useScanStepper } from "@/hooks";
import { useScanStepperStore } from "@/store/scanStepperStore";
import { organizeFilesByFolder } from "@/utils/helpers";

import { HelpGuide } from "./HelpGuide";
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

  const { fetchReadmeFiles, fetchPreviousDocs } = useScanStepper();
  const [isAllSelected, setIsAllSelected] = useState(false);

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

  const onAllSelect = () => {
    if (isAllSelected) {
      setRepoDocs({ readme: [] });
      setIsAllSelected(false);
      return;
    }
    setRepoDocs({ readme: filteredReadmeFiles.map((file) => file.path) });
    setIsAllSelected(true);
  };

  const handleAdditionalDocsChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setRepoDocs({ additionalDocs: e.target.value });
  };

  // Fetch previous docs if user is a subscriber
  useEffect(() => {
    if (selectedOwner && selectedRepo) {
      fetchPreviousDocs(selectedOwner.login, selectedRepo.name);
    }
  }, [selectedOwner, selectedRepo, fetchPreviousDocs]);

  // Fetch readme files when owner/repo/branch changes
  useEffect(() => {
    if (selectedOwner && selectedRepo && selectedBranch) {
      fetchReadmeFiles(selectedOwner, selectedRepo, selectedBranch);
    }
  }, [fetchReadmeFiles, selectedOwner, selectedRepo, selectedBranch]);

  return (
    <div className="h-full w-full flex flex-col overflow-y-hidden">
      <section className="flex-1 min-h-0 flex justify-center">
        <div className="w-full sm:w-3/4">
          <div className="flex flex-col items-center text-center sm:flex-row gap-8">
            <div className="flex-1 flex flex-col items-center sm:items-start w-full sm:max-w-[70%]">
              <h3 className="text-sm font-normal mb-2 text-default-600 font-inter leading-6"> Readme files </h3>

              <div className="border-2 bg-content-1 border-default-100 rounded-xl max-h-[23.85rem] overflow-auto w-[90%] sm:w-full">
                <div className="flex">
                  <Checkbox isSelected={isAllSelected} onValueChange={onAllSelect} color="secondary" className="ml-2" />
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
                </div>
                <Divider className="bg-default-100 h-[2px] mb-3" />
                <FolderStructureView
                  items={organizeFilesByFolder(filteredReadmeFiles)}
                  onSelect={handleSelectionChange}
                  selectedPaths={repoDocs.readme}
                  isDisabled={isFileLimitExceeded}
                  isLoading={isLoading}
                  variant="readme"
                  emptyText="No readme files found under this branch"
                />
              </div>
            </div>
            <div className="w-full sm:w-[30%]">
              <HelpGuide
                selectedLines={totalSelectedChars + repoDocs.additionalDocs.length}
                totalLines={ENTERPRISE_PLAN_DETAILS.MAX_DOCS_CHARS}
                selectedFiles={repoDocs.readme.length}
                totalFiles={ENTERPRISE_PLAN_DETAILS.MAX_DOCS_FILES}
                description={HELP_DESCRIPTION.readme}
                variant="readme"
              />
            </div>
          </div>
          <div className="flex flex-col items-center sm:items-start">
            <h4 className="text-sm text-default-600 mb-2 mt-4">Any additional documentation?</h4>

            <Textarea
              value={repoDocs.additionalDocs}
              onChange={handleAdditionalDocsChange}
              classNames={{
                inputWrapper:
                  "border-2 border-default-100 bg-content-1 hover:border-gray-600 group-data-[focus=true]:bg-content-1 data-[hover=true]:bg-content-1",
              }}
              placeholder="Enter additional documentation..."
              className="flex flex-col items-center w-[90%] sm:w-full"
            />
          </div>
        </div>
      </section>
    </div>
  );
};

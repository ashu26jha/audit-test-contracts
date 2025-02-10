"use client";
import { type FC, useCallback, useMemo, useState } from "react";

import { Input, Divider, Checkbox } from "@nextui-org/react";
import { Search } from "lucide-react";

import { FREE_PLAN_DETAILS, ENTERPRISE_PLAN_DETAILS, PRO_PLAN_DETAILS } from "@/config/constants";
import { HELP_DESCRIPTION } from "@/config/helpDescription";
import { useAuth } from "@/contexts/AuthContext";
import { useScanStepperStore } from "@/store/scanStepperStore";
import { organizeFilesByFolder } from "@/utils/helpers";

import { HelpGuide } from "./HelpGuide";
import { FolderStructureView } from "../common/FolderStructureView";

export const ContractSelection: FC = () => {
  const {
    solidityFiles,
    contractSearch,
    setContractSearch,
    setSelectedContracts,
    selectedContracts,
    isLoading,
    isFileLimitExceeded,
  } = useScanStepperStore();
  const [isAllSelected, setIsAllSelected] = useState(false);

  const { user } = useAuth();

  const filteredSolidityFiles = useMemo(() => {
    const searchLower = contractSearch.toLowerCase();
    return solidityFiles.filter(
      (file) => file.name.toLowerCase().includes(searchLower) || file.path.toLowerCase().includes(searchLower),
    );
  }, [solidityFiles, contractSearch]);

  const calculateTotalSelectedLines = useCallback(() => {
    const fileMap = new Map(solidityFiles.map((file) => [file.path, file.lineCount]));
    return selectedContracts.reduce((acc, path) => {
      return acc + (fileMap.get(path) || 0);
    }, 0);
  }, [selectedContracts, solidityFiles]);

  const totalSelectedLines = calculateTotalSelectedLines();

  const handleSelectionChange = useCallback(
    (path: string) => {
      if (selectedContracts.includes(path)) {
        setSelectedContracts(selectedContracts.filter((p) => p !== path));
      } else {
        setSelectedContracts([...selectedContracts, path]);
      }
    },
    [selectedContracts, setSelectedContracts],
  );

  const getScanLimits = () => {
    if (user?.subscription.type === "free") {
      return FREE_PLAN_DETAILS;
    }
    if (user?.subscription.type === "pro") {
      return PRO_PLAN_DETAILS;
    }
    return ENTERPRISE_PLAN_DETAILS;
  };

  const onAllSelect = () => {
    if (isAllSelected) {
      setSelectedContracts([]);
      setIsAllSelected(false);
      return;
    }
    setSelectedContracts(filteredSolidityFiles.map((file) => file.path));
    setIsAllSelected(true);
  };

  return (
    <div className="flex gap-8 w-3/4 min-w-[300px]">
      <div className="flex-1 max-w-[70%]">
        <h3 className="text-base font-normal mb-2 font-inter leading-6">Select Contracts</h3>
        <div className="border-2 bg-content-1 border-default-100 rounded-xl h-[22rem]">
          <div className="flex">
            <Checkbox isSelected={isAllSelected} onValueChange={onAllSelect} color="secondary" className="ml-2" />
            <Input
              classNames={{
                inputWrapper: "bg-content-1",
              }}
              radius="none"
              aria-label="Search contracts"
              isClearable={true}
              placeholder="Search contracts..."
              value={contractSearch}
              onValueChange={setContractSearch}
              startContent={<Search size={18} />}
            />
          </div>
          <Divider className="bg-default-100 h-[2px]" />
          <FolderStructureView
            items={organizeFilesByFolder(filteredSolidityFiles)}
            onSelect={handleSelectionChange}
            selectedPaths={selectedContracts}
            isDisabled={isFileLimitExceeded}
            isLoading={isLoading}
            variant="contract"
          />
        </div>
      </div>
      <div className="w-[30%]">
        <HelpGuide
          selectedLines={totalSelectedLines}
          totalLines={getScanLimits().MAX_LINES}
          selectedFiles={selectedContracts.length}
          totalFiles={getScanLimits().MAX_FILES}
          description={HELP_DESCRIPTION.contract}
          variant="contract"
        />
      </div>
    </div>
  );
};

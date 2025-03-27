"use client";
import { type FC, useCallback, useEffect, useMemo, useState } from "react";

import { Input, Divider, Checkbox } from "@nextui-org/react";
import { Search } from "lucide-react";

import { FREE_PLAN_DETAILS, ENTERPRISE_PLAN_DETAILS, PRO_PLAN_DETAILS } from "@/config/constants";
import { HELP_DESCRIPTION } from "@/config/helpDescription";
import { useAuth } from "@/contexts/AuthContext";
import { useScanStepper } from "@/hooks";
import { useScanStepperStore } from "@/store/scanStepperStore";
import { organizeFilesByFolder } from "@/utils/helpers";

import { HelpGuide } from "./HelpGuide";
import { FolderStructureView } from "../common/FolderStructureView";

export const ContractSelection: FC = () => {
  const {
    solidityFiles,
    contractSearch,
    selectedOwner,
    selectedRepo,
    invariants,
    setContractSearch,
    setSelectedContracts,
    selectedContracts,
    isLoading,
    isFileLimitExceeded,
  } = useScanStepperStore();
  const [isAllSelected, setIsAllSelected] = useState(false);
  const [invariantPaths, setinvariantPaths] = useState<string[]>([]);
  const { fetchInvariants } = useScanStepper();

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

  useEffect(() => {
    if (selectedOwner && selectedRepo) {
      fetchInvariants(selectedOwner, selectedRepo);
    }
  }, [fetchInvariants, selectedOwner, selectedRepo]);

  useEffect(() => {
    if (invariants && invariants.length > 0) {
      const invariantPaths = invariants.map((inv) => inv.path);
      setinvariantPaths(invariantPaths);
    }
  }, [invariants]);

  return (
    <div className="flex flex-col sm:flex-row items-center sm:items-start text-center sm:text-left gap-8 sm:w-3/4 min-w-[250px]">
      <div className="flex-1 flex flex-col  items-center sm:items-start sm:max-w-[70%]">
        <h3 className="text-sm text-default-600 font-normal mb-2 font-inter leading-6">Select Contracts</h3>
        <div className="border-2 bg-content-1 border-default-100 rounded-xl h-[23.85rem] w-[90%] sm:w-full">
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
            invariantPaths={invariantPaths}
            variant="contract"
            emptyText="No contracts found under this branch"
          />
        </div>
      </div>
      <div className="w-full sm:w-[30%]">
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

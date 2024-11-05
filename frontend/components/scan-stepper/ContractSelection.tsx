"use client";
import React, { useCallback } from "react";

import { Input, Table, TableHeader, TableColumn, TableBody, TableRow, TableCell, Spinner } from "@nextui-org/react";
import type { Selection } from "@nextui-org/react";
import Image from "next/image";

import { HelpGuide } from "./HelpGuide";
import { LIMITS } from "../../config/constants";
import { useScanStepperStore } from "../../store/scanStepperStore";

export const ContractSelection: React.FC = () => {
  const {
    solidityFiles,
    contractSearch,
    setContractSearch,
    setSelectedContracts,
    selectedContracts,
    isSolidityFilesLoading,
    isFileLimitExceeded,
  } = useScanStepperStore();

  const filteredSolidityFiles = solidityFiles.filter(
    (file) =>
      file.name.toLowerCase().includes(contractSearch.toLowerCase()) ||
      file.path.toLowerCase().includes(contractSearch.toLowerCase()),
  );

  const calculateTotalSelectedLines = useCallback(() => {
    return selectedContracts.reduce((acc, path) => {
      const file = solidityFiles.find((f) => f.path === path);
      return acc + (file?.lineCount || 0);
    }, 0);
  }, [selectedContracts, solidityFiles]);

  const totalSelectedLines = calculateTotalSelectedLines();

  const handleSelectionChange = (selection: Selection) => {
    if (selection === "all") {
      setSelectedContracts(filteredSolidityFiles.map((file) => file.path));
    } else {
      const newSelection = Array.from(selection) as string[];
      setSelectedContracts(newSelection);
    }
  };

  return (
    <div className="flex gap-8">
      <div className="flex-1 max-w-[70%]">
        <h3 className="text-base font-normal mb-2 font-inter leading-6">Select Contracts</h3>
        <div className="mb-4">
          <Input
            aria-label="Search contracts"
            isClearable={true}
            placeholder="Search contracts..."
            value={contractSearch}
            onChange={(e) => setContractSearch(e.target.value)}
            onClear={() => setContractSearch("")}
            startContent={<Image src="/search.svg" alt="Search" width={16} height={16} />}
          />
        </div>

        <div className="overflow-auto max-h-60">
          <Table
            color="secondary"
            aria-label="Solidity files table"
            selectionMode="multiple"
            onSelectionChange={handleSelectionChange}
            disabledKeys={
              isFileLimitExceeded
                ? solidityFiles.filter((file) => !selectedContracts.includes(file.path)).map((file) => file.path)
                : []
            }
            classNames={{
              base: "max-w-full",
              table: "min-w-full",
            }}
          >
            <TableHeader>
              <TableColumn>Name</TableColumn>
              <TableColumn>Lines of Code</TableColumn>
              <TableColumn>Path</TableColumn>
            </TableHeader>
            <TableBody
              isLoading={isSolidityFilesLoading}
              loadingContent={<Spinner />}
              emptyContent={
                <div className="flex flex-col items-center">
                  <Image src="/empty_contract.svg" alt="No contracts found" width={100} height={100} className="mt-8" />
                  <p className="mt-2 text-gray-500">No contracts found</p>
                </div>
              }
            >
              {filteredSolidityFiles.map((file) => (
                <TableRow key={file.path}>
                  <TableCell>{file.name}</TableCell>
                  <TableCell>{file.lineCount}</TableCell>
                  <TableCell>{file.path}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </div>
      <div className="w-[30%]">
        <HelpGuide
          selectedLines={totalSelectedLines}
          totalLines={LIMITS.MAX_LINES}
          selectedFiles={selectedContracts.length}
          totalFiles={LIMITS.MAX_FILES}
        />
      </div>
    </div>
  );
};

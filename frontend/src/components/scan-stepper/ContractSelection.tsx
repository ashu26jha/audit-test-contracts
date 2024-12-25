"use client";
import { type FC, useCallback, useMemo } from "react";

import { Input, Table, TableHeader, TableColumn, TableBody, TableRow, TableCell, Spinner } from "@nextui-org/react";
import type { Selection } from "@nextui-org/react";
import Image from "next/image";

import { BASIC_PLAN_DETAILS, PRO_PLAN_DETAILS } from "@/config/constants";
import { HELP_DESCRIPTION } from "@/config/helpDescription";
import { useAuth } from "@/contexts/AuthContext";
import { useScanStepperStore } from "@/store/scanStepperStore";

import { HelpGuide } from "./HelpGuide";

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

  const allPaths = useMemo(() => filteredSolidityFiles.map((file) => file.path), [filteredSolidityFiles]);

  const handleSelectionChange = useCallback(
    (selection: Selection) => {
      if (selection === "all") {
        setSelectedContracts(allPaths);
      } else {
        setSelectedContracts(Array.from(selection).map(String));
      }
    },
    [allPaths, setSelectedContracts],
  );

  return (
    <div className="flex gap-8 w-3/4 min-w-[300px]">
      <div className="flex-1 max-w-[70%]">
        <h3 className="text-base font-normal mb-2 font-inter leading-6">Select Contracts</h3>
        <div className="overflow-auto">
          <Table
            isHeaderSticky
            aria-label="Readme files table"
            selectionMode="multiple"
            color="secondary"
            onSelectionChange={handleSelectionChange}
            selectedKeys={selectedContracts}
            disabledKeys={
              isFileLimitExceeded
                ? solidityFiles.filter((file) => !selectedContracts.includes(file.path)).map((file) => file.path)
                : []
            }
            classNames={{
              base: "max-w-full max-h-80 gap-0 border-2 border-default-100 rounded-xl overflow-hidden",
              table: "min-w-full",
              th: "bg-background",
              wrapper: "rounded-none",
            }}
            topContent={
              <Input
                classNames={{
                  base: "border-b-2 border-default-100",
                  inputWrapper: "bg-content-1",
                }}
                radius="none"
                aria-label="Search contracts"
                isClearable={true}
                placeholder="Search contracts..."
                value={contractSearch}
                onChange={(e) => setContractSearch(e.target.value)}
                onClear={() => setContractSearch("")}
                startContent={<Image src="/svg/search.svg" alt="Search" width={16} height={16} />}
              />
            }
            topContentPlacement="outside"
          >
            <TableHeader>
              <TableColumn>Name</TableColumn>
              <TableColumn>Lines of Code</TableColumn>
              <TableColumn>Path</TableColumn>
            </TableHeader>
            <TableBody
              isLoading={!!isLoading}
              loadingContent={<Spinner />}
              emptyContent={
                <div className="flex flex-col items-center">
                  <Image
                    src="/svg/empty_contract.svg"
                    alt="No contracts found"
                    width={100}
                    height={100}
                    className="mt-8"
                  />
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
          totalLines={user?.subscription.isActive ? PRO_PLAN_DETAILS.MAX_LINES : BASIC_PLAN_DETAILS.MAX_LINES}
          selectedFiles={selectedContracts.length}
          totalFiles={user?.subscription.isActive ? PRO_PLAN_DETAILS.MAX_FILES : BASIC_PLAN_DETAILS.MAX_FILES}
          description={HELP_DESCRIPTION.contract}
          variant="contract"
        />
      </div>
    </div>
  );
};

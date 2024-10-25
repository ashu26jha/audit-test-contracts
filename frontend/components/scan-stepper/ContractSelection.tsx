"use client";
import React, { useCallback, useEffect } from "react";

import { Input, Table, TableHeader, TableColumn, TableBody, TableRow, TableCell, Spinner } from "@nextui-org/react";
import Image from "next/image";

import { MAX_TOKENS } from "../../config/constants";
import { useScanStepperStore } from "../../store/scanStepperStore";

export const ContractSelection: React.FC = () => {
  const {
    solidityFiles,
    contractSearch,
    tokens,
    setContractSearch,
    setSelectedContracts,
    setTokens,
    selectedContracts,
    isSolidityFilesLoading,
  } = useScanStepperStore();

  const filteredSolidityFiles = solidityFiles.filter(
    (file) =>
      file.name.toLowerCase().includes(contractSearch.toLowerCase()) ||
      file.path.toLowerCase().includes(contractSearch.toLowerCase()),
  );

  const calculateTotalTokens = useCallback(() => {
    return selectedContracts.reduce((acc, path) => {
      const file = solidityFiles.find((f) => f.path === path);
      return acc + (file?.token || 0);
    }, 0);
  }, [selectedContracts, solidityFiles]);

  useEffect(() => {
    setTokens(calculateTotalTokens());
  }, [calculateTotalTokens, setTokens]);

  return (
    <div id="contract-selection" className="contract-selection">
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
          onSelectionChange={(selection) => {
            if (selection === "all") {
              setSelectedContracts(filteredSolidityFiles.map((file) => file.path));
            } else {
              setSelectedContracts(Array.from(selection) as string[]);
            }
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

      {tokens > MAX_TOKENS && (
        <p className="text-[#F871A0] bg-[#F3126033]/10 p-2 rounded-md text-center">
          Too many contracts selected! Please select fewer contracts to achieve better results.
        </p>
      )}
    </div>
  );
};

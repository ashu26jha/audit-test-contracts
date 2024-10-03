import React from "react";

import { Input, Table, TableHeader, TableColumn, TableBody, TableRow, TableCell } from "@nextui-org/react";
import Image from "next/image";

import { useScanStepperStore } from "../../store/scanStepperStore";

export const ContractSelection: React.FC = () => {
  const { solidityFiles, contractSearch, setContractSearch, setSelectedContracts } = useScanStepperStore();

  const filteredSolidityFiles = solidityFiles.filter(
    (file) =>
      file.name.toLowerCase().includes(contractSearch.toLowerCase()) ||
      file.path.toLowerCase().includes(contractSearch.toLowerCase()),
  );

  return (
    <>
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
          aria-label="Solidity files table"
          selectionMode="multiple"
          onSelectionChange={(selection) => setSelectedContracts(Array.from(selection) as string[])}
        >
          <TableHeader>
            <TableColumn>NAME</TableColumn>
            <TableColumn>PATH</TableColumn>
          </TableHeader>
          <TableBody
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
                <TableCell>{file.path}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </>
  );
};

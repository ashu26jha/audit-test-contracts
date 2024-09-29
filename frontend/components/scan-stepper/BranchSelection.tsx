import React from "react";
import { Autocomplete, AutocompleteItem } from "@nextui-org/react";
import Image from "next/image";
import { useScanStepperStore } from "../../store/scanStepperStore";

export const BranchSelection: React.FC = () => {
  const { branches, setSelectedBranch } = useScanStepperStore();

  return (
    <div className="mb-6">
      <Autocomplete
        variant="bordered"
        label="Select Branch"
        labelPlacement="outside"
        placeholder="Search branch"
        startContent={<Image src="/search.svg" alt="Branch" width={12} height={12} />}
        className="w-full"
        onSelectionChange={(keys) => {
          const selected = keys as string;
          setSelectedBranch(selected);
        }}
      >
        {branches.map((branch) => (
          <AutocompleteItem key={branch} value={branch} className="hover:bg-[#4F46E5] transition-colors duration-300">
            {branch}
          </AutocompleteItem>
        ))}
      </Autocomplete>
    </div>
  );
};

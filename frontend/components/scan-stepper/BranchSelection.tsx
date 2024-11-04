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
        startContent={<Image src="/branch-icon.svg" alt="Branch" width={24} height={24} className="mr-2" />}
        className="w-full"
        onSelectionChange={(keys) => {
          const selected = keys as string;
          setSelectedBranch(selected);
        }}
      >
        {branches.map((branch) => (
          <AutocompleteItem
            key={branch.name}
            textValue={branch.name}
            className="hover:bg-[#4F46E5] transition-colors duration-300 flex"
          >
            <div className="flex items-center">
              <Image src="/branch-icon.svg" alt="Branch" width={24} height={24} className="mr-2" />
              {branch.name}
              {branch.isDefault ? (
                <Image src="/default.svg" alt="Default" width={50} height={50} className="ml-2" />
              ) : (
                <></>
              )}
            </div>
          </AutocompleteItem>
        ))}
      </Autocomplete>
    </div>
  );
};

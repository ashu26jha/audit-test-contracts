"use client";

import { type FC, useEffect } from "react";

import { Autocomplete, AutocompleteItem } from "@nextui-org/react";
import Image from "next/image";

import { IS_CAIRO_LIVE } from "@/config/constants";
import { useScanStepperStore } from "@/store/scanStepperStore";

// Define language options with value and display text
const languageOptions = [
  { value: "sol", display: "solidity" },
  { value: "cairo", display: "cairo" },
];

export const BranchSelection: FC = () => {
  const { branches, selectedBranch, setSelectedBranch, selectedLanguage, setSelectedLanguage, isLoading } =
    useScanStepperStore();

  useEffect(() => {
    if (branches.length > 0 && !selectedBranch) {
      const defaultBranch = branches.find((branch) => branch.isDefault)?.name;
      if (defaultBranch) {
        setSelectedBranch(defaultBranch);
      }
    }
  }, [branches, selectedBranch, setSelectedBranch]);

  return (
    <div className="mb-6 w-2/5 min-w-[300px]">
      <Autocomplete
        label="Select Branch"
        labelPlacement="outside"
        placeholder="Search branch"
        startContent={<Image src="/svg/branch-icon.svg" alt="Branch" width={24} height={24} className="mr-2" />}
        classNames={{
          base: "w-full mb-6",
        }}
        inputProps={{
          classNames: {
            inputWrapper:
              "border-2 border-default-100 bg-content-1 hover:border-gray-600 group-data-[focus=true]:bg-content-1 data-[hover=true]:bg-content-1",
          },
        }}
        onSelectionChange={(keys) => {
          const selected = keys as string;
          setSelectedBranch(selected);
        }}
        isLoading={isLoading}
        selectedKey={selectedBranch}
      >
        {branches.map((branch) => (
          <AutocompleteItem
            key={branch.name}
            textValue={branch.name}
            className="hover:bg-[#4F46E5] transition-colors duration-300 flex"
          >
            <div className="flex items-center">
              <Image src="/svg/branch-icon.svg" alt="Branch" width={24} height={24} className="mr-2" />
              {branch.name}
              {branch.isDefault ? (
                <Image src="/svg/default.svg" alt="Default" width={50} height={50} className="ml-2" />
              ) : null}
            </div>
          </AutocompleteItem>
        ))}
      </Autocomplete>

      {IS_CAIRO_LIVE && (
        <Autocomplete
          label="Select Language"
          labelPlacement="outside"
          placeholder="Search language"
          startContent={<Image src="/svg/branch-icon.svg" alt="Branch" width={24} height={24} className="mr-2" />}
          classNames={{
            base: "w-full mb-6",
          }}
          inputProps={{
            classNames: {
              inputWrapper:
                "border-2 border-default-100 bg-content-1 hover:border-gray-600 group-data-[focus=true]:bg-content-1 data-[hover=true]:bg-content-1",
            },
          }}
          onSelectionChange={(keys) => {
            const selected = keys as ScanLanguage;
            setSelectedLanguage(selected);
          }}
          selectedKey={selectedLanguage}
        >
          {languageOptions.map((option) => (
            <AutocompleteItem
              key={option.value}
              textValue={option.display}
              className="hover:bg-[#4F46E5] transition-colors duration-300 flex"
            >
              {option.display}
            </AutocompleteItem>
          ))}
        </Autocomplete>
      )}
    </div>
  );
};

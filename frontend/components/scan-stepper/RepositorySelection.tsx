import React from "react";

import { Autocomplete, AutocompleteItem } from "@nextui-org/react";
import Image from "next/image";

import { useScanStepperStore } from "../../store/scanStepperStore";

export const RepositorySelection: React.FC = () => {
  const { selectedOwner, repositories, setSelectedRepo } = useScanStepperStore();

  if (!selectedOwner) {
    return (
      <div className="mb-6">
        <label htmlFor="repository-autocomplete" className="block text-sm font-medium mb-2 text-left">
          Git Repository
          <span style={{ color: "red", marginLeft: "4px" }}>*</span>
        </label>
        <div className="bg-[#222222] rounded p-8 flex flex-col items-center justify-center text-center">
          <p className="text-sm text-gray-400">
            <Image src="/empty_repository.svg" alt="Empty Repository" width={55} height={55} className="m-auto mb-4" />
            Repository would appear here,
            <br />
            after selecting the organization.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="mb-6">
      <Autocomplete
        id="repository-autocomplete"
        variant="bordered"
        label={
          <>
            Git Repository
            <span style={{ color: "red", marginLeft: "4px" }}>*</span>
          </>
        }
        labelPlacement="outside"
        placeholder="Search a repository"
        className="w-full className='hover:bg-[#4F46E5] transition-colors duration-300'"
        onSelectionChange={(key) => {
          const selected = key as string;
          setSelectedRepo(repositories.find((repo) => repo.name === selected) || null);
        }}
      >
        {repositories.map((repo) => (
          <AutocompleteItem
            key={repo.name}
            value={repo.name}
            className="hover:bg-[#4F46E5] transition-colors duration-300"
          >
            {repo.name}
          </AutocompleteItem>
        ))}
      </Autocomplete>
    </div>
  );
};

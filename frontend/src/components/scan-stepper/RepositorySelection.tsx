"use client";

import { type FC, useEffect, useState } from "react";

import { Select, SelectItem, Input, type Selection, Autocomplete, AutocompleteItem, Spinner } from "@nextui-org/react";
import Image from "next/image";
import Link from "next/link";

import { SERVICES } from "@/config/constants";
import { useRepositoryUrl } from "@/hooks/useRepositoryUrl";
import { useScanStepperStore } from "@/store/scanStepperStore";
import { useUserDataStore } from "@/store/userDataStore";

export const RepositorySelection: FC = () => {
  const { owners, repositories, isOrganizationLoading } = useUserDataStore();
  const { isLoading, selectedOwner, setSelectedOwner, repositoryURL, isValidURL, setSelectedRepo, resetStepper } =
    useScanStepperStore();
  const { inputURL, debouncedURL, setInputURL, validateAndSetUrl, resetUrl, errorMessage, isCheckingURL } =
    useRepositoryUrl();
  const [selectedOrg, setSelectedOrg] = useState<string | null>(null);
  const [isPrivate, setIsPrivate] = useState<boolean>(false);

  useEffect(() => {
    resetStepper();
  }, [resetStepper]);

  useEffect(() => {
    validateAndSetUrl(debouncedURL);
  }, [debouncedURL, validateAndSetUrl]);

  const handleOrganizationSelect = (keys: Selection) => {
    const selected = Array.from(keys)[0] as string;
    setSelectedOrg(selected);
    setSelectedOwner(owners.find((owner) => owner.login === selected) || null);
    resetUrl();
  };

  return (
    <div className="w-2/5 min-w-[300px]">
      <Select
        label="Git Organization"
        classNames={{
          base: "w-full mb-6",
          trigger: "border-2 border-default-100 bg-content-1 hover:border-gray-600",
        }}
        placeholder="Select one"
        labelPlacement="outside"
        selectedKeys={selectedOrg ? [selectedOrg] : []}
        onSelectionChange={handleOrganizationSelect}
        isLoading={isOrganizationLoading}
      >
        {owners.map((org) => (
          <SelectItem key={org.login} value={org.login}>
            {org.login}
          </SelectItem>
        ))}
      </Select>

      {!selectedOwner || repositoryURL ? (
        <div className="flex flex-col gap-y-2 mb-2">
          <label htmlFor="repository-autocomplete" className="block text-sm font-medium text-left">
            Git Repository
            <span style={{ color: "red", marginLeft: "4px" }}>*</span>
          </label>
          <div className="bg-content-1 border-2 border-default-100 rounded-xl p-6 flex flex-col items-center justify-center text-center">
            <p className="text-sm text-gray-400">
              <Image
                src="/svg/empty_repository.svg"
                alt="Empty Repository"
                width={55}
                height={55}
                className="m-auto mb-4"
              />
              Repository would appear here,
              <br />
              after selecting the organization.
            </p>
          </div>
        </div>
      ) : (
        <Autocomplete
          id="repository-autocomplete"
          label="Git Repository"
          labelPlacement="outside"
          placeholder="Search a repository or add one from Github"
          classNames={{
            base: "w-full mb-6",
          }}
          inputProps={{
            classNames: {
              inputWrapper:
                "border-2 border-default-100 bg-content-1 hover:border-gray-600 group-data-[focus=true]:bg-content-1 data-[hover=true]:bg-content-1",
            },
          }}
          isLoading={isLoading}
          onSelectionChange={(key) => {
            const selected = key as string;
            const selectedRepository = repositories.find((repo) => repo.name === selected) || null;
            setSelectedRepo(selectedRepository);
            setIsPrivate(selectedRepository?.private || false);
          }}
          startContent={
            isPrivate ? <Image src="/svg/private.svg" alt="Private" className="ml-2" width={14} height={14} /> : null
          }
        >
          {repositories.map((repo) => (
            <AutocompleteItem
              key={repo.name}
              textValue={repo.name}
              className="hover:bg-[#4F46E5] transition-colors duration-300"
            >
              <div className="flex items-center">
                {repo.name}{" "}
                {repo.private ? (
                  <Image src="/svg/private.svg" alt="Private" className="ml-2" width={14} height={14} />
                ) : null}
              </div>
            </AutocompleteItem>
          ))}
        </Autocomplete>
      )}

      <Link href={SERVICES.GITHUB_APP_URL} className="text-sm text-[#AE7EDE]" target="_blank" rel="noopener noreferrer">
        <div className="flex items-center">
          Add Repo from Github
          <Image src="/svg/link.svg" alt="Link" className="ml-2" width={14} height={14} />
        </div>
      </Link>

      <div className="flex items-center justify-center mt-6">
        <div className="w-full h-[2px] bg-gray-700"></div>
        <span className="mx-5 text-gray-300">Or</span>
        <div className="w-full h-[2px] bg-gray-700"></div>
      </div>

      <Input
        label="Git Repository URL"
        placeholder="https://github.com/owner/repo"
        labelPlacement="outside"
        value={inputURL}
        onChange={(e) => setInputURL(e.target.value)}
        classNames={{
          inputWrapper:
            "border-2 border-default-100 bg-content-1 hover:border-gray-600 group-data-[focus=true]:bg-content-1 data-[hover=true]:bg-content-1",
        }}
        isInvalid={repositoryURL !== "" && !isValidURL && !isCheckingURL}
        errorMessage={!isValidURL && !isCheckingURL ? errorMessage : ""}
        isDisabled={isCheckingURL}
        startContent={isCheckingURL ? <Spinner size="sm" /> : null}
      />
    </div>
  );
};

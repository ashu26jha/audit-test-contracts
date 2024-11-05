import React, { useEffect, useState } from "react";

import { Select, SelectItem, Input, type Selection, Autocomplete, AutocompleteItem } from "@nextui-org/react";
import Image from "next/image";
import Link from "next/link";
import { useDebounce } from "use-debounce";

import { SERVICES } from "@/config/constants";
import { useScanStepper } from "@/hooks/useScanStepper";
import { useScanStepperStore } from "@/store/scanStepperStore";

export const RepositorySelection: React.FC = () => {
  const {
    owners,
    setSelectedOwner,
    setRepositoryURL,
    selectedOwner,
    repositories,
    repositoryURL,
    setSelectedRepo,
    resetStepper,
  } = useScanStepperStore();
  const { extractOwnerAndRepo } = useScanStepper();
  const [selectedOrg, setSelectedOrg] = useState<string | null>(null);
  const [isInvalidURL, setIsInvalidURL] = useState<boolean>(false);
  const [inputURL, setInputURL] = useState<string>("");

  const [debouncedURL] = useDebounce(inputURL, 300);

  const [isPrivate, setIsPrivate] = useState<boolean>(false);

  useEffect(() => {
    resetStepper();
  }, [resetStepper]);

  useEffect(() => {
    if (debouncedURL.trim()) {
      const result = extractOwnerAndRepo(debouncedURL);
      if (!result) {
        setIsInvalidURL(true);
      } else {
        setIsInvalidURL(false);
        setRepositoryURL(debouncedURL);
      }
    } else {
      setIsInvalidURL(false);
      setRepositoryURL("");
    }
  }, [debouncedURL, extractOwnerAndRepo, setRepositoryURL]);

  const handleOrganizationSelect = (keys: Selection) => {
    const selected = Array.from(keys)[0] as string;
    setIsInvalidURL(false);
    setSelectedOrg(selected);
    setSelectedOwner(owners.find((owner) => owner.login === selected) || null);
    setInputURL("");
    setRepositoryURL("");
  };

  const handleURLChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const url = e.target.value;
    setInputURL(url);
    setSelectedOrg(null);
    setSelectedOwner(null);
  };

  return (
    <>
      <Select
        variant="bordered"
        label="Git Organization"
        placeholder="Select one"
        labelPlacement="outside"
        className="w-full"
        selectedKeys={selectedOrg ? [selectedOrg] : []}
        onSelectionChange={handleOrganizationSelect}
        isLoading={useScanStepperStore.getState().isOrganizationLoading}
      >
        {owners.map((org) => (
          <SelectItem key={org.login} value={org.login}>
            {org.login}
          </SelectItem>
        ))}
      </Select>

      {!selectedOwner || repositoryURL ? (
        <>
          <label htmlFor="repository-autocomplete" className="block text-sm font-medium text-left">
            Git Repository
            <span style={{ color: "red", marginLeft: "4px" }}>*</span>
          </label>
          <div className="bg-[#222222] rounded p-6 flex flex-col items-center justify-center text-center">
            <p className="text-sm text-gray-400">
              <Image
                src="/empty_repository.svg"
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
        </>
      ) : (
        <Autocomplete
          id="repository-autocomplete"
          variant="bordered"
          label="Git Repository"
          labelPlacement="outside"
          placeholder="Search a repository"
          className="w-full"
          isLoading={useScanStepperStore.getState().isRepositoryLoading}
          onSelectionChange={(key) => {
            const selected = key as string;
            const selectedRepository = repositories.find((repo) => repo.name === selected) || null;
            setSelectedRepo(selectedRepository);
            setIsPrivate(selectedRepository?.private || false);
          }}
          startContent={
            isPrivate ? <Image src="/private.svg" alt="Private" className="ml-2" width={14} height={14} /> : null
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
                  <Image src="/private.svg" alt="Private" className="ml-2" width={14} height={14} />
                ) : null}
              </div>
            </AutocompleteItem>
          ))}
        </Autocomplete>
      )}

      <Link
        href={SERVICES.GITHUB_APP_URL}
        className="text-sm text-[#AE7EDE] mt-[-0.5rem]"
        target="_blank"
        rel="noopener noreferrer"
      >
        <div className="flex items-center">
          Add Repo from Github
          <Image src="/link.svg" alt="Link" className="ml-2" width={14} height={14} />
        </div>
      </Link>

      <div className="flex items-center justify-center mb-3 mt-3">
        <div className="w-full h-[2px] bg-gray-700"></div>
        <span className="mx-5 text-gray-300">Or</span>
        <div className="w-full h-[2px] bg-gray-700"></div>
      </div>

      <Input
        variant="bordered"
        label="Git Repository URL"
        placeholder="https://github.com/owner/repo"
        labelPlacement="outside"
        value={inputURL}
        onChange={handleURLChange}
        className="w-full"
        isInvalid={isInvalidURL}
        errorMessage={isInvalidURL ? "Invalid GitHub URL" : ""}
      />
    </>
  );
};

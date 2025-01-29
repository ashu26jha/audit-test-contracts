"use client";

import { useCallback, useEffect, useState, type FC } from "react";

import { Autocomplete, AutocompleteItem, Card, Select, SelectItem, Snippet, type Selection } from "@nextui-org/react";
import Image from "next/image";

import { useGithubApp } from "@/hooks";
import { getRepositories } from "@/services/api";
import { useUserDataStore } from "@/store/userDataStore";

const GithubAction: FC = () => {
  const { owners, isOrganizationLoading } = useUserDataStore();
  const [selectedOrg, setSelectedOrg] = useState<string | null>(null);
  const [selectedOwner, setSelectedOwner] = useState<Owner | null>(null);
  const [selectedRepo, setSelectedRepo] = useState<Repository | null>(null);
  const [isPrivate, setIsPrivate] = useState<boolean | null>(null);
  const [repositories, setRepositories] = useState<Repository[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  useGithubApp();

  const types = [
    { key: "jest", label: "Jest" },
    { key: "cypress", label: "Cypress" },
  ];

  const handleOrganizationSelect = (keys: Selection) => {
    const selected = Array.from(keys)[0] as string;
    setSelectedOrg(selected);
    setSelectedOwner(owners.find((owner) => owner.login === selected) || null);
  };

  const fetchRepositories = useCallback(
    async (owner: Owner) => {
      setIsLoading(true);
      try {
        const repositories = await getRepositories(owner.login, owner.type);
        setRepositories(repositories);
      } catch (error) {
        console.error("Error fetching repositories:", error);
      } finally {
        setIsLoading(false);
      }
    },
    [setRepositories, setIsLoading],
  );

  useEffect(() => {
    if (selectedOwner) {
      fetchRepositories(selectedOwner);
    }
  }, [selectedOwner, fetchRepositories]);

  return (
    <div>
      <div>
        <p className="text-sm mb-2">Your API key</p>
        <Card className="bg-content-1 rounded-xl p-3 border w-[34rem] border-default-100 flex justify-center ">
          <Snippet className="bg-black w-full" symbol="">
            4f3a2b1c-9e7d-4a5e-8c2f-6b1e3f4a5b6c
          </Snippet>
        </Card>
      </div>

      <div className="mt-8">
        <p className="text-sm mb-2">Step 1: Select Repository</p>
        <Card className="bg-content-1 rounded-xl p-3 border w-[34rem] border-default-100 flex justify-center gap-y-3">
          <Select
            label="Git Organization"
            classNames={{
              base: "w-full",
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

          {!selectedOwner ? (
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
                isPrivate ? (
                  <Image src="/svg/private.svg" alt="Private" className="ml-2" width={14} height={14} />
                ) : null
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
        </Card>
      </div>

      <div className="mt-8">
        <p className="text-sm mb-2">Step 2: Output a Coverage report file in your CI</p>
        <Card className="bg-content-1 rounded-xl p-3 border w-[34rem] border-default-100 flex justify-center gap-y-3">
          <p className="text-sm ">Select Type</p>
          <Select
            classNames={{
              base: "w-full",
              trigger: "border-2 border-default-100 bg-content-1 hover:border-gray-600",
            }}
            placeholder="Select one"
            labelPlacement="outside"
          >
            {types.map((type) => (
              <SelectItem key={type.key}>{type.label}</SelectItem>
            ))}
          </Select>

          <p className="text-sm ">Install requirements in your terminal</p>
          <Snippet className="bg-black w-full" symbol="">
            npm install --save-dev jest
          </Snippet>

          <p className="text-sm ">In a GitHub Action, run tests and generate a coverage report</p>
          <Snippet className="bg-black w-full" symbol="">
            npx jest --coverage
          </Snippet>
        </Card>
      </div>

      <div className="mt-8">
        <p className="text-sm mb-2">Step 3: Add repository token as repository secret</p>
        <Card className="bg-content-1 rounded-xl p-3 border w-[34rem] border-default-100 flex justify-center  gap-y-3">
          <p className="text-sm ">Admin required to access repo configuration › secrets and variable › actions</p>
          <Snippet className="bg-black w-full" symbol="">
            AUDIT_AGENT_TOKEN
          </Snippet>

          <Snippet className="bg-black w-full" symbol="">
            bdbca2e2-042d-48ba-9b21-c2433bbea40f
          </Snippet>
        </Card>
      </div>

      <div className="mt-8">
        <p className="text-sm mb-2">Step 4: Add Codecov to your GitHub Actions workflow yaml file</p>
        <Card className="bg-content-1 rounded-xl p-3 border w-[34rem] border-default-100 flex justify-center gap-y-3">
          <p className="text-sm">After tests run, this will upload your coverage report to Codecov</p>
          <Snippet className="bg-black w-full" symbol="">
            <span>- name: Upload coverage reports to Codecov</span>
            <span>uses: codecov/ codecov-action@v5 {selectedRepo?.name}</span>
            <span>{"with: token: ${( secrets. CODECOV_TOKEN }}"}</span>
          </Snippet>
        </Card>
      </div>

      <div className="mt-8">
        <p className="text-sm mb-2">Step 5: Merge to main or your preferred feature branch</p>
        <Card className="bg-content-1 rounded-xl p-3 border w-[34rem] border-default-100 flex justify-center gap-y-3">
          <p className="text-sm">
            Once merged to your default branch, subsequent pull requests will have Codecov checks and comments.
            Additionally, you&apos;ll find your repo coverage dashboard here. If you have merged, try reloading the
            page.
          </p>
        </Card>
      </div>
    </div>
  );
};

export default GithubAction;

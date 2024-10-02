import { useCallback } from "react";

import {
  getOrganizationsAndPersonal,
  getRepositories,
  getRepositoryContents,
  getBranches,
  initiateScan,
} from "../services/api";
import { useScanStepperStore } from "../store/scanStepperStore";

export const useScanStepper = () => {
  const {
    setOwners,
    setRepositories,
    setBranches,
    setSolidityFiles,
    selectedOwner,
    selectedRepo,
    selectedBranch,
    selectedContracts,
    setSelectedOwner,
    setSelectedRepo,
    setRepositoryURL,
  } = useScanStepperStore();

  const fetchOwners = useCallback(
    async (token: string) => {
      try {
        const owners = await getOrganizationsAndPersonal(token);
        setOwners(owners);
      } catch (error) {
        console.error("Error fetching owners:", error);
      }
    },
    [setOwners],
  );

  const fetchRepositories = useCallback(
    async (token: string, owner: Owner) => {
      try {
        const repositories = await getRepositories(token, owner.login, owner.type);
        setRepositories(repositories);
      } catch (error) {
        console.error("Error fetching repositories:", error);
      }
    },
    [setRepositories],
  );

  const fetchBranches = useCallback(
    async (token: string, owner: Owner, repo: Repository) => {
      try {
        const branches = await getBranches(token, owner.login, repo.name);
        setBranches(branches);
      } catch (error) {
        console.error("Error fetching branches:", error);
      }
    },
    [setBranches],
  );

  const fetchSolidityFiles = useCallback(
    async (token: string, owner: Owner, repo: Repository, branch: string) => {
      try {
        const files = await getRepositoryContents(token, owner.login, repo.name, branch);
        setSolidityFiles(files);
      } catch (error) {
        console.error("Error fetching Solidity files:", error);
      }
    },
    [setSolidityFiles],
  );

  const initiateScanProcess = useCallback(
    async (token: string) => {
      try {
        if (!selectedOwner || !selectedRepo) {
          throw new Error("Owner or repository not selected");
        }
        const response = await initiateScan(token, {
          repositoryURL: `https://github.com/${selectedOwner.login}/${selectedRepo.name}`,
          contractFiles: selectedContracts,
          branchName: selectedBranch,
        });
        return response;
      } catch (error) {
        console.error("Error initiating scan:", error);
        throw error;
      }
    },
    [selectedOwner, selectedRepo, selectedBranch, selectedContracts],
  );

  const extractOwnerAndRepo = useCallback(
    (url: string) => {
      try {
        const parsedUrl = new URL(url);
        const pathParts = parsedUrl.pathname.split("/").filter(Boolean);

        if (pathParts.length >= 2 && parsedUrl.hostname === "github.com") {
          const owner = pathParts[0];
          const repo = pathParts[1];

          setSelectedOwner({ login: owner, type: "user" });
          setSelectedRepo({ name: repo, updatedAt: "" });
          setRepositoryURL(url);

          return { owner, repo };
        } else {
          throw new Error("Invalid GitHub URL");
        }
      } catch (error) {
        console.error("Error parsing GitHub URL:", error);
        return null;
      }
    },
    [setSelectedOwner, setSelectedRepo, setRepositoryURL],
  );

  return {
    fetchOwners,
    fetchRepositories,
    fetchBranches,
    fetchSolidityFiles,
    initiateScanProcess,
    extractOwnerAndRepo,
  };
};

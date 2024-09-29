import { useCallback } from "react";
import { useScanStepperStore } from "../store/scanStepperStore";
import {
  getOrganizationsAndPersonal,
  getRepositories,
  getRepositoryContents,
  getBranches,
  initiateScan,
} from "../services/api";

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

  return {
    fetchOwners,
    fetchRepositories,
    fetchBranches,
    fetchSolidityFiles,
    initiateScanProcess,
  };
};

import { useCallback } from "react";

import { useScanStepperStore } from "@/store/scanStepperStore";
import { useUserDataStore } from "@/store/userDataStore";

import { getRepositories, getRepositoryContents, getBranches, initiateScan } from "../services/api";

export const useScanStepper = () => {
  const { setRepositories } = useUserDataStore();
  const {
    setBranches,
    setSolidityFiles,
    selectedOwner,
    selectedRepo,
    selectedBranch,
    selectedContracts,
    setSelectedOwner,
    setSelectedRepo,
    setRepositoryURL,
    setIsLoading,
  } = useScanStepperStore();

  const fetchRepositories = useCallback(
    async (token: string, owner: Owner) => {
      try {
        setIsLoading(true);
        const repositories = await getRepositories(token, owner.login, owner.type);
        setRepositories(repositories);
      } catch (error) {
        console.error("Error fetching repositories:", error);
      } finally {
        setIsLoading(false);
      }
    },
    [setRepositories, setIsLoading],
  );

  const fetchBranches = useCallback(
    async (token: string, owner: Owner, repo: Repository) => {
      try {
        setIsLoading(true);
        const branches = await getBranches(token, owner.login, repo.name);
        setBranches(branches);
      } catch (error) {
        console.error("Error fetching branches:", error);
      } finally {
        setIsLoading(false);
      }
    },
    [setBranches, setIsLoading],
  );

  const fetchSolidityFiles = useCallback(
    async (token: string, owner: Owner, repo: Repository, branch: string) => {
      try {
        setIsLoading(true);
        const files = await getRepositoryContents(token, owner.login, repo.name, branch);
        setSolidityFiles(files);
      } catch (error) {
        console.error("Error fetching Solidity files:", error);
      } finally {
        setIsLoading(false);
      }
    },
    [setSolidityFiles, setIsLoading],
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
          branchName: selectedBranch || "",
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
          setSelectedRepo({ name: repo, updatedAt: "", private: false });
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
    fetchRepositories,
    fetchBranches,
    fetchSolidityFiles,
    initiateScanProcess,
    extractOwnerAndRepo,
  };
};

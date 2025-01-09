import { useCallback } from "react";

import { useAuth } from "@/contexts/AuthContext";
import {
  getRepositories,
  getRepositoryContents,
  getBranches,
  initiateScan,
  getReadmeFiles,
  getRepositoryDocs,
} from "@/services/api";
import { useScanStepperStore } from "@/store/scanStepperStore";
import { useUserDataStore } from "@/store/userDataStore";
import { sanitizeString } from "@/utils/helpers";

export const useScanStepper = () => {
  const { setRepositories } = useUserDataStore();
  const {
    selectedOwner,
    selectedRepo,
    selectedBranch,
    selectedContracts,
    repoDocs,
    setSelectedOwner,
    setSelectedRepo,
    setBranches,
    setSolidityFiles,
    setReadmeFiles,
    setRepositoryURL,
    setIsLoading,
    setRepoDocs,
  } = useScanStepperStore();
  const { user } = useAuth();

  const fetchPreviousDocs = useCallback(
    async (owner: string, repo: string) => {
      const res = await getRepositoryDocs(owner, repo);

      if (res?.docs && user?.subscription.type !== "free") {
        // Set previous readme files and QA answers if they exist
        setRepoDocs(res.docs);
      } else {
        setRepoDocs({ readme: [], qa: {} });
      }
    },
    [setRepoDocs, user],
  );

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

  const fetchBranches = useCallback(
    async (owner: Owner, repo: Repository) => {
      try {
        setIsLoading(true);
        const branches = await getBranches(owner.login, repo.name);
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
    async (owner: Owner, repo: Repository, branch: string) => {
      try {
        setIsLoading(true);
        const files = await getRepositoryContents(owner.login, repo.name, branch);
        setSolidityFiles(files);
      } catch (error) {
        console.error("Error fetching Solidity files:", error);
      } finally {
        setIsLoading(false);
      }
    },
    [setSolidityFiles, setIsLoading],
  );

  const fetchReadmeFiles = useCallback(
    async (owner: Owner, repo: Repository, branch: string) => {
      try {
        setIsLoading(true);
        const files = await getReadmeFiles(owner.login, repo.name, branch);
        setReadmeFiles(files);
      } catch (error) {
        console.error("Error fetching Readme files:", error);
      } finally {
        setIsLoading(false);
      }
    },
    [setReadmeFiles, setIsLoading],
  );

  const initiateScanProcess = useCallback(async () => {
    try {
      if (!selectedOwner || !selectedRepo) {
        throw new Error("Owner or repository not selected");
      }

      const qa = Object.entries(repoDocs.qa).reduce(
        (acc, [key, value]) => {
          acc[key] = sanitizeString(value);
          return acc;
        },
        {} as Record<string, string>,
      );

      const response = await initiateScan({
        repositoryURL: `https://github.com/${selectedOwner.login}/${selectedRepo.name}`,
        contractFiles: selectedContracts,
        branchName: selectedBranch || "",
        docs: {
          readme: repoDocs.readme,
          qa,
        },
      });
      return response;
    } catch (error) {
      console.error("Error initiating scan:", error);
      throw error;
    }
  }, [repoDocs, selectedOwner, selectedRepo, selectedBranch, selectedContracts]);

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
    fetchReadmeFiles,
    fetchPreviousDocs,
    initiateScanProcess,
    extractOwnerAndRepo,
  };
};

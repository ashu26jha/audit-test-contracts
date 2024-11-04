import { create } from "zustand";

interface ScanStepperState {
  currentStep: number;
  selectedOwner: Owner | null;
  selectedRepo: Repository | null;
  selectedBranch: string | undefined;
  selectedContracts: string[];
  owners: Owner[];
  repositories: Repository[];
  branches: Branch[];
  solidityFiles: File[];
  isLoading: boolean;
  isNextEnabled: boolean;
  contractSearch: string;
  repositoryURL: string;
  isBranchLoading: boolean;
  isOrganizationLoading: boolean;
  isRepositoryLoading: boolean;
  isSolidityFilesLoading: boolean;
  isLineExceeded: boolean;
  isFileLimitExceeded: boolean;
  setCurrentStep: (step: number) => void;
  setSelectedOwner: (owner: Owner | null) => void;
  setSelectedRepo: (repo: Repository | null) => void;
  setSelectedBranch: (branch: string) => void;
  setSelectedContracts: (contracts: string[]) => void;
  setContractSearch: (search: string) => void;
  setOwners: (owners: Owner[]) => void;
  setRepositories: (repositories: Repository[]) => void;
  setBranches: (branches: Branch[]) => void;
  setSolidityFiles: (files: File[]) => void;
  setIsLoading: (isLoading: boolean) => void;
  setIsNextEnabled: (isEnabled: boolean) => void;
  setRepositoryURL: (url: string) => void;
  setIsBranchLoading: (isLoaded: boolean) => void;
  setIsOrganizationLoading: (isLoading: boolean) => void;
  setIsRepositoryLoading: (isLoading: boolean) => void;
  setIsSolidityFilesLoading: (isLoaded: boolean) => void;
  setIsLineExceeded: (isLineExceeded: boolean) => void;
  setIsFileLimitExceeded: (isLineExceeded: boolean) => void;
  resetStepper: () => void;
}

export const useScanStepperStore = create<ScanStepperState>((set) => ({
  currentStep: 1,
  selectedOwner: null,
  selectedRepo: null,
  selectedBranch: "",
  selectedContracts: [],
  owners: [],
  repositories: [],
  branches: [],
  solidityFiles: [],
  isLoading: false,
  isNextEnabled: false,
  contractSearch: "",
  repositoryURL: "",
  isBranchLoading: false,
  isOrganizationLoading: false,
  isRepositoryLoading: false,
  isSolidityFilesLoading: false,
  isLineExceeded: false,
  isFileLimitExceeded: false,
  setCurrentStep: (step) => set({ currentStep: step }),
  setSelectedOwner: (owner) => set({ selectedOwner: owner }),
  setSelectedRepo: (repo) => set({ selectedRepo: repo }),
  setSelectedBranch: (branch) => set({ selectedBranch: branch }),
  setSelectedContracts: (contracts) => set({ selectedContracts: contracts }),
  setContractSearch: (search) => set({ contractSearch: search }),
  setOwners: (owners) => set({ owners }),
  setRepositories: (repositories) => set({ repositories }),
  setBranches: (branches) => set({ branches }),
  setSolidityFiles: (files) => set({ solidityFiles: files }),
  setIsLoading: (isLoading) => set({ isLoading }),
  setIsNextEnabled: (isEnabled) => set({ isNextEnabled: isEnabled }),
  setRepositoryURL: (url) => set({ repositoryURL: url }),
  setIsBranchLoading: (isLoaded) => set({ isBranchLoading: isLoaded }),
  setIsOrganizationLoading: (isLoaded) => set({ isOrganizationLoading: isLoaded }),
  setIsRepositoryLoading: (isLoaded) => set({ isRepositoryLoading: isLoaded }),
  setIsSolidityFilesLoading: (isLoaded) => set({ isSolidityFilesLoading: isLoaded }),
  setIsLineExceeded: (isLineExceeded) => set({ isLineExceeded }),
  setIsFileLimitExceeded: (isLineExceeded) => set({ isFileLimitExceeded: isLineExceeded }),
  resetStepper: () =>
    set({
      currentStep: 1,
      selectedOwner: null,
      selectedRepo: null,
      selectedBranch: "",
      selectedContracts: [],
      repositories: [],
      branches: [],
      solidityFiles: [],
      isLoading: false,
      isNextEnabled: false,
      contractSearch: "",
      repositoryURL: "",
    }),
}));

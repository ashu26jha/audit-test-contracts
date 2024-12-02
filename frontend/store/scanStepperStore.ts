import { create } from "zustand";

interface ScanStepperState {
  currentStep: number;
  selectedOwner: Owner | null;
  selectedRepo: Repository | null;
  selectedBranch: string | undefined;
  selectedContracts: string[];
  branches: Branch[];
  solidityFiles: File[];
  isLoading: boolean;
  isScanning: boolean;
  isNextEnabled: boolean;
  contractSearch: string;
  repositoryURL: string;
  isLineExceeded: boolean;
  isFileLimitExceeded: boolean;
  setCurrentStep: (step: number) => void;
  setSelectedOwner: (owner: Owner | null) => void;
  setSelectedRepo: (repo: Repository | null) => void;
  setSelectedBranch: (branch: string) => void;
  setSelectedContracts: (contracts: string[]) => void;
  setContractSearch: (search: string) => void;
  setBranches: (branches: Branch[]) => void;
  setSolidityFiles: (files: File[]) => void;
  setIsLoading: (isLoading: boolean) => void;
  setIsScanning: (isScanning: boolean) => void;
  setIsNextEnabled: (isEnabled: boolean) => void;
  setRepositoryURL: (url: string) => void;
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
  branches: [],
  solidityFiles: [],
  isLoading: false,
  isScanning: false,
  isNextEnabled: false,
  contractSearch: "",
  repositoryURL: "",
  isLineExceeded: false,
  isFileLimitExceeded: false,
  setCurrentStep: (step) => set({ currentStep: step }),
  setSelectedOwner: (owner) => set({ selectedOwner: owner }),
  setSelectedRepo: (repo) => set({ selectedRepo: repo }),
  setSelectedBranch: (branch) => set({ selectedBranch: branch }),
  setSelectedContracts: (contracts) => set({ selectedContracts: contracts }),
  setContractSearch: (search) => set({ contractSearch: search }),
  setBranches: (branches) => set({ branches }),
  setSolidityFiles: (files) => set({ solidityFiles: files }),
  setIsLoading: (isLoading) => set({ isLoading }),
  setIsScanning: (isScanning) => set({ isScanning }),
  setIsNextEnabled: (isEnabled) => set({ isNextEnabled: isEnabled }),
  setRepositoryURL: (url) => set({ repositoryURL: url }),
  setIsLineExceeded: (isLineExceeded) => set({ isLineExceeded }),
  setIsFileLimitExceeded: (isLineExceeded) => set({ isFileLimitExceeded: isLineExceeded }),
  resetStepper: () =>
    set({
      currentStep: 1,
      selectedOwner: null,
      selectedRepo: null,
      selectedBranch: "",
      selectedContracts: [],
      solidityFiles: [],
      isLoading: false,
      isScanning: false,
      isNextEnabled: false,
      contractSearch: "",
      repositoryURL: "",
    }),
}));

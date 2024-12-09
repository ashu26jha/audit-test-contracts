import { create } from "zustand";

interface ScanStepperState {
  showStepper: boolean;
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
  isValidURL: boolean;
  isLineExceeded: boolean;
  isFileLimitExceeded: boolean;
  setShowStepper: (show: boolean) => void;
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
  setIsValidURL: (isValidURL: boolean) => void;
  setIsLineExceeded: (isLineExceeded: boolean) => void;
  setIsFileLimitExceeded: (isLineExceeded: boolean) => void;
  resetStepper: () => void;
}

export const useScanStepperStore = create<ScanStepperState>((set) => ({
  showStepper: false,
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
  isValidURL: false,
  isLineExceeded: false,
  isFileLimitExceeded: false,
  setShowStepper: (show) => set({ showStepper: show }),
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
  setIsValidURL: (isValidURL) => set({ isValidURL }),
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
      isValidURL: false,
    }),
}));

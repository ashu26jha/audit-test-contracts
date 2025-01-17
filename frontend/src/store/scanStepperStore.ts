import { create } from "zustand";

interface ScanStepperState {
  showStepper: boolean;
  currentStep: number;
  selectedOwner: Owner | null;
  selectedRepo: Repository | null;
  branches: Branch[];
  selectedBranch: string | undefined;
  selectedContracts: string[];
  contractSearch: string;
  solidityFiles: SolidityFile[];
  readmeFiles: ReadmeFile[];
  repoDocs: RepoDocs;
  isLoading: boolean;
  isScanning: boolean;
  isNextEnabled: boolean;
  repositoryURL: string;
  isValidURL: boolean;
  isLineExceeded: boolean;
  isFileLimitExceeded: boolean;
  selectedPlan: string | null;
  setShowStepper: (show: boolean) => void;
  setCurrentStep: (step: number) => void;
  setSelectedOwner: (owner: Owner | null) => void;
  setSelectedRepo: (repo: Repository | null) => void;
  setBranches: (branches: Branch[]) => void;
  setSelectedBranch: (branch: string) => void;
  setSelectedContracts: (contracts: string[]) => void;
  setContractSearch: (search: string) => void;
  setSolidityFiles: (files: SolidityFile[]) => void;
  setReadmeFiles: (files: ReadmeFile[]) => void;
  setRepoDocs: (docs: Partial<RepoDocs>) => void;
  setIsLoading: (isLoading: boolean) => void;
  setIsScanning: (isScanning: boolean) => void;
  setIsNextEnabled: (isEnabled: boolean) => void;
  setRepositoryURL: (url: string) => void;
  setIsValidURL: (isValidURL: boolean) => void;
  setIsLineExceeded: (isLineExceeded: boolean) => void;
  setIsFileLimitExceeded: (isLineExceeded: boolean) => void;
  setSelectedPlan: (plan: string) => void;
  resetStepper: (step: number) => void;
}

export const useScanStepperStore = create<ScanStepperState>((set) => ({
  showStepper: false,
  currentStep: 0,
  selectedOwner: null,
  selectedRepo: null,
  branches: [],
  selectedBranch: "",
  selectedContracts: [],
  contractSearch: "",
  solidityFiles: [],
  readmeFiles: [],
  repoDocs: {
    readme: [],
    qa: {},
  },
  isLoading: false,
  isScanning: false,
  isNextEnabled: false,
  repositoryURL: "",
  isValidURL: false,
  isLineExceeded: false,
  isFileLimitExceeded: false,
  selectedPlan: null,
  setSelectedPlan: (plan) => set({ selectedPlan: plan }),
  setShowStepper: (show) => set({ showStepper: show }),
  setCurrentStep: (step) => set({ currentStep: step }),
  setSelectedOwner: (owner) => set({ selectedOwner: owner }),
  setSelectedRepo: (repo) => set({ selectedRepo: repo }),
  setBranches: (branches) => set({ branches }),
  setSelectedBranch: (branch) => set({ selectedBranch: branch }),
  setSelectedContracts: (contracts) => set({ selectedContracts: contracts }),
  setContractSearch: (search) => set({ contractSearch: search }),
  setSolidityFiles: (files) => set({ solidityFiles: files }),
  setReadmeFiles: (files) => set({ readmeFiles: files }),
  setIsLoading: (isLoading) => set({ isLoading }),
  setIsScanning: (isScanning) => set({ isScanning }),
  setIsNextEnabled: (isEnabled) => set({ isNextEnabled: isEnabled }),
  setRepositoryURL: (url) => set({ repositoryURL: url }),
  setIsValidURL: (isValidURL) => set({ isValidURL }),
  setIsLineExceeded: (isLineExceeded) => set({ isLineExceeded }),
  setIsFileLimitExceeded: (isLineExceeded) => set({ isFileLimitExceeded: isLineExceeded }),
  setRepoDocs: (docs) => set((state) => ({ repoDocs: { ...state.repoDocs, ...docs } })),
  resetStepper: (step) =>
    set({
      currentStep: step,
      selectedOwner: null,
      selectedRepo: null,
      selectedBranch: "",
      selectedContracts: [],
      branches: [],
      solidityFiles: [],
      readmeFiles: [],
      isLoading: false,
      isScanning: false,
      isNextEnabled: false,
      contractSearch: "",
      repositoryURL: "",
      isValidURL: false,
      isLineExceeded: false,
      isFileLimitExceeded: false,
      selectedPlan: null,
      repoDocs: {
        readme: [],
        qa: {},
      },
    }),
}));

import { create } from "zustand";

interface UserDataState {
  owners: Owner[];
  repositories: Repository[];
  hasGithubApp: boolean | null;
  isOrganizationLoading: boolean;
  setOwners: (owners: Owner[]) => void;
  setRepositories: (repositories: Repository[]) => void;
  setHasGithubApp: (hasGithubApp: boolean | null) => void;
  setIsOrganizationLoading: (isLoading: boolean) => void;
}

export const useUserDataStore = create<UserDataState>((set) => ({
  owners: [],
  repositories: [],
  hasGithubApp: null,
  isOrganizationLoading: false,
  setOwners: (owners) => set({ owners }),
  setRepositories: (repositories) => set({ repositories }),
  setHasGithubApp: (hasGithubApp) => set({ hasGithubApp }),
  setIsOrganizationLoading: (isLoading) => set({ isOrganizationLoading: isLoading }),
}));

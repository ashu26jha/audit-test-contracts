import { create } from "zustand";

interface SubscriptionState {
  freeScanAllowed: boolean;
  isLoading: boolean;
  error: string | null;
  nextAvailableScanDate: Date | null;
  setNextAvailableScanDate: (date: Date | null) => void;
  setFreeScanAllowed: (allowed: boolean) => void;
  setIsLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
}

export const useSubscriptionStore = create<SubscriptionState>((set) => ({
  freeScanAllowed: false,
  isLoading: false,
  error: null,
  setFreeScanAllowed: (allowed) => set({ freeScanAllowed: allowed }),
  setIsLoading: (loading) => set({ isLoading: loading }),
  setError: (error) => set({ error }),
  nextAvailableScanDate: null,
  setNextAvailableScanDate: (date) => set({ nextAvailableScanDate: date }),
}));

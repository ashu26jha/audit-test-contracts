import { create } from "zustand";

interface PaymentStore {
  isProcessing: boolean;
  error: string | null;
  shouldPoll: boolean;
  setIsProcessing: (isProcessing: boolean) => void;
  setError: (error: string | null) => void;
  setShouldPoll: (shouldPoll: boolean) => void;
}

export const usePaymentStore = create<PaymentStore>((set) => ({
  isProcessing: false,
  error: null,
  shouldPoll: true,
  setIsProcessing: (isProcessing) => set({ isProcessing }),
  setError: (error) => set({ error }),
  setShouldPoll: (shouldPoll) => set({ shouldPoll }),
}));

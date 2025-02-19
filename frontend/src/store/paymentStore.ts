import { create } from "zustand";

interface PaymentStore {
  isProcessing: boolean;
  error: string | null;
  shouldPoll: boolean;
  toastStarted: boolean;
  isScanLoading: boolean;
  setToastStarted: (toastStarted: boolean) => void;
  setIsProcessing: (isProcessing: boolean) => void;
  setError: (error: string | null) => void;
  setShouldPoll: (shouldPoll: boolean) => void;
  setIsScanLoading: (isScanLoading: boolean) => void;
}

export const usePaymentStore = create<PaymentStore>((set) => ({
  isProcessing: false,
  error: null,
  shouldPoll: true,
  toastStarted: false,
  isScanLoading: false,
  setToastStarted: (toastStarted) => set({ toastStarted }),
  setIsProcessing: (isProcessing) => set({ isProcessing }),
  setError: (error) => set({ error }),
  setShouldPoll: (shouldPoll) => set({ shouldPoll }),
  setIsScanLoading: (isScanLoading) => set({ isScanLoading }),
}));

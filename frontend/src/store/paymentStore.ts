import { create } from "zustand";

interface PaymentStore {
  isProcessing: boolean;
  error: string | null;
  shouldPoll: boolean;
  isPaid: boolean;
  setIsProcessing: (isProcessing: boolean) => void;
  setError: (error: string | null) => void;
  setShouldPoll: (shouldPoll: boolean) => void;
  setIsPaid: (isPaid: boolean) => void;
}

export const usePaymentStore = create<PaymentStore>((set) => ({
  isProcessing: false,
  error: null,
  shouldPoll: true,
  isPaid: false,
  setIsProcessing: (isProcessing) => set({ isProcessing }),
  setError: (error) => set({ error }),
  setShouldPoll: (shouldPoll) => set({ shouldPoll }),
  setIsPaid: (isPaid) => set({ isPaid }),
}));

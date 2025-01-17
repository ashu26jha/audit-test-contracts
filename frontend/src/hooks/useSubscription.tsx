import { useCallback } from "react";

import type { AxiosError } from "axios";

import { useAuth } from "@/contexts/AuthContext";
import { createPortalSession, createSubscriptionSession, isFreeScanAllowed } from "@/services/api";
import { useSubscriptionStore } from "@/store/subscriptonStore";

import { useToast } from "./useToast";

export const useSubscription = () => {
  const {
    freeScanAllowed,
    isLoading,
    error,
    setFreeScanAllowed,
    setIsLoading,
    setError,
    nextAvailableScanDate,
    setNextAvailableScanDate,
  } = useSubscriptionStore();

  const { user } = useAuth();
  const { toast } = useToast();

  const checkIfFreeScanAllowed = useCallback(async () => {
    if (user?.subscription.type !== "free") {
      setFreeScanAllowed(true);
      return;
    }
    const response = await isFreeScanAllowed();
    setFreeScanAllowed(response.is_allowed);
    setNextAvailableScanDate(response.next_available_at);
  }, [user?.subscription.type, setFreeScanAllowed, setNextAvailableScanDate]);

  const handleSubscribe = useCallback(
    async (subscriptionType: Exclude<SubscriptionType, "free">) => {
      try {
        setIsLoading(true);
        setError(null);

        const res = await createSubscriptionSession(subscriptionType);

        setIsLoading(false);
        window.location.assign(res.data.url);
      } catch (err) {
        const error =
          ((err as AxiosError).response?.data as { message?: string })?.message ??
          "An error occurred while initiating subscription session";
        console.error("Error creating checkout session:", err);
        setError(error);
        toast({
          title: error,
          status: "error",
          duration: 3000,
        });
        setIsLoading(false);
      }
    },
    [setError, setIsLoading, toast],
  );

  const handleCustomerPortalSession = async () => {
    try {
      setIsLoading(true);
      setError(null);

      const session = await createPortalSession();

      setIsLoading(false);
      window.location.assign(session.url);
    } catch (err) {
      const error =
        ((err as AxiosError).response?.data as { message?: string })?.message ?? "An error occurred, please try again";
      console.error("Error creating customer portal session:", err);
      setError(error);
      toast({
        title: error,
        status: "error",
        duration: 3000,
      });
      setIsLoading(false);
    }
  };

  return {
    freeScanAllowed,
    checkIfFreeScanAllowed,
    handleSubscribe,
    handleCustomerPortalSession,
    nextAvailableScanDate,
    isLoading,
    error,
  };
};

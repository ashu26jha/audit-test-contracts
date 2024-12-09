import { useCallback, useState } from "react";

import { useDebounce } from "use-debounce";

import { validateRepository } from "@/services/api";
import { useScanStepperStore } from "@/store/scanStepperStore";

import { useScanStepper } from "./useScanStepper";

export const useRepositoryUrl = () => {
  const { setRepositoryURL, setIsValidURL } = useScanStepperStore();
  const { extractOwnerAndRepo } = useScanStepper();
  const [inputURL, setInputURL] = useState<string>("");
  const [debouncedURL] = useDebounce(inputURL, 300);
  const [isCheckingURL, setIsCheckingURL] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string>("");

  const validateAndSetUrl = useCallback(
    async (url: string) => {
      if (url.trim()) {
        const result = extractOwnerAndRepo(url);
        if (!result) {
          setIsValidURL(false);
          setErrorMessage("Invalid GitHub URL format");
        } else {
          try {
            setIsCheckingURL(true);
            await validateRepository(url);
            setIsValidURL(true);
            setErrorMessage("");
            setRepositoryURL(url);
          } catch (err: any) {
            setIsValidURL(false);
            setErrorMessage(
              err.response?.data?.detail || "Unable to access repository. Are you sure this repo is public?",
            );
          } finally {
            setIsCheckingURL(false);
          }
        }
      } else {
        setIsValidURL(false);
        setErrorMessage("");
        setRepositoryURL("");
      }
    },
    [setIsValidURL, setRepositoryURL, extractOwnerAndRepo],
  );

  const resetUrl = () => {
    setIsValidURL(false);
    setErrorMessage("");
    setRepositoryURL("");
    setInputURL("");
  };

  return {
    errorMessage,
    inputURL,
    debouncedURL,
    isCheckingURL,
    setInputURL,
    validateAndSetUrl,
    resetUrl,
  };
};

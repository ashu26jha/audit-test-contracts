import { useCallback, useState } from "react";

import { useDebounce } from "use-debounce";

import { useScanStepperStore } from "@/store/scanStepperStore";

import { useScanStepper } from "./useScanStepper";

export const useRepositoryUrl = () => {
  const { setRepositoryURL } = useScanStepperStore();
  const { extractOwnerAndRepo } = useScanStepper();
  const [isInvalidURL, setIsInvalidURL] = useState<boolean>(false);
  const [inputURL, setInputURL] = useState<string>("");
  const [debouncedURL] = useDebounce(inputURL, 300);

  const validateAndSetUrl = useCallback(
    (url: string) => {
      if (url.trim()) {
        const result = extractOwnerAndRepo(url);
        if (!result) {
          setIsInvalidURL(true);
        } else {
          setIsInvalidURL(false);
          setRepositoryURL(url);
        }
      } else {
        setIsInvalidURL(false);
        setRepositoryURL("");
      }
    },
    [setIsInvalidURL, setRepositoryURL, extractOwnerAndRepo],
  );

  const resetUrl = () => {
    setIsInvalidURL(false);
    setRepositoryURL("");
    setInputURL("");
  };

  return {
    isInvalidURL,
    inputURL,
    debouncedURL,
    setInputURL,
    validateAndSetUrl,
    resetUrl,
  };
};

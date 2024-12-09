import { useCallback, useEffect } from "react";

import { getOrganizationsAndPersonal } from "@/services/api";
import { useUserDataStore } from "@/store/userDataStore";

export const useGithubApp = () => {
  const { hasGithubApp, setOwners, setHasGithubApp, setIsOrganizationLoading } = useUserDataStore();

  const checkGithubAppInstallation = useCallback(async () => {
    setIsOrganizationLoading(true);
    try {
      const owners = await getOrganizationsAndPersonal();
      setOwners(owners);
      setHasGithubApp(owners.length > 0);
      return owners.length > 0;
    } catch (error) {
      console.error("Error checking GitHub App installation:", error);
      setHasGithubApp(false);
      return false;
    } finally {
      setIsOrganizationLoading(false);
    }
  }, [setHasGithubApp, setOwners, setIsOrganizationLoading]);

  useEffect(() => {
    checkGithubAppInstallation();
  }, [checkGithubAppInstallation]);

  return {
    hasGithubApp,
  };
};

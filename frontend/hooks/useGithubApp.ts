import { useCallback, useEffect } from "react";

import { useAuth } from "@/contexts/AuthContext";
import { getOrganizationsAndPersonal } from "@/services/api";
import { useUserDataStore } from "@/store/userDataStore";

export const useGithubApp = () => {
  const { token } = useAuth();
  const { hasGithubApp, setOwners, setHasGithubApp, setIsOrganizationLoading } = useUserDataStore();

  const checkGithubAppInstallation = useCallback(
    async (token: string) => {
      setIsOrganizationLoading(true);
      try {
        const owners = await getOrganizationsAndPersonal(token);
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
    },
    [setHasGithubApp, setOwners, setIsOrganizationLoading],
  );

  useEffect(() => {
    if (token) {
      checkGithubAppInstallation(token);
    }
  }, [token, checkGithubAppInstallation]);

  return {
    hasGithubApp,
  };
};

import { useState, useEffect, useCallback } from "react";

import { useAuth } from "@/contexts/AuthContext";
import { getAllowedRepositories } from "@/services/api";
import { useUserDataStore } from "@/store/userDataStore";

export const useAllowedRepositories = () => {
  const { user } = useAuth();
  const { allowedRepositories, setAllowedRepositories } = useUserDataStore();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchRepositories = useCallback(async () => {
    if (!user) return;

    try {
      setLoading(true);
      const data = await getAllowedRepositories(user.username);
      setAllowedRepositories(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch repositories");
    } finally {
      setLoading(false);
    }
  }, [user, setAllowedRepositories]);

  useEffect(() => {
    fetchRepositories();
  }, [fetchRepositories]);

  return { allowedRepositories, loading, error };
};

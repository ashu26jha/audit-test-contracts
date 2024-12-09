import { useState, useEffect } from "react";

import { useAuth } from "@/contexts/AuthContext";
import { getAllowedRepositories } from "@/services/api";

export const useAllowedRepositories = () => {
  const { user } = useAuth();
  const [allowedRepositories, setAllowedRepositories] = useState<Repository[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchRepositories = async () => {
      if (!user?.username) return;

      try {
        setLoading(true);
        const data = await getAllowedRepositories(user.username);
        setAllowedRepositories(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to fetch repositories");
      } finally {
        setLoading(false);
      }
    };

    fetchRepositories();
  }, [user]);

  return { allowedRepositories, loading, error };
};

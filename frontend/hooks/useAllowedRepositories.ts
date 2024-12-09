import { useState, useEffect } from "react";

import { useAuth } from "@/contexts/AuthContext";
import { getAllowedRepositories } from "@/services/api";

export const useAllowedRepositories = () => {
  const { token, user } = useAuth();
  const [repositories, setRepositories] = useState<Repository[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchRepositories = async () => {
      if (!token || !user?.username) return;

      try {
        setLoading(true);
        const data = await getAllowedRepositories(token, user.username);
        setRepositories(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to fetch repositories");
      } finally {
        setLoading(false);
      }
    };

    fetchRepositories();
  }, [token, user]);

  return { repositories, loading, error };
};

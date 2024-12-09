import { useState, useEffect, useCallback } from "react";

import { useAuth } from "@/contexts/AuthContext";
import { getRepoInfo } from "@/services/api";

interface GitHubRepoResponse {
  repo_full_name: string;
  repo_name: string;
  repo_url: string;
}

const useFetchGithubRepoInfo = (repoUrl: string) => {
  const { user } = useAuth();
  const [repoInfo, setRepoInfo] = useState<GitHubRepoResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchRepoInfo = useCallback(
    async (repoUrl: string) => {
      if (!user) {
        setError("No user found");
        setLoading(false);
        return;
      }
      try {
        setLoading(true);
        const response = await getRepoInfo(repoUrl);
        setRepoInfo(response);
      } catch (err) {
        setError((err as Error).message ?? String(err));
      } finally {
        setLoading(false);
      }
    },
    [user],
  );

  useEffect(() => {
    if (repoUrl) {
      fetchRepoInfo(repoUrl);
    }
  }, [repoUrl, fetchRepoInfo]);

  return { repoInfo, loading, error };
};

export default useFetchGithubRepoInfo;

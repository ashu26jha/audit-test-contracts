import { useState, useEffect, useCallback } from "react";
import { useAuth } from "@/contexts/AuthContext";
import { getRepoInfo } from "@/services/api";

interface GitHubRepoResponse {
  repo_full_name: string;
  repo_name: string;
  repo_url: string;
}

// To use: const { repoInfo, loading, error } = useFetchGithubRepoInfo({ repoUrl: "" });
const useFetchGithubRepoInfo = (repoUrl: string) => {
  const { token } = useAuth();
  const [repoInfo, setRepoInfo] = useState<GitHubRepoResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchRepoInfo = useCallback(
    async (repoUrl: string) => {
      if (!token) {
        setError("No token found");
        setLoading(false);
        return;
      }
      try {
        setLoading(true);
        const response = await getRepoInfo(token, repoUrl);
        setRepoInfo(response);
      } catch (err) {
        setError((err as Error).message ?? String(err));
      } finally {
        setLoading(false);
      }
    },
    [token],
  );

  useEffect(() => {
    if (repoUrl) {
      fetchRepoInfo(repoUrl);
    }
  }, [repoUrl, fetchRepoInfo]);

  return { repoInfo, loading, error };
};

export default useFetchGithubRepoInfo;

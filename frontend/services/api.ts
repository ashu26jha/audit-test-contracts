import axios from "axios";

import { SERVICES } from "@/config/constants";

const api = axios.create({
  baseURL: SERVICES.API_URL,
  headers: {
    "Content-Type": "application/json",
  },
});

export const initiateGithubLogin = () => {
  if (typeof window !== "undefined") {
    window.location.href = `${SERVICES.API_URL}/api/v1/auth/github-login`;
  }
};

export const getUser = async (token: string) => {
  const response = await api.get("/api/v1/auth/me", {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
  return response.data;
};

export const getOrganizationsAndPersonal = async (token: string) => {
  const response = await api.get("/api/v1/github/organizations", {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
  return response.data.data;
};

export const getRepositories = async (token: string, owner: string, ownerType: string) => {
  const response = await api.get(`/api/v1/github/repositories/${owner}?owner_type=${ownerType}`, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
  return response.data.data;
};

export const getBranches = async (token: string, owner: string, repo: string) => {
  const response = await api.get(`/api/v1/github/repository-branches/${owner}/${repo}`, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
  return response.data.data;
};

export const getRepositoryContents = async (
  token: string,
  owner: string,
  repo: string,
  branch: string,
  path: string = "",
) => {
  const response = await api.get(`/api/v1/github/repository-contents/${owner}/${repo}?branch=${branch}&path=${path}`, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
  return response.data.data;
};

export const initiateScan = async (
  token: string,
  data: {
    repositoryURL: string;
    contractFiles: string[];
    branchName: string;
  },
) => {
  const response = await api.post("/api/v1/audit-agent", data, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
  return response.data;
};

export const getPartialScanResults = async (token: string, scanId: string) => {
  const response = await api.get(`/api/v1/scans/partial/${scanId}`, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
  const result = response.data.data.partial_result;
  const scan = response.data.data.scan;
  result.scan = scan;
  return result;
};

export const getFullScanResults = async (token: string, scanId: string) => {
  const response = await api.get(`/api/v1/scans/full/${scanId}`, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
  const result = response.data.data.result;
  const scan = response.data.data.scan;
  result.scan = scan;
  // Sort the findings by severity
  const severityOrder = ["Critical", "High", "Medium", "Low", "Info", "Best Practices"];
  result.findings.sort((a: Finding, b: Finding) => {
    return severityOrder.indexOf(a.Severity) - severityOrder.indexOf(b.Severity);
  });
  return result;
};

export const getScanHistory = async (token: string) => {
  const response = await api.get("/api/v1/scans-history", {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
  return response.data.data;
};

export const getRepoInfo = async (token: string, repoUrl: string) => {
  const response = await api.get(`/api/v1/github/validate-repo-url`, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
    params: {
      repo_url: repoUrl,
    },
  });
  return response.data.data;
};

export const createCheckoutSession = async (token: string, scanId: string) => {
  const response = await api.post(
    "/api/v1/payments/create-stripe-session",
    { scanId },
    {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    },
  );
  return response.data;
};

export const sendPdfReport = async (token: string, scanId: string) => {
  try {
    const response = await api.get(`/api/v1/generate-pdf/${scanId}`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
    return response.data;
  } catch (error) {
    if (axios.isAxiosError(error) && error.response) {
      if (error.response.status === 429) {
        return {
          success: false,
          message: "You have to wait a minute before you can generate a new report. Please try again later.",
        };
      }
    }
    return { success: false, message: (error as Error).message };
  }
};

export default api;

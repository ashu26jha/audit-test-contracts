import axios from "axios";

import { SERVICES } from "@/config/constants";

// For direct backend calls
const api = axios.create({
  baseURL: SERVICES.API_URL,
  headers: {
    "Content-Type": "application/json",
  },
  withCredentials: true,
});

export const initiateGithubLogin = () => {
  if (typeof window !== "undefined") {
    window.location.href = `${SERVICES.API_URL}/api/v1/auth/github-login`;
  }
};

export const getUser = async () => {
  const response = await api.get("/api/v1/auth/me");
  return response.data.data;
};

export const logUserOut = async () => {
  const response = await api.post("/api/v1/auth/logout", {});
  return response.data.data;
};

export const getOrganizationsAndPersonal = async () => {
  const response = await api.get("/api/v1/github/organizations");
  return response.data.data;
};

export const validateRepository = async (repoUrl: string) => {
  const response = await api.get("/api/v1/github/validate-repository", {
    params: { repo_url: repoUrl },
  });
  return response.data;
};

export const getAllowedRepositories = async (owner: string) => {
  const response = await api.get(`/api/v1/github/repositories/${owner}`);
  return response.data.data;
};

export const getRepositories = async (owner: string, ownerType: string) => {
  const response = await api.get(`/api/v1/github/repositories/${owner}?owner_type=${ownerType}`);
  return response.data.data;
};

export const getBranches = async (owner: string, repo: string) => {
  const response = await api.get(`/api/v1/github/repository-branches/${owner}/${repo}`);
  return response.data.data;
};

export const getRepositoryContents = async (owner: string, repo: string, branch: string, path: string = "") => {
  const response = await api.get(`/api/v1/github/repository-contents/${owner}/${repo}?branch=${branch}&path=${path}`);
  return response.data.data;
};

export const getReadmeFiles = async (owner: string, repo: string, branch: string, path: string = "") => {
  const response = await api.get(`/api/v1/github/repository-readme/${owner}/${repo}?branch=${branch}&path=${path}`);
  return response.data.data;
};

export const getRepositoryDocs = async (owner: string, repo: string): Promise<DocsResponse> => {
  const response = await api.get(`/api/v1/github/repository-docs/${owner}/${repo}`);
  return response.data.data;
};

export const getPartialScanResults = async (scanId: string) => {
  const response = await api.get(`/api/v1/scans/partial/${scanId}`);
  const result = response.data.data.partial_result;
  const scan = response.data.data.scan;
  result.scan = scan;
  return result;
};

export const getScanHistory = async () => {
  const response = await api.get("/api/v1/scans/history");
  return response.data.data;
};

// STRIPE ROUTES //

export const createCheckoutSession = async (scanId: string): Promise<StripeCheckoutResponse> => {
  const response = await api.post("/api/v1/payments/create-stripe-session", { scanId });
  return response.data;
};

export const createSubscriptionSession = async (scanId?: string): Promise<StripeCheckoutResponse> => {
  const response = await api.post("/api/v1/payments/create-subscription-session", { scanId });
  return response.data;
};

export const createPortalSession = async () => {
  const response = await api.post("/api/v1/payments/create-portal-session");
  return response.data.data;
};

// PROTECTED ROUTES //

export const initiateScan = async (data: InitiateScanRequest) => {
  const response = await axios.post("/api/launchScan", data, {
    withCredentials: true,
  });
  return response.data;
};

export const getFullScanResults = async (scanId: string) => {
  const response = await axios.get(`/api/getFullScanResults`, {
    params: { scanId },
    withCredentials: true,
  });
  return response.data;
};

export const sendPdfReport = async (scanId: string) => {
  try {
    const response = await axios.get(`/api/sendReport`, {
      params: { scanId },
      withCredentials: true,
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

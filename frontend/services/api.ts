import axios from 'axios';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const initiateGithubLogin = () => {
  console.log('initiateGithubLogin', `${API_URL}/api/v1/auth/github-login`);
  window.location.href = `${API_URL}/api/v1/auth/github-login`;
};

export const getUser = async (token: string) => {
  console.log('token', `${token}`);
  const response = await api.get('/api/v1/auth/me', {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
  console.log('getUser', response.data);
  return response.data;
};

export const getOrganizationsAndPersonal = async (token: string) => {
  const response = await api.get('/api/v1/github/organizations', {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
  return response.data.data;
};

export const getRepositories = async (
  token: string,
  owner: string,
  ownerType: string
) => {
  const response = await api.get(
    `/api/v1/github/repositories/${owner}?owner_type=${ownerType}`,
    {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    }
  );
  console.log('getRepositories', response.data);
  return response.data.data;
};

export const getBranches = async (
  token: string,
  owner: string,
  repo: string
) => {
  const response = await api.get(
    `/api/v1/github/repository-branches/${owner}/${repo}`,
    {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    }
  );
  return response.data.data;
};

export const getRepositoryContents = async (
  token: string,
  owner: string,
  repo: string,
  branch: string,
  path: string = ''
) => {
  const response = await api.get(
    `/api/v1/github/repository-contents/${owner}/${repo}?branch=${branch}&path=${path}`,
    {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    }
  );
  return response.data.data;
};

export const initiateScan = async (
  token: string,
  data: {
    repositoryURL: string;
    contractFiles: string[];
  }
) => {
  const response = await api.post('/api/v1/audit-agent', data, {
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

export const getScanHistory = async (token: string) => {
  const response = await api.get('/api/v1/scans-history', {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
  return response.data.data;
};


export const getRepoInfo = async (token: string, repoUrl: string,) => {
  const response = await api.get(`/api/v1/github/repository-info`, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
    params: {
      repo_url: repoUrl,
    },
  });
  return response.data.data;
};

export default api;

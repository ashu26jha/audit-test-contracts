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
  return response.data;
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
  return response.data;
};

export const getRepositoryContents = async (
  token: string,
  owner: string,
  repo: string,
  path: string = ''
) => {
  const response = await api.get(
    `/api/v1/github/repository-contents/${owner}/${repo}?path=${path}`,
    {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    }
  );
  console.log('getRepositoryContents', response.data);
  return response.data;
};

export default api;

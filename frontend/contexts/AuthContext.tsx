"use client";
import React, { createContext, useState, useContext, useEffect, useCallback } from "react";

import { getUser } from "../services/api";

interface User {
  id: string;
  githubId: string;
  name: string;
  username: string;
  email: string;
  avatarUrl: string;
}

interface AuthContextType {
  user: User | null;
  token: string | null;
  loading: boolean;
  setToken: (token: string | null) => void;
  logout: () => void;
  isPublicRoute: (pathname: string) => boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [token, setToken] = useState<string | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchUser = useCallback(async (authToken: string) => {
    try {
      const userData = await getUser(authToken);
      setUser(userData);
    } catch (error) {
      console.error("Failed to fetch user data:", error);
      setToken(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const storedToken = localStorage.getItem("token");
    if (storedToken) {
      setToken(storedToken);
      (async () => {
        await fetchUser(storedToken);
      })();
    } else {
      setLoading(false);
    }
  }, [fetchUser]);

  useEffect(() => {
    if (token) {
      localStorage.setItem("token", token);
      setLoading(true);
      (async () => {
        await fetchUser(token);
      })();
    } else {
      localStorage.removeItem("token");
      setUser(null);
      setLoading(false);
    }
  }, [token, fetchUser]);

  const logout = useCallback(() => {
    setToken(null);
    setUser(null);
    localStorage.removeItem("token");
  }, []);

  const isPublicRoute = useCallback((pathname: string): boolean => {
    const publicRoutes = ["/login", "/payment-result", "/login-success"];
    return (
      publicRoutes.includes(pathname) ||
      pathname.startsWith("/scan-results/") ||
      /^\/scan-results\/[^/]+$/.test(pathname)
    );
  }, []);

  const value = {
    user,
    token,
    loading,
    setToken,
    logout,
    isPublicRoute,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
};

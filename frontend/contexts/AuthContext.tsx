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

const AuthContext = createContext<AuthContextType>({
  user: null,
  token: null,
  loading: true,
  setToken: () => {},
  logout: () => {},
  isPublicRoute: () => false,
});

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
      setUser(null);
      localStorage.removeItem("token");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    try {
      if (token) {
        localStorage.setItem("token", token);
        setLoading(true);
        fetchUser(token);
      } else {
        const storedToken = localStorage.getItem("token");
        if (storedToken) {
          setToken(storedToken);
          setLoading(true);
          fetchUser(storedToken);
        } else {
          localStorage.removeItem("token");
          setUser(null);
          setLoading(false);
        }
      }
    } catch (error) {
      console.error("Auth state error:", error);
      setToken(null);
      setUser(null);
      setLoading(false);
      localStorage.removeItem("token");
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

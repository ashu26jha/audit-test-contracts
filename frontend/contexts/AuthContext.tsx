"use client";
import React, { createContext, useState, useContext, useEffect, useCallback, useMemo } from "react";

import { useRouter, usePathname } from "next/navigation";

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
  const router = useRouter();
  const pathname = usePathname();

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

  const isPublicRoute = useCallback((pathname: string): boolean => {
    const publicRoutes = ["/login", "/payment-result", "/login-success"];
    return (
      publicRoutes.includes(pathname) ||
      pathname.startsWith("/scan-results/") ||
      /^\/scan-results\/[^/]+$/.test(pathname)
    );
  }, []);

  const logout = useCallback(() => {
    setToken(null);
    setUser(null);
    localStorage.removeItem("token");
    router.push("/login");
  }, [router]);

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

  useEffect(() => {
    if (!loading) {
      if (user && (pathname === "/" || pathname === "/login")) {
        router.push("/dashboard");
      }
      if (!user && !isPublicRoute(pathname)) {
        logout();
      }
    }
  }, [user, loading, pathname, router, isPublicRoute, logout]);

  const value = useMemo(
    () => ({
      user,
      token,
      loading,
      setToken,
      logout,
      isPublicRoute,
    }),
    [user, token, loading, setToken, logout, isPublicRoute],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
};

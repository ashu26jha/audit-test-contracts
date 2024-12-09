"use client";
import React, { createContext, useState, useContext, useEffect, useCallback, useMemo, memo } from "react";

import { useRouter, usePathname } from "next/navigation";

import { Loading } from "@/components/Loading";
import { getUser, logUserOut } from "@/services/api";

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
  loading: boolean;
  error: string | null;
  setError: (error: string | null) => void;
  isPublicRoute: (pathname: string) => boolean;
  logout: (url?: string) => Promise<void>;
}

const AuthContext = createContext<AuthContextType | null>(null);

interface ProtectedRouteProps {
  children: React.ReactNode;
}

const PUBLIC_ROUTES = ["/login", "/payment-result", "/login-success"] as const;
const SCAN_RESULTS_PATTERN = /^\/scan-results\/[^/]+$/;

export const ProtectedRoute = memo<ProtectedRouteProps>(({ children }) => {
  const { loading, user, isPublicRoute } = useAuth();
  const pathname = usePathname();
  const router = useRouter();

  useEffect(() => {
    if (!loading && !user && !isPublicRoute(pathname)) {
      router.replace("/login");
    }
  }, [loading, user, isPublicRoute, pathname, router]);

  if (loading) return <Loading />;
  if (!user && !isPublicRoute(pathname)) return null;
  return <>{children}</>;
});

ProtectedRoute.displayName = "ProtectedRoute";

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const router = useRouter();
  const pathname = usePathname();
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const isPublicRoute = useCallback((pathname: string): boolean => {
    return (
      PUBLIC_ROUTES.includes(pathname as (typeof PUBLIC_ROUTES)[number]) ||
      pathname.startsWith("/scan-results/") ||
      SCAN_RESULTS_PATTERN.test(pathname)
    );
  }, []);

  const logout = useCallback(
    async (url: string = "/login") => {
      setLoading(true);
      try {
        setUser(null);
        localStorage.removeItem("token");
        router.push(url);
        await logUserOut();
      } catch (error) {
        console.error("Logout failed:", error);
        setError("Logout failed. Please try again.");
      } finally {
        setLoading(false);
      }
    },
    [router, setError],
  );

  useEffect(() => {
    let isActive = true;

    const sync = async () => {
      setLoading(true);
      setError(null);

      try {
        const userData = await getUser();
        if (!isActive) return;

        if (!userData) {
          throw new Error("No user data received");
        }

        setUser(userData);

        // Check for legacy auth
        const hasLegacyToken = Boolean(localStorage.getItem("token"));

        if (hasLegacyToken) {
          await logout();
          router.push("/login?migrate=true");
        }
      } catch (error) {
        if (!isActive) return;
        console.error("Auth error:", error);
        setError("Authentication failed. Please try again.");
        await logout("/login?error=auth_failed");
      } finally {
        if (isActive) {
          setLoading(false);
        }
      }
    };

    sync();

    return () => {
      isActive = false;
    };
  }, [logout, router]);

  useEffect(() => {
    if (!loading) {
      const handleRouting = async () => {
        if (user && (pathname === "/" || pathname === "/login")) {
          router.push("/dashboard");
        }
      };
      handleRouting();
    }
  }, [user, loading, pathname, router]);

  const value = useMemo<AuthContextType>(
    () => ({
      user,
      loading,
      error,
      setError,
      isPublicRoute,
      logout,
    }),
    [user, loading, error, setError, isPublicRoute, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
};

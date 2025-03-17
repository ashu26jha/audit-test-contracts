"use client";
import { type FC, createContext, useState, useContext, useEffect, useCallback, useMemo } from "react";

import type { AxiosError } from "axios";
import { useRouter, usePathname } from "next/navigation";

import { getUser, logUserOut, initiateGithubLogin } from "@/services/api";

interface AuthContextType {
  user: User | null;
  loading: boolean;
  error: string | null;
  setError: (error: string | null) => void;
  isPublicRoute: (pathname: string) => boolean;
  logout: (url?: string) => Promise<void>;
  refetchUser: () => Promise<void>;
  login: () => void;
  loginLoading: boolean;
}

const AuthContext = createContext<AuthContextType | null>(null);

const PUBLIC_ROUTES = ["/login", "/payment-result", "/login-success"] as const;
const SCAN_RESULTS_PATTERN = /^\/scan-results\/[^/]+$/;

export const AuthProvider: FC<{ children: React.ReactNode }> = ({ children }) => {
  const router = useRouter();
  const pathname = usePathname();
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [loginLoading, setLoginLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isPublicRoute = useCallback((pathname: string): boolean => {
    return (
      PUBLIC_ROUTES.includes(pathname as (typeof PUBLIC_ROUTES)[number]) ||
      pathname.startsWith("/scan-results/") ||
      SCAN_RESULTS_PATTERN.test(pathname)
    );
  }, []);

  // Reset authentication state when returning to login page
  useEffect(() => {
    if (pathname === "/login" && !pathname.includes("login-success")) {
      setLoginLoading(false);
    }

    // If we're on login-success page, we know the auth flow completed successfully
    if (pathname === "/login-success") {
      setLoginLoading(false);
    }
  }, [pathname]);

  const login = useCallback(() => {
    setLoginLoading(true);
    initiateGithubLogin();
  }, []);

  const logout = useCallback(
    async (url: string = "/login") => {
      setLoading(true);
      try {
        setUser(null);
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

  const refetchUser = useCallback(async () => {
    const userData = await getUser();
    setUser(userData);
  }, [setUser]);

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
      } catch (error) {
        if (!isActive) return;

        // Check if the session is expired (401)
        if ((error as AxiosError)?.status === 401) {
          setError("Session expired. Please login again.");
          await logout("/login?error=session_expired");
        } else {
          // For other errors, just set user to null without error message
          // This handles the case of a user with no session yet
          setUser(null);
        }
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
        if (user && pathname === "/login") {
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
      loginLoading,
      error,
      refetchUser,
      setError,
      isPublicRoute,
      logout,
      login,
    }),
    [user, loading, loginLoading, error, refetchUser, setError, isPublicRoute, logout, login],
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

"use client";
import { type FC, createContext, useState, useContext, useEffect, useCallback, useMemo } from "react";

import { useRouter, usePathname } from "next/navigation";

import { getUser, logUserOut } from "@/services/api";

interface AuthContextType {
  user: User | null;
  loading: boolean;
  error: string | null;
  setError: (error: string | null) => void;
  isPublicRoute: (pathname: string) => boolean;
  logout: (url?: string) => Promise<void>;
}

const AuthContext = createContext<AuthContextType | null>(null);

const PUBLIC_ROUTES = ["/login", "/payment-result", "/login-success"] as const;
const SCAN_RESULTS_PATTERN = /^\/scan-results\/[^/]+$/;

export const AuthProvider: FC<{ children: React.ReactNode }> = ({ children }) => {
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

        {
          /* TODO: Remove this when subscriptions backend is done */
        }
        const subscriptionData = {
          isActive: true,
          type: "pro",
          credits: 12,
          monthlyCredits: 10,
          expiresAt: "2024-02-20T15:30:00Z",
        };

        {
          /* TODO: Remove this when subscriptions backend is done */
        }
        userData.subscription = subscriptionData;

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

"use client";

import { type FC, useEffect, memo } from "react";

import { useRouter, usePathname } from "next/navigation";

import { Loading } from "@/components/layout";
import { useAuth } from "@/contexts/AuthContext";

interface ProtectedRouteProps {
  readonly children: React.ReactNode;
}

const ProtectedRoute: FC<ProtectedRouteProps> = ({ children }) => {
  const { loading, user, isPublicRoute } = useAuth();
  const pathname = usePathname();
  const router = useRouter();

  useEffect(() => {
    if (!loading && !user && !isPublicRoute(pathname)) {
      router.replace("/login");
    }
  }, [loading, user, isPublicRoute, pathname, router]);

  if (loading) {
    return <Loading />;
  }

  if (!user && !isPublicRoute(pathname)) {
    return null;
  }

  return children;
};

ProtectedRoute.displayName = "ProtectedRoute";

export default memo(ProtectedRoute);

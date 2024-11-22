"use client";
import { useEffect } from "react";

import { useRouter, usePathname } from "next/navigation";

import { Loading } from "@/components/Loading";

import { useAuth } from "../contexts/AuthContext";

export default function Home() {
  const { user, loading, isPublicRoute } = useAuth();
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    if (!loading) {
      if (user && pathname === "/") {
        router.push("/dashboard");
      } else if (!user && !isPublicRoute(pathname) && pathname !== "/") {
        router.push("/login");
      }
    }
  }, [user, loading, router, pathname, isPublicRoute]);

  if (loading) {
    return <Loading />;
  }

  return null;
}

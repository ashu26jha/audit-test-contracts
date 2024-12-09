"use client";

import { useEffect } from "react";

import { useRouter } from "next/navigation";

import { Loading } from "@/components/layout";
import { useAuth } from "@/contexts/AuthContext";

const LoginSuccessPage = () => {
  const router = useRouter();
  const { user, loading, error } = useAuth();

  useEffect(() => {
    const redirectTimer = setTimeout(() => {
      if (!loading && !user && !error) {
        router.push("/login?error=timeout");
      }
    }, 10000); // 10 second timeout

    if (error) {
      router.push("/login?error=auth_failed");
    } else if (!loading && user) {
      router.replace("/dashboard");
    }

    return () => clearTimeout(redirectTimer);
  }, [error, router, loading, user]);

  if (loading) {
    return <Loading />;
  }

  return null;
};

export default LoginSuccessPage;

"use client";

import { useEffect } from "react";

import { useRouter, useSearchParams } from "next/navigation";

import { useAuth } from "@/contexts/AuthContext";

const LoginSuccessPage = () => {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { setToken, user, loading, logout } = useAuth();

  const token = searchParams.get("token");

  useEffect(() => {
    if (!token) {
      logout();
      return;
    }

    setToken(token);

    if (!loading && user) {
      router.replace("/dashboard");
    }
  }, [token, router, setToken, loading, user, logout]);

  return null;
};

export default LoginSuccessPage;

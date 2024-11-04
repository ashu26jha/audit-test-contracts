"use client";

import { useEffect } from "react";

import { useRouter, useSearchParams } from "next/navigation";

import { useAuth } from "../../contexts/AuthContext";

const LoginSuccessPage = () => {
  const router = useRouter();
  const searchParams = useSearchParams();
  const token = searchParams.get("token");

  const { setToken, user, loading } = useAuth();

  useEffect(() => {
    if (!token) {
      console.error("No token found in URL");
      router.push("/login");
      return;
    }

    setToken(token);

    if (!loading && user) {
      router.replace("/dashboard");
    }
  }, [token, router, setToken, loading, user]);

  return null;
};

export default LoginSuccessPage;

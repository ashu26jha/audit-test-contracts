"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useSearchParams } from "next/navigation";
import { useAuth } from "../../contexts/AuthContext";

const LoginSuccessPage = () => {
  const router = useRouter();
  const searchParams = useSearchParams();
  const token = searchParams.get("token");

  const { setToken } = useAuth();

  useEffect(() => {
    if (token) {
      if (typeof token === "string") {
        setToken(token);
        router.push("/dashboard");
      } else {
        console.error("No token found in URL");
        router.push("/login");
      }
    }
  }, [token, router, setToken]);

  return <div>Processing login...</div>;
};

export default LoginSuccessPage;

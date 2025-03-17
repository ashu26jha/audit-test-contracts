"use client";

import { useEffect, type FC } from "react";

import { Button, Card, CardBody, Image } from "@nextui-org/react";
import { useRouter, usePathname, useSearchParams } from "next/navigation";

import { Loading } from "@/components/layout";
import { useAuth } from "@/contexts/AuthContext";

const LoginView: FC = () => {
  const { user, loading, loginLoading, error, setError, login } = useAuth();
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const urlError = searchParams.get("error");

  useEffect(() => {
    if (urlError) {
      setError(null);
    }
  }, [urlError, setError]);

  useEffect(() => {
    if (!loading) {
      if (user && pathname === "/login") {
        router.push("/dashboard");
      }
    }
  }, [user, loading, router, pathname]);

  if (loading) {
    return <Loading />;
  }

  if (user) {
    return null;
  }

  const getErrorMessage = () => {
    if (urlError === "no_token") return "Login failed. Please try again.";
    if (urlError === "timeout") return "Login timed out. Please try again.";
    if (urlError === "auth_failed") return "Authentication failed. Please try again.";
    if (urlError === "session_expired") return "Session expired. Please login again.";
    return error;
  };

  return (
    <div className="absolute inset-0 flex items-center justify-center">
      <Card className="max-w-[420px] p-5">
        <CardBody className="py-10">
          <div className="flex flex-col items-center">
            <Image src="/svg/nethermind_logo.svg" alt="AuditAgent Logo" width={100} height={100} className="mb-5" />
            <p className="text-sm text-center mb-5">Login to Explore</p>
            <p className="text-sm text-center mb-5">Please continue with your GitHub account</p>
            <Button
              color="secondary"
              startContent={<Image src="/svg/github.svg" alt="GitHub" width={20} height={20} />}
              onPress={login}
              isLoading={loginLoading}
              isDisabled={loginLoading}
            >
              {loginLoading ? "Redirecting..." : "Continue with GitHub"}
            </Button>
            {getErrorMessage() && <p className="text-red-500 mt-4 text-center text-sm">{getErrorMessage()}</p>}
          </div>
        </CardBody>
      </Card>
    </div>
  );
};

export default LoginView;

"use client";

import { useEffect } from "react";

import { Button, Card, CardBody, Image } from "@nextui-org/react";
import { useRouter, usePathname } from "next/navigation";

import { Loading } from "@/components/Loading";

import { useAuth } from "../../contexts/AuthContext";
import { initiateGithubLogin } from "../../services/api";

const LoginPage = () => {
  const { user, loading } = useAuth();
  const router = useRouter();
  const pathname = usePathname();

  console.log("NEXT_PUBLIC_API_URL", process.env.NEXT_PUBLIC_API_URL);
  console.log("NEXT_PUBLIC_GITHUB_APP_URL", process.env.NEXT_PUBLIC_GITHUB_APP_URL);

  useEffect(() => {
    if (!loading && user && pathname === "/login") {
      router.push("/dashboard");
    }
  }, [user, loading, router, pathname]);

  if (loading) {
    return <Loading />;
  }

  if (user) {
    return null;
  }

  return (
    <div className="flex items-center justify-center h-[calc(100%-6rem)]">
      <Card className="max-w-[420px] p-5">
        <CardBody className="py-10">
          <div className="flex flex-col items-center">
            <Image src="/nethermind_logo.svg" alt="AuditAgent Logo" width={100} height={100} className="mb-5" />
            <p className="text-sm text-center mb-5">Login to Explore</p>
            <p className="text-sm text-center mb-5">Please continue with your GitHub account</p>
            <Button
              color="secondary"
              startContent={<Image src="/github.svg" alt="GitHub" width={20} height={20} />}
              onPress={initiateGithubLogin}
            >
              Continue with GitHub
            </Button>
          </div>
        </CardBody>
      </Card>
    </div>
  );
};

export default LoginPage;

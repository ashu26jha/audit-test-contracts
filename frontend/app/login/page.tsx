"use client";

import { Button, Card, CardBody, Image } from "@nextui-org/react";
import { initiateGithubLogin } from "../../services/api";
import { useAuth } from "../../contexts/AuthContext";
import { useRouter, usePathname } from "next/navigation";
import { useEffect } from "react";
import { Loading } from "@/components/Loading";

const LoginPage = () => {
  const { user, loading, isPublicRoute } = useAuth();
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    if (!loading && user && pathname !== "/payment-result") {
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
    <div className="flex items-center justify-center">
      <Card className="max-w-[420px] p-5">
        <CardBody className="py-10">
          <div className="flex flex-col items-center">
            <Image src="/nethermind_logo.svg" alt="Audit Agent Logo" width={100} height={100} className="mb-5" />
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

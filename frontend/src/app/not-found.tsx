"use client";

import { type FC } from "react";

import { Button, Card, CardBody, CardHeader, Divider } from "@nextui-org/react";
import Image from "next/image";
import { useRouter } from "next/navigation";

import { Loading } from "@/components/layout";
import { useAuth } from "@/contexts/AuthContext";

const NotFoundPage: FC = () => {
  const router = useRouter();
  const { user, loading } = useAuth();

  if (loading) {
    return <Loading />;
  }

  if (!user) {
    router.push("/login");
  }

  return (
    <Card className="h-full">
      <CardHeader>
        <div className="flex justify-between items-center mb-1 ml-4 mr-4 w-full">
          <h2 className="text-l font-light">404 - Page Not Found</h2>
          <Button color="secondary" className="bg-[#8B5CF6] text-white" onPress={() => router.push("/dashboard")}>
            Go to Dashboard
          </Button>
        </div>
      </CardHeader>
      <Divider />

      <CardBody className="overflow-y-auto">
        <div className="flex flex-col items-center justify-center h-[60vh]">
          <Image src="/svg/404-icon.svg" alt="404 Not Found" width={100} height={100} />
          <h3 className="text-xl my-4">Oops! Page Not Found</h3>
          <p className="text-gray-400 text-center">
            The page you&apos;re looking for doesn&apos;t exist or has been moved.
            <br />
            Please check the URL or return to the dashboard.
          </p>
        </div>
      </CardBody>
    </Card>
  );
};

export default NotFoundPage;

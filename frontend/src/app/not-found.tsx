"use client";

import { type FC } from "react";

import { Button } from "@nextui-org/react";
import Image from "next/image";
import { useRouter } from "next/navigation";

import { Container, Loading } from "@/components/layout";
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

  const breadcrumbItems = [
    { label: "Home", href: "/dashboard" },
    { label: "404 Not Found", href: "#" },
  ];

  const actionButton = (
    <Button color="secondary" className="bg-[#8B5CF6] text-white" onPress={() => router.push("/dashboard")}>
      Go to Dashboard
    </Button>
  );

  return (
    <Container breadcrumbItems={breadcrumbItems} buttons={actionButton}>
      <div className="flex flex-col items-center justify-center h-[65vh]">
        <Image src="/svg/404-icon.svg" alt="404 Not Found" width={120} height={120} className="mb-6" />
        <h3 className="text-xl my-4">Oops! Page Not Found</h3>
        <p className="text-gray-400 text-center">
          The page you&apos;re looking for doesn&apos;t exist or has been moved.
          <br />
          Please check the URL or return to the dashboard.
        </p>
      </div>
    </Container>
  );
};

export default NotFoundPage;

"use client";
import { useAuth } from "../../contexts/AuthContext";
import React from "react";
import Image from "next/image";
import { Card, CardBody, CardHeader, Divider, Input, Button, Avatar } from "@nextui-org/react";
import { LogOut } from "lucide-react";
import { useRouter } from "next/navigation";

const ProfilePage: React.FC = () => {
  const router = useRouter();

  const { user, logout } = useAuth();

  if (!user) {
    router.push("/login");
    return null;
  }

  const { email, username, name, avatarUrl } = user;

  const handleLogout = () => {
    logout();
    router.push("/login");
  };

  return (
    <Card className="h-full">
      <CardHeader>
        <div className="flex justify-between items-center mb-1 ml-4 mr-4 w-full">
          <div className="text-sm text-gray-400 flex">
            Dashboard <div className="mx-2">/</div> <div className="text-white">Profile</div>
          </div>
          <Button
            variant="light"
            onPress={() => router.back()}
            className="bg-[#27272a] border border-[#3F3F46] rounded-lg"
          >
            Go Back
          </Button>
        </div>
      </CardHeader>
      <Divider />

      <CardBody className="flex flex-col items-center gap-6 pb-8">
        <div className="w-1/3">
          <div className="w-full flex justify-center">
            <Avatar src={avatarUrl} size="sm" className="w-20 h-20 text-large rounded-md mt-8" />
          </div>
          {name && (
            <div className="flex flex-col">
              {" "}
              {/* Added white border */}
              <div className="text-sm text-gray-400 mt-8">Name</div>
              <div className="text-md mt-1 border border-[#3F3F46] p-2 rounded-md">{name}</div>
            </div>
          )}
          <div className="flex flex-col mt-8 ">
            {" "}
            {/* Added white border */}
            <div className="text-sm text-gray-400">Email</div>
            <div className="text-md mt-1 border border-[#3F3F46] p-2 rounded-md">{email}</div>
          </div>

          <div className="flex flex-col mt-8">
            <div className="text-sm text-gray-400 ">GitHub Username</div>
            <div className="flex w-full justify-between">
              <div className="flex items-center text-md mt-1 border border-[#3F3F46] p-2 rounded-md w-full">
                {username}
                <Image src="/github.svg" alt="GitHub" width={20} height={20} className="ml-auto" />
              </div>
            </div>
          </div>

          <Button
            variant="flat"
            startContent={<LogOut size={14} />}
            className="w-full mt-8 hover:bg-[#F3126033] hover:text-danger text-white"
            onClick={handleLogout}
          >
            Log Out
          </Button>
        </div>
      </CardBody>
    </Card>
  );
};

export default ProfilePage;

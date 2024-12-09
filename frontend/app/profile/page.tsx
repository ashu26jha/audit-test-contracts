"use client";
import { type FC, useState } from "react";

import { Divider, Button, Avatar } from "@nextui-org/react";
import { LogOut } from "lucide-react";
import Image from "next/image";

import AllowedRepositories from "@/components/AllowedRepositories";
import Breadcrumb from "@/components/shared/Breadcrumb";
import SubscriptionCard from "@/components/SubscriptionCard";
import { useAuth } from "@/contexts/AuthContext";

const ProfilePage: FC = () => {
  const { user, logout } = useAuth();
  const [selectedTab, setSelectedTab] = useState("details");

  if (!user) return null;

  const { email, username, name, avatarUrl } = user;

  const renderUserDetails = () => {
    return (
      <div className="w-1/3">
        <div className="w-full flex-col">
          <div className="text-sm font-normal text-[#A1A1AA] mt-8">Profile Picture</div>
          <Avatar src={avatarUrl} size="sm" className="w-20 h-20 text-large rounded-md mt-2" />
        </div>
        {name && (
          <div className="flex flex-col">
            {" "}
            {/* Added white border */}
            <div className="text-sm font-normal text-[#A1A1AA] mt-8">Name</div>
            <div className="text-medium text-[#A1A1AA] mt-1 border border-[#27272A] p-2 px-4 rounded-2xl bg-[#18181B]">
              {name}
            </div>
          </div>
        )}
        <div className="flex flex-col mt-8 ">
          {" "}
          {/* Added white border */}
          <div className="text-sm font-normal text-[#A1A1AA]">Email</div>
          <div className="text-medium text-[#A1A1AA] mt-1 border border-[#27272A] p-2 px-4 rounded-2xl bg-[#18181B]">
            {email}
          </div>
        </div>

        <div className="flex flex-col mt-8">
          <div className="text-sm font-normal text-[#A1A1AA]">GitHub Username</div>
          <div className="flex w-full justify-between">
            <div className="flex items-center text-md mt-1 border text-medium text-[#A1A1AA] border-[#27272A] p-2 px-4 rounded-2xl w-full bg-[#18181B]">
              {username}
              <Image src="/github.svg" alt="GitHub" width={20} height={20} className="ml-auto" />
            </div>
          </div>
        </div>

        <Button
          variant="flat"
          startContent={<LogOut size={14} />}
          className="w-full mt-8 bg-[#3F3F46] hover:bg-[#F3126033] hover:text-danger text-white"
          onClick={() => logout()}
        >
          Log Out
        </Button>
      </div>
    );
  };

  const renderSubscription = () => (
    <div className="w-full max-w-[500px] p-4">
      <SubscriptionCard
        price={990}
        description="Ideal for growing teams and active development."
        features={[
          "10 scan credits (Refreshes every month)",
          "Up to 2,500 lines of code per scan",
          "Up to 15 contracts per scan",
          "CI Integration",
          "Slither integration",
          "Advanced vulnerability detection",
          "PDF output",
          "Dedicated Telegram or Slack channel support",
          "Crypto Payment (Get in touch with Sales)",
        ]}
        nextPaymentDate="23 Dec 2024"
      />
    </div>
  );

  return (
    <div className="h-full relative flex flex-col">
      <div className="w-full">
        <div className="flex justify-between items-center mb-1 ml-4 mr-4 w-full pb-4 px-4">
          <Breadcrumb base="Dashboard" current="Profile Settings" />
          <div className="flex space-x-2">
            <Button
              variant="flat"
              size="md"
              className={`${selectedTab === "details" ? "bg-[#27272a] border-[#A1A1AA]" : "border-[#3F3F46]"} border-1 rounded-md p-4`}
              onClick={() => setSelectedTab("details")}
            >
              User Details
            </Button>
            <Button
              variant="flat"
              size="md"
              className={`${selectedTab === "repositories" ? "bg-[#27272a] border-[#A1A1AA]" : "border-[#3F3F46]"} border-1 rounded-md p-4`}
              onClick={() => setSelectedTab("repositories")}
            >
              Repositories
            </Button>
            <Button
              variant="flat"
              size="md"
              className={`${selectedTab === "subscription" ? "bg-[#27272a] border-[#A1A1AA]" : "border-[#3F3F46]"} border-1 rounded-md p-4`}
              onClick={() => setSelectedTab("subscription")}
            >
              Subscription
            </Button>
          </div>
        </div>
        <Divider />
      </div>

      <div className="flex flex-col items-center gap-6 pb-8">
        {selectedTab === "details" && renderUserDetails()}
        {selectedTab === "repositories" && <AllowedRepositories />}
        {selectedTab === "subscription" && renderSubscription()}
      </div>
    </div>
  );
};

export default ProfilePage;

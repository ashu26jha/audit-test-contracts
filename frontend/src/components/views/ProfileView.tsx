"use client";
import { useState, type FC } from "react";

import { Divider, Button } from "@nextui-org/react";

import { AllowedRepositories, SubscriptionCard, UserDetails } from "@/components/profile";
import { PRO_PLAN_DETAILS } from "@/config/constants";
import { useAuth } from "@/contexts/AuthContext";

import { Breadcrumb } from "../layout";

const ProfileView: FC = () => {
  const { user, logout } = useAuth();
  const [selectedTab, setSelectedTab] = useState("details");

  if (!user) return null;

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
            {/* TODO: Uncomment this when subscription is implemented */}
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

      <div className="h-full flex flex-col items-center gap-6 pb-8 mt-10">
        {selectedTab === "details" && <UserDetails user={user} logout={logout} />}
        {selectedTab === "repositories" && <AllowedRepositories />}
        {selectedTab === "subscription" && (
          <SubscriptionCard
            price={PRO_PLAN_DETAILS.PRICE}
            description="Ideal for growing teams and active development."
            features={[
              `${PRO_PLAN_DETAILS.SCAN_CREDITS} scan credits (Refreshes every month)`,
              `Up to ${PRO_PLAN_DETAILS.MAX_LINES} lines of code per scan`,
              `Up to ${PRO_PLAN_DETAILS.MAX_FILES} contracts per scan`,
              "CI Integration",
              "PDF output",
              "Priority in the scan queue",
              "Dedicated Telegram or Slack channel support",
              "Crypto Payment (Get in touch with Sales)",
            ]}
            nextPaymentDate={user.subscription.expiresAt}
            isSubscribed={user.subscription.isActive}
          />
        )}
      </div>
    </div>
  );
};

export default ProfileView;

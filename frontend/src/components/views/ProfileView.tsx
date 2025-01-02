"use client";
import { useState, type FC } from "react";

import { Button } from "@nextui-org/react";
import { useSearchParams } from "next/navigation";

import { Container } from "@/components/layout";
import { AllowedRepositories, SubscriptionCard, UserDetails } from "@/components/profile";
import { PRO_PLAN_DETAILS } from "@/config/constants";
import { useAuth } from "@/contexts/AuthContext";

const ProfileView: FC = () => {
  const { user, logout } = useAuth();
  const searchParams = useSearchParams();
  const [selectedTab, setSelectedTab] = useState(searchParams.get("tab") || "details");

  if (!user) return null;

  return (
    <Container
      breadcrumbItems={["Dashboard", "Profile Settings"]}
      buttons={
        <div className="flex space-x-2">
          <ButtonProfile
            selectedTab={selectedTab}
            tabName="details"
            label="User Details"
            onClick={() => setSelectedTab("details")}
          />
          <ButtonProfile
            selectedTab={selectedTab}
            tabName="repositories"
            label="Repositories"
            onClick={() => setSelectedTab("repositories")}
          />
          <ButtonProfile
            selectedTab={selectedTab}
            tabName="subscription"
            label="Subscription"
            onClick={() => setSelectedTab("subscription")}
          />
        </div>
      }
    >
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
              "CI/CD Integration",
              "PDF output",
              "Priority in the scan queue",
              "Additional context documentation",
              "Dedicated Telegram or Slack channel support",
              "Crypto Payment (Get in touch with Sales)",
            ]}
            nextPaymentDate={user.subscription.expiresAt}
            isSubscribed={user.subscription.isActive}
          />
        )}
      </div>
    </Container>
  );
};

export default ProfileView;

interface ButtonProfileProps {
  selectedTab: string;
  tabName: string;
  label: string;
  onClick: (tab: string) => void;
}

const ButtonProfile: FC<ButtonProfileProps> = ({ selectedTab, tabName, label, onClick }) => (
  <Button
    variant="flat"
    size="md"
    className={`${
      selectedTab === tabName ? "bg-[#27272a] border-[#A1A1AA]" : "border-[#3F3F46]"
    } border-1 rounded-md p-4`}
    onPress={() => onClick(tabName)}
  >
    {label}
  </Button>
);

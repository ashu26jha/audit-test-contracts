import { type FC } from "react";

import { Button } from "@nextui-org/button";
import Image from "next/image";

import { ENTERPRISE_PLAN_DETAILS, PAGES, PRO_PLAN_DETAILS } from "@/config/constants";
import { useAuth } from "@/contexts/AuthContext";
import { useSubscription } from "@/hooks/useSubscription";

import SubscriptionCard from "./SubscriptionCard";

const SubscriptionDetails: FC = () => {
  const { user } = useAuth();
  const { handleCustomerPortalSession, isLoading } = useSubscription();

  const handleManageSubscription = async () => {
    await handleCustomerPortalSession();
  };

  if (!user) return null;

  return (
    <div className="flex flex-col justify-center w-full max-w-[58rem] items-center gap-y-6">
      <div className="flex justify-between gap-x-6 h-full">
        <SubscriptionCard
          planName={PRO_PLAN_DETAILS.PLAN_NAME}
          price={PRO_PLAN_DETAILS.PRICE}
          description={PRO_PLAN_DETAILS.DESCRIPTION}
          features={PRO_PLAN_DETAILS.features}
          nextPaymentDate={user.subscription.expiresAt}
          isSubscribed={user.subscription.type === "pro"}
          subscriptionType={PRO_PLAN_DETAILS.SUBSCRIPTION_TYPE}
          userSubscribedDifferentPlan={user.subscription.type !== "pro" && user.subscription.type !== "free"}
          hasActiveSubscription={user.subscription.type !== "free"}
        />
        <SubscriptionCard
          planName={ENTERPRISE_PLAN_DETAILS.PLAN_NAME}
          price={ENTERPRISE_PLAN_DETAILS.PRICE}
          description={ENTERPRISE_PLAN_DETAILS.DESCRIPTION}
          features={ENTERPRISE_PLAN_DETAILS.features}
          nextPaymentDate={user.subscription.expiresAt}
          isSubscribed={user.subscription.type === "enterprise"}
          subscriptionType={ENTERPRISE_PLAN_DETAILS.SUBSCRIPTION_TYPE}
          userSubscribedDifferentPlan={user.subscription.type !== "enterprise" && user.subscription.type !== "free"}
          hasActiveSubscription={user.subscription.type !== "free"}
        />
      </div>

      {user.subscription.type !== "free" && (
        <div className="flex justify-between gap-3 w-[28rem]">
          <Button
            size="lg"
            className="flex-1 bg-transparent border border-default"
            as="a"
            href={PAGES.CONTACT}
            target="_blank"
            rel="noopener noreferrer"
          >
            Contact Us
            <Image src="/svg/link.svg" alt="contact-sales" width={14} height={14} className="ml-2" />
          </Button>
          <Button
            size="lg"
            className="flex-1 text-xs bg-default-100"
            onPress={handleManageSubscription}
            isLoading={isLoading}
          >
            Manage Plan/Upgrade Plan
            <Image src="/svg/link.svg" alt="manage-plan" width={14} height={14} className="ml-2" />
          </Button>
        </div>
      )}
    </div>
  );
};

export default SubscriptionDetails;

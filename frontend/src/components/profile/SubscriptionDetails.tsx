import { useState, type FC } from "react";

import { Button } from "@nextui-org/button";
import Image from "next/image";

import { ENTERPRISE_PLAN_DETAILS, PAGES, PRO_PLAN_DETAILS } from "@/config/constants";
import { useAuth } from "@/contexts/AuthContext";
import { createPortalSession } from "@/services/api";

import SubscriptionCard from "./SubscriptionCard";
import TalkToSalesCard from "../TalkToSalesCard";

const SubscriptionDetails: FC = () => {
  const { user } = useAuth();
  const [isLoading, setIsLoading] = useState(false);

  const handleManageSubscription = async () => {
    setIsLoading(true);
    const session = await createPortalSession();
    console.log(session);
    setIsLoading(false);
    window.open(session.url, "_blank");
  };

  if (!user) return null;

  return (
    <div className="flex flex-col justify-center w-full max-w-[58rem] items-center gap-y-6">
      <div className="flex justify-between gap-x-6 h-full">
        {(user.subscription.type === "free" || user.subscription.type === "pro") && (
          <SubscriptionCard
            planName={PRO_PLAN_DETAILS.PLAN_NAME}
            price={PRO_PLAN_DETAILS.PRICE}
            description={PRO_PLAN_DETAILS.DESCRIPTION}
            features={PRO_PLAN_DETAILS.features}
            nextPaymentDate={user.subscription.expiresAt}
            isSubscribed={user.subscription.type !== "free"}
            subscriptionType={PRO_PLAN_DETAILS.SUBSCRIPTION_TYPE}
          />
        )}
        {(user.subscription.type === "free" || user.subscription.type === "enterprise") && (
          <SubscriptionCard
            planName={ENTERPRISE_PLAN_DETAILS.PLAN_NAME}
            price={ENTERPRISE_PLAN_DETAILS.PRICE}
            description={ENTERPRISE_PLAN_DETAILS.DESCRIPTION}
            features={ENTERPRISE_PLAN_DETAILS.features}
            nextPaymentDate={user.subscription.expiresAt}
            isSubscribed={user.subscription.type !== "free"}
            subscriptionType={ENTERPRISE_PLAN_DETAILS.SUBSCRIPTION_TYPE}
          />
        )}
      </div>

      {user.subscription.type !== "free" && (
        <div className="flex justify-between gap-3 w-[28rem]">
          <Button
            className="flex-1 bg-transparent border border-default"
            as="a"
            href={PAGES.CONTACT}
            target="_blank"
            rel="noopener noreferrer"
          >
            Contact Sales
            <Image src="/svg/link.svg" alt="contact-sales" width={14} height={14} className="ml-2" />
          </Button>
          <Button className="flex-1 text-xs bg-default-100" onPress={handleManageSubscription} isLoading={isLoading}>
            Manage Plan/Upgrade Plan
            <Image src="/svg/link.svg" alt="manage-plan" width={14} height={14} className="ml-2" />
          </Button>
        </div>
      )}

      {user.subscription.type === "free" && <TalkToSalesCard />}
    </div>
  );
};

export default SubscriptionDetails;

import { type FC } from "react";

import { ENTERPRISE_PLAN_DETAILS, FREE_PLAN_DETAILS, PRO_PLAN_DETAILS } from "@/config/constants";
import { useAuth } from "@/contexts/AuthContext";

import { SubscriptionCard } from "../profile";

export const SubscriptionSelection: FC = () => {
  const { user } = useAuth();

  return (
    <div className="w-full flex justify-center gap-x-4 mb-10 px-4">
      <SubscriptionCard
        planName={FREE_PLAN_DETAILS.PLAN_NAME}
        price={FREE_PLAN_DETAILS.PRICE}
        description={FREE_PLAN_DETAILS.DESCRIPTION}
        features={FREE_PLAN_DETAILS.features}
        nextPaymentDate={new Date()} // We can pass any date here because it wont be displayed
        isSubscribed={user?.subscription.type === "free"}
        subscriptionType={FREE_PLAN_DETAILS.SUBSCRIPTION_TYPE}
      />
      <SubscriptionCard
        planName={PRO_PLAN_DETAILS.PLAN_NAME}
        price={PRO_PLAN_DETAILS.PRICE}
        description={PRO_PLAN_DETAILS.DESCRIPTION}
        features={PRO_PLAN_DETAILS.features}
        nextPaymentDate={new Date()} // We can pass any date here because it wont be displayed
        isSubscribed={false} // This will always be false because the cards will only be shown if the user is not subscribed
        subscriptionType={PRO_PLAN_DETAILS.SUBSCRIPTION_TYPE}
      />
      <SubscriptionCard
        planName={ENTERPRISE_PLAN_DETAILS.PLAN_NAME}
        price={ENTERPRISE_PLAN_DETAILS.PRICE}
        description={ENTERPRISE_PLAN_DETAILS.DESCRIPTION}
        features={ENTERPRISE_PLAN_DETAILS.features}
        nextPaymentDate={new Date()} // We can pass any date here because it wont be displayed
        isSubscribed={false} // This will always be false because the cards will only be shown if the user is not subscribed
        subscriptionType={ENTERPRISE_PLAN_DETAILS.SUBSCRIPTION_TYPE}
      />
    </div>
  );
};

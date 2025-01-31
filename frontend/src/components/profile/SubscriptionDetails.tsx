import { type FC } from "react";

import { ENTERPRISE_PLAN_DETAILS, PRO_PLAN_DETAILS } from "@/config/constants";
import { useAuth } from "@/contexts/AuthContext";

import SubscriptionCard from "./SubscriptionCard";

const SubscriptionDetails: FC = () => {
  const { user } = useAuth();

  if (!user) return null;

  return (
    <div className="flex flex-col justify-center w-full max-w-[58rem] items-center gap-y-6">
      <div className="flex justify-between gap-x-6 h-full">
        <SubscriptionCard
          auditType={PRO_PLAN_DETAILS.AUDIT_TYPE}
          planName={PRO_PLAN_DETAILS.PLAN_NAME}
          price={PRO_PLAN_DETAILS.PRICE}
          description={PRO_PLAN_DETAILS.DESCRIPTION}
          features={PRO_PLAN_DETAILS.features}
          nextPaymentDate={user.subscription.expiresAt}
          isSubscribed={user.subscription.type === "pro"}
          subscriptionType={PRO_PLAN_DETAILS.SUBSCRIPTION_TYPE}
          userSubscribedDifferentPlan={user.subscription.type !== "pro" && user.subscription.type !== "free"}
          hasActiveSubscription={user.subscription.type !== "free"}
          currentSubscriptionType={user.subscription.type}
          variant="profile"
          isSelectable={false}
        />
        <SubscriptionCard
          auditType={ENTERPRISE_PLAN_DETAILS.AUDIT_TYPE}
          planName={ENTERPRISE_PLAN_DETAILS.PLAN_NAME}
          price={ENTERPRISE_PLAN_DETAILS.PRICE}
          description={ENTERPRISE_PLAN_DETAILS.DESCRIPTION}
          features={ENTERPRISE_PLAN_DETAILS.features}
          nextPaymentDate={user.subscription.expiresAt}
          isSubscribed={user.subscription.type === "enterprise"}
          subscriptionType={ENTERPRISE_PLAN_DETAILS.SUBSCRIPTION_TYPE}
          userSubscribedDifferentPlan={user.subscription.type !== "enterprise" && user.subscription.type !== "free"}
          hasActiveSubscription={user.subscription.type !== "free"}
          currentSubscriptionType={user.subscription.type}
          variant="profile"
          isSelectable={false}
        />
      </div>
    </div>
  );
};

export default SubscriptionDetails;

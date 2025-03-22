import { type FC } from "react";

import { ENTERPRISE_PLAN_DETAILS, FREE_PLAN_DETAILS, PRO_PLAN_DETAILS } from "@/config/constants";
import { useAuth } from "@/contexts/AuthContext";
import { useSubscription } from "@/hooks/useSubscription";
import { useScanStepperStore } from "@/store/scanStepperStore";

import SubscriptionCard from "./SubscriptionCard";

export const SubscriptionSelection: FC = () => {
  const { user } = useAuth();
  const { selectedPlan } = useScanStepperStore();
  const { freeScanAllowed, nextAvailableScanDate } = useSubscription();

  if (!user) return null;
  return (
    <div className="w-full flex flex-col sm:flex-row justify-center gap-x-4 mb-10 px-4 gap-y-4">
      <SubscriptionCard
        auditType={FREE_PLAN_DETAILS.AUDIT_TYPE}
        planName={FREE_PLAN_DETAILS.PLAN_NAME}
        price={FREE_PLAN_DETAILS.PRICE}
        description={FREE_PLAN_DETAILS.DESCRIPTION}
        features={FREE_PLAN_DETAILS.features}
        nextPaymentDate={nextAvailableScanDate ?? new Date()} // We are passing the next available scan date
        subscriptionType={FREE_PLAN_DETAILS.SUBSCRIPTION_TYPE}
        isSelectable={freeScanAllowed}
        isSelected={selectedPlan === FREE_PLAN_DETAILS.SUBSCRIPTION_TYPE}
        isFreeScanUsed={!freeScanAllowed}
      />
      <SubscriptionCard
        auditType={PRO_PLAN_DETAILS.AUDIT_TYPE}
        planName={PRO_PLAN_DETAILS.PLAN_NAME}
        price={PRO_PLAN_DETAILS.PRICE}
        description={PRO_PLAN_DETAILS.DESCRIPTION}
        features={PRO_PLAN_DETAILS.features}
        nextPaymentDate={new Date()} // We can pass any date here because it wont be displayed
        subscriptionType={PRO_PLAN_DETAILS.SUBSCRIPTION_TYPE}
        isSelectable={true}
        isSelected={selectedPlan === PRO_PLAN_DETAILS.SUBSCRIPTION_TYPE}
      />
      <SubscriptionCard
        auditType={ENTERPRISE_PLAN_DETAILS.AUDIT_TYPE}
        planName={ENTERPRISE_PLAN_DETAILS.PLAN_NAME}
        price={ENTERPRISE_PLAN_DETAILS.PRICE}
        description={ENTERPRISE_PLAN_DETAILS.DESCRIPTION}
        features={ENTERPRISE_PLAN_DETAILS.features}
        nextPaymentDate={new Date()} // We can pass any date here because it wont be displayed
        subscriptionType={ENTERPRISE_PLAN_DETAILS.SUBSCRIPTION_TYPE}
        isSelectable={false}
      />
    </div>
  );
};

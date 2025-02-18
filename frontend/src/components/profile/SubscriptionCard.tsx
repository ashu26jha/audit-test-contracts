import { type FC } from "react";

import { Button, Card, CardBody, CardFooter, Divider } from "@nextui-org/react";
import { ArrowUpRight, CircleCheck } from "lucide-react";
import Image from "next/image";
import { tv } from "tailwind-variants";

import { PAGES } from "@/config/constants";
import { useSubscription } from "@/hooks/useSubscription";
import { formatDate } from "@/utils/datetime";

interface SubscriptionCardProps {
  auditType: string;
  planName: string;
  price: number;
  description: string;
  features: string[];
  nextPaymentDate: Date;
  isSubscribed: boolean;
  subscriptionType: SubscriptionType;
  userSubscribedDifferentPlan?: boolean;
  hasActiveSubscription?: boolean;
  currentSubscriptionType: "free" | "pro" | "enterprise";
}

const SubscriptionCard: FC<SubscriptionCardProps> = ({
  planName,
  price,
  description,
  features,
  nextPaymentDate,
  isSubscribed,
  subscriptionType,
  userSubscribedDifferentPlan,
  hasActiveSubscription = false,
  currentSubscriptionType,
}) => {
  const { handleSubscribe, isLoading: isSubscribing, handleCustomerPortalSession } = useSubscription();
  const button = tv({
    base: "mr-auto text-white mx-6 w-36 my-6 flex items-center justify-center gap-2 px-4 py-2 rounded-lg",
    variants: {
      type: {
        pro: "bg-secondary",
        enterprise: "bg-default",
      },
    },
  });

  const handleManageSubscription = async () => {
    await handleCustomerPortalSession();
  };

  const card = tv({
    base: "bg-content-1 w-[28rem] rounded-xl p-3 border-2 border-default-100 cursor-pointer transition-all duration-200 px-0",
    variants: {
      hasActiveSubscription: {
        false: "hover:scale-[1.01] hover:shadow-lg group hover:border-secondary",
      },
    },
  });

  const handleSubscription = async () => {
    if (isSubscribed) {
      handleManageSubscription();
      return;
    }

    if (subscriptionType === "pro") {
      await handleSubscribe(subscriptionType);
    }
    if (subscriptionType === "enterprise") {
      window.open(PAGES.ENTERPRISE_PLAN, "_blank");
    }
  };

  return (
    <Card className={card({ hasActiveSubscription })} isPressable onPress={handleSubscription}>
      <CardBody className="px-0">
        <div>
          <div className="flex gap-x-3 items-center mb-2 px-6 ">
            <div className="flex items-center gap-x-3">
              <div className="font-medium text-base text-[#A1A1AA]">{planName}</div>
            </div>
            {isSubscribed && (
              <div className="bg-[#9353D333] px-2 py-1 rounded text-xs text-[#C9A9E9]">CURRENT PLAN</div>
            )}
          </div>

          <div className="flex items-center gap-1 px-6">
            <span className="text-3xl font-medium">
              {subscriptionType !== "enterprise" ? `$${price}` : "Get In Touch"}
            </span>
            {subscriptionType === "pro" && <span className="text-gray-400 text-sm">/ month</span>}
          </div>

          <div className="text-[#A1A1AA] font-normal text-sm my-3 px-6">{description}</div>

          {!isSubscribed && subscriptionType !== "free" && !userSubscribedDifferentPlan && (
            <Button
              as="div"
              isLoading={subscriptionType === "pro" && isSubscribing}
              onPress={handleSubscription}
              className={`${button({ type: subscriptionType })}`}
              endContent={<ArrowUpRight />}
            >
              <span>{subscriptionType === "pro" ? "Subscribe" : "Contact us"}</span>
            </Button>
          )}

          {subscriptionType === "pro" && currentSubscriptionType === "pro" && (
            <Button
              as="div"
              isLoading={subscriptionType === "pro" && isSubscribing}
              onPress={handleManageSubscription}
              className={`${button({ type: subscriptionType })}`}
              endContent={<ArrowUpRight />}
            >
              <span>Manage Plan</span>
            </Button>
          )}

          {subscriptionType === "enterprise" && hasActiveSubscription && (
            <Button
              as="div"
              onPress={handleSubscription}
              className={`${button({ type: subscriptionType })} `}
              endContent={<ArrowUpRight size={18} />}
            >
              <span>Contact us</span>
            </Button>
          )}

          {subscriptionType === "pro" && hasActiveSubscription && !isSubscribed && (
            <Button
              as="div"
              onPress={handleSubscription}
              className={`${button({ type: subscriptionType })}`}
              endContent={<ArrowUpRight />}
            >
              <span>Subscribe</span>
            </Button>
          )}

          <Divider className="mb-6 bg-[#22262F]" />

          <div className="space-y-4 px-6">
            {features.map((feature, index) => (
              <div key={index} className="flex items-center gap-3 text-base font-normal">
                <CircleCheck size={20} className="text-default-600" />
                <span className="text-sm">{feature}</span>
              </div>
            ))}
          </div>
        </div>
      </CardBody>

      {isSubscribed && subscriptionType !== "free" && (
        <CardFooter className="p-0 border-t border-[#22262F]">
          <div className="mt-6 text-[#F59E0B] text-sm flex items-center gap-2 px-6 pb-4 w-full">
            <Image src="/svg/payment-circle.svg" alt="payment" width={16} height={16} />
            Next payment is on {formatDate(nextPaymentDate)}
          </div>
        </CardFooter>
      )}
    </Card>
  );
};

export default SubscriptionCard;

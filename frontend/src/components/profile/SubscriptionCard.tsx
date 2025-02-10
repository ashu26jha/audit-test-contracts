import { type FC } from "react";

import { Button, Card, CardBody, CardFooter } from "@nextui-org/react";
import { ArrowUpRight, Circle, CircleCheck } from "lucide-react";
import Image from "next/image";
import { tv } from "tailwind-variants";

import { PAGES } from "@/config/constants";
import { useSubscription } from "@/hooks/useSubscription";
import { useScanStepperStore } from "@/store/scanStepperStore";
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
  isSelectable: boolean;
  isSelected?: boolean;
  currentSubscriptionType: "free" | "pro" | "enterprise";
  variant: "profile" | "scan-now";
  isFreeScanUsed?: boolean;
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
  isSelectable,
  isSelected,
  currentSubscriptionType,
  variant,
  isFreeScanUsed,
}) => {
  const { handleSubscribe, isLoading: isSubscribing, handleCustomerPortalSession } = useSubscription();
  const { setSelectedPlan } = useScanStepperStore();
  const button = tv({
    base: "mr-auto text-white",
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
    base: "bg-content-1 w-[28rem] rounded-xl p-3 border-2 border-default-100 ursor-pointer transition-all duration-200",
    variants: {
      hasActiveSubscription: {
        false: "hover:scale-[1.01] hover:shadow-lg group hover:border-secondary",
      },
      isSelected: {
        true: "border-secondary",
      },
    },
  });

  const handleSubscription = async () => {
    if (isSelectable) {
      setSelectedPlan(subscriptionType);
    } else {
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
    }
  };

  return (
    <Card className={card({ hasActiveSubscription, isSelected })} isPressable onPress={handleSubscription}>
      <CardBody>
        <div>
          <div className="flex justify-between items-center mb-2">
            <div className="flex items-center gap-x-3">
              <div className="font-medium text-base text-[#A1A1AA]">{planName}</div>
            </div>
            {isSubscribed && (
              <div className="bg-[#9353D333] px-2 py-1 rounded text-xs text-[#C9A9E9]">CURRENT PLAN</div>
            )}
            {isSelectable && !isSelected && <Circle className="text-default-400" />}
            {isSelectable && isSelected && (
              <Image src="/svg/radio_selected.svg" alt="selected" width={23} height={23} />
            )}
          </div>

          <div className="flex items-center gap-1 mb-2">
            <span className="text-3xl font-medium">
              {subscriptionType !== "enterprise" ? `$${price}` : "Get In Touch"}
            </span>
            {subscriptionType === "pro" && <span className="text-gray-400 text-sm">/ month</span>}
            {variant === "scan-now" && subscriptionType === "enterprise" && (
              <Button
                size="sm"
                as="div"
                onPress={handleSubscription}
                className={`${button({ type: subscriptionType })} ml-4 w-28 flex items-center justify-center gap-2 px-4 py-2 rounded-lg `}
                endContent={<ArrowUpRight />}
              >
                <span>Contact us</span>
              </Button>
            )}
          </div>

          <div className="text-[#A1A1AA] font-normal text-sm my-6">{description}</div>

          {variant === "profile" && !isSubscribed && subscriptionType !== "free" && !userSubscribedDifferentPlan && (
            <Button
              as="div"
              isLoading={subscriptionType === "pro" && isSubscribing}
              onPress={handleSubscription}
              className={`${button({ type: subscriptionType })} w-36 my-6 flex items-center justify-center gap-2 px-4 py-2 rounded-lg `}
              endContent={<ArrowUpRight />}
            >
              <span>{subscriptionType === "pro" ? "Subscribe" : "Contact us"}</span>
            </Button>
          )}

          {variant === "profile" && subscriptionType === "pro" && currentSubscriptionType === "pro" && (
            <Button
              as="div"
              isLoading={subscriptionType === "pro" && isSubscribing}
              onPress={handleManageSubscription}
              className={`${button({ type: subscriptionType })} w-36 my-6 flex items-center justify-center gap-2 px-4 py-2 rounded-lg `}
              endContent={<ArrowUpRight />}
            >
              <span>Manage Plan</span>
            </Button>
          )}

          {variant === "profile" && subscriptionType === "enterprise" && hasActiveSubscription && (
            <Button
              as="div"
              onPress={handleSubscription}
              className={`${button({ type: subscriptionType })}  w-36 my-6 flex items-center justify-center gap-2 px-4 py-2 rounded-lg `}
              endContent={<ArrowUpRight />}
            >
              <span>Contact us</span>
            </Button>
          )}

          {variant === "profile" && subscriptionType === "pro" && hasActiveSubscription && !isSubscribed && (
            <Button
              as="div"
              onPress={handleSubscription}
              className={`${button({ type: subscriptionType })}  w-36 my-6 flex items-center justify-center gap-2 px-4 py-2 rounded-lg `}
              endContent={<ArrowUpRight />}
            >
              <span>Subscribe</span>
            </Button>
          )}

          <div className="space-y-4">
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
        <CardFooter>
          <div className="mt-6 text-[#F59E0B] text-sm flex items-center gap-2">
            <Image src="/svg/payment-circle.svg" alt="payment" width={16} height={16} />
            Next payment is on {formatDate(nextPaymentDate)}
          </div>
        </CardFooter>
      )}

      {isFreeScanUsed && (
        <CardFooter>
          <div className="mt-6 text-[#F59E0B] text-sm flex items-center gap-2">
            <Image src="/svg/payment-circle.svg" alt="payment" width={16} height={16} />
            Free Plan Used. Refreshes on {formatDate(nextPaymentDate)}
          </div>
        </CardFooter>
      )}
    </Card>
  );
};

export default SubscriptionCard;

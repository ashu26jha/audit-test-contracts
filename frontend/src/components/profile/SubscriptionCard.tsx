import { useState, type FC } from "react";

import { Button, Card, CardBody, CardFooter } from "@nextui-org/react";
import type { AxiosError } from "axios";
import { ArrowUpRight, CircleCheck } from "lucide-react";
import Image from "next/image";
import { tv } from "tailwind-variants";

import { useToast } from "@/hooks";
import { createSubscriptionSession } from "@/services/api";
import { formatDate } from "@/utils/datetime";

interface SubscriptionCardProps {
  planName: string;
  price: number;
  description: string;
  features: string[];
  nextPaymentDate: Date;
  isSubscribed: boolean;
  subscriptionType: Exclude<SubscriptionType, "free">;
}

const SubscriptionCard: FC<SubscriptionCardProps> = ({
  planName,
  price,
  description,
  features,
  nextPaymentDate,
  isSubscribed,
  subscriptionType,
}) => {
  const [isLoading, setIsLoading] = useState(false);
  const { toast } = useToast();
  const button = tv({
    base: "mt-5 mr-auto text-white",
    variants: {
      type: {
        pro: "bg-secondary",
        enterprise: "bg-default",
      },
    },
  });

  const handleSubscription = async () => {
    try {
      setIsLoading(true);
      const res = await createSubscriptionSession(subscriptionType);
      setIsLoading(false);
      window.location.assign(res.data.url);
    } catch (error) {
      setIsLoading(false);
      console.error("Error initiating subscription session:", error);
      toast({
        title:
          ((error as AxiosError).response?.data as { message?: string })?.message ??
          "An error occurred while initiating subscription session",
        status: "error",
        duration: 3000,
      });
    }
  };

  return (
    <Card
      className="bg-content-1 w-[28rem] rounded-xl p-3 border-2 border-default-100 ursor-pointer transition-all duration-200 hover:scale-[1.01] hover:shadow-lg group hover:border-secondary"
      isPressable
    >
      <CardBody>
        <div>
          <div className="flex justify-between items-center mb-2">
            <div className="font-medium text-base text-[#A1A1AA]">{planName}</div>
            {isSubscribed && (
              <div className="bg-[#9353D333] px-2 py-1 rounded text-xs text-[#C9A9E9]">CURRENT PLAN</div>
            )}
          </div>

          <div className="flex items-baseline gap-1 mb-2">
            <span className="text-3xl font-medium">${price}</span>
            <span className="text-gray-400 text-sm">/ month</span>
          </div>

          <div className="text-[#A1A1AA] font-normal text-sm my-6">{description}</div>

          {!isSubscribed && (
            <Button
              isLoading={isLoading}
              onPress={handleSubscription}
              className={`${button({ type: subscriptionType })} my-6 flex items-center justify-center gap-2 px-4 py-2 rounded-lg `}
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

      {isSubscribed && (
        <CardFooter>
          <div className="mt-6 text-[#F59E0B] text-sm flex items-center gap-2">
            <Image src="/svg/payment-circle.svg" alt="payment" width={16} height={16} />
            Next payment is on {formatDate(nextPaymentDate)}
          </div>
        </CardFooter>
      )}
    </Card>
  );
};

export default SubscriptionCard;

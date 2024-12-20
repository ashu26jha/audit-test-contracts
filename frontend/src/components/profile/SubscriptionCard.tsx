import { useState, type FC } from "react";

import { Button } from "@nextui-org/react";
import Image from "next/image";
import { tv } from "tailwind-variants";

import { PAGES } from "@/config/constants";
import { createPortalSession, createSubscriptionSession } from "@/services/api";
import { formatDate } from "@/utils/datetime";

interface SubscriptionCardProps {
  price: number;
  description: string;
  features: string[];
  nextPaymentDate: Date;
  isSubscribed: boolean;
}

const SubscriptionCard: FC<SubscriptionCardProps> = ({
  price,
  description,
  features,
  nextPaymentDate,
  isSubscribed,
}) => {
  const [isLoading, setIsLoading] = useState(false);

  const handleManageSubscription = async () => {
    setIsLoading(true);
    if (isSubscribed) {
      const session = await createPortalSession();
      setIsLoading(false);
      window.open(session.url, "_blank");
    } else {
      const res = await createSubscriptionSession();
      setIsLoading(false);
      window.location.assign(res.data.url);
    }
  };

  const actionBtn = tv({
    base: "flex-1 bg-secondary",
    variants: {
      isSubscribed: {
        true: "bg-default-100",
      },
    },
  });

  return (
    <>
      <div className="bg-content-1 w-[28rem] rounded-xl p-6 border border-default-100">
        <div className="flex justify-between items-center mb-2">
          <div className="font-medium text-base text-[#A1A1AA]">Subscription</div>
          <div className="bg-[#9353D333] px-2 py-1 rounded text-xs text-[#C9A9E9]">
            {isSubscribed ? "CURRENT PLAN" : "ADVANCED SCAN"}
          </div>
        </div>

        <div className="flex items-baseline gap-1 mb-2">
          <span className="text-3xl font-semibold">${price}</span>
          <span className="text-gray-400 text-sm">/ month</span>
        </div>

        <div className="text-[#A1A1AA] font-normal text-sm mb-6">{description}</div>

        <div className="space-y-4">
          {features.map((feature, index) => (
            <div key={index} className="flex items-center gap-3 text-base font-normal">
              <Image src="/svg/check-circle.svg" alt="check" width={20} height={20} />
              <span>{feature}</span>
            </div>
          ))}
        </div>

        {isSubscribed && (
          <div className="mt-6 text-[#F59E0B] text-sm flex items-center gap-2">
            <Image src="/svg/payment-circle.svg" alt="payment" width={16} height={16} />
            Next payment is on {formatDate(nextPaymentDate)}
          </div>
        )}
      </div>
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
        <Button className={actionBtn({ isSubscribed })} onPress={handleManageSubscription} isLoading={isLoading}>
          {isSubscribed ? "Manage Plan" : "Pay & Subscribe"}
          <Image src="/svg/link.svg" alt="manage-plan" width={14} height={14} className="ml-2" />
        </Button>
      </div>
    </>
  );
};

export default SubscriptionCard;

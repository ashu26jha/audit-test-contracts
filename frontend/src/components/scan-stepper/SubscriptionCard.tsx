import { type FC } from "react";

import { Card, CardBody, CardFooter, Divider } from "@nextui-org/react";
import { ArrowUpRight, Circle, CircleCheck } from "lucide-react";
import Image from "next/image";
import { tv } from "tailwind-variants";

import { PAGES } from "@/config/constants";
import { useScanStepperStore } from "@/store/scanStepperStore";
import { formatDate } from "@/utils/datetime";

interface SubscriptionCardProps {
  auditType: string;
  planName: string;
  price: number;
  description: string;
  features: string[];
  nextPaymentDate: Date;
  subscriptionType: SubscriptionType;
  isSelectable: boolean;
  isSelected?: boolean;
  isFreeScanUsed?: boolean;
}

const SubscriptionCard: FC<SubscriptionCardProps> = ({
  planName,
  price,
  description,
  features,
  nextPaymentDate,
  subscriptionType,
  isSelectable,
  isSelected,
  isFreeScanUsed,
}) => {
  const { setSelectedPlan } = useScanStepperStore();

  const card = tv({
    base: "bg-content-1 w-full sm:w-[28rem] rounded-xl p-3 border-2 border-default-100 cursor-pointer transition-all duration-200 hover:scale-[1.01] hover:shadow-lg group hover:border-secondary px-0",
    variants: {
      isSelected: {
        true: "border-secondary",
      },
    },
  });

  const handleSubscription = async () => {
    if (isSelectable) {
      setSelectedPlan(subscriptionType);
    } else {
      if (subscriptionType === "enterprise") {
        window.open(PAGES.ENTERPRISE_PLAN, "_blank");
      }
    }
  };

  return (
    <Card className={card({ isSelected })} isPressable={!isFreeScanUsed} onPress={handleSubscription}>
      <CardBody className="px-0">
        <div>
          <div className="flex justify-between items-center mb-2 px-6">
            <div className="flex items-center gap-x-3">
              <div className="font-medium text-base text-[#A1A1AA]">{planName}</div>
            </div>
            {isSelectable && !isSelected && <Circle className="text-default-400" />}
            {isSelectable && isSelected && (
              <Image src="/svg/radio_selected.svg" alt="selected" width={23} height={23} />
            )}

            {subscriptionType == "enterprise" && <ArrowUpRight />}
          </div>

          <div className="flex items-center gap-1 mb-2 px-6">
            <span className="text-3xl font-medium">
              {subscriptionType !== "enterprise" ? `$${price}` : "Get In Touch"}
            </span>
            {subscriptionType === "pro" && <span className="text-gray-400 text-sm">/ month</span>}
          </div>

          <div className="text-[#A1A1AA] font-normal text-sm my-6 px-6">{description}</div>

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

      {isFreeScanUsed && (
        <CardFooter className="p-0 border-t border-[#22262F]">
          <div className="mt-6 text-[#F59E0B] text-sm flex items-center gap-2 px-6 pb-4">
            <Image src="/svg/payment-circle.svg" alt="payment" width={16} height={16} />
            Free Plan Used. Refreshes on {formatDate(nextPaymentDate)}
          </div>
        </CardFooter>
      )}
    </Card>
  );
};

export default SubscriptionCard;

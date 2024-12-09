import React from "react";

import { Button } from "@nextui-org/react";
import Image from "next/image";

interface SubscriptionCardProps {
  price: number;
  description: string;
  features: string[];
  nextPaymentDate: string;
}

const SubscriptionCard: React.FC<SubscriptionCardProps> = ({ price, description, features, nextPaymentDate }) => {
  return (
    <div className="bg-[#18181B] rounded-xl p-6 border border-[#27272A]">
      <div className="flex justify-between items-center mb-2">
        <div className="font-medium text-base text-[#A1A1AA]">Subscription</div>
        <div className="bg-[#9353D333] px-2 py-1 rounded text-xs text-[#C9A9E9]">CURRENT PLAN</div>
      </div>

      <div className="flex items-baseline gap-1 mb-2">
        <span className="text-3xl font-semibold">${price}</span>
        <span className="text-gray-400 text-sm">/ month</span>
      </div>

      <div className="text-[#A1A1AA] font-normal text-sm mb-6">{description}</div>

      <div className="space-y-4">
        {features.map((feature, index) => (
          <div key={index} className="flex items-center gap-3 text-base font-normal">
            <Image src="/check-circle.svg" alt="check" width={20} height={20} />
            <span>{feature}</span>
          </div>
        ))}
      </div>

      <div className="mt-6 text-[#F59E0B] text-sm flex items-center gap-2">
        <Image src="/payment-circle.svg" alt="payment" width={16} height={16} />
        Next payment is on {nextPaymentDate}
      </div>

      <div className="flex gap-3 mt-6">
        <Button
          className="flex-1 bg-transparent border border-[#3F3F46]"
          as="a"
          href="https://auditagent.nethermind.io/contact-us"
          target="_blank"
          rel="noopener noreferrer"
        >
          Contact Sales
          <Image src="/link.svg" alt="contact-sales" width={14} height={14} className="ml-2" />
        </Button>
        <Button className="flex-1 bg-[#27272A]">
          Manage Plan
          <Image src="/link.svg" alt="manage-plan" width={14} height={14} className="ml-2" />
        </Button>
      </div>
    </div>
  );
};

export default SubscriptionCard;

import { type FC } from "react";

import { Card, Chip, Divider } from "@nextui-org/react";
import { ArrowUpRight, CircleCheck } from "lucide-react";
import { tv } from "tailwind-variants";

interface SubscriptionPlanCardProps {
  type: "single" | "subscription";
  features: string[];
  price: number;
  onSelect?: () => void;
}

const SubscriptionPlanCard: FC<SubscriptionPlanCardProps> = ({ features, type, price, onSelect }) => {
  const card = tv({
    base: "bg-content-1 flex flex-col cursor-pointer transition-all duration-200 hover:scale-[1.01] hover:shadow-lg group",
    variants: {
      type: {
        single: "border-2 border-transparent hover:border-default w-5/12 hover:brightness-150 peer",
        subscription: "border-2 border-transparent hover:border-secondary w-8/12 hover:brightness-150 peer",
      },
    },
  });

  const chip = tv({
    variants: {
      type: {
        single: "bg-default-flat",
        subscription: "bg-secondary-flat",
      },
    },
  });

  const button = tv({
    base: "mt-5 mr-auto text-white pointer-events-none",
    variants: {
      type: {
        single: "bg-default hover:bg-default",
        subscription: "bg-secondary hover:bg-secondary",
      },
    },
  });

  return (
    <Card className={card({ type })} isPressable onPress={onSelect}>
      <section className="p-6 flex flex-col relative">
        <div className="flex items-center gap-x-3">
          <h4 className="font-medium text-default-500">{type === "single" ? "Single Payment" : "Subscription"}</h4>
          <Chip radius="sm" classNames={{ base: chip({ type }), content: "text-xs" }}>
            {type === "single" ? "LIMITED SCAN" : "ADVANCED SCAN"}
          </Chip>
        </div>

        {type === "single" && (
          <div className="flex items-end mt-5 gap-x-3">
            <p className="text-3xl">${price}</p>
            <p className="line-through text-default-500">$99</p>
            <p className="text-lg">(Time-Limited Offer)</p>
          </div>
        )}

        {type === "subscription" && (
          <div className="flex items-end mt-5 gap-x-1">
            <p className="text-3xl">${price}</p>
            <p className="text-default-500">/ month</p>
          </div>
        )}

        <p className="mt-2 text-default-500 text-sm">
          {type === "single"
            ? "Perfect for small projects or testing purposes."
            : "Ideal for growing teams and active development."}
        </p>

        <div className={`${button({ type })} flex items-center justify-center gap-2 px-4 py-2 rounded-lg `}>
          <span>{type === "single" ? "Pay & Scan" : "Subscribe & Get Full Report For Free"}</span>
          <ArrowUpRight />
        </div>
      </section>

      <Divider />

      <section className="p-6 flex flex-col gap-y-4">
        {features.map((feature, i) => (
          <PlanFeatureRow key={i} feature={feature} />
        ))}
      </section>
    </Card>
  );
};

export default SubscriptionPlanCard;

const PlanFeatureRow = ({ feature }: { feature: string }) => {
  return (
    <div className="flex items-center gap-x-3">
      <CircleCheck size={"16"} className="text-default-600" />
      <p className="text-sm">{feature}</p>
    </div>
  );
};

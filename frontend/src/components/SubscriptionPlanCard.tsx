import type { FC } from "react";

import { Button, Card, Chip, Divider } from "@nextui-org/react";
import { ArrowUpRight, CircleCheck } from "lucide-react";
import { tv } from "tailwind-variants";

interface SubscriptionPlanCardProps {
  type: "limited" | "advanced";
  features: string[];
  price: number;
}

const SubscriptionPlanCard: FC<SubscriptionPlanCardProps> = ({ features, type, price }) => {
  const card = tv({
    base: "bg-content-1 flex flex-col",
    variants: {
      type: {
        limited: "border-none w-5/12",
        advanced: "border border-secondary w-8/12",
      },
    },
  });

  const chip = tv({
    variants: {
      type: {
        limited: "bg-default-flat",
        advanced: "bg-secondary-flat",
      },
    },
  });

  const button = tv({
    base: "mt-5 mr-auto text-white",
    variants: {
      type: {
        limited: "bg-default",
        advanced: "bg-secondary",
      },
    },
  });

  return (
    <Card className={card({ type })}>
      <section className="p-6 flex flex-col">
        <div className="flex items-center gap-x-3">
          <h4 className="font-medium text-default-500 ">{type === "limited" ? "Single Scan" : "Advanced"}</h4>
          <Chip radius="sm" classNames={{ base: chip({ type }), content: "text-xs" }}>
            {type === "limited" ? "LIMITED AUDIT" : "ADVANCED AUDIT"}
          </Chip>
        </div>

        {type === "limited" && (
          <div className="flex items-end mt-5 gap-x-3">
            <p className="text-3xl">${price}</p>
            <p className="line-through text-default-500">$200</p>
            <p className="text-lg">(Time-bound offer)</p>
          </div>
        )}

        {type === "advanced" && (
          <div className="flex items-end mt-5 gap-x-1">
            <p className="text-3xl">${price}</p>
            <p className="text-default-500">/ month</p>
          </div>
        )}

        <p className="mt-2 text-default-500 text-sm">
          {type === "limited"
            ? "Perfect for small projects or testing purposes."
            : "Ideal for growing teams and active development."}
        </p>

        <Button
          color="default"
          size="md"
          radius="sm"
          variant="solid"
          className={button({ type })}
          endContent={<ArrowUpRight />}
        >
          {type === "limited" ? "Pay & Scan" : "Subscribe & Get Full Report For Free"}
        </Button>
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

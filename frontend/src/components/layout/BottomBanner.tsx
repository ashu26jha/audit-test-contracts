"use client";

import { type FC, type ReactNode } from "react";

import { Button, Card, CardBody } from "@nextui-org/react";

interface BottomBannerProps {
  title: string;
  description: string;
  buttonText: string;
  buttonIcon?: ReactNode;
  action: () => void;
  gradientFrom?: string;
  gradientTo?: string;
  height?: string;
  cardBgColor?: string;
  titleColor?: string;
  descriptionColor?: string;
  buttonClassName?: string;
}

const BottomBanner: FC<BottomBannerProps> = ({
  title,
  description,
  buttonText,
  buttonIcon,
  action,
  gradientFrom = "#3B175F",
  gradientTo = "#18181B00",
  height = "8rem",
  cardBgColor = "bg-background",
  titleColor = "text-white",
  descriptionColor = "text-default-500",
  buttonClassName = "bg-secondary",
}) => {
  return (
    <div className="sticky bottom-0 left-0 right-0 z-10 rounded-b-xl overflow-hidden">
      <div
        className="bg-transparent flex justify-center items-end"
        style={{
          background: `linear-gradient(to top, ${gradientFrom}, ${gradientTo})`,
          height,
        }}
      >
        <Card className={`lg:w-[80%] ${cardBgColor} bottom-6 flex justify-between items-center p-2`}>
          <CardBody className="flex flex-row justify-between items-center space-x-2">
            <div className="flex flex-col pl-5">
              <strong className={`text-sm ${titleColor}`}>{title}</strong>
              <p className={`text-sm ${descriptionColor}`}>{description}</p>
            </div>
            <Button onPress={action} color="secondary" className={buttonClassName} startContent={buttonIcon}>
              {buttonText}
            </Button>
          </CardBody>
        </Card>
      </div>
    </div>
  );
};

export default BottomBanner;

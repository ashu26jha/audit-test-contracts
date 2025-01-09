import React, { type FC } from "react";

import { Button, Card } from "@nextui-org/react";
import { ArrowUpRight } from "lucide-react";

import { PAGES } from "@/config/constants";

const TalkToSalesCard: FC = () => {
  return (
    <Card className="bg-content-1 h-20 p-6 w-full text-center flex flex-row items-center">
      <p className="text-lg font-medium">Talk to Sales</p>
      <p className="text-default-500 ml-3">We provide customized solutions and offer crypto payments.</p>
      <Button
        color="default"
        size="md"
        radius="sm"
        variant="bordered"
        className="ml-auto border border-default w-32 text-white"
        as="a"
        href={PAGES.CONTACT}
        target="_blank"
        rel="noopener noreferrer"
      >
        Contact Sales
        <ArrowUpRight />
      </Button>
    </Card>
  );
};

export default TalkToSalesCard;

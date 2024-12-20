import type { Dispatch, FC, SetStateAction } from "react";

import { Button, Card, Modal, ModalBody, ModalContent, ModalHeader } from "@nextui-org/react";
import { ArrowUpRight } from "lucide-react";

import { BASIC_PLAN_DETAILS, PAGES, PRO_PLAN_DETAILS } from "@/config/constants";
import { usePaymentProcessing, type PaymentType } from "@/hooks";

import SubscriptionPlanCard from "../SubscriptionPlanCard";

interface SubscriptionPlansModalProps {
  isOpen: boolean;
  setIsOpen: Dispatch<SetStateAction<boolean>>;
  scanId: string;
}

const LIMITED_PLAN_FEATURES = [
  `${BASIC_PLAN_DETAILS.SCAN_CREDITS} scan credit only`,
  `Up to ${BASIC_PLAN_DETAILS.MAX_LINES} lines of code per scan`,
  `${BASIC_PLAN_DETAILS.MAX_FILES} contracts per scan`,
  "PDF output",
];

const ADVANCED_PLAN_FEATURES = [
  "Everything in single payment",
  `${PRO_PLAN_DETAILS.SCAN_CREDITS} scan credits (Refreshes every month)`,
  `Up to ${PRO_PLAN_DETAILS.MAX_LINES} lines of code per scan`,
  `Up to ${PRO_PLAN_DETAILS.MAX_FILES} contracts per scan`,
  "CI integration",
  "Additional context documentation",
  "Priority in the scan queue",
  "Dedicated Telegram or Slack channel support",
  "Crypto Payment (Get in touch with Sales)",
];

const PaymentsModal: FC<SubscriptionPlansModalProps> = ({ isOpen, setIsOpen, scanId }) => {
  const { handlePayment, error } = usePaymentProcessing(scanId);

  const handlePlanSelection = async (paymentType: PaymentType) => {
    await handlePayment(paymentType);
    setIsOpen(false);
  };

  return (
    <Modal backdrop="blur" classNames={{ base: "bg-black" }} size="5xl" isOpen={isOpen} onOpenChange={setIsOpen}>
      <ModalContent>
        <ModalHeader className="text-base font-normal max-h border-b border-content-1">
          Select Option to Continue
        </ModalHeader>

        <ModalBody className="py-8">
          <div className="flex gap-x-4">
            <SubscriptionPlanCard
              features={LIMITED_PLAN_FEATURES}
              type="single"
              price={BASIC_PLAN_DETAILS.PRICE}
              onSelect={() => handlePlanSelection("single")}
            />
            <SubscriptionPlanCard
              features={ADVANCED_PLAN_FEATURES}
              type="subscription"
              price={PRO_PLAN_DETAILS.PRICE}
              onSelect={() => handlePlanSelection("subscription")}
            />
          </div>

          {error && <div className="text-red-500 text-sm mt-2 text-center">{error}</div>}

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
        </ModalBody>
      </ModalContent>
    </Modal>
  );
};

export default PaymentsModal;

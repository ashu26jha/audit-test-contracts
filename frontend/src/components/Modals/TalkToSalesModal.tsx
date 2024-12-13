import { type Dispatch, type FC, type SetStateAction } from "react";

import { Button, Modal, ModalBody, ModalContent, ModalHeader } from "@nextui-org/react";
import { MessagesSquare, MoveUpRight } from "lucide-react";

import { PAGES } from "@/config/constants";
import { useAuth } from "@/contexts/AuthContext";

interface TalkToSalesModalProps {
  isOpen: boolean;
  setIsOpen: Dispatch<SetStateAction<boolean>>;
}

const TalkToSalesModal: FC<TalkToSalesModalProps> = ({ isOpen, setIsOpen }) => {
  const { user } = useAuth();
  return (
    <Modal isOpen={isOpen} size="sm" backdrop="blur" onOpenChange={setIsOpen}>
      <ModalContent className="bg-black">
        <ModalHeader className="text-base font-normal">Talk to Sales</ModalHeader>
        <ModalBody className="p-6 w-full flex flex-col justify-center items-center gap-y-4">
          <div className="w-full flex justify-center items-center rounded-2xl h-24 bg-content-1">
            <MessagesSquare size={50} className="text-secondary" />
          </div>

          <p className="font-medium">No Scan Credit Left</p>

          <p className="text-sm text-default-500 text-center">
            You have utilized all {user?.subscription.monthlyCredits} scan credits for this month. Please contract our
            sales team so you can continue auditing this month.
          </p>

          <Button
            as="a"
            href={PAGES.CONTACT}
            target="_blank"
            rel="noopener noreferrer"
            fullWidth
            className="bg-secondary"
            endContent={<MoveUpRight size={16} />}
          >
            View Form
          </Button>
        </ModalBody>
      </ModalContent>
    </Modal>
  );
};

export default TalkToSalesModal;

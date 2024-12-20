import { type Dispatch, type FC, type SetStateAction } from "react";

import { Button, Modal, ModalBody, ModalContent, ModalHeader } from "@nextui-org/react";
import { Hourglass } from "lucide-react";

type CreditWarningModalProps = {
  isOpen: boolean;
  setIsOpen: Dispatch<SetStateAction<boolean>>;
  onClick?: (e: React.MouseEvent<HTMLButtonElement>) => void;
};

const CreditWarningModal: FC<CreditWarningModalProps> = ({ isOpen, setIsOpen, onClick }) => {
  return (
    <Modal isOpen={isOpen} onOpenChange={setIsOpen} size="sm" backdrop="blur">
      <ModalContent className="bg-black">
        <ModalHeader className="text-base font-normal">Scan Credit Warning</ModalHeader>
        <ModalBody className="p-6 w-full flex flex-col justify-center items-center gap-y-4">
          <div className="w-full flex justify-center items-center rounded-2xl h-24 bg-content-1">
            <Hourglass size={40} className="text-secondary" />
          </div>

          <p className="font-medium">1 Scan Credit Remaining</p>

          <p className="text-sm text-default-500 text-center">
            You have only 1 scan credit remaining for this month. Once all the scan credits has been used, you will need
            to contact our sales team.
          </p>

          <Button fullWidth className="bg-secondary" onPress={() => onClick}>
            Continue
          </Button>
        </ModalBody>
      </ModalContent>
    </Modal>
  );
};

export default CreditWarningModal;

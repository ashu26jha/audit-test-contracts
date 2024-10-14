"use client";

import { useEffect, useState } from "react";

import { Modal, ModalContent, ModalHeader, ModalBody, ModalFooter, Button } from "@nextui-org/react";
import Image from "next/image";

const ScanInfoModal: React.FC = () => {
  const [isOpen, setIsOpen] = useState(false);

  useEffect(() => {
    const hasShownModal = localStorage.getItem("hasShownScanInfoModal");
    if (!hasShownModal) {
      setIsOpen(true);
    }
  }, []);

  const handleClose = () => {
    setIsOpen(false);
    localStorage.setItem("hasShownScanInfoModal", "true");
  };

  return (
    <Modal
      size="xl"
      backdrop="blur"
      isOpen={isOpen}
      onClose={handleClose} // Use onClose instead of onOpenChange
      isDismissable={false}
      hideCloseButton
    >
      <ModalContent className="bg-[#000000]">
        <ModalHeader className="flex flex-col gap-1 bg-[#000000] text-white">
          Important Information Before You Begin
        </ModalHeader>
        <ModalBody>
          <div className="flex flex-row gap-1 bg-[#18181B] m-4 rounded-lg p-4">
            <div className="flex flex-col gap-1 border-r border-[#27272A] p-4">
              <Image src="/beta.svg" width={60} height={60} alt="beta" />
            </div>

            <div className="flex flex-col gap-1 ml-4 mt-2 mb-2">
              <p className="text-sm text-white mt-2">Beta Version</p>
              <p className="text-sm text-gray-400 mb-2 mt-2 mr-2">
                This is a beta product. We’re improving continuously, and your feedback helps us grow.
              </p>
            </div>
          </div>

          <div className="flex flex-row gap-1 bg-[#18181B] m-4 rounded-lg p-4">
            <div className="flex flex-col gap-1 border-r border-[#27272A] p-4">
              <Image src="/vulnerability.svg" width={60} height={60} alt="vulnerability" />
            </div>

            <div className="flex flex-col gap-1 ml-4 mt-2 mb-2">
              <p className="text-sm text-white mt-2">Top Finding is Free</p>
              <p className="text-sm text-gray-400 mb-2 mt-2 mr-2">
                Get the most critical vulnerability for free. Upgrade for $20 to get the full report with detailed
                insights.
              </p>
            </div>
          </div>

          <div className="flex flex-row gap-1 bg-[#18181B] m-4 rounded-lg p-4">
            <div className="flex flex-col gap-1 border-r border-[#27272A] p-4">
              <Image src="/code.svg" width={60} height={60} alt="code" />
            </div>

            <div className="flex flex-col gap-1 ml-4 mt-2 mb-2">
              <p className="text-sm text-white mt-2">Code Length Limit</p>
              <p className="text-sm text-gray-400 mb-2 mt-2 mr-2">
                While in beta, we can analyze approx. 4,000 lines of code to help you enhance your code’s security.
              </p>
            </div>
          </div>
        </ModalBody>
        <ModalFooter>
          <Button className="m-auto w-full" color="secondary" onPress={handleClose}>
            Understood
          </Button>
        </ModalFooter>
      </ModalContent>
    </Modal>
  );
};

export default ScanInfoModal;

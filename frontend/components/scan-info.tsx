import React from "react";
import { Modal, ModalContent, ModalHeader, ModalBody, ModalFooter, Button } from "@nextui-org/react";
import Image from "next/image";

interface ScanInfoProps {
  isOpen: boolean;
  onClose: () => void;
  scanData: any;
}

const ScanInfo: React.FC<ScanInfoProps> = ({ isOpen, onClose, scanData }) => {
  function getOrganizationName(scanData: any) {
    const organizationId = scanData.scan.repositoryURL;
    const organizationName = organizationId.split("/")[3];
    return organizationName;
  }

  return (
    <Modal
      scrollBehavior="inside"
      size="2xl"
      backdrop="blur"
      isOpen={isOpen}
      onClose={onClose}
      className="bg-[#0F0F0F] text-white"
      motionProps={{
        variants: {
          enter: {
            y: 0,
            opacity: 1,
            transition: {
              duration: 0.3,
              ease: "easeOut",
            },
          },
          exit: {
            y: -20,
            opacity: 0,
            transition: {
              duration: 0.2,
              ease: "easeIn",
            },
          },
        },
      }}
    >
      <ModalContent>
        <ModalHeader className="flex flex-col gap-1">Scanned Code Info</ModalHeader>
        <ModalBody>
          <div className="flex flex-row gap-1 bg-[#18181B] m-4 rounded-lg">
            <div className="flex flex-col gap-1 border-r-1 border-[#27272A] p-4">
              <Image src="/repository.svg" width={50} height={50} alt="repository" />
            </div>

            <div className="flex flex-col gap-1 ml-4 mt-2 mb-2">
              <p className="text-sm text-gray-400">Organization</p>
              <p>{getOrganizationName(scanData)}</p>

              <p className="text-sm text-gray-400 mt-4">Repository</p>
              <p>{scanData.scan.repositoryName}</p>
            </div>
          </div>

          <div className="flex flex-row gap-1 bg-[#18181B] m-4 rounded-lg">
            <div className="flex flex-col gap-1 border-r-1 border-[#27272A] p-4">
              <Image src="/branch.svg" width={50} height={50} alt="repository" />
            </div>

            <div className="flex flex-col gap-1 ml-4 mt-2 mb-2">
              <p className="text-sm text-gray-400">Branch</p>
              <p>{scanData.scan.branchName}</p>

              <p className="text-sm text-gray-400 mt-4">Scanned Commit</p>
              <p>{scanData.scan.commitHash.slice(0, 7)}</p>
            </div>
          </div>

          <div className="flex flex-row gap-1 bg-[#18181B] m-4 rounded-lg">
            <div className="flex flex-col gap-1 border-r-1 border-[#27272A] p-4">
              <Image src="/contract.svg" width={50} height={50} alt="repository" />
            </div>

            <div className="flex flex-col gap-1 ml-4 mt-2 mb-2">
              <p className="text-sm text-gray-400">Contract Files</p>
              <p>
                {scanData.scan.contractFiles.map((file: any) => (
                  <div className="mt-1" key={file}>
                    {file}
                  </div>
                ))}
              </p>
            </div>
          </div>
        </ModalBody>
        <ModalFooter>
          <Button color="danger" variant="light" onPress={onClose}>
            Close
          </Button>
        </ModalFooter>
      </ModalContent>
    </Modal>
  );
};

export default ScanInfo;

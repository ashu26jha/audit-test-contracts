import { Fragment, type FC } from "react";

import { Modal, ModalContent, ModalHeader, ModalBody, ModalFooter, Button } from "@nextui-org/react";
import Image from "next/image";

interface InfoSectionProps {
  icon: string;
  items: { label: string; value: string | string[] }[];
}

interface ScanInfoProps {
  isOpen: boolean;
  onClose: () => void;
  scanData: ScanResult;
}

const ScanInfo: FC<ScanInfoProps> = ({ isOpen, onClose, scanData }) => {
  function getOrganizationName(scanData: ScanResult) {
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
          <InfoSection
            icon="/repository.svg"
            items={[
              { label: "Organization", value: getOrganizationName(scanData) },
              { label: "Repository", value: scanData.scan.repositoryName },
            ]}
          />
          <InfoSection
            icon="/branch.svg"
            items={[
              { label: "Branch", value: scanData.scan.branchName },
              { label: "Scanned Commit", value: scanData.scan.commitHash.slice(0, 7) ?? "N/A" },
            ]}
          />
          <InfoSection icon="/contract.svg" items={[{ label: "Contract Files", value: scanData.scan.contractFiles }]} />
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

const InfoSection: FC<InfoSectionProps> = ({ icon, items }) => (
  <div className="flex flex-row gap-1 bg-[#18181B] m-4 rounded-lg">
    <div className="flex flex-col gap-1 border-r-1 border-[#27272A] p-4">
      <Image src={icon} width={50} height={50} alt="icon" />
    </div>
    <div className="flex flex-col gap-1 ml-4 mt-2 mb-2">
      {items.map(({ label, value }, index) => (
        <Fragment key={label}>
          {index > 0 && <p className="text-sm text-gray-400 mt-4">{label}</p>}
          {index === 0 && <p className="text-sm text-gray-400">{label}</p>}
          {Array.isArray(value) ? (
            <>
              {value.map((item) => (
                <p className="mt-1" key={item}>
                  {item}
                </p>
              ))}
            </>
          ) : (
            <p>{value}</p>
          )}
        </Fragment>
      ))}
    </div>
  </div>
);

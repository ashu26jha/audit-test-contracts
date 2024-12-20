import { type FC } from "react";

import { Card, CardBody, Chip } from "@nextui-org/react";
import { Hash, Calendar, AlertTriangle, FileText } from "lucide-react";
import Image from "next/image";

interface ScanCardProps {
  scan: ScanHistoryItem;
  onClick: (scanId: string) => void;
}

const ScanCard: FC<ScanCardProps> = ({ scan, onClick }) => {
  const formattedDate = new Date(scan.startedAt + "Z").toLocaleString(navigator.language, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone,
  });

  const isCompleted = scan.status === "completed";
  const isPaid = isCompleted && scan.paid_status;
  const isFree = isPaid && (scan.total_findings === 0 || scan.total_findings === 1);

  const chipColor = isPaid ? "success" : isCompleted ? "warning" : "primary";
  const chipLabel = isFree ? "free" : isPaid ? "paid" : isCompleted ? "unpaid" : scan.status;

  return (
    <Card
      isPressable
      className="bg-[#222222] cursor-pointer hover:bg-[#333333] transition-colors duration-300"
      onPress={() => onClick(scan.scan_id)}
    >
      <CardBody>
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center">
            <div className="w-10 h-10 mr-3 bg-gray-700 rounded-full flex items-center justify-center">
              <Image src={scan.logo ?? "/svg/github.svg"} alt="logo" width={24} height={24} />
            </div>
            <span className="font-semibold">{scan.repositoryName ?? "Repo Name"}</span>
          </div>
          <Chip color={chipColor} size="sm">
            {chipLabel}
          </Chip>
        </div>
        <div className="space-y-2">
          <div className="flex items-center">
            <Hash size={16} className="mr-2 text-gray-400" />
            <span className="text-sm">Scan ID: {scan.scan_number}</span>
          </div>
          <div className="flex items-center">
            <Calendar size={16} className="mr-2 text-gray-400" />
            <span className="text-sm">Scanned Date: {formattedDate}</span>
          </div>
          <div className="flex items-center">
            <AlertTriangle size={16} className="mr-2 text-gray-400" />
            <span className="text-sm">Vulnerabilities Found: {scan.total_findings ?? 0}</span>
          </div>
          <div className="flex items-center">
            <FileText size={16} className="mr-2 text-gray-400" />
            <span className="text-sm">Contracts Scanned: {scan.contractFiles.length}</span>
          </div>
        </div>
      </CardBody>
    </Card>
  );
};

export default ScanCard;

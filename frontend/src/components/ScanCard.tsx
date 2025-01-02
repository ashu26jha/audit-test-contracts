import { type FC } from "react";

import { Card, CardBody, Chip } from "@nextui-org/react";
import { Hash, Calendar, AlertTriangle, type LucideIcon } from "lucide-react";
import Image from "next/image";

interface ScanCardProps {
  repository: RepositoriesData;
  onClick: () => void;
}

const ScanCard: FC<ScanCardProps> = ({ repository, onClick }) => {
  const { latestScan } = repository;

  const formattedDate = new Date(latestScan?.startedAt + "Z").toLocaleString(navigator.language, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone,
  });

  const chipColor = repository.hasUnpaidScans ? "warning" : repository.hasActiveScans ? "primary" : "success";
  const chipLabel = repository.hasUnpaidScans
    ? "unpaid scans"
    : repository.hasActiveScans
      ? "active scans"
      : "all paid";

  return (
    <Card
      isPressable
      className="bg-content-1 border border-default-100 cursor-pointer hover:bg-content2 transition-colors duration-300"
      onPress={onClick}
    >
      <CardBody>
        <div className="flex items-center justify-between mb-4 border-b border-default-100 pb-4">
          <div className="flex items-center">
            <div className="w-10 h-10 mr-3 bg-gray-700 rounded-lg flex items-center justify-center">
              <Image
                src={repository.logo ?? "/svg/github.svg"}
                alt="logo"
                width={24}
                height={24}
                className="rounded-sm"
              />
            </div>
            <span className="font-semibold">{repository.repositoryName ?? "Repo Name"}</span>
          </div>
          <Chip color={chipColor} size="sm">
            {chipLabel}
          </Chip>
        </div>
        <div className="space-y-2">
          <InfoRow icon={Calendar} label="Last Scanned" value={formattedDate} />
          <InfoRow icon={AlertTriangle} label="Total Vulnerabilities" value={latestScan?.total_findings ?? "-"} />
          <InfoRow icon={Hash} label="No. of Scans" value={repository.totalScans} />
        </div>
      </CardBody>
    </Card>
  );
};

export default ScanCard;

interface InfoRowProps {
  icon: LucideIcon;
  label: string;
  value: string | number;
}

const InfoRow: FC<InfoRowProps> = ({ icon: Icon, label, value }) => {
  return (
    <div className="flex items-center justify-between">
      <div className="flex items-center">
        <Icon size={16} className="mr-2 text-gray-400" />
        <span className="text-sm">{label}</span>
      </div>
      <span className="text-sm">{value}</span>
    </div>
  );
};

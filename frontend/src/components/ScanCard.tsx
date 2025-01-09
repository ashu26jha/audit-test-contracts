import { type FC } from "react";

import { Card, CardBody } from "@nextui-org/react";
import { Hash, Calendar, AlertTriangle, type LucideIcon } from "lucide-react";
import Image from "next/image";

import { formatDate } from "@/utils/datetime";

interface ScanCardProps {
  repository: RepositoriesData;
  onClick: () => void;
}

const ScanCard: FC<ScanCardProps> = ({ repository, onClick }) => {
  const { latestScan } = repository;

  const formattedDate = formatDate(latestScan?.startedAt + "Z", "MMM d, yyyy, HH:mm");

  return (
    <Card
      isPressable
      className="bg-content-1 border border-default-100 cursor-pointer hover:bg-content2 transition-colors duration-300"
      onPress={onClick}
    >
      <CardBody>
        <div className="flex items-center justify-between mb-4 border-b border-default-100 pb-4">
          <div className="flex items-center">
            <div className="w-10 h-10 mr-3 bg-default-100 rounded-lg flex items-center justify-center border border-default">
              <Image
                src={repository.logo ?? "/svg/default_repo.svg"}
                alt="logo"
                width={22}
                height={22}
                className="rounded-sm"
              />
            </div>
            <span className="font-semibold">{repository.repositoryName ?? "Repo Name"}</span>
          </div>
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

"use client";

import type { FC } from "react";

import {
  Table,
  TableHeader,
  TableColumn,
  TableBody,
  TableRow,
  TableCell,
  Pagination,
  Chip,
  Button,
} from "@nextui-org/react";
import { ArrowRight } from "lucide-react";

import { formatScanStatus, getScanStatusVariant } from "@/utils/formatters";

const columns = [
  { key: "scanID", label: "SCAN ID" },
  { key: "status", label: "STATUS" },
  { key: "vulnerabilities", label: "VULNERABILITIES" },
  { key: "contracts", label: "CONTRACTS" },
  { key: "date", label: "DATE" },
  { key: "commitHash", label: "COMMIT HASH" },
  { key: "action", label: "ACTION" },
];

interface ScanTableProps {
  scans: ScanHistoryItem[];
  currentPage: number;
  totalPages: number;
  onPageChange: (page: number) => void;
  onScanClick: (scanId: string) => void;
}

const ScanTable: FC<ScanTableProps> = ({ scans, currentPage, totalPages, onPageChange, onScanClick }) => {
  return (
    <Table
      aria-label="Repository scans table"
      classNames={{
        th: "bg-background",
        wrapper: "bg-content-1 border-2 border-default-100",
        tr: "h-11",
      }}
      bottomContent={
        scans.length > 0 && (
          <Pagination
            color="secondary"
            className="mx-auto"
            page={currentPage}
            total={totalPages}
            onChange={onPageChange}
            isDisabled={totalPages <= 1}
          />
        )
      }
      bottomContentPlacement="outside"
    >
      <TableHeader columns={columns}>
        {columns.map((column) => (
          <TableColumn key={column.key}>{column.label}</TableColumn>
        ))}
      </TableHeader>
      <TableBody emptyContent={"No scans found."}>
        {scans.map((scan) => (
          <TableRow key={scan.scan_id}>
            <TableCell>{scan.scan_number}</TableCell>
            <TableCell>
              <Chip color={getScanStatusVariant(scan.status, scan.paid_status)} variant="flat" size="sm" radius="sm">
                {formatScanStatus(scan.status, scan.paid_status)}
              </Chip>
            </TableCell>
            <TableCell>{scan.total_findings}</TableCell>
            <TableCell>{scan.contractFiles.length}</TableCell>
            <TableCell>{new Date(scan.startedAt + "Z").toLocaleString()}</TableCell>
            <TableCell>{scan.commitHash}</TableCell>
            <TableCell>
              <Button
                className="text-secondary-600 min-w-0 p-0 h-auto bg-transparent"
                variant="light"
                onPress={() => onScanClick(scan.scan_id)}
                endContent={<ArrowRight size={15} />}
              >
                View
              </Button>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
};

export default ScanTable;

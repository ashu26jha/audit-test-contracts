import { useMemo, useState } from "react";

import type { DateValue, RangeValue } from "@nextui-org/react";

export const useScansFiltering = (scans: ScanHistoryItem[]) => {
  const [selectedFilter, setSelectedFilter] = useState<FilterKey | null>(null);
  const [selectedDateRange, setSelectedDateRange] = useState<RangeValue<DateValue> | null>(null);

  const filteredScans = useMemo(() => {
    let filteredScans = [...scans];
    // Apply date range filter if selected
    if (selectedDateRange?.start && selectedDateRange?.end) {
      const startDate = new Date(selectedDateRange.start.toString());
      const endDate = new Date(selectedDateRange.end.toString());
      endDate.setHours(23, 59, 59, 999);

      filteredScans = filteredScans.filter((scan) => {
        const scanDate = new Date(scan.startedAt);
        return scanDate >= startDate && scanDate <= endDate;
      });
    }

    switch (selectedFilter) {
      case "newest":
        return filteredScans.sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime());
      case "oldest":
        return filteredScans.sort((a, b) => new Date(a.startedAt).getTime() - new Date(b.startedAt).getTime());
      case "most_vulnerabilities":
        return filteredScans.sort((a, b) => (b.total_findings ?? 0) - (a.total_findings ?? 0));
      case "least_vulnerabilities":
        return filteredScans.sort((a, b) => (a.total_findings ?? 0) - (b.total_findings ?? 0));
      default:
        // Default sorting: newest first
        return filteredScans.sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime());
    }
  }, [scans, selectedFilter, selectedDateRange]);

  return {
    selectedDateRange,
    setSelectedDateRange,
    selectedFilter,
    setSelectedFilter,
    filteredScans,
  };
};

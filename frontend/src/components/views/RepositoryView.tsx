"use client";

import { type FC, useState, useEffect } from "react";

import { AlertCircle } from "lucide-react";
import { useRouter } from "next/navigation";

import { Container, Loading, ScanFilters, ScanTable, StateMessage } from "@/components/layout";
import { useFetchScanHistory, useScansFiltering } from "@/hooks";

interface RepositoryViewProps {
  repoId: string;
}

const RepositoryView: FC<RepositoryViewProps> = ({ repoId }) => {
  const router = useRouter();
  const { getRepositoryScans, repositories, isLoading } = useFetchScanHistory();
  const [currentPage, setCurrentPage] = useState(1);
  const rowsPerPage = 10;

  const repository = repositories.find((repo) => repo.repositoryName === repoId);
  const rawScans = repository ? getRepositoryScans(repository.repositoryName) : [];

  const { selectedDateRange, setSelectedDateRange, selectedFilter, setSelectedFilter, filteredScans } =
    useScansFiltering(rawScans);

  // Reset pagination when filter changes
  useEffect(() => {
    setCurrentPage(1);
  }, [selectedFilter]);

  if (isLoading) return <Loading text="Loading data" subText="Please wait..." />;

  if (!isLoading && !repository) {
    return <StateMessage message="Repository not found" icon={<AlertCircle size={20} />} />;
  }

  const pages = Math.ceil(filteredScans.length / rowsPerPage);
  const start = (currentPage - 1) * rowsPerPage;
  const end = start + rowsPerPage;
  const paginatedScans = filteredScans.slice(start, end);

  return (
    <Container
      breadcrumbItems={[
        { label: "Dashboard", href: "/dashboard" },
        { label: repository?.repositoryName ?? "", href: `/repository/${repository?.repositoryName}` },
      ]}
      buttons={
        <ScanFilters
          selectedDateRange={selectedDateRange}
          setSelectedDateRange={setSelectedDateRange}
          selectedFilter={selectedFilter}
          onFilterSelect={setSelectedFilter}
          onClearFilter={() => setSelectedFilter(null)}
        />
      }
    >
      <ScanTable
        scans={paginatedScans}
        currentPage={currentPage}
        totalPages={pages}
        onPageChange={setCurrentPage}
        onScanClick={(scanId) => router.push(`/scan-results/${scanId}`)}
      />
    </Container>
  );
};

export default RepositoryView;

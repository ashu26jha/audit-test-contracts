"use client";

import { type FC } from "react";

import { useSearchParams } from "next/navigation";

import { ProtectedRoute } from "@/components/layout";
import { ScanInfoModal } from "@/components/Modals";
import { DashboardView, ScanStepperView } from "@/components/views";

const DashboardPage: FC = () => {
  const searchParams = useSearchParams();
  const tab = searchParams.get("tab") || "home";

  return (
    <ProtectedRoute>
      <ScanInfoModal />
      {tab === "scan" ? <ScanStepperView /> : <DashboardView />}
    </ProtectedRoute>
  );
};

export default DashboardPage;

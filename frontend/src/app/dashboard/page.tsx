"use client";

import { type FC } from "react";

import { ProtectedRoute } from "@/components/layout";
import ScanInfoModal from "@/components/Modals/ScanInfoModal";
import { DashboardView, ScanStepperView } from "@/components/views";
import { useScanStepperStore } from "@/store/scanStepperStore";

const DashboardPage: FC = () => {
  const { showStepper } = useScanStepperStore();

  return (
    <ProtectedRoute>
      <ScanInfoModal />
      {showStepper ? <ScanStepperView /> : <DashboardView />}
    </ProtectedRoute>
  );
};

export default DashboardPage;

"use client";

import { useCallback, useEffect, useState, type FC } from "react";

import { Button, Card, CardHeader } from "@nextui-org/react";
import type { AxiosError } from "axios";
import { ArrowRight } from "lucide-react";
import { useRouter } from "next/navigation";

import { STEPS } from "@/config/steps";
import { useAuth } from "@/contexts/AuthContext";
import { useToast, useScanStepper } from "@/hooks";
import { useScanStepperStore } from "@/store/scanStepperStore";

import { Loading } from "../layout";
import Breadcrumb from "../layout/Breadcrumb";
import CreditWarningModal from "../Modals/CreditWarningModal";
import TalkToSalesModal from "../Modals/TalkToSalesModal";
import { BranchSelection, ContractSelection, RepositorySelection, StepperVisualization } from "../scan-stepper";

const ScanStepperView: FC = () => {
  const router = useRouter();
  const { setShowStepper } = useScanStepperStore();
  const { toast } = useToast();
  const {
    currentStep,
    selectedOwner,
    selectedRepo,
    selectedBranch,
    selectedContracts,
    isScanning,
    repositoryURL,
    isValidURL,
    isLineExceeded,
    isFileLimitExceeded,
    setCurrentStep,
    setIsScanning,
    setIsNextEnabled,
    resetStepper,
  } = useScanStepperStore();
  const { fetchRepositories, fetchBranches, fetchSolidityFiles, initiateScanProcess } = useScanStepper();
  const [openWarningDialog, setOpenWarningDialog] = useState<boolean>(false);
  const { user } = useAuth();

  useEffect(() => {
    if (selectedOwner) {
      fetchRepositories(selectedOwner);
    }
  }, [selectedOwner, fetchRepositories]);

  useEffect(() => {
    if (selectedOwner && selectedRepo) {
      fetchBranches(selectedOwner, selectedRepo);
    }
  }, [selectedOwner, selectedRepo, fetchBranches]);

  useEffect(() => {
    if (selectedOwner && selectedRepo && selectedBranch) {
      fetchSolidityFiles(selectedOwner, selectedRepo, selectedBranch);
    }
  }, [selectedOwner, selectedRepo, selectedBranch, fetchSolidityFiles]);

  const isNextStepEnabled = useCallback(() => {
    const isStep1Valid =
      currentStep === 1 && selectedOwner !== null && selectedRepo !== null && (repositoryURL === "" || isValidURL);
    const isStep2Valid = currentStep === 2 && selectedBranch !== "";
    const isStep3Valid = currentStep === 3 && selectedContracts.length > 0;
    return isStep1Valid || isStep2Valid || isStep3Valid;
  }, [currentStep, selectedOwner, selectedRepo, selectedBranch, selectedContracts, repositoryURL, isValidURL]);

  useEffect(() => {
    resetStepper();
  }, [resetStepper]);

  useEffect(() => {
    setIsNextEnabled(isNextStepEnabled());
  }, [isNextStepEnabled, setIsNextEnabled]);

  const startScan = async () => {
    // prettier-ignore
    if (typeof window !== "undefined" && window._mtm != undefined) {
      window._mtm.push({ "event": "scan-started" });
    }
    setIsScanning(true);
    try {
      const response = await initiateScanProcess();
      router.push(`/scan-results/${response.data.scan_id}`);
    } catch (error) {
      console.error("Error initiating scan:", error);
      setIsScanning(false);
      toast({
        title:
          ((error as AxiosError).response?.data as { message?: string })?.message ??
          "An error occurred while initiating the scan.",
        status: "error",
        duration: 3000,
      });
    }
  };

  const handleScan = async () => {
    if (currentStep === STEPS.length) {
      if (user?.subscription.credits === 1 || user?.subscription.credits === 0) {
        setOpenWarningDialog(true);
        return;
      }

      startScan();
    } else {
      if (typeof window !== "undefined" && window._mtm != undefined) {
        // prettier-ignore
        if (currentStep === 1) {
          window._mtm.push({ "event": "branch-selection" });
        } else if (currentStep === 2) {
          window._mtm.push({ "event": "contract-selection" });
        }
      }
      setCurrentStep(currentStep + 1);
    }
  };

  const handleBack = () => {
    if (currentStep === 1) {
      resetStepper();
      setShowStepper(false);
    }
    if (currentStep > 1) {
      setCurrentStep(currentStep - 1);
    }

    router.push("/dashboard");
  };

  if (isScanning) {
    return <Loading subText="Preparing your scan, please wait..." />;
  }

  return (
    <>
      {user?.subscription.credits === 1 && (
        <CreditWarningModal isOpen={openWarningDialog} setIsOpen={setOpenWarningDialog} onClick={startScan} />
      )}

      {user?.subscription.credits === 0 && (
        <TalkToSalesModal isOpen={openWarningDialog} setIsOpen={setOpenWarningDialog} />
      )}

      <Card className="h-full">
        <CardHeader className="p-4 flex justify-between items-center border-t border-b border-gray-800">
          <Breadcrumb base="Dashboard" current="Scan Code" />
          <div>
            <Button className="mr-2" onClick={handleBack}>
              Go Back
            </Button>
            <Button
              color="secondary"
              className="bg-[#8B5CF6] disabled:bg-[#7f69b3] disabled:hover:bg-[#7f69b3]"
              disabled={
                !useScanStepperStore.getState().isNextEnabled ||
                (currentStep === STEPS.length && (isLineExceeded || isFileLimitExceeded))
              }
              endContent={<ArrowRight size={20} />}
              onClick={handleScan}
            >
              {currentStep === STEPS.length ? "Scan Code" : "Next"}
            </Button>
          </div>
        </CardHeader>

        <main className="flex-grow p-8 overflow-y-auto">
          <StepperVisualization currentStep={currentStep} />

          <div className="max-w-5xl mx-auto mt-4 flex flex-col gap-4">
            {currentStep === 1 && <RepositorySelection />}
            {currentStep === 2 && <BranchSelection />}
            {currentStep === 3 && <ContractSelection />}
          </div>
        </main>
      </Card>
    </>
  );
};

export default ScanStepperView;

"use client";

import { useCallback, useEffect, useState, type FC } from "react";

import { Button } from "@nextui-org/react";
import type { AxiosError } from "axios";
import { ArrowRight } from "lucide-react";
import { useRouter } from "next/navigation";

import { Container, Loading } from "@/components/layout";
import { CreditWarningModal, TalkToSalesModal } from "@/components/Modals";
import {
  BranchSelection,
  ContractSelection,
  RepositorySelection,
  StepperVisualization,
} from "@/components/scan-stepper";
import { DocsSelection } from "@/components/scan-stepper/DocsSelection";
import { STEPS } from "@/config/steps";
import { useAuth } from "@/contexts/AuthContext";
import { useToast, useScanStepper } from "@/hooks";
import { useScanStepperStore } from "@/store/scanStepperStore";

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
  const { user, refetchUser } = useAuth();

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
    const isSetp4Valid = currentStep === 4;
    return isStep1Valid || isStep2Valid || isStep3Valid || isSetp4Valid;
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
      refetchUser();
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
      if (user?.subscription.isActive && (user?.subscription.credits === 1 || user?.subscription.credits === 0)) {
        setOpenWarningDialog(true);
        return;
      }

      await startScan();
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
      {user?.subscription.isActive && user?.subscription.credits === 1 && (
        <CreditWarningModal isOpen={openWarningDialog} setIsOpen={setOpenWarningDialog} onClick={startScan} />
      )}

      {user?.subscription.isActive && user?.subscription.credits === 0 && (
        <TalkToSalesModal
          isOpen={openWarningDialog}
          setIsOpen={setOpenWarningDialog}
          creditsPerMonth={user?.subscription.credits}
        />
      )}

      <Container
        breadcrumbItems={["Dashboard", "Scan Code"]}
        buttons={
          <div>
            <Button className="mr-2 rounded-lg bg-content-1 border border-default-flat" onPress={handleBack}>
              Go Back
            </Button>
            <Button
              color="secondary"
              className="bg-[#8B5CF6] disabled:bg-[#7f69b3] disabled:hover:bg-[#7f69b3] rounded-lg"
              isDisabled={!useScanStepperStore.getState().isNextEnabled || isLineExceeded || isFileLimitExceeded}
              endContent={<ArrowRight size={20} />}
              onPress={handleScan}
            >
              {currentStep === STEPS.length ? "Scan Code" : "Next"}
            </Button>
          </div>
        }
      >
        <div className="h-24 flex justify-center items-start border-b-2 border-default-100">
          <StepperVisualization currentStep={currentStep} />
        </div>

        <div className="flex-1 min-h-0 w-full flex flex-col items-center gap-4 overflow-auto pt-8">
          {currentStep === 1 && <RepositorySelection />}
          {currentStep === 2 && <BranchSelection />}
          {currentStep === 3 && <ContractSelection />}
          {currentStep === 4 && <DocsSelection />}
        </div>
      </Container>
    </>
  );
};

export default ScanStepperView;

import React, { useCallback, useEffect } from "react";

import { Button, Card, CardHeader } from "@nextui-org/react";
import type { AxiosError } from "axios";
import { ArrowRight } from "lucide-react";
import { useRouter } from "next/navigation";

import { useAuth } from "@/contexts/AuthContext";
import { STEPS } from "@/data/steps";
import { useToast, useScanStepper } from "@/hooks";
import { useScanStepperStore } from "@/store/scanStepperStore";

import { Loading } from "./Loading";
import { BranchSelection, ContractSelection, RepositorySelection, StepperVisualization } from "./scan-stepper/";
import Breadcrumb from "./shared/Breadcrumb";

interface ScanStepperProps {
  setShowStepper: (show: boolean) => void;
}

const ScanStepper: React.FC<ScanStepperProps> = ({ setShowStepper }) => {
  const router = useRouter();
  const { toast } = useToast();
  const { user } = useAuth();
  const {
    currentStep,
    selectedOwner,
    selectedRepo,
    selectedBranch,
    selectedContracts,
    isScanning,
    repositoryURL,
    isLineExceeded,
    isFileLimitExceeded,
    setCurrentStep,
    setIsScanning,
    setIsNextEnabled,
    resetStepper,
  } = useScanStepperStore();
  const { fetchRepositories, fetchBranches, fetchSolidityFiles, initiateScanProcess } = useScanStepper();

  useEffect(() => {
    if (user && selectedOwner) {
      fetchRepositories(selectedOwner);
    }
  }, [user, selectedOwner, fetchRepositories]);

  useEffect(() => {
    if (user && selectedOwner && selectedRepo) {
      fetchBranches(selectedOwner, selectedRepo);
    }
  }, [user, selectedOwner, selectedRepo, fetchBranches]);

  useEffect(() => {
    if (user && selectedOwner && selectedRepo && selectedBranch) {
      fetchSolidityFiles(selectedOwner, selectedRepo, selectedBranch);
    }
  }, [user, selectedOwner, selectedRepo, selectedBranch, fetchSolidityFiles]);

  const isNextStepEnabled = useCallback(() => {
    const isStep1Valid =
      currentStep === 1 && ((selectedOwner !== null && selectedRepo !== null) || repositoryURL !== "");
    const isStep2Valid = currentStep === 2 && selectedBranch !== "";
    const isStep3Valid = currentStep === 3 && selectedContracts.length > 0;
    return isStep1Valid || isStep2Valid || isStep3Valid;
  }, [currentStep, selectedOwner, selectedRepo, selectedBranch, selectedContracts, repositoryURL]);

  useEffect(() => {
    resetStepper();
  }, [resetStepper]);

  useEffect(() => {
    setIsNextEnabled(isNextStepEnabled());
  }, [isNextStepEnabled, setIsNextEnabled]);

  const handleScan = async () => {
    if (currentStep === STEPS.length) {
      // prettier-ignore
      if (typeof window !== "undefined" && window._mtm != undefined) {
        window._mtm.push({ "event": "scan-started" });
      }
      setIsScanning(true);
      try {
        if (user) {
          const response = await initiateScanProcess();
          router.push(`/scan-results/${response.data.scan_id}`);
        }
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
    return <Loading subText="Please wait while we analyze your code." />;
  }

  return (
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
        <StepperVisualization />

        <div className="max-w-5xl mx-auto mt-4 flex flex-col gap-4">
          {currentStep === 1 && <RepositorySelection />}
          {currentStep === 2 && <BranchSelection />}
          {currentStep === 3 && <ContractSelection />}
        </div>
      </main>
    </Card>
  );
};

export default ScanStepper;

import React, { useCallback, useEffect } from "react";

import { Button, Card, CardHeader } from "@nextui-org/react";
import type { AxiosError } from "axios";
import { ArrowRight } from "lucide-react";
import { useRouter } from "next/navigation";

import { STEPS } from "@/data/steps";
import { useToast } from "@/hooks/useToast";

import { Loading } from "./Loading";
import { useAuth } from "../contexts/AuthContext";
import { useScanStepper } from "../hooks/useScanStepper";
import { useScanStepperStore } from "../store/scanStepperStore";
import { BranchSelection } from "./scan-stepper/BranchSelection";
import { ContractSelection } from "./scan-stepper/ContractSelection";
import { RepositorySelection } from "./scan-stepper/RepositorySelection";
import { StepperVisualization } from "./scan-stepper/StepperVisualization";
import { MAX_TOKENS } from "../config/constants";

const ScanStepper: React.FC = () => {
  const router = useRouter();
  const { toast } = useToast();
  const { token } = useAuth();
  const {
    currentStep,
    selectedOwner,
    selectedRepo,
    selectedBranch,
    selectedContracts,
    isLoading,
    repositoryURL,
    tokens,
    setCurrentStep,
    setIsLoading,
    setIsNextEnabled,
    resetStepper,
  } = useScanStepperStore();

  const { fetchOwners, fetchRepositories, fetchBranches, fetchSolidityFiles, initiateScanProcess } = useScanStepper();

  useEffect(() => {
    if (token) {
      fetchOwners(token);
    }
  }, [token, fetchOwners]);

  useEffect(() => {
    if (token && selectedOwner) {
      fetchRepositories(token, selectedOwner);
    }
  }, [token, selectedOwner, fetchRepositories]);

  useEffect(() => {
    if (token && selectedOwner && selectedRepo) {
      fetchBranches(token, selectedOwner, selectedRepo);
    }
  }, [token, selectedOwner, selectedRepo, fetchBranches]);

  useEffect(() => {
    if (token && selectedOwner && selectedRepo && selectedBranch) {
      fetchSolidityFiles(token, selectedOwner, selectedRepo, selectedBranch);
    }
  }, [token, selectedOwner, selectedRepo, selectedBranch, fetchSolidityFiles]);

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
      if (tokens > MAX_TOKENS) {
        return;
      }
      setIsLoading(true);
      try {
        if (token) {
          const response = await initiateScanProcess(token);
          router.push(`/scan-results/${response.data.scan_id}`);
        }
      } catch (error) {
        console.error("Error initiating scan:", error);
        setIsLoading(false);
        toast({
          title:
            ((error as AxiosError).response?.data as { message?: string })?.message ??
            "An error occurred while initiating the scan.",
          status: "error",
          duration: 3000,
        });
      }
    } else {
      setCurrentStep(currentStep + 1);
    }
  };

  const handleBack = () => {
    if (currentStep === 1) {
      resetStepper();
    }
    if (currentStep > 1) {
      setCurrentStep(currentStep - 1);
    }

    router.push("/dashboard");
  };

  if (isLoading) {
    return <Loading subText="Please wait while we analyze your code." />;
  }

  return (
    <Card className="h-full">
      <CardHeader className="p-4 flex justify-between items-center border-t border-b border-gray-800">
        <div className="text-sm text-gray-400 flex">
          Dashboard <div className="mx-2">/</div> <div className="text-white">Scan Code</div>
        </div>
        <div>
          <Button className="mr-2" onClick={handleBack} disabled={currentStep === 1}>
            Go Back
          </Button>
          <Button
            color="secondary"
            className="bg-[#8B5CF6] disabled:bg-[#7f69b3] disabled:hover:bg-[#7f69b3]"
            disabled={!useScanStepperStore.getState().isNextEnabled}
            endContent={<ArrowRight size={20} />}
            onClick={handleScan}
          >
            {currentStep === STEPS.length ? "Scan Code" : "Next"}
          </Button>
        </div>
      </CardHeader>

      <main className="flex-grow p-8 overflow-y-auto">
        <StepperVisualization />

        <div className="max-w-2xl mx-auto mt-4 flex flex-col gap-4">
          {currentStep === 1 && <RepositorySelection />}
          {currentStep === 2 && <BranchSelection />}
          {currentStep === 3 && <ContractSelection />}
        </div>
      </main>
    </Card>
  );
};

export default ScanStepper;

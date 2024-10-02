import React, { useEffect } from "react";

import { Button, Card, CardHeader } from "@nextui-org/react";
import { ArrowRight } from "lucide-react";
import { useRouter } from "next/navigation";

import { STEPS } from "@/data/steps";

import { Loading } from "./Loading";
import { useAuth } from "../contexts/AuthContext";
import { useScanStepper } from "../hooks/useScanStepper";
import { useScanStepperStore } from "../store/scanStepperStore";
import { BranchSelection } from "./scan-stepper/BranchSelection";
import { ContractSelection } from "./scan-stepper/ContractSelection";
import { OwnerSelection } from "./scan-stepper/OwnerSelection";
import { RepositorySelection } from "./scan-stepper/RepositorySelection";
import { StepperVisualization } from "./scan-stepper/StepperVisualization";

const ScanStepper: React.FC = () => {
  const router = useRouter();
  const { token } = useAuth();
  const {
    currentStep,
    selectedOwner,
    selectedRepo,
    selectedBranch,
    selectedContracts,
    isLoading,
    setCurrentStep,
    setIsLoading,
    setIsNextEnabled,
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

  useEffect(() => {
    setIsNextEnabled(
      (currentStep === 1 && selectedOwner !== null && selectedRepo !== null) ||
        (currentStep === 2 && selectedBranch !== "") ||
        (currentStep === 3 && selectedContracts.length > 0),
    );
  }, [currentStep, selectedOwner, selectedRepo, selectedBranch, selectedContracts, setIsNextEnabled]);

  const handleScan = async () => {
    if (currentStep === STEPS.length) {
      setIsLoading(true);
      try {
        if (token) {
          const response = await initiateScanProcess(token);
          console.log("Scan initiated:", response);
          router.push(`/scan-results/${response.data.scan_id}`);
        }
      } catch (error) {
        console.error("Error initiating scan:", error);
        setIsLoading(false);
      }
    } else {
      setCurrentStep(currentStep + 1);
    }
  };

  const handleBack = () => {
    if (currentStep > 1) {
      setCurrentStep(currentStep - 1);
    } else {
      router.push("/dashboard");
    }
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

      <main className="flex-grow p-8">
        <StepperVisualization />

        <div className="max-w-2xl mx-auto mt-4">
          {currentStep === 1 && (
            <>
              <OwnerSelection />
              <RepositorySelection />
            </>
          )}

          {currentStep === 2 && <BranchSelection />}

          {currentStep === 3 && <ContractSelection />}
        </div>
      </main>
    </Card>
  );
};

export default ScanStepper;

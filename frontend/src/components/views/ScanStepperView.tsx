"use client";

import { useCallback, useEffect, useMemo, useState, type FC } from "react";

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
  SubscriptionSelection,
} from "@/components/scan-stepper";
import { DocsSelection } from "@/components/scan-stepper/DocsSelection";
import { useAuth } from "@/contexts/AuthContext";
import { useToast, useScanStepper } from "@/hooks";
import { useSubscription } from "@/hooks/useSubscription";
import { usePaymentStore } from "@/store/paymentStore";
import { useScanStepperStore } from "@/store/scanStepperStore";

import InvariantsSelection from "../scan-stepper/InvariantsSelection";
import QnASelection from "../scan-stepper/QnASelection";

const ScanStepperView: FC = () => {
  const router = useRouter();
  const { toast } = useToast();
  const {
    currentStep,
    selectedOwner,
    selectedRepo,
    selectedBranch,
    selectedLanguage,
    selectedContracts,
    isScanning,
    repositoryURL,
    isValidURL,
    isLineExceeded,
    isFileLimitExceeded,
    selectedPlan,
    setCurrentStep,
    setIsScanning,
    setIsNextEnabled,
    resetStepper,
  } = useScanStepperStore();
  const { fetchRepositories, fetchBranches, fetchContractFiles, initiateScanProcess, stepsData } = useScanStepper();
  const [openWarningDialog, setOpenWarningDialog] = useState<boolean>(false);
  const { user, refetchUser } = useAuth();
  const { freeScanAllowed, checkIfFreeScanAllowed, handleSubscribe } = useSubscription();

  const { setToastStarted, setShouldPoll } = usePaymentStore();

  const stepIndexIncrement = useMemo(() => {
    const isSubscribed = user?.subscription.type !== "free";
    if (isSubscribed) {
      return 0;
    }
    return 1;
  }, [user?.subscription.type]);

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
    if (selectedOwner && selectedRepo && selectedBranch && selectedLanguage) {
      fetchContractFiles(selectedOwner, selectedRepo, selectedBranch, selectedLanguage);
    }
  }, [selectedOwner, selectedRepo, selectedBranch, selectedLanguage, fetchContractFiles]);

  const isNextStepEnabled = useCallback(() => {
    let isStep0Valid =
      currentStep === 0 && selectedPlan !== null && freeScanAllowed && user?.subscription.type === "free";

    if (!freeScanAllowed && selectedPlan === "pro") {
      isStep0Valid = true;
    }

    const isStep1Valid =
      currentStep === 1 && selectedOwner !== null && selectedRepo !== null && (repositoryURL === "" || isValidURL);
    const isStep2Valid = currentStep === 2 && selectedBranch !== "";
    const isStep3Valid = currentStep === 3 && selectedContracts.length > 0;
    const isSetp4Valid = currentStep === 4;
    const isSetp5Valid = currentStep === 5;
    const isSetp6Valid = currentStep === 6;

    return isStep0Valid || isStep1Valid || isStep2Valid || isStep3Valid || isSetp4Valid || isSetp5Valid || isSetp6Valid;
  }, [
    freeScanAllowed,
    currentStep,
    selectedOwner,
    selectedRepo,
    selectedBranch,
    selectedContracts,
    repositoryURL,
    isValidURL,
    selectedPlan,
    user,
  ]);

  useEffect(() => {
    resetStepper(user?.subscription.type === "free" ? 0 : 1);
  }, [resetStepper, user?.subscription.type]);

  useEffect(() => {
    setIsNextEnabled(isNextStepEnabled());
  }, [isNextStepEnabled, setIsNextEnabled]);

  useEffect(() => {
    checkIfFreeScanAllowed();
  }, [checkIfFreeScanAllowed]);

  const startScan = async () => {
    // prettier-ignore
    if (typeof window !== "undefined" && window._mtm != undefined) {
      window._mtm.push({ "event": "scan-started" });
    }
    setIsScanning(true);
    try {
      const response = await initiateScanProcess();
      refetchUser();
      setToastStarted(false); // To start the toast
      setShouldPoll(true); // To start polling the scan progress
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
    if (currentStep === 0 && selectedPlan === "pro") {
      await handleSubscribe("pro");
      return;
    }

    if (currentStep + stepIndexIncrement === stepsData.length) {
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
    if (user?.subscription.type === "free" && currentStep === 0) {
      resetStepper(0);
      router.push("/dashboard?tab=home");
    } else if (user?.subscription.type !== "free" && currentStep === 1) {
      resetStepper(1);
      router.push("/dashboard?tab=home");
    } else {
      setCurrentStep(currentStep - 1);
    }
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
          creditsPerMonth={user?.subscription.monthlyCredits}
        />
      )}

      <Container
        breadcrumbItems={[
          { label: "Dashboard", href: "/dashboard?tab=home" },
          { label: "Scan Code", href: "/dashboard?tab=scan" },
        ]}
        disableTopPadding={true}
        buttons={
          <div className="flex flex-row gap-2">
            <Button
              className="mr-2 rounded-lg bg-content-1 border border-default-flat"
              onPress={handleBack}
              disableAnimation
            >
              Go Back
            </Button>
            <Button
              color="secondary"
              className="bg-[#8B5CF6] disabled:bg-[#7f69b3] disabled:hover:bg-[#7f69b3] rounded-lg"
              isDisabled={!useScanStepperStore.getState().isNextEnabled || isLineExceeded || isFileLimitExceeded}
              disableAnimation
              endContent={<ArrowRight size={20} />}
              onPress={handleScan}
            >
              {currentStep === 0 && (freeScanAllowed && selectedPlan === "free" ? "Continue" : "Pay & Continue")}
              {currentStep > 0 && (currentStep + stepIndexIncrement === stepsData.length ? "Scan Code" : "Next")}
            </Button>
          </div>
        }
      >
        <div className="sm:h-16 p-2 flex justify-center items-center border-b-2 border-default-100">
          <StepperVisualization currentStep={currentStep} />
        </div>

        <div className="flex-1 min-h-0 w-full flex flex-col items-center gap-4 overflow-auto py-8">
          {currentStep === 0 && <SubscriptionSelection />}
          {currentStep === 1 && <RepositorySelection />}
          {currentStep === 2 && <BranchSelection />}
          {currentStep === 3 && <ContractSelection />}
          {currentStep === 4 && <DocsSelection />}
          {currentStep === 5 && <QnASelection />}
          {currentStep === 6 && <InvariantsSelection />}
        </div>
      </Container>
    </>
  );
};

export default ScanStepperView;

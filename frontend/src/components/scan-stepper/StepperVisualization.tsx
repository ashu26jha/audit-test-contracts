import { useMemo, type FC } from "react";

import Image from "next/image";

import { useAuth } from "@/contexts/AuthContext";
import { useScanStepper } from "@/hooks";

interface StepperVisualizationProps {
  readonly currentStep: number;
}

export const StepperVisualization: FC<StepperVisualizationProps> = ({ currentStep }) => {
  const { stepsData } = useScanStepper();
  const { user } = useAuth();

  const indexIncrement = useMemo(() => {
    const isSubscribed = user?.subscription.type !== "free";
    if (isSubscribed) {
      return 1;
    }
    return 0;
  }, [user?.subscription.type]);

  return (
    <div className="flex justify-center flex-col sm:flex-row">
      {stepsData.map((step, index) => (
        <div key={step.label} className="flex items-center gap-x-3">
          <div className="flex items-center p-1 sm:p-0 justify-center gap-x-1">
            <div
              className={`size-5 rounded-full flex items-center justify-center ${
                index + indexIncrement === currentStep ? "text-red-500" : "text-gray-400"
              }`}
            >
              {index + indexIncrement !== currentStep && step.notSelectedIcon}

              {index + indexIncrement === currentStep && step.selectedIcon}
            </div>
            <span
              className={`text-sm font-semibold ${index + indexIncrement === currentStep ? "text-[#AE7EDE]" : "text-gray-400"}`}
            >
              {index + 1}. {step.label}
            </span>

            {index + indexIncrement < currentStep && (
              <Image src="/svg/check-icon.svg" alt="check" width={18} height={18} />
            )}
          </div>
          {index + indexIncrement < stepsData.length - 1 + indexIncrement && (
            <div className="hidden sm:flex w-16 h-px bg-gray-700 mx-2" />
          )}
        </div>
      ))}
    </div>
  );
};

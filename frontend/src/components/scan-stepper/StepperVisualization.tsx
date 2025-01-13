import { useMemo, type FC } from "react";

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
    <div className="flex justify-center">
      {stepsData.map((step, index) => (
        <div key={step.label} className="flex items-center gap-x-3">
          <div className="flex flex-col items-center justify-center">
            <div
              className={`w-12 h-12 rounded-full flex items-center justify-center ${
                index + indexIncrement === currentStep ? "text-red-500" : "text-gray-400"
              }`}
            >
              {index + indexIncrement < currentStep
                ? step.selectedIcon
                : index + indexIncrement === currentStep
                  ? step.selectingIcon
                  : step.notSelectedIcon}
            </div>
            <span className={`text-sm ${index + indexIncrement === currentStep ? "text-[#C9A9E9]" : "text-gray-400"}`}>
              {step.label}
            </span>
          </div>
          {index + indexIncrement < stepsData.length - 1 + indexIncrement && (
            <div className="w-16 h-px bg-gray-700 mx-2" />
          )}
        </div>
      ))}
    </div>
  );
};

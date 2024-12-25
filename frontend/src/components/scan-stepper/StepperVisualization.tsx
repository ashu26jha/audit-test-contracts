import { type FC } from "react";

import { STEPS } from "@/config/steps";

interface StepperVisualizationProps {
  readonly currentStep: number;
}

export const StepperVisualization: FC<StepperVisualizationProps> = ({ currentStep }) => {
  return (
    <div className="flex justify-center">
      {STEPS.map((step, index) => (
        <div key={step.label} className="flex items-center gap-x-3">
          <div className="flex flex-col items-center justify-center">
            <div
              className={`w-12 h-12 rounded-full flex items-center justify-center ${
                index + 1 === currentStep ? "text-red-500" : "text-gray-400"
              }`}
            >
              {index + 1 < currentStep
                ? step.selectedIcon
                : index + 1 === currentStep
                  ? step.selectingIcon
                  : step.notSelectedIcon}
            </div>
            <span className={`text-sm ${index + 1 === currentStep ? "text-[#C9A9E9]" : "text-gray-400"}`}>
              {step.label}
            </span>
          </div>
          {index < STEPS.length - 1 && <div className="w-16 h-px bg-gray-700 mx-2" />}
        </div>
      ))}
    </div>
  );
};

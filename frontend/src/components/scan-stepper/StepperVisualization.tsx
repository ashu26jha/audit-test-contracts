import { type FC } from "react";

import { STEPS } from "@/config/steps";

interface StepperVisualizationProps {
  readonly currentStep: number;
}

export const StepperVisualization: FC<StepperVisualizationProps> = ({ currentStep }) => {
  return (
    <div className="flex justify-center mb-12">
      {STEPS.map((step, index) => (
        <div key={step.label} className="flex items-center">
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
          <span className={`mx-2 text-sm ${index + 1 === currentStep ? "text-[#C9A9E9]" : "text-gray-400"}`}>
            {step.label}
          </span>
          {index < STEPS.length - 1 && <div className="w-16 h-px bg-gray-700 mx-2" />}
        </div>
      ))}
    </div>
  );
};

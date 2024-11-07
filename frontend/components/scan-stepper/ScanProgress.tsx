import React from "react";

import { Card } from "@nextui-org/react";
import { CircularProgressbar, buildStyles } from "react-circular-progressbar";
import "react-circular-progressbar/dist/styles.css";

const GradientSVG = () => {
  const gradientTransform = `rotate(100)`;
  const gradientId = "progressGradient";

  return (
    <svg style={{ height: 0 }}>
      <defs>
        <linearGradient id={gradientId} gradientTransform={gradientTransform}>
          <stop offset="0%" stopColor="#EC4899" />
          <stop offset="100%" stopColor="#A855F7" />
        </linearGradient>
      </defs>
    </svg>
  );
};

interface ScanProgressProps {
  progress: number;
}

export const ScanProgress: React.FC<ScanProgressProps> = ({ progress }) => {
  const gradientId = "progressGradient";

  return (
    <>
      <Card className="w-full max-w-xl mx-auto p-6 space-y-4">
        <div className="flex justify-center items-center">
          <div style={{ width: "110px", height: "110px" }}>
            <GradientSVG />
            <CircularProgressbar
              value={progress}
              text={`${Math.round(progress)}%`}
              styles={buildStyles({
                pathColor: `url(#${gradientId})`,
                textColor: "#ffffff",
                trailColor: "rgba(255, 255, 255, 0.2)",
                textSize: "1.3rem",
                pathTransitionDuration: 0.5,
                pathTransition: "ease-out",
                strokeLinecap: "round",
                backgroundColor: "rgba(0, 0, 0, 0.8)",
              })}
            />
          </div>
        </div>

        <div className="space-y-2">
          <h2 className="text-xl font-semibold text-center">Analyzing Your Code...</h2>
          <p className="text-center text-small text-default-500">Please wait. This may take several minutes.</p>
        </div>
      </Card>
    </>
  );
};

import { type FC } from "react";

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

export const ScanProgress: FC<ScanProgressProps> = ({ progress }) => {
  const gradientId = "progressGradient";

  return (
    <div className="flex flex-col items-center space-y-4 w-56">
      <Card className="p-4">
        <div style={{ width: "64px", height: "64px" }}>
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
      </Card>

      <p className="font-medium">Analyzing Your Code...</p>
      <p className="text-foreground-500 text-center text-sm">
        Please wait, this may take several minutes. You&apos;ll receive an email once the scan is complete.
      </p>
    </div>
  );
};

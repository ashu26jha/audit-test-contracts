import { type FC } from "react";

import { Spinner } from "@nextui-org/react";

interface LoadingProps {
  text?: string;
  subText?: string;
}

export const Loading: FC<LoadingProps> = ({ text = "Loading", subText = "Please wait..." }) => {
  return (
    <div className="h-full bg-black text-white flex flex-col items-center justify-center">
      <div className="bg-[#222222] w-[300px] rounded-lg p-8 flex flex-col items-center text-center">
        <Spinner size="lg" color="secondary" />
        <p className="mt-4 text-lg font-semibold">{text}</p>
        <p className="mt-2 text-sm text-gray-400">{subText}</p>
      </div>
    </div>
  );
};

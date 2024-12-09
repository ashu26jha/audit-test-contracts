"use client";

import { useEffect } from "react";

import { Button } from "@nextui-org/button";
import { AlertTriangle } from "lucide-react";

import { StateMessage } from "@/components/layout";

interface ErrorProps {
  readonly error: Error;
  readonly reset: () => void;
}

export default function Error({ error, reset }: ErrorProps) {
  useEffect(() => {
    console.error(error);
  }, [error]);

  return (
    <StateMessage icon={<AlertTriangle size={40} className="text-red-500" />} message={error.message}>
      <Button color="secondary" className="bg-[#8B5CF6] text-white mt-4" onClick={() => reset()}>
        Try again
      </Button>
    </StateMessage>
  );
}

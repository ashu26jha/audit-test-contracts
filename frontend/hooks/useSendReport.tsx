import { useCallback, useState } from "react";

import { useAuth } from "@/contexts/AuthContext";
import { sendPdfReport } from "@/services/api";

import { useToast } from "./useToast";

interface SendReportResponse {
  isLoading: boolean;
  sendReportAgain: (scanId: string) => Promise<void>;
}

export const useSendReport = (): SendReportResponse => {
  const { toast } = useToast();
  const { user } = useAuth();
  const [isLoading, setIsLoading] = useState(false);

  const sendReportAgain = useCallback(
    async (scanId: string) => {
      if (!user) {
        console.error("No user found");
        return;
      }

      setIsLoading(true);
      try {
        const res = await sendPdfReport(scanId);
        if (res.success) {
          toast({
            title: "Report sent",
            status: "success",
          });
        } else {
          toast({
            title: res.message,
            status: "error",
          });
        }
      } catch (error) {
        toast({
          title: "Failed to send report",
          status: "error",
        });
      } finally {
        setIsLoading(false);
      }
    },
    [user, toast],
  );

  return {
    isLoading,
    sendReportAgain,
  };
};

import { Button, Progress, Spinner } from "@nextui-org/react";
import { AlertCircle, CheckCircle2, CircleX, ExternalLink } from "lucide-react";
import { useRouter } from "next/navigation";
import toast, { type Toast } from "react-hot-toast";

import { useScanResult } from "@/hooks";

interface ScanProgressToastProps {
  scanId: string;
  t: Toast;
}

const ScanProgressToast: React.FC<ScanProgressToastProps> = ({ scanId, t }) => {
  const router = useRouter();
  const { scanData, error } = useScanResult(scanId);

  const getStatusContent = () => {
    if (scanData.scan.status === "failed" || error) {
      return {
        icon: <AlertCircle className="w-5 h-5 text-red-500" />,
        title: "Scan Failed",
        message: "An error occurred during the scan",
        progressColor: "bg-red-500",
      };
    }

    if (scanData.scan.progress === 100) {
      return {
        icon: <CheckCircle2 className="w-5 h-5 text-green-500" />,
        title: "Scan Completed",
        message: "View the detailed scan results",
        progressColor: "bg-green-500",
      };
    }

    return {
      icon: <Spinner size="sm" color="secondary" />,
      title: `Scanning ${scanData.scan.repositoryName}`,
      message: "Analyzing smart contracts...",
      progressColor: "bg-purple-600",
    };
  };

  const statusContent = getStatusContent();

  return (
    <div
      className={`
        bg-zinc-900 border border-zinc-800 px-4 py-3 rounded-lg shadow-lg min-w-[500px] max-w-[700px]
        transform transition-all duration-300 ease-in-out
        ${t.visible ? "animate-enter" : "animate-leave"}
      `}
    >
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center space-x-2">
          {statusContent.icon}
          <span className="text-white text-sm font-medium">{statusContent.title}</span>
        </div>
        <div className="flex items-center space-x-4">
          <span className="text-purple-400 text-sm font-medium">{scanData.scan.progress ?? 0}%</span>
          {scanData.scan.status !== "in_progress" && (
            <button
              onClick={() => toast.dismiss(t.id)}
              className="text-zinc-500 hover:text-zinc-300 transition-colors focus:outline-none"
            >
              <CircleX className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>

      <Progress
        size="sm"
        radius="full"
        classNames={{
          base: "mb-2",
          track: "bg-zinc-800",
          indicator: statusContent.progressColor,
        }}
        value={scanData.scan.progress ?? 0}
        aria-label="Scan Progress"
      />

      <div className="flex items-center justify-between">
        <p className="text-zinc-400 text-xs">{statusContent.message}</p>
        {scanData.scan.progress === 100 && scanData.scan.status !== "failed" && (
          <Button
            size="sm"
            variant="light"
            className="text-purple-400 hover:text-purple-300"
            onPress={() => {
              router.push(`/scan-results/${scanId}`);
              toast.dismiss(t.id);
            }}
          >
            View Results
            <ExternalLink className="w-3 h-3 ml-1" />
          </Button>
        )}
      </div>
    </div>
  );
};

export default ScanProgressToast;

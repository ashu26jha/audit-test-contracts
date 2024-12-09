import { CheckCircleIcon } from "@heroicons/react/24/solid";
import toast, { type Toast } from "react-hot-toast";

interface ToastOptions {
  title: string;
  status: "success" | "error" | "warning" | "info";
  duration?: number;
}

const toastStyles = {
  success: "bg-green-500 text-white",
  error: "bg-red-500 text-white",
  warning: "bg-yellow-500 text-white",
  info: "bg-blue-500 text-white",
};

export const useToast = () => {
  const showToast = ({ title, status, duration = 3000 }: ToastOptions) => {
    toast.custom(
      (t: Toast) => (
        <div
          className={`${toastStyles[status]} px-2 py-1 rounded-md shadow-md flex items-center space-x-2 ${
            t.visible ? "animate-enter" : "animate-leave"
          }`}
        >
          {status === "success" && <CheckCircleIcon className="w-5 h-5 text-white" />}
          <span className="text-white text-sm font-normal leading-tight">{title}</span>
        </div>
      ),
      { duration },
    );
  };

  return { toast: showToast };
};

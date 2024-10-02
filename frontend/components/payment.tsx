import React from "react";

import { Button, Card } from "@nextui-org/react";
import { Check, X } from "lucide-react";
import { useRouter } from "next/navigation";

interface PaymentProps {
  status: "success" | "failed";
  onRetry: () => void;
}

const Payment: React.FC<PaymentProps> = ({ status, onRetry }) => {
  const router = useRouter();

  return (
    <div className="h-full bg-black text-white flex flex-col items-center justify-center">
      <Card className="bg-[#222222] p-8 max-w-md w-full text-center">
        <div
          className={`bg-[#333333] w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-6 ${status === "failed" ? "text-red-500" : "text-purple-500"}`}
        >
          {status === "success" ? <Check size={32} /> : <X size={32} />}
        </div>
        <h2 className="text-2xl font-semibold mb-4">{status === "success" ? "Payment Received" : "Payment Failed"}</h2>
        {status === "success" ? (
          <p className="text-gray-400 mb-6">
            You will receive the full vulnerabilities report shortly on the following email:
            <br />
            <span className="text-white">auditagent@nethermind.io</span>
          </p>
        ) : (
          <p className="text-gray-400 mb-6">We did not receive your payment, please try again!</p>
        )}
        {status === "success" ? (
          <Button color="secondary" className="bg-[#8B5CF6] w-full" onPress={() => router.push("/dashboard")}>
            Go to Dashboard
          </Button>
        ) : (
          <div className="flex gap-4">
            <Button color="default" variant="flat" className="flex-1" onPress={() => router.back()}>
              Go Back
            </Button>
            <Button color="secondary" className="bg-[#8B5CF6] flex-1" onPress={onRetry}>
              Retry Payment
            </Button>
          </div>
        )}
      </Card>
      <p className="text-gray-500 mt-8 text-sm">Need help? Reach out to us at auditagent@nethermind.io</p>
    </div>
  );
};

export default Payment;

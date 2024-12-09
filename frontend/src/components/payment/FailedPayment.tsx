import { type FC } from "react";

import { Button, Card } from "@nextui-org/react";
import { X } from "lucide-react";

interface FailedPaymentProps {
  onRetry: () => void;
  onBack: () => void;
}

const FailedPayment: FC<FailedPaymentProps> = ({ onRetry, onBack }) => (
  <Card className="bg-[#222222] p-8 max-w-md w-full text-center">
    <div className="bg-[#333333] w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-6 text-red-500">
      <X size={32} />
    </div>
    <h2 className="text-2xl font-semibold mb-4">Payment Failed</h2>
    <p className="text-gray-400 mb-6">We did not receive your payment, please try again!</p>
    <div className="flex gap-4">
      <Button color="default" variant="flat" className="flex-1" onPress={onBack}>
        Go Back
      </Button>
      <Button color="secondary" className="bg-[#8B5CF6] flex-1" onPress={onRetry}>
        Retry Payment
      </Button>
    </div>
  </Card>
);

export default FailedPayment;

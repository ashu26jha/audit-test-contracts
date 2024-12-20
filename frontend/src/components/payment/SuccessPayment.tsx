import { type FC } from "react";

import { Button, Card } from "@nextui-org/react";
import { Check } from "lucide-react";

interface SuccessPaymentProps {
  scanId: string | null;
  userEmail?: string;
  onBack: () => void;
}

const SuccessPayment: FC<SuccessPaymentProps> = ({ scanId, userEmail, onBack }) => {
  const msg = scanId
    ? "You will receive the full vulnerabilities report shortly on the following email:"
    : "Your payment has been successfully processed. You now have access to all the Pro features.";

  return (
    <Card className="bg-[#222222] p-8 max-w-md w-full text-center">
      <div className="bg-[#333333] w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-6 text-purple-500">
        <Check size={32} />
      </div>
      <h2 className="text-2xl font-semibold mb-4">Payment Received</h2>
      <div className="text-gray-400 mb-6">
        {msg}
        {scanId && <div className="text-white pt-2">{userEmail}</div>}
      </div>

      <Button color="secondary" className="bg-[#8B5CF6] w-full" onPress={onBack}>
        {scanId ? "Go to Results" : "Go to Dashboard"}
      </Button>
    </Card>
  );
};
export default SuccessPayment;

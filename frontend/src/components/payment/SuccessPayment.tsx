import { type FC } from "react";

import { Button, Card } from "@nextui-org/react";
import { Check } from "lucide-react";
import { useRouter } from "next/navigation";

interface SuccessPaymentProps {
  scanId: string;
  userEmail?: string;
}

const SuccessPayment: FC<SuccessPaymentProps> = ({ scanId, userEmail }) => {
  const router = useRouter();

  return (
    <Card className="bg-[#222222] p-8 max-w-md w-full text-center">
      <div className="bg-[#333333] w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-6 text-purple-500">
        <Check size={32} />
      </div>
      <h2 className="text-2xl font-semibold mb-4">Payment Received</h2>
      <p className="text-gray-400 mb-6">
        You will receive the full vulnerabilities report shortly on the following email:
        <br />
        <span className="text-white">{userEmail}</span>
      </p>
      <Button color="secondary" className="bg-[#8B5CF6] w-full" onPress={() => router.push(`/scan-results/${scanId}`)}>
        Go to Results
      </Button>
    </Card>
  );
};

export default SuccessPayment;

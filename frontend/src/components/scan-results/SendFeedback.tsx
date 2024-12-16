import type { FC } from "react";

import { Button, Card, CardBody } from "@nextui-org/react";
import Image from "next/image";

import { openFeedbackEmail } from "@/utils/email";

interface SendFeedbackProps {
  scanData: ScanResult;
}

const alreadyPaidMessage = (isSingleFinding: boolean) => {
  if (isSingleFinding) {
    return `This scan was free because we only found a single vulnerability.`;
  } else {
    return `You have already paid for this scan results.`;
  }
};

const SendFeedback: FC<SendFeedbackProps> = ({ scanData }) => {
  const isSingleFinding = scanData.total_findings === 1;

  const handleSendFeedback = () => {
    const subject = `Feedback for Scan ${scanData.scan_number}`;
    const body = `Dear AuditAgent Support Team,
    
    I would like to provide feedback for my recent scan (ID: ${scanData.scan_number}).
    
    [Please enter your feedback here]
    
    Thank you,
    [Your Name]`;

    openFeedbackEmail(subject, body);
  };

  return (
    <Card className="flex justify-between items-center p-2 bg-[#222222]">
      <CardBody className="flex flex-row justify-between items-center space-x-2">
        <div className="flex flex-col pl-5">
          <strong className="text-sm">{alreadyPaidMessage(isSingleFinding)}</strong>
          <p className="text-sm">Click on the Send Feedback button if you have any suggestions.</p>
        </div>

        <Button
          endContent={<Image src="/svg/feedback.svg" width={20} height={20} alt="feedback" />}
          onPress={handleSendFeedback}
        >
          Send Feedback
        </Button>
      </CardBody>
    </Card>
  );
};

export default SendFeedback;

import type { FC } from "react";

import { Button, Card, CardBody } from "@nextui-org/react";
import Image from "next/image";

import { openFeedbackEmail } from "@/utils/email";

interface SendFeedbackProps {
  scanData: ScanResult;
}

const SendFeedback: FC<SendFeedbackProps> = ({ scanData }) => {
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
          <p>Click on the Send Feedback button if you have any suggestions.</p>
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

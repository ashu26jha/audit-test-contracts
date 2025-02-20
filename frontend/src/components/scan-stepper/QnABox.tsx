import { type ChangeEventHandler, type FC } from "react";

import { Textarea } from "@nextui-org/input";

import { QUESTIONS } from "@/config/QnAQuestions";
import { useScanStepperStore } from "@/store/scanStepperStore";

export const QnABox: FC = () => {
  const { repoDocs, setRepoDocs } = useScanStepperStore();

  const handleChange = (index: number, value: string) => {
    setRepoDocs({
      qa: {
        ...repoDocs.qa,
        [index.toString()]: value,
      },
    });
  };

  return (
    <div>
      <div className="bg-content-1 rounded-xl p-6 border border-default-100 flex flex-col gap-6">
        {QUESTIONS.map((q, index) => (
          <QnATextarea
            key={index}
            value={repoDocs.qa[index.toString()] || ""}
            onChange={(e) => handleChange(index, e.target.value)}
            maxLength={q.maxLength}
            question={q.question}
          />
        ))}
      </div>
    </div>
  );
};

interface QnATextareaProps {
  value: string;
  maxLength: number;
  onChange: ChangeEventHandler<HTMLInputElement> | undefined;
  question: string;
}

const QnATextarea = ({ value, maxLength, onChange, question }: QnATextareaProps) => {
  return (
    <div>
      <div className="flex justify-between items-center mb-2">
        <h4 className="text-sm text-default-600">{question}</h4>
        <p className="text-sm text-default-500">
          {value.length}/{maxLength}
        </p>
      </div>
      <Textarea
        value={value}
        onChange={onChange}
        minRows={1}
        placeholder="Enter Answer"
        maxLength={maxLength}
        classNames={{
          inputWrapper:
            "border-2 border-default-100 bg-content-1 hover:border-gray-600 group-data-[focus=true]:bg-content-1 data-[hover=true]:bg-content-1",
        }}
      />
    </div>
  );
};

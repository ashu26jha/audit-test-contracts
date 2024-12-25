interface QnAQuestion {
  question: string;
  maxLength: number;
}

export const QUESTIONS: QnAQuestion[] = [
  { question: "1. On what chains are the smart contracts going to be deployed?", maxLength: 50 },
  {
    question:
      "2. Are there any limitations on values set by admins (or other roles) in the codebase or in protocols you integrate with, including restrictions on array lengths?",
    maxLength: 500,
  },
  { question: "3. Is the codebase expected to comply with any specific EIPs?", maxLength: 50 },
  {
    question:
      "4. Are there any off-chain mechanisms involved in the protocol (e.g., keeper bots, arbitrage bots, etc.)? We assume these mechanisms will not misbehave, delay, or go offline unless otherwise specified.",
    maxLength: 500,
  },
  { question: "5. Any design choices you made that you would like to mention?", maxLength: 500 },
  { question: "6. Additional audit information?", maxLength: 500 },
];

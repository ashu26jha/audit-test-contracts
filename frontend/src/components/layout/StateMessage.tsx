import type { FC } from "react";

interface StateMessageProps {
  icon: React.ReactNode;
  message: string;
  readonly children?: React.ReactNode;
}

const StateMessage: FC<StateMessageProps> = ({ icon, message, children }) => (
  <div className="h-[calc(100%-6rem)]">
    <div className="flex flex-col items-center justify-center h-full">
      {icon}
      <p className="mt-4 text-lg">{message}</p>
      {children}
    </div>
  </div>
);

export default StateMessage;

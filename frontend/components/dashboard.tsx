import React from "react";
import { Button } from "@nextui-org/react";

const Dashboard: React.FC = () => {
  return (
    <div className="min-h-screen bg-[#0E0E0E] text-white p-4">
      {/* Header */}
      <header className="flex justify-between items-center mb-8">
        <h1 className="text-blue-400 text-2xl font-bold">Dashboard</h1>
        <Button color="primary" className="bg-white text-black">
          Scan Code
        </Button>
      </header>

      {/* Main content */}
      <main className="flex flex-col items-center justify-center h-[calc(100vh-100px)]">
        <div className="w-32 h-32 bg-gray-700 rounded-full mb-4"></div>
        <p className="text-gray-400 text-center">
          You don&apos;t have a scanned file yet.
          <br />
          Please select a new file to scan
        </p>
      </main>
    </div>
  );
};

export default Dashboard;

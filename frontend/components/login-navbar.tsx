import React from "react";

import Image from "next/image";

const LoginNavbar: React.FC = () => {
  return (
    <div className="w-full h-[88px] p-8 justify-center items-center inline-flex">
      <div className="py-1 justify-center items-center gap-1 flex">
        <Image src="/logo.svg" alt="logo" width={195} height={150} />
      </div>
    </div>
  );
};

export default LoginNavbar;

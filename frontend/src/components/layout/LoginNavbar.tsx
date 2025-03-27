import { type FC } from "react";

import Image from "next/image";

const LoginNavbar: FC = () => {
  return (
    <div className="w-full h-[88px] p-8 justify-center items-center inline-flex bg-black">
      <div className="py-1 justify-center items-center gap-1 flex">
        <Image
          src="/svg/logo.svg"
          alt="logo"
          width={195}
          height={150}
          priority
          className="min-w-[195px] aspect-[13/10]"
        />
      </div>
    </div>
  );
};

export default LoginNavbar;

import type { FC, ReactNode } from "react";

import { Avatar, Button } from "@nextui-org/react";
import { LogOut } from "lucide-react";
import Image from "next/image";

interface UserDetailsProps {
  user: User;
  logout: () => void;
}

const UserDetails: FC<UserDetailsProps> = ({ user, logout }) => {
  const { email, username, name, avatarUrl } = user;

  return (
    <div className="flex flex-col gap-8 w-1/3">
      <div className="w-full flex flex-col items-center">
        <Avatar src={avatarUrl} size="sm" className="w-20 h-20 text-large rounded-md" />
      </div>

      {name && <ProfileField label="Name" value={name} />}
      <ProfileField label="Email" value={email} />
      <ProfileField
        label="GitHub Username"
        value={username}
        icon={<Image src="/svg/github.svg" alt="GitHub" width={20} height={20} className="ml-auto" />}
      />

      <Button
        variant="flat"
        startContent={<LogOut size={14} />}
        className="w-full bg-[#3F3F46] hover:bg-[#F3126033] hover:text-danger text-white"
        onClick={() => logout()}
      >
        Log Out
      </Button>
    </div>
  );
};

export default UserDetails;

interface ProfileFieldProps {
  label: string;
  value: string;
  icon?: ReactNode;
}

const ProfileField: FC<ProfileFieldProps> = ({ label, value, icon }) => (
  <div className="flex flex-col ">
    <div className="text-sm font-normal text-[#A1A1AA]">{label}</div>
    <div className="flex w-full justify-between">
      <div className="flex items-center text-md mt-1 border text-medium text-[#A1A1AA] border-[#27272A] p-2 px-4 rounded-lg w-full bg-[#18181B]">
        {value}
        {icon}
      </div>
    </div>
  </div>
);

"use client";

import type { FC } from "react";

import { ChevronDownIcon } from "@heroicons/react/24/solid";
import { Navbar as NextUINavbar, NavbarContent, NavbarBrand } from "@nextui-org/navbar";
import { Avatar, Dropdown, DropdownTrigger, DropdownMenu, DropdownItem, Button } from "@nextui-org/react";
import { Sparkles } from "lucide-react";
import Image from "next/image";
import NextLink from "next/link";
import { useRouter, usePathname } from "next/navigation";
import { tv } from "tailwind-variants";

import { useAuth } from "@/contexts/AuthContext";
import { useScanStepperStore } from "@/store/scanStepperStore";

import LoginNavbar from "./LoginNavbar";

const Navbar: FC = () => {
  const router = useRouter();
  const { user, loading, logout } = useAuth();
  const { setShowStepper } = useScanStepperStore();
  const pathname = usePathname();

  const scansRemainingIndicator = tv({
    base: "h-10 bg-secondary-flat border-1.5 border-secondary text-secondary-700 rounded-lg",
    variants: {
      isSubscribed: {
        true: "bg-transparent border-default text-default-900",
      },
    },
  });

  if (pathname === "/login-success") {
    return null;
  }

  if (!user || loading || pathname === "/login") {
    return <LoginNavbar />;
  }

  return (
    <NextUINavbar
      maxWidth="full"
      position="sticky"
      className="h-20 px-4 py-6 bg-zinc-900 shadow border-b border-zinc-800 flex flex-row"
    >
      <NavbarBrand as="li" className="gap-3 max-w-fit min-w-[130px]">
        <NextLink
          className="flex justify-start items-center gap-1"
          href="/dashboard"
          onClick={() => setShowStepper(false)}
        >
          <Image src="/svg/logo.svg" alt="logo" width={195} height={150} priority />
        </NextLink>
      </NavbarBrand>

      <NavbarContent justify="end">
        <Button
          className={scansRemainingIndicator({
            isSubscribed: user.subscription.isActive && user.subscription.credits !== 0,
          })}
          startContent={<Sparkles size={14} />}
        >
          {/* TODO: Display 0 credits for now for clarity when no more scans left */}
          {/* {user.subscription.isActive && user.subscription.credits !== 0 && ( */}
          {user.subscription.isActive && (
            <p className="text-sm">
              {user.subscription.credits === 1 ? "1 Scan Left" : `${user.subscription.credits} Scans Left`}
            </p>
          )}

          {/* {(!user.subscription.isActive || user.subscription.credits === 0) && <p className="text-sm"> Upgrade Plan</p>} */}
          {!user.subscription.isActive && <p className="text-sm"> Upgrade Plan</p>}
        </Button>

        <div className="justify-start items-center gap-1.5 flex">
          <Dropdown placement="bottom-end">
            <DropdownTrigger>
              <div className="justify-center items-center gap-2 flex cursor-pointer">
                {user?.avatarUrl ? (
                  <Avatar src={user.avatarUrl} size="sm" className="bg-zinc-700 text-zinc-300 rounded-[10px]" />
                ) : (
                  <></>
                )}{" "}
                <p className="text-neutral-50 text-base leading-normal">{user?.username ?? "Guest"}</p>
                <ChevronDownIcon className="w-4 h-4 text-neutral-50" />
              </div>
            </DropdownTrigger>
            <DropdownMenu aria-label="Profile Actions" variant="flat" className="rounded-lg">
              <DropdownItem
                key="profile"
                startContent={<Image src="/svg/profile.svg" alt="profile" width={20} height={20} />}
                onPress={() => {
                  router.push("/profile");
                }}
              >
                Profile
              </DropdownItem>
              <DropdownItem
                key="logout"
                startContent={<Image src="/svg/logout.svg" alt="logout" width={20} height={20} />}
                color="danger"
                onPress={() => logout()}
              >
                Log out
              </DropdownItem>
            </DropdownMenu>
          </Dropdown>
        </div>
      </NavbarContent>
    </NextUINavbar>
  );
};

export default Navbar;

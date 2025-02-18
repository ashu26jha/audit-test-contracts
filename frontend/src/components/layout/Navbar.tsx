"use client";

import { useEffect, type FC } from "react";

import { ChevronDownIcon } from "@heroicons/react/24/solid";
import { Navbar as NextUINavbar, NavbarContent, NavbarBrand } from "@nextui-org/navbar";
import { Avatar, Dropdown, DropdownTrigger, DropdownMenu, DropdownItem, Button } from "@nextui-org/react";
import Image from "next/image";
import NextLink from "next/link";
import { useRouter, usePathname } from "next/navigation";

import { PAGES } from "@/config/constants";
import { useAuth } from "@/contexts/AuthContext";
import { useSubscription } from "@/hooks/useSubscription";

import LoginNavbar from "./LoginNavbar";

const Navbar: FC = () => {
  const router = useRouter();
  const { user, loading, logout } = useAuth();
  const pathname = usePathname();
  const { checkIfFreeScanAllowed, freeScanAllowed } = useSubscription();

  useEffect(() => {
    checkIfFreeScanAllowed();
  }, [checkIfFreeScanAllowed]);

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
      <NavbarBrand as="li" className="max-w-fit min-w-[130px]">
        <NextLink className="flex justify-start items-center" href="/dashboard?tab=home">
          <Image src="/svg/logo.svg" alt="logo" width={175} height={150} priority />
        </NextLink>
      </NavbarBrand>

      <NavbarContent justify="end">
        <Button
          as="a"
          href={PAGES.MANUAL_AUDIT}
          target="_blank"
          className="h-10 bg-secondary-flat border-1.5 border-secondary text-secondary-700 rounded-lg"
          startContent={<Image src="/svg/book-security-review.svg" width={18} height={18} alt="book-security-review" />}
        >
          Book a Security Review
        </Button>

        <div className="justify-start items-center gap-1.5 flex">
          <Dropdown placement="bottom-end">
            <DropdownTrigger>
              <div className="justify-center items-center gap-3 flex cursor-pointer">
                {user?.avatarUrl ? (
                  <Avatar src={user.avatarUrl} size="sm" className="bg-zinc-700 text-zinc-300 rounded-[10px]" />
                ) : (
                  <></>
                )}
                <div>
                  <p className="text-neutral-50 text-sm leading-normal">{user?.username ?? "Guest"}</p>
                  {user?.subscription.type === "free" && (
                    <p className="text-xs">{`${freeScanAllowed ? "1" : "0"} Free Scan Left`}</p>
                  )}
                  {user?.subscription.type !== "free" && (
                    <p className="text-xs">{`${user.subscription.credits} Scans Left`}</p>
                  )}
                </div>
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

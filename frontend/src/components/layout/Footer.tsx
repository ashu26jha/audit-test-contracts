"use client";

import type { FC } from "react";

import { Link } from "@nextui-org/link";
import Image from "next/image";
import { usePathname } from "next/navigation";

import { CONTACT, PAGES } from "@/config/constants";
import { useAuth } from "@/contexts/AuthContext";

function FooterLink({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <Link
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="text-[#A1A1AA] hover:underline flex items-center text-xs md:text-sm whitespace-nowrap"
    >
      {children}
    </Link>
  );
}

function Elipsis({ className = "" }: { className?: string }) {
  return <div className={`w-1 h-1 bg-gray-400 rounded-full mx-3 ${className}`}></div>;
}

const Footer: FC = () => {
  const { user } = useAuth();
  const pathname = usePathname();

  if (pathname === "/login" || !user) {
    return (
      <footer className="w-full flex items-center justify-center py-3 px-4 text-center bg-black">
        <p className="text-sm text-gray-400">
          By proceeding you agree to our{" "}
          <Link
            href={PAGES.DISCLAIMER}
            target="_blank"
            rel="noopener noreferrer"
            className="text-sm text-gray-400 underline hover:text-gray-300"
          >
            Terms of Use
          </Link>{" "}
          and{" "}
          <Link
            href={PAGES.PRIVACY_POLICY}
            target="_blank"
            rel="noopener noreferrer"
            className="text-sm text-gray-400 underline hover:text-gray-300 mr-1"
          >
            Privacy Policy
          </Link>
          • Copyright © {`${new Date().getFullYear()}`} by Nethermind
        </p>
      </footer>
    );
  }

  return (
    <footer className="z-20 px-4 sm:px-2 lg:px-10 lg:py-4 md:py-3 py-2 bg-zinc-900 shadow border-b border-zinc-800 flex flex-col md:flex-row font-inter font-normal text-[#A1A1AA] md:justify-between items-center text-sm gap-2 md:gap-0">
      <div className="flex flex-col md:flex-row items-center md:items-center gap-x-2 lg:gap-x-0">
        <div className="hidden lg:flex items-center gap-2">
          Powered by <Image src="/svg/nethermind.svg" alt="logo" width={120} height={20} />
        </div>
        <div className="pb-2 md:pb-0 lg:hidden">
          <Image src="/svg/nethermind.svg" alt="logo" width={100} height={16} />
        </div>

        <Elipsis className="hidden lg:block" />
        <div className="text-xs md:text-sm">©{new Date().getFullYear()} Nethermind. All rights reserved</div>
      </div>

      <div className="flex flex-wrap justify-center md:justify-end items-center gap-x-2 lg:gap-x-0">
        <FooterLink href={PAGES.CONTACT}>Contact</FooterLink>
        <Elipsis className="hidden lg:block" />
        <FooterLink href={`mailto:${CONTACT.EMAIL}`}>Support</FooterLink>
        <Elipsis className="hidden lg:block" />
        <FooterLink href={CONTACT.TELEGRAM}>Telegram</FooterLink>
        <Elipsis className="hidden lg:block" />
        <FooterLink href={PAGES.DISCLAIMER}>Terms</FooterLink>
        <Elipsis className="hidden lg:block" />
        <FooterLink href={PAGES.PRIVACY_POLICY}>Privacy</FooterLink>
      </div>
    </footer>
  );
};

export default Footer;

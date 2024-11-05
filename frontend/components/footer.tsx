"use client";

import { Link } from "@nextui-org/link";
import Image from "next/image";
import { usePathname } from "next/navigation";

import { CONTACT, PAGES } from "@/config/constants";

function FooterLink({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <Link
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="text-[#A1A1AA] hover:underline flex items-center text-sm"
    >
      {children}
    </Link>
  );
}

function Elipsis() {
  return <div className="w-1 h-1 bg-gray-400 rounded-full mx-3"></div>;
}

export default function Footer() {
  const pathname = usePathname();

  if (pathname !== "/login") {
    return (
      <footer className="z-20 px-10 py-4 bg-zinc-900 shadow border-b border-zinc-800 flex flex-row font-inter font-normal text-[#A1A1AA] justify-between items-center text-sm ">
        <div className="flex items-center">
          <div className="flex items-center gap-2">
            Powered by <Image src="/nethermind.svg" alt="logo" width={120} height={20} />
          </div>
          <Elipsis />
          <div>©2024 Nethermind. All rights reserved</div>
        </div>
        <div className="flex items-center">
          <FooterLink href={PAGES.CONTACT}>Contact Us</FooterLink>
          <Elipsis />
          <FooterLink href={`mailto:${CONTACT.EMAIL}`}>Support Email</FooterLink>
          <Elipsis />
          <FooterLink href={CONTACT.TELEGRAM}>Telegram</FooterLink>
          <Elipsis />
          <FooterLink href={PAGES.DISCLAIMER}>Terms of Use</FooterLink>
          <Elipsis />
          <FooterLink href={PAGES.PRIVACY_POLICY}>Privacy Policy</FooterLink>
        </div>
      </footer>
    );
  }

  return (
    <footer className="w-full flex items-center justify-center py-3">
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
          className=" text-sm text-gray-400 underline hover:text-gray-300 mr-1"
        >
          Privacy Policy
        </Link>
        • Copyright © 2024 by Nethermind
      </p>
    </footer>
  );
}

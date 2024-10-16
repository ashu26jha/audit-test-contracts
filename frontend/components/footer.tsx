"use client";

import { Link } from "@nextui-org/link";
import Image from "next/image";
import { usePathname } from "next/navigation";

import { AA_EMAIL, CONTACT_PAGE_URL, DISCLAIMER_PAGE_URL, TELEGRAM_URL } from "@/config/constants";

function FooterLink({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <Link
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="text-[#A1A1AA] hover:underline flex items-center"
    >
      {children} <Image src="/arrow_to_top_right.svg" alt="arrow" width={16} height={16} className="ml-1" />
    </Link>
  );
}

export default function Footer() {
  const pathname = usePathname();

  if (pathname !== "/login") {
    return (
      <footer className="px-10 py-4 bg-zinc-900 shadow border-b border-zinc-800 flex flex-row font-inter font-normal text-[#A1A1AA] justify-between items-center text-sm">
        <div className="flex gap-2">
          Powered by <Image src="/nethermind.svg" alt="logo" width={120} height={20} />
        </div>
        <div className="flex gap-4">
          <FooterLink href={DISCLAIMER_PAGE_URL}>Terms of Use</FooterLink>
          <FooterLink href={CONTACT_PAGE_URL}>Contact Us</FooterLink>
          <FooterLink href={`mailto:${AA_EMAIL}`}>Support Email</FooterLink>
          <FooterLink href={TELEGRAM_URL}>Telegram</FooterLink>
        </div>
        <div>©2024 Nethermind. All rights reserved</div>
      </footer>
    );
  }

  return (
    <footer className="w-full flex items-center justify-center py-3">
      <p className="text-sm text-gray-400">
        By proceeding you agree to our{" "}
        <Link
          href="https://auditagent.nethermind.io/terms-of-use"
          target="_blank"
          rel="noopener noreferrer"
          className="text-sm text-gray-400 underline hover:text-gray-300"
        >
          Terms of Use
        </Link>{" "}
        and{" "}
        <Link
          href="https://nethermind.io/privacy-policy"
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

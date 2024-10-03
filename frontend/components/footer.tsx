"use client";

import { Link } from "@nextui-org/link";
import { usePathname } from "next/navigation";

export default function Footer() {
  const pathname = usePathname();

  if (pathname !== "/login") {
    return null;
  }

  return (
    <footer className="w-full flex items-center justify-center py-3">
      <p className="text-sm text-gray-400">
        By proceeding you agree to our <Link href="https://nethermind.io/terms-of-use">Terms of Use</Link> and{" "}
        <Link href="https://nethermind.io/privacy-policy" className="mr-1">
          Privacy Policy
        </Link>
        • Copyright © 2024 by Nethermind
      </p>
    </footer>
  );
}

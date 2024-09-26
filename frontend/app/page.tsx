"use client";
import { Link } from "@nextui-org/link";
import { Snippet } from "@nextui-org/snippet";
import { Code } from "@nextui-org/code";
import { button as buttonStyles } from "@nextui-org/theme";

import { siteConfig } from "@/config/site";
import { title, subtitle } from "@/components/primitives";
import { GithubIcon } from "@/components/icons";

import { useEffect } from "react";
import { useRouter, usePathname } from "next/navigation";
import { useAuth } from "../contexts/AuthContext";

export default function Home() {
  const { user, loading, isPublicRoute } = useAuth();
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    if (!loading) {
      console.log("user", user);
      if (user && pathname === "/") {
        router.push("/dashboard");
      } else if (!user && !isPublicRoute(pathname) && pathname !== "/") {
        router.push("/login");
      }
    }
  }, [user, loading, router, pathname, isPublicRoute]);

  if (loading) {
    return <div>Loading...</div>;
  }

  return null;
}

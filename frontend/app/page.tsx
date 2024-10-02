"use client";
import { useEffect } from "react";

// import { Code } from "@nextui-org/code";
// import { Link } from "@nextui-org/link";
// import { Snippet } from "@nextui-org/snippet";
// import { button as buttonStyles } from "@nextui-org/theme";
import { useRouter, usePathname } from "next/navigation";

// import { GithubIcon } from "@/components/icons";
// import { title, subtitle } from "@/components/primitives";
// import { siteConfig } from "@/config/site";

import { Loading } from "@/components/Loading";

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
    return <Loading />;
  }

  return null;
}

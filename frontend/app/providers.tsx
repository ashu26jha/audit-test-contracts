"use client";

import { useState, useEffect, type ReactNode } from "react";

import { NextUIProvider } from "@nextui-org/system";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { ThemeProvider as NextThemesProvider } from "next-themes";
import { type ThemeProviderProps } from "next-themes/dist/types";

import { AuthProvider } from "@/contexts/AuthContext";

const queryClient = new QueryClient();

export interface ProvidersProps {
  readonly children: ReactNode;
  readonly themeProps?: ThemeProviderProps;
}

export function Providers({ children, themeProps }: ProvidersProps) {
  const router = useRouter();
  const [mounted, setMounted] = useState(false);

  useEffect(() => setMounted(true), []);

  return (
    <NextUIProvider navigate={router.push}>
      <NextThemesProvider {...themeProps}>
        <QueryClientProvider client={queryClient}>
          <AuthProvider>{mounted && children}</AuthProvider>
        </QueryClientProvider>
      </NextThemesProvider>
    </NextUIProvider>
  );
}

"use client";

import { useState, useEffect, ReactNode } from "react";
import { NextUIProvider } from "@nextui-org/system";
import { useRouter } from "next/navigation";
import { ThemeProvider as NextThemesProvider } from "next-themes";
import { ThemeProviderProps } from "next-themes/dist/types";
import { AuthProvider } from "../contexts/AuthContext";
import { Toaster } from "react-hot-toast";

export interface ProvidersProps {
  children: ReactNode;
  themeProps?: ThemeProviderProps;
}

export function Providers({ children, themeProps }: ProvidersProps) {
  const router = useRouter();
  const [mounted, setMounted] = useState(false);

  useEffect(() => setMounted(true), []);

  return (
    <NextUIProvider navigate={router.push}>
      <NextThemesProvider {...themeProps}>
        <AuthProvider>
          {mounted && children}
          <Toaster
            position="bottom-center"
            toastOptions={{
              className: "",
              style: {
                boxShadow: "none",
              },
            }}
          />
        </AuthProvider>
      </NextThemesProvider>
    </NextUIProvider>
  );
}

import "@/styles/globals.css";
import clsx from "clsx";
import type { Metadata, Viewport } from "next";
import Script from "next/script";

import Footer from "@/components/footer";
import { Navbar } from "@/components/navbar";
import { fontSans } from "@/config/fonts";
import { siteConfig } from "@/config/site";

import { Providers } from "./providers";

export const metadata: Metadata = {
  title: {
    default: siteConfig.name,
    template: `%s - ${siteConfig.name}`,
  },
  description: siteConfig.description,
  icons: {
    icon: "/favicon.ico",
  },
};

export const viewport: Viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "white" },
    { media: "(prefers-color-scheme: dark)", color: "black" },
  ],
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html suppressHydrationWarning lang="en">
      <head />
      <body className={clsx("min-h-screen bg-background font-sans antialiased", fontSans.variable)}>
        <Providers themeProps={{ attribute: "class", defaultTheme: "dark" }}>
          <div className="relative flex flex-col h-screen">
            <Navbar />
            <main className="container h-full mx-auto max-w-10xl pt-16 px-8 flex-grow overflow-y-auto pb-6">
              {children}
            </main>
            <Footer />
          </div>
        </Providers>

        <Script
          id="matomo-tracking"
          strategy="afterInteractive"
          dangerouslySetInnerHTML={{
            __html: `
              var _paq = window._paq = window._paq || [];
              /* tracker methods like "setCustomDimension" should be called before "trackPageView" */
              _paq.push(['trackPageView']);
              _paq.push(['enableLinkTracking']);
              (function () {
                var u = "https://nethermind.matomo.cloud/";
                _paq.push(['setTrackerUrl', u + 'matomo.php']);
                _paq.push(['setSiteId', '5']);
                var d = document, g = d.createElement('script'), s = d.getElementsByTagName('script')[0];
                g.async = true;
                g.src = 'https://cdn.matomo.cloud/nethermind.matomo.cloud/matomo.js';
                s.parentNode.insertBefore(g, s);
              })();
            `,
          }}
        />
        {/* TODO: Integrate with above script, currently better to have it separate */}
        <Script
          id="tag-manager"
          strategy="afterInteractive"
          dangerouslySetInnerHTML={{
            __html: `
              var _mtm = window._mtm = window._mtm || [];
              _mtm.push({ 'mtm.startTime': (new Date().getTime()), 'event': 'mtm.Start' });
              (function() {
                var d=document, g=d.createElement('script'), s=d.getElementsByTagName('script')[0];
                g.async=true; g.src='https://cdn.matomo.cloud/nethermind.matomo.cloud/container_VPsOumJZ.js'; s.parentNode.insertBefore(g,s);
              })();
            `,
          }}
        />
      </body>
    </html>
  );
}

export type SiteConfig = typeof siteConfig;

export const siteConfig = {
  name: "Audit Agent",
  description:
    "Audit Agent - An intelligent AI-powered tool for conducting comprehensive audits and assessments across various domains, streamlining the audit process with advanced analytics and reporting capabilities.",
  navItems: [
    {
      label: "Home",
      href: "/",
    },
    {
      label: "Login",
      href: "/login",
    },
    {
      label: "Login Success",
      href: "/login-success",
    },
    {
      label: "Dashboard",
      href: "/dashboard",
    },
    {
      label: "Docs",
      href: "/docs",
    },
    {
      label: "Pricing",
      href: "/pricing",
    },
    {
      label: "Blog",
      href: "/blog",
    },
    {
      label: "About",
      href: "/about",
    },
  ],
  navMenuItems: [
    {
      label: "Profile",
      href: "/profile",
    },
    {
      label: "Dashboard",
      href: "/dashboard",
    },
    {
      label: "Projects",
      href: "/projects",
    },
    {
      label: "Team",
      href: "/team",
    },
    {
      label: "Calendar",
      href: "/calendar",
    },
    {
      label: "Settings",
      href: "/settings",
    },
    {
      label: "Help & Feedback",
      href: "/help-feedback",
    },
    {
      label: "Logout",
      href: "/logout",
    },
  ],
  links: {
    github: "https://github.com/nextui-org/nextui",
    twitter: "https://twitter.com/getnextui",
    docs: "https://nextui.org",
    discord: "https://discord.gg/9b6yyZKmH4",
    sponsor: "https://patreon.com/jrgarciadev",
  },
};

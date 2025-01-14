// Contact Information
export const CONTACT = {
  EMAIL: "auditagent@nethermind.io",
  TELEGRAM: "https://t.me/ai_smart_contract_auditor",
} as const;

// API and External Services
export const SERVICES = {
  API_URL: process.env.NEXT_PUBLIC_API_URL ?? "https://api.auditagent.nethermind.io",
  GITHUB_APP_URL: process.env.NEXT_PUBLIC_GITHUB_APP_URL ?? "https://github.com/apps/auditagent-app/installations/new",
} as const;

// Legal and Information Pages
export const PAGES = {
  CONTACT: "https://auditagent.nethermind.io/contact-us",
  DISCLAIMER: "https://auditagent.nethermind.io/terms-of-use",
  PRIVACY_POLICY: "https://auditagent.nethermind.io/privacy-policy",
} as const;

// Application Limits
export const FREE_PLAN_DETAILS = {
  AUDIT_TYPE: "LIMITED AUDIT",
  PLAN_NAME: "Free Plan",
  DESCRIPTION: "Suitable for small projects or testing purposes.",
  MAX_FILES: 3,
  MAX_LINES: 500,
  PRICE: 0,
  SCAN_CREDITS: 1,
  MAX_DOCS_CHARS: 0,
  MAX_DOCS_FILES: 0,
  SUBSCRIPTION_TYPE: "free",
  get features() {
    return [
      `${this.SCAN_CREDITS} scan per month`,
      `Up to ${this.MAX_LINES} lines of code per scan`,
      `Up to ${this.MAX_FILES} contracts per scan`,
      "PDF report export",
    ];
  },
} as const;

export const PRO_PLAN_DETAILS = {
  AUDIT_TYPE: "STANDARD AUDIT",
  PLAN_NAME: "Professional Plan",
  DESCRIPTION: "Ideal for growing teams and active development.",
  MAX_FILES: 10,
  MAX_LINES: 2000,
  PRICE: 199,
  SCAN_CREDITS: 5,
  MAX_DOCS_CHARS: 0,
  MAX_DOCS_FILES: 0,
  SUBSCRIPTION_TYPE: "pro",
  get features() {
    return [
      `${this.SCAN_CREDITS} scan credits (Refreshes every month)`,
      `Up to ${this.MAX_LINES} lines of code per scan`,
      `Up to ${this.MAX_FILES} contracts per scan`,
      "Priority in the scan queue",
    ];
  },
} as const;

export const ENTERPRISE_PLAN_DETAILS = {
  AUDIT_TYPE: "ADVANCED AUDIT",
  PLAN_NAME: "Enterprise Plan",
  DESCRIPTION: "Perfect for large projects and active development.",
  MAX_FILES: 50,
  MAX_LINES: 8000,
  PRICE: 999,
  SCAN_CREDITS: 10,
  MAX_DOCS_CHARS: 20000,
  MAX_DOCS_FILES: 5,
  SUBSCRIPTION_TYPE: "enterprise",
  get features() {
    return [
      "Everything in PRO",
      `${this.SCAN_CREDITS} scan credits (Refreshes every month)`,
      `Up to ${this.MAX_LINES} lines of code per scan`,
      `Up to ${this.MAX_FILES} contracts per scan`,
      "CI integration",
      "Crypto Payments",
      "Custom Extensions",
      "Additional context documentation",
      "Dedicated Telegram or Slack channel support",
    ];
  },
} as const;

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
export const BASIC_PLAN_DETAILS = {
  MAX_FILES: 5,
  MAX_LINES: 800,
  PRICE: 49,
  SCAN_CREDITS: 1,
} as const;

export const PRO_PLAN_DETAILS = {
  MAX_FILES: 25,
  MAX_LINES: 4000,
  PRICE: 990,
  SCAN_CREDITS: 20,
} as const;

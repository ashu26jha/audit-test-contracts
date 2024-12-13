import { nextui } from "@nextui-org/theme";

/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/hooks/**/*.{js,ts,jsx,tsx}",
    "./src/styles/**/*.{js,ts,jsx,tsx,css}",
    "./node_modules/@nextui-org/theme/dist/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ["var(--font-sans)"],
        mono: ["var(--font-mono)"],
      },
      colors: {
        green: {
          500: "#0e793c",
        },
        red: {
          500: "#ef4444",
        },
        yellow: {
          500: "#eab308",
        },
        blue: {
          500: "#3b82f6",
        },
        background: "#0F0F0F",
        content: {
          1: "#18181B",
        },
        default: {
          DEFAULT: "#3F3F46",
          100: "#27272A",
          500: "#A1A1AA",
          600: "#D4D4D8",
          900: "#FAFAFA",
          flat: "#3F3F4666",
        },
        secondary: {
          DEFAULT: "#9353D3",
          flat: "#9353D333",
          700: "#C9A9E9",
        },
      },
      keyframes: {
        enter: {
          "0%": { transform: "scale(0.9)", opacity: 0 },
          "100%": { transform: "scale(1)", opacity: 1 },
        },
        leave: {
          "0%": { transform: "scale(1)", opacity: 1 },
          "100%": { transform: "scale(0.9)", opacity: 0 },
        },
      },
      animation: {
        enter: "enter 0.2s ease-out",
        leave: "leave 0.15s ease-in forwards",
      },
    },
  },
  darkMode: "class",
  plugins: [nextui(), require("@tailwindcss/typography")],
};

import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";

// ── Fonts ──────────────────────────────────────────────────────
const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
  display: "swap",
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-jetbrains",
  display: "swap",
});

// ── Metadata ──────────────────────────────────────────────────
export const metadata: Metadata = {
  title: {
    default: "AegisAI — Autonomous Security Platform",
    template: "%s | AegisAI",
  },
  description:
    "AegisAI is an Autonomous Multi-Agent Framework for Hybrid Application Security (VAPT). " +
    "Combines SAST, DAST, and AI-driven exploit reasoning into a unified security platform.",
  keywords: [
    "VAPT",
    "penetration testing",
    "SAST",
    "DAST",
    "LangGraph",
    "AI security",
    "vulnerability assessment",
    "OWASP",
  ],
  authors: [{ name: "AegisAI Contributors" }],
  openGraph: {
    title: "AegisAI — Autonomous Security Platform",
    description:
      "Multi-Agent AI framework for hybrid application security testing.",
    type: "website",
  },
  robots: {
    index: false, // Security tool — do not index
    follow: false,
  },
};

// ── Root Layout ───────────────────────────────────────────────
export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <body
        className={`${inter.variable} ${jetbrainsMono.variable} font-sans bg-slate-950 text-slate-100 antialiased min-h-screen`}
      >
        {/* Global navigation will be added here */}
        <main className="relative">{children}</main>
      </body>
    </html>
  );
}

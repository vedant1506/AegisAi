import type { Metadata } from "next";
import Dashboard from "@/components/Dashboard";

export const metadata: Metadata = {
  title: "Dashboard",
  description:
    "AegisAI Security Dashboard — start a VAPT scan, monitor agent progress, and review vulnerability reports.",
};

/**
 * Home Page — renders the main scan dashboard.
 * Styled with an ultra-clean, elegant dark theme featuring
 * ambient liquid glass refraction without intrusive neon glowing.
 */
export default function HomePage() {
  return (
    <section
      id="home"
      className="min-h-screen liquid-bg relative overflow-x-hidden"
    >
      {/* Delicate ambient liquid light layers (very low opacity for gentle glass refraction) */}
      <div className="pointer-events-none fixed inset-0 z-0 overflow-hidden" aria-hidden="true">
        <div className="absolute -top-32 -left-32 w-[34rem] h-[34rem] rounded-full bg-cyan-500/[0.035] blur-[130px]" />
        <div className="absolute top-1/4 -right-32 w-[36rem] h-[36rem] rounded-full bg-indigo-500/[0.03] blur-[150px]" />
        <div className="absolute bottom-10 left-1/3 w-[30rem] h-[30rem] rounded-full bg-sky-500/[0.025] blur-[140px]" />
      </div>

      <div className="relative z-10">
        <Dashboard />
      </div>
    </section>
  );
}

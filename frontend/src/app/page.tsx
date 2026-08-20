import type { Metadata } from "next";
import Dashboard from "@/components/Dashboard";

export const metadata: Metadata = {
  title: "Dashboard",
  description:
    "AegisAI Security Dashboard — start a VAPT scan, monitor agent progress, and review vulnerability reports.",
};

/**
 * Home Page — renders the main scan dashboard.
 * All state management lives inside the Dashboard component
 * so this server component stays lean.
 */
export default function HomePage() {
  return (
    <section
      id="home"
      className="min-h-screen bg-gradient-to-br from-slate-950 via-aegis-950/30 to-slate-950"
    >
      <Dashboard />
    </section>
  );
}

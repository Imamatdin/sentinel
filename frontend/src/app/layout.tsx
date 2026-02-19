import type { Metadata } from "next";
import "./globals.css";
import Sidebar from "@/components/layout/Sidebar";

export const metadata: Metadata = {
  title: "SENTINEL",
  description: "Autonomous AI pentesting platform powered by Cerebras inference",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-sentinel-bg text-sentinel-text">
        <div className="flex h-screen">
          <Sidebar />
          <main className="flex-1 ml-48 overflow-auto">
            {children}
          </main>
        </div>
      </body>
    </html>
  );
}

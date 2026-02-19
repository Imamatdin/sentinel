"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import clsx from "clsx";

const NAV_ITEMS = [
  { href: "/", label: "Dashboard", icon: ">" },
  { href: "/engagements", label: "Engagements", icon: "#" },
  { href: "/findings", label: "Findings", icon: "!" },
  { href: "/genome", label: "Genome", icon: "~" },
  { href: "/settings", label: "Settings", icon: "*" },
];

export default function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-48 bg-sentinel-surface border-r border-sentinel-border flex flex-col h-screen fixed left-0 top-0 z-20">
      {/* Logo */}
      <div className="px-4 py-4 border-b border-sentinel-border">
        <Link href="/" className="font-mono text-sm font-bold tracking-[0.3em] text-sentinel-bright">
          SENTINEL
        </Link>
        <div className="text-[10px] font-mono text-sentinel-muted mt-0.5">v0.1.0</div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-2">
        {NAV_ITEMS.map((item) => {
          const isActive =
            item.href === "/"
              ? pathname === "/"
              : pathname.startsWith(item.href);

          return (
            <Link
              key={item.href}
              href={item.href}
              className={clsx(
                "flex items-center gap-3 px-4 py-2.5 text-sm font-mono transition-colors",
                isActive
                  ? "text-sentinel-bright bg-sentinel-border/50 border-r-2 border-sentinel-bright"
                  : "text-sentinel-muted hover:text-sentinel-text hover:bg-sentinel-border/30"
              )}
            >
              <span className="w-4 text-center text-xs">{item.icon}</span>
              {item.label}
            </Link>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="px-4 py-3 border-t border-sentinel-border">
        <div className="text-[10px] font-mono text-sentinel-muted">
          Cerebras Inference
        </div>
      </div>
    </aside>
  );
}

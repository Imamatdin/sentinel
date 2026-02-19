"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";

export default function NewEngagementPage() {
  const router = useRouter();
  const [targetUrl, setTargetUrl] = useState("http://localhost:3000");
  const [requireApproval, setRequireApproval] = useState(true);
  const [scanDepth, setScanDepth] = useState(3);
  const [llmProvider, setLlmProvider] = useState("cerebras");
  const [excludedPaths, setExcludedPaths] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError("");

    try {
      const result = await api.engagements.create({
        target_url: targetUrl,
        require_approval: requireApproval,
        scan_depth: scanDepth,
        llm_provider: llmProvider,
        excluded_paths: excludedPaths
          .split("\n")
          .map((p) => p.trim())
          .filter(Boolean),
      });
      router.push(`/engagements/${result.id}`);
    } catch (err: any) {
      setError(err.message || "Failed to create engagement");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="p-6 max-w-2xl">
      <h1 className="text-lg font-mono text-sentinel-bright mb-6">New Engagement</h1>

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Target URL */}
        <div>
          <label className="block text-xs font-mono text-sentinel-muted uppercase mb-1">
            Target URL
          </label>
          <input
            type="url"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            className="w-full bg-sentinel-bg border border-sentinel-border rounded px-3 py-2 text-sm font-mono text-sentinel-text focus:border-sentinel-bright outline-none"
            required
          />
        </div>

        {/* LLM Provider */}
        <div>
          <label className="block text-xs font-mono text-sentinel-muted uppercase mb-1">
            LLM Provider
          </label>
          <select
            value={llmProvider}
            onChange={(e) => setLlmProvider(e.target.value)}
            className="w-full bg-sentinel-bg border border-sentinel-border rounded px-3 py-2 text-sm font-mono text-sentinel-text focus:border-sentinel-bright outline-none"
          >
            <option value="cerebras">Cerebras</option>
            <option value="claude">Claude</option>
            <option value="openai">OpenAI</option>
          </select>
        </div>

        {/* Scan Depth */}
        <div>
          <label className="block text-xs font-mono text-sentinel-muted uppercase mb-1">
            Scan Depth: {scanDepth}
          </label>
          <input
            type="range"
            min={1}
            max={10}
            value={scanDepth}
            onChange={(e) => setScanDepth(Number(e.target.value))}
            className="w-full"
          />
        </div>

        {/* Require Approval */}
        <div className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={requireApproval}
            onChange={(e) => setRequireApproval(e.target.checked)}
            id="approval"
            className="rounded"
          />
          <label htmlFor="approval" className="text-sm font-mono text-sentinel-text">
            Require human approval for critical exploits
          </label>
        </div>

        {/* Excluded Paths */}
        <div>
          <label className="block text-xs font-mono text-sentinel-muted uppercase mb-1">
            Excluded Paths (one per line)
          </label>
          <textarea
            value={excludedPaths}
            onChange={(e) => setExcludedPaths(e.target.value)}
            rows={3}
            className="w-full bg-sentinel-bg border border-sentinel-border rounded px-3 py-2 text-sm font-mono text-sentinel-text focus:border-sentinel-bright outline-none"
            placeholder="/admin&#10;/logout"
          />
        </div>

        {error && (
          <div className="text-sm font-mono text-severity-critical">{error}</div>
        )}

        <div className="flex gap-3">
          <button type="submit" disabled={submitting} className="btn-primary">
            {submitting ? "Creating..." : "Create Engagement"}
          </button>
          <button
            type="button"
            onClick={() => router.back()}
            className="btn-secondary"
          >
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
}

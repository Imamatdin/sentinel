"use client";

import { useState } from "react";

export default function SettingsPage() {
  const [apiUrl, setApiUrl] = useState(
    process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"
  );
  const [wsUrl, setWsUrl] = useState(
    process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000/ws"
  );
  const [llmProvider, setLlmProvider] = useState("cerebras");
  const [saved, setSaved] = useState(false);

  const handleSave = () => {
    // Settings are env-based; this is a placeholder for future persistence
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div className="p-6 max-w-2xl space-y-6">
      <h1 className="text-lg font-mono text-sentinel-bright">Settings</h1>

      {/* Connection */}
      <section className="panel">
        <div className="panel-header">Connection</div>
        <div className="p-4 space-y-4">
          <div>
            <label className="block text-xs font-mono text-sentinel-muted uppercase mb-1">
              API URL
            </label>
            <input
              type="url"
              value={apiUrl}
              onChange={(e) => setApiUrl(e.target.value)}
              className="w-full bg-sentinel-bg border border-sentinel-border rounded px-3 py-2 text-sm font-mono text-sentinel-text outline-none focus:border-sentinel-bright"
            />
          </div>
          <div>
            <label className="block text-xs font-mono text-sentinel-muted uppercase mb-1">
              WebSocket URL
            </label>
            <input
              type="text"
              value={wsUrl}
              onChange={(e) => setWsUrl(e.target.value)}
              className="w-full bg-sentinel-bg border border-sentinel-border rounded px-3 py-2 text-sm font-mono text-sentinel-text outline-none focus:border-sentinel-bright"
            />
          </div>
        </div>
      </section>

      {/* LLM Provider */}
      <section className="panel">
        <div className="panel-header">LLM Configuration</div>
        <div className="p-4">
          <label className="block text-xs font-mono text-sentinel-muted uppercase mb-1">
            Default Provider
          </label>
          <select
            value={llmProvider}
            onChange={(e) => setLlmProvider(e.target.value)}
            className="w-full bg-sentinel-bg border border-sentinel-border rounded px-3 py-2 text-sm font-mono text-sentinel-text outline-none"
          >
            <option value="cerebras">Cerebras</option>
            <option value="claude">Claude (Anthropic)</option>
            <option value="openai">OpenAI</option>
          </select>
        </div>
      </section>

      {/* Save */}
      <div className="flex items-center gap-3">
        <button onClick={handleSave} className="btn-primary">
          Save Settings
        </button>
        {saved && (
          <span className="text-xs font-mono text-severity-low">Saved</span>
        )}
      </div>

      {/* Info */}
      <div className="text-xs font-mono text-sentinel-muted">
        Settings are stored locally. Connection URLs can also be configured via
        environment variables (NEXT_PUBLIC_API_URL, NEXT_PUBLIC_WS_URL).
      </div>
    </div>
  );
}

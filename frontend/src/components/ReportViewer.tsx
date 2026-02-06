'use client';

import { useState } from 'react';

interface ReportViewerProps {
  redReport: string;
  blueReport: string;
}

export function ReportViewer({ redReport, blueReport }: ReportViewerProps) {
  const [activeTab, setActiveTab] = useState<'red' | 'blue'>('red');

  const report = activeTab === 'red' ? redReport : blueReport;

  return (
    <div className="panel">
      {/* Tab bar */}
      <div className="flex border-b border-sentinel-800">
        <TabButton
          active={activeTab === 'red'}
          onClick={() => setActiveTab('red')}
          label="Pentest Report"
          team="RED"
        />
        <TabButton
          active={activeTab === 'blue'}
          onClick={() => setActiveTab('blue')}
          label="Incident Report"
          team="BLUE"
        />
      </div>

      {/* Report content */}
      <div className="p-6">
        {report ? (
          <div className="prose prose-invert prose-sm max-w-none">
            <pre className="whitespace-pre-wrap font-mono text-sm leading-relaxed text-sentinel-300">
              {report}
            </pre>
          </div>
        ) : (
          <p className="text-sentinel-600 text-sm font-mono text-center py-8">
            No report generated. Enable reports in the configuration.
          </p>
        )}
      </div>
    </div>
  );
}

function TabButton({
  active,
  onClick,
  label,
  team,
}: {
  active: boolean;
  onClick: () => void;
  label: string;
  team: string;
}) {
  return (
    <button
      onClick={onClick}
      className={`px-4 py-3 text-sm font-mono flex items-center gap-2 transition-colors
        ${active
          ? 'text-sentinel-100 border-b-2 border-sentinel-300 -mb-px'
          : 'text-sentinel-500 hover:text-sentinel-300'
        }`}
    >
      <span className={`badge ${team === 'RED' ? 'badge-red' : 'badge-blue'} text-[10px]`}>
        {team}
      </span>
      {label}
    </button>
  );
}

"use client";

interface Props {
  onZoomIn?: () => void;
  onZoomOut?: () => void;
  onReset?: () => void;
  onToggleLabels?: () => void;
  showLabels?: boolean;
}

export default function GraphControls({
  onZoomIn,
  onZoomOut,
  onReset,
  onToggleLabels,
  showLabels = true,
}: Props) {
  return (
    <div className="flex gap-1">
      <button onClick={onZoomIn} className="btn-secondary px-2 py-1 text-xs" title="Zoom In">
        +
      </button>
      <button onClick={onZoomOut} className="btn-secondary px-2 py-1 text-xs" title="Zoom Out">
        -
      </button>
      <button onClick={onReset} className="btn-secondary px-2 py-1 text-xs" title="Reset View">
        Reset
      </button>
      <button
        onClick={onToggleLabels}
        className={`btn-secondary px-2 py-1 text-xs ${showLabels ? "bg-sentinel-border" : ""}`}
        title="Toggle Labels"
      >
        Labels
      </button>
    </div>
  );
}

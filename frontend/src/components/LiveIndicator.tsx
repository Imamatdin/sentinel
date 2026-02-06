interface LiveIndicatorProps {
  active: boolean;
  size?: 'sm' | 'md';
}

export function LiveIndicator({ active, size = 'sm' }: LiveIndicatorProps) {
  const sizeClass = size === 'sm' ? 'w-2 h-2' : 'w-3 h-3';

  return (
    <span className="relative inline-flex">
      {active && (
        <span
          className={`absolute inline-flex ${sizeClass} rounded-full bg-sentinel-400 opacity-75 animate-ping`}
        />
      )}
      <span
        className={`relative inline-flex ${sizeClass} rounded-full ${
          active ? 'bg-sentinel-300' : 'bg-sentinel-700'
        }`}
      />
    </span>
  );
}

interface Props {
  technique: string;
}

export default function MITREBadge({ technique }: Props) {
  if (!technique) return null;

  return (
    <span className="px-2 py-0.5 text-[10px] font-mono rounded border border-sentinel-border text-sentinel-muted bg-sentinel-bg">
      {technique}
    </span>
  );
}

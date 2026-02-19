interface Props {
  title: string;
  paths: [string, string][];
  type: "new" | "closed" | "persistent";
}

const TYPE_STYLES: Record<string, string> = {
  new: "border-l-severity-critical",
  closed: "border-l-severity-low",
  persistent: "border-l-sentinel-muted",
};

const TYPE_PREFIX: Record<string, string> = {
  new: "+",
  closed: "-",
  persistent: "=",
};

export default function PathDelta({ title, paths, type }: Props) {
  return (
    <div>
      <h3 className="text-sm font-mono text-sentinel-muted uppercase mb-2">{title}</h3>
      <div className="space-y-1">
        {paths.map(([url, category], i) => (
          <div
            key={`${url}-${i}`}
            className={`flex items-center gap-3 px-3 py-2 bg-sentinel-surface border-l-2 rounded-r text-xs font-mono ${TYPE_STYLES[type]}`}
          >
            <span className="text-sentinel-muted w-4">{TYPE_PREFIX[type]}</span>
            <span className="text-sentinel-text flex-1 truncate">{url}</span>
            <span className="text-sentinel-muted">{category}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

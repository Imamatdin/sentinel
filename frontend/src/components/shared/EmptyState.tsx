interface Props {
  title: string;
  description?: string;
  action?: React.ReactNode;
}

export default function EmptyState({ title, description, action }: Props) {
  return (
    <div className="flex flex-col items-center justify-center p-12 text-center">
      <p className="text-sentinel-muted font-mono text-sm uppercase tracking-widest mb-2">
        {title}
      </p>
      {description && (
        <p className="text-sentinel-text text-sm max-w-md leading-relaxed mb-4">
          {description}
        </p>
      )}
      {action}
    </div>
  );
}

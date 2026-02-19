export default function LoadingSpinner({ size = "md" }: { size?: "sm" | "md" | "lg" }) {
  const sizeClasses = {
    sm: "w-4 h-4 border",
    md: "w-8 h-8 border-2",
    lg: "w-12 h-12 border-2",
  };

  return (
    <div className="flex items-center justify-center p-4">
      <div
        className={`${sizeClasses[size]} border-sentinel-muted border-t-sentinel-bright rounded-full animate-spin`}
      />
    </div>
  );
}

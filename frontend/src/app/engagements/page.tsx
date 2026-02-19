"use client";

import Link from "next/link";
import { useEngagements } from "@/hooks/useEngagement";
import EngagementCard from "@/components/dashboard/EngagementCard";
import LoadingSpinner from "@/components/shared/LoadingSpinner";
import EmptyState from "@/components/shared/EmptyState";

export default function EngagementsPage() {
  const { engagements, isLoading } = useEngagements();

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-mono text-sentinel-bright">Engagements</h1>
        <Link href="/engagements/new" className="btn-primary">
          New Engagement
        </Link>
      </div>

      {isLoading ? (
        <LoadingSpinner />
      ) : engagements.length === 0 ? (
        <EmptyState
          title="No Engagements"
          description="Create your first engagement to begin."
          action={
            <Link href="/engagements/new" className="btn-primary">
              New Engagement
            </Link>
          }
        />
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {engagements.map((eng) => (
            <EngagementCard key={eng.id} engagement={eng} />
          ))}
        </div>
      )}
    </div>
  );
}

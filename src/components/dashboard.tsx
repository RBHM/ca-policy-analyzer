"use client";

import { AnalysisResult, TenantSummary } from "@/lib/analyzer";
import { ScoreRing, StatCard } from "./ui-primitives";
import {
  ShieldCheck,
  ShieldAlert,
  ShieldOff,
  FileBarChart,
  AlertCircle,
  AlertTriangle,
} from "lucide-react";

export function Dashboard({ result }: { result: AnalysisResult }) {
  const s = result.tenantSummary;

  return (
    <div className="space-y-6">
      {/* Top Row — Score + Summary Stats */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-6">
        {/* Score Ring — spans 2 cols */}
        <div className="flex flex-col items-center justify-center rounded-xl border border-gray-800 bg-gray-900 p-6 sm:col-span-2">
          <ScoreRing score={result.overallScore} />
          <p className="mt-3 text-sm text-gray-400">Security Posture Score</p>
          <p className="text-xs text-gray-600">
            Based on {s.totalFindings} finding{s.totalFindings !== 1 ? "s" : ""}
          </p>
        </div>

        {/* Policy Stats */}
        <StatCard
          label="Enabled"
          value={s.enabledPolicies}
          icon={ShieldCheck}
          variant="success"
        />
        <StatCard
          label="Report-only"
          value={s.reportOnlyPolicies}
          icon={FileBarChart}
          variant="warning"
        />
        <StatCard
          label="Disabled"
          value={s.disabledPolicies}
          icon={ShieldOff}
          variant="default"
        />
        <StatCard
          label="Total"
          value={s.totalPolicies}
          icon={ShieldCheck}
          variant="default"
        />
      </div>

      {/* Finding Severity Breakdown */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
        <StatCard
          label="Critical"
          value={s.criticalFindings}
          icon={ShieldAlert}
          variant={s.criticalFindings > 0 ? "danger" : "default"}
        />
        <StatCard
          label="High"
          value={s.highFindings}
          icon={AlertCircle}
          variant={s.highFindings > 0 ? "danger" : "default"}
        />
        <StatCard
          label="Medium"
          value={s.mediumFindings}
          icon={AlertTriangle}
          variant={s.mediumFindings > 0 ? "warning" : "default"}
        />
        <StatCard
          label="Low"
          value={s.lowFindings}
          icon={AlertTriangle}
          variant="default"
        />
        <StatCard
          label="Info"
          value={s.infoFindings}
          icon={AlertTriangle}
          variant="default"
        />
      </div>
    </div>
  );
}

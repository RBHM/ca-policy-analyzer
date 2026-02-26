/**
 * MS Learn Exclusions View
 *
 * Displays documented Microsoft Learn exclusion findings —
 * policies that are missing required exclusions or have misconfigurations
 * per official MS documentation.
 */

"use client";

import { useState } from "react";
import { ExclusionFinding } from "@/data/known-exclusions";
import type { ImpactSeverity } from "@/data/known-exclusions";
import { Card, SeverityBadge } from "./ui-primitives";
import {
  ExternalLink,
  ChevronDown,
  ChevronRight,
  AlertTriangle,
  CheckCircle2,
  BookOpen,
  Filter,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface ExclusionsViewProps {
  findings: ExclusionFinding[];
}

const SEVERITY_ORDER: ImpactSeverity[] = ["critical", "high", "medium", "info"];

export function ExclusionsView({ findings }: ExclusionsViewProps) {
  const [severityFilter, setSeverityFilter] = useState<
    ImpactSeverity | "all"
  >("all");
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());

  const filtered =
    severityFilter === "all"
      ? findings
      : findings.filter((f) => f.exclusion.severity === severityFilter);

  const grouped = SEVERITY_ORDER.map((sev) => ({
    severity: sev,
    items: filtered.filter((f) => f.exclusion.severity === sev),
  })).filter((g) => g.items.length > 0);

  const toggle = (id: string) =>
    setExpandedIds((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });

  const sevCounts = {
    critical: findings.filter((f) => f.exclusion.severity === "critical").length,
    high: findings.filter((f) => f.exclusion.severity === "high").length,
    medium: findings.filter((f) => f.exclusion.severity === "medium").length,
    info: findings.filter((f) => f.exclusion.severity === "info").length,
  };

  if (findings.length === 0) {
    return (
      <Card>
        <div className="flex flex-col items-center justify-center py-12 text-center">
          <CheckCircle2 className="h-12 w-12 text-green-500 mb-4" />
          <h3 className="text-xl font-bold text-white mb-2">No Impact Issues Found</h3>
          <p className="text-gray-400 max-w-md">
            All policies pass the documented Microsoft Learn exclusion checks.
            No missing exclusions or misconfigurations detected.
          </p>
        </div>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <Card>
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <BookOpen className="h-5 w-5 text-blue-400" />
              <h3 className="text-lg font-bold text-white">
                MS Learn: Documented Exclusions
              </h3>
            </div>
            <p className="text-sm text-gray-400">
              Policies flagged for missing exclusions or misconfigurations per
              official Microsoft documentation. These may cause service outages,
              user lockouts, or device sign-in failures.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-amber-400" />
            <span className="text-2xl font-bold text-white">
              {findings.length}
            </span>
            <span className="text-sm text-gray-400">finding(s)</span>
          </div>
        </div>

        {/* Severity counts */}
        <div className="mt-4 flex flex-wrap gap-3">
          {sevCounts.critical > 0 && (
            <span className="rounded-full bg-red-500/15 px-3 py-1 text-xs font-medium text-red-400">
              {sevCounts.critical} Critical
            </span>
          )}
          {sevCounts.high > 0 && (
            <span className="rounded-full bg-orange-500/15 px-3 py-1 text-xs font-medium text-orange-400">
              {sevCounts.high} High
            </span>
          )}
          {sevCounts.medium > 0 && (
            <span className="rounded-full bg-yellow-500/15 px-3 py-1 text-xs font-medium text-yellow-400">
              {sevCounts.medium} Medium
            </span>
          )}
          {sevCounts.info > 0 && (
            <span className="rounded-full bg-blue-500/15 px-3 py-1 text-xs font-medium text-blue-400">
              {sevCounts.info} Info
            </span>
          )}
        </div>
      </Card>

      {/* Filter */}
      <div className="flex items-center gap-2">
        <Filter className="h-4 w-4 text-gray-500" />
        {(
          [
            { key: "all", label: "All" },
            { key: "critical", label: "Critical" },
            { key: "high", label: "High" },
            { key: "medium", label: "Medium" },
            { key: "info", label: "Info" },
          ] as const
        ).map((f) => (
          <button
            key={f.key}
            onClick={() => setSeverityFilter(f.key)}
            className={cn(
              "rounded-md px-3 py-1.5 text-xs font-medium transition-colors",
              severityFilter === f.key
                ? "bg-gray-700 text-white"
                : "text-gray-400 hover:text-white"
            )}
          >
            {f.label}
          </button>
        ))}
      </div>

      {/* Findings list */}
      {grouped.map((group) => (
        <div key={group.severity} className="space-y-3">
          <h4 className="text-sm font-semibold text-gray-300 uppercase tracking-wider">
            {group.severity} ({group.items.length})
          </h4>

          {group.items.map((finding, idx) => {
            const uid = `${finding.exclusion.id}-${finding.policyId}-${idx}`;
            const isOpen = expandedIds.has(uid);

            return (
              <Card key={uid}>
                <button
                  onClick={() => toggle(uid)}
                  className="w-full flex items-start gap-3 text-left"
                >
                  {isOpen ? (
                    <ChevronDown className="h-4 w-4 mt-0.5 text-gray-500 shrink-0" />
                  ) : (
                    <ChevronRight className="h-4 w-4 mt-0.5 text-gray-500 shrink-0" />
                  )}

                  <div className="flex-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2 mb-1">
                      <SeverityBadge severity={finding.exclusion.severity} />
                      <span className="text-sm font-semibold text-white truncate">
                        {finding.exclusion.title}
                      </span>
                    </div>
                    <p className="text-xs text-gray-500">
                      Policy:{" "}
                      <span className="text-gray-400">
                        {finding.policyName}
                      </span>
                    </p>
                  </div>
                </button>

                {isOpen && (
                  <div className="mt-4 ml-7 space-y-4 border-t border-gray-800 pt-4">
                    {/* What's wrong */}
                    <div>
                      <h5 className="text-xs font-semibold text-gray-400 uppercase mb-1">
                        Assessment
                      </h5>
                      <p className="text-sm text-gray-300">
                        {finding.result.detail}
                      </p>
                    </div>

                    {/* Impacted resources */}
                    {finding.result.impactedResources &&
                      finding.result.impactedResources.length > 0 && (
                        <div>
                          <h5 className="text-xs font-semibold text-red-400 uppercase mb-1">
                            Impacted Resources
                          </h5>
                          <ul className="list-disc list-inside space-y-0.5">
                            {finding.result.impactedResources.map((r, i) => (
                              <li
                                key={i}
                                className="text-sm text-gray-400"
                              >
                                {r}
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}

                    {/* Documented requirement */}
                    <div>
                      <h5 className="text-xs font-semibold text-blue-400 uppercase mb-1">
                        MS Learn Requirement
                      </h5>
                      <p className="text-sm text-gray-300">
                        {finding.exclusion.requirement}
                      </p>
                    </div>

                    {/* Remediation */}
                    <div>
                      <h5 className="text-xs font-semibold text-green-400 uppercase mb-1">
                        Remediation
                      </h5>
                      <p className="text-sm text-gray-300">
                        {finding.exclusion.remediation}
                      </p>
                    </div>

                    {/* Doc link */}
                    <a
                      href={finding.exclusion.docUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 transition-colors"
                    >
                      <ExternalLink className="h-3.5 w-3.5" />
                      View Microsoft Learn Documentation
                    </a>
                  </div>
                )}
              </Card>
            );
          })}
        </div>
      ))}
    </div>
  );
}

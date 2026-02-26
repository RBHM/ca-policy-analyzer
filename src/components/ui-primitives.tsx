"use client";

import { Severity } from "@/lib/analyzer";
import { cn } from "@/lib/utils";
import {
  AlertCircle,
  AlertTriangle,
  Info,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";

// ─── Severity Badge ──────────────────────────────────────────────────────────

const severityConfig: Record<
  Severity,
  { icon: typeof AlertCircle; label: string; className: string }
> = {
  critical: {
    icon: ShieldAlert,
    label: "Critical",
    className: "bg-red-500/10 text-red-400 border-red-500/30",
  },
  high: {
    icon: AlertCircle,
    label: "High",
    className: "bg-orange-500/10 text-orange-400 border-orange-500/30",
  },
  medium: {
    icon: AlertTriangle,
    label: "Medium",
    className: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  },
  low: {
    icon: Info,
    label: "Low",
    className: "bg-blue-500/10 text-blue-400 border-blue-500/30",
  },
  info: {
    icon: Info,
    label: "Info",
    className: "bg-gray-500/10 text-gray-400 border-gray-500/30",
  },
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  const config = severityConfig[severity];
  const Icon = config.icon;

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium",
        config.className
      )}
    >
      <Icon className="h-3 w-3" />
      {config.label}
    </span>
  );
}

// ─── Score Ring ──────────────────────────────────────────────────────────────

export function ScoreRing({
  score,
  size = 120,
}: {
  score: number;
  size?: number;
}) {
  const radius = (size - 12) / 2;
  const circumference = 2 * Math.PI * radius;
  const progress = (score / 100) * circumference;

  const color =
    score >= 80
      ? "text-green-500"
      : score >= 60
      ? "text-yellow-500"
      : score >= 40
      ? "text-orange-500"
      : "text-red-500";

  const bgColor =
    score >= 80
      ? "stroke-green-500/20"
      : score >= 60
      ? "stroke-yellow-500/20"
      : score >= 40
      ? "stroke-orange-500/20"
      : "stroke-red-500/20";

  return (
    <div className="relative inline-flex items-center justify-center">
      <svg width={size} height={size} className="-rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          strokeWidth={8}
          className={bgColor}
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          strokeWidth={8}
          strokeDasharray={circumference}
          strokeDashoffset={circumference - progress}
          strokeLinecap="round"
          className={cn("transition-all duration-1000", color.replace("text-", "stroke-"))}
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className={cn("text-3xl font-bold", color)}>{score}</span>
        <span className="text-xs text-gray-500">/ 100</span>
      </div>
    </div>
  );
}

// ─── Stat Card ───────────────────────────────────────────────────────────────

export function StatCard({
  label,
  value,
  icon: Icon,
  variant = "default",
}: {
  label: string;
  value: number | string;
  icon: typeof ShieldCheck;
  variant?: "default" | "success" | "warning" | "danger";
}) {
  const variantClasses = {
    default: "border-gray-800 bg-gray-900",
    success: "border-green-500/30 bg-green-500/5",
    warning: "border-yellow-500/30 bg-yellow-500/5",
    danger: "border-red-500/30 bg-red-500/5",
  };

  const iconClasses = {
    default: "text-gray-400",
    success: "text-green-500",
    warning: "text-yellow-500",
    danger: "text-red-500",
  };

  return (
    <div
      className={cn(
        "rounded-xl border p-4 transition-colors",
        variantClasses[variant]
      )}
    >
      <div className="flex items-center gap-3">
        <Icon className={cn("h-5 w-5", iconClasses[variant])} />
        <div>
          <p className="text-2xl font-bold text-white">{value}</p>
          <p className="text-xs text-gray-500">{label}</p>
        </div>
      </div>
    </div>
  );
}

// ─── Card Container ──────────────────────────────────────────────────────────

export function Card({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "rounded-xl border border-gray-800 bg-gray-900 p-6",
        className
      )}
    >
      {children}
    </div>
  );
}

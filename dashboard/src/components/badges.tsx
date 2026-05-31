import type { Severity, TriageStatus } from "../api/types";

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge sev-${severity}`}>{severity}</span>;
}

export function StatusBadge({ status }: { status: TriageStatus }) {
  return <span className={`badge status status-${status}`}>{status.replace("_", " ")}</span>;
}

export function ChainBar({ score }: { score: number }) {
  if (!score) return <span className="muted">—</span>;
  return (
    <span title={`chainability ${score.toFixed(2)}`}>
      <span className="chain-bar" style={{ width: `${Math.round(score * 48)}px` }} />{" "}
      <span className="muted">{score.toFixed(2)}</span>
    </span>
  );
}

export function ClassPill({ scanClass }: { scanClass: string }) {
  return <span className="pill">{scanClass}</span>;
}

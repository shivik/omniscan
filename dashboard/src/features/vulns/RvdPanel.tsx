import type { Finding } from "../../api/types";

// Renders RVD-specific enrichment surfaced under a finding (SKILLS.md §D.1): the
// reasoning trace, composition path, chainability, verification confidence, and the
// PoC reference (which the API already restricts for non-admin roles).
export function RvdPanel({ finding }: { finding: Finding }) {
  if (finding.scan_class !== "RVD") return null;
  const x = finding.extra as Record<string, unknown>;
  const reasoning = (x.reasoning_trace as string) ?? "";
  const composition = (x.composition_path as string[]) ?? [];
  const verified = Boolean(x.verified);
  const confidence = typeof x.confidence === "number" ? x.confidence : undefined;
  const pocRef = x.poc_ref as string | undefined;
  const backend = x.backend as string | undefined;

  return (
    <div className="card" style={{ borderColor: "var(--embargo)" }}>
      <h3 style={{ color: "var(--embargo)" }}>RVD — Residual Vulnerability Discovery</h3>
      <dl className="kv">
        <dt>Verification</dt>
        <dd>
          {verified ? (
            <span className="badge sev-high">verified</span>
          ) : (
            <span className="badge status">unverified hypothesis</span>
          )}
          {confidence !== undefined && <span className="muted"> · confidence {confidence.toFixed(2)}</span>}
        </dd>
        <dt>Chainability</dt>
        <dd>{finding.chainability_score.toFixed(2)} (first-class score across findings)</dd>
        <dt>Composition path</dt>
        <dd>{composition.length ? composition.join(" → ") : <span className="muted">—</span>}</dd>
        <dt>Backend</dt>
        <dd className="muted">{backend ?? "—"}</dd>
        <dt>PoC artifact</dt>
        <dd>
          {pocRef ? (
            <code>{pocRef}</code>
          ) : (
            <span className="muted">none generated</span>
          )}
          <div className="muted" style={{ fontSize: 12 }}>
            PoC artifacts are encrypted at rest and admin-gated.
          </div>
        </dd>
      </dl>
      {reasoning && (
        <>
          <div className="muted" style={{ margin: "8px 0 4px" }}>Reasoning trace</div>
          <div className="trace">{reasoning}</div>
        </>
      )}
    </div>
  );
}

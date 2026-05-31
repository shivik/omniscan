import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../../api/client";
import type { Finding } from "../../api/types";
import { SeverityBadge } from "../../components/badges";

// The "find what nobody else finds" surface. RVD findings tiered by residual risk
// (SKILLS.md §R.0): the unknown-unknowns tier is the flagship — compositional flaws
// that no signature scanner matches. Everything here is RVD output: embargoed by
// default, unverified until a human reproduces it, surfaced for triage — not asserted
// as fact. Backed by GET /findings?scan_class=RVD (no UI business logic).

type Tier = "unknown_unknown" | "known_unknown" | "known_known";

const TIERS: { key: Tier; title: string; blurb: string }[] = [
  {
    key: "unknown_unknown",
    title: "Unknown-unknowns",
    blurb:
      "Compositional / emergent weaknesses with no signature to match — the flaws conventional scanners are blind to. New to your posture; new candidates for cybersecurity review.",
  },
  {
    key: "known_unknown",
    title: "Known-unknowns",
    blurb: "Classes tools cover only partially — stateful logic, auth-boundary confusion.",
  },
  {
    key: "known_known",
    title: "Known-knowns",
    blurb: "Standard, signature-detectable classes RVD also surfaced.",
  },
];

function tierOf(f: Finding): Tier {
  const t = (f.extra?.risk_tier as Tier) || "unknown_unknown";
  return ["unknown_unknown", "known_unknown", "known_known"].includes(t) ? t : "unknown_unknown";
}

export function ResidualRisk() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    let live = true;
    api
      .listFindings({ scan_class: "RVD" })
      .then((rows) => live && (setFindings(rows), setError(null)))
      .catch((e) => live && setError(e.message))
      .finally(() => live && setLoading(false));
    return () => {
      live = false;
    };
  }, []);

  const grouped: Record<Tier, Finding[]> = {
    unknown_unknown: [],
    known_unknown: [],
    known_known: [],
  };
  for (const f of findings) grouped[tierOf(f)].push(f);

  return (
    <div>
      <h2 style={{ color: "var(--embargo)" }}>Residual Risk · Unknown-Unknowns</h2>
      <p className="muted" style={{ maxWidth: 760 }}>
        Flagship RVD discovery. These are candidate residual and compositional weaknesses found by
        agentic reasoning over your <strong>authorized</strong> code — not signature matches. They
        are <strong>embargoed</strong> and <strong>unverified</strong> until a human reproduces
        them. High signal, but treat each as a lead for triage, not a confirmed vulnerability.
      </p>

      {error && <div className="error">{error}</div>}
      {loading ? (
        <div className="empty">Loading…</div>
      ) : findings.length === 0 ? (
        <div className="empty">
          No RVD findings yet. Run an RVD scan (Scans → New scan → RVD) on an owned target.
        </div>
      ) : (
        TIERS.map((tier) => (
          <div className="card" key={tier.key}>
            <h3>
              {tier.title}{" "}
              <span className="pill">{grouped[tier.key].length}</span>
            </h3>
            <div className="muted" style={{ marginTop: -6, marginBottom: 10 }}>
              {tier.blurb}
            </div>
            {grouped[tier.key].length === 0 ? (
              <div className="muted">None.</div>
            ) : (
              grouped[tier.key].map((f) => (
                <ResidualCard key={f.id} finding={f} onOpen={() => navigate(`/findings/${f.id}`)} />
              ))
            )}
          </div>
        ))
      )}
    </div>
  );
}

function ResidualCard({ finding, onOpen }: { finding: Finding; onOpen: () => void }) {
  const x = finding.extra as Record<string, unknown>;
  const verified = Boolean(x.verified);
  const confidence = typeof x.confidence === "number" ? x.confidence : undefined;
  const path = (x.composition_path as string[] | undefined) ?? [];
  const trace = (x.reasoning_trace as string) ?? "";

  return (
    <div
      className="comment"
      style={{ cursor: "pointer" }}
      onClick={onOpen}
      title="Open finding detail"
    >
      <div className="toolbar" style={{ marginBottom: 6, gap: 8 }}>
        <SeverityBadge severity={finding.effective_severity} />
        <span className={`badge ${verified ? "sev-high" : "status"}`}>
          {verified ? "verified" : "unverified hypothesis"}
        </span>
        {confidence !== undefined && (
          <span className="muted">confidence {confidence.toFixed(2)}</span>
        )}
        <span className="muted">· chain {finding.chainability_score.toFixed(2)}</span>
      </div>
      <div style={{ fontWeight: 600 }}>{finding.title}</div>
      {path.length > 0 && (
        <div className="muted" style={{ fontSize: 12 }}>
          composition: {path.join(" → ")}
        </div>
      )}
      {trace && (
        <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>
          {trace.length > 220 ? trace.slice(0, 220) + "…" : trace}
        </div>
      )}
    </div>
  );
}

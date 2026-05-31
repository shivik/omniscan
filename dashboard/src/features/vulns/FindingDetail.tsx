import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, getRole } from "../../api/client";
import type { Finding, HistoryEvent, Severity, TriageStatus } from "../../api/types";
import { ChainBar, ClassPill, SeverityBadge, StatusBadge } from "../../components/badges";
import { Comments } from "./Comments";
import { RvdPanel } from "./RvdPanel";

const STATUSES: TriageStatus[] = [
  "open",
  "confirmed",
  "false_positive",
  "accepted_risk",
  "fixed",
  "embargoed",
];
const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

function canTriage(): boolean {
  const role = getRole();
  return role === "triager" || role === "admin";
}

export function FindingDetail() {
  const { id } = useParams<{ id: string }>();
  const [finding, setFinding] = useState<Finding | null>(null);
  const [history, setHistory] = useState<HistoryEvent[]>([]);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    if (!id) return;
    try {
      const [f, h] = await Promise.all([api.getFinding(id), api.history(id)]);
      setFinding(f);
      setHistory(h);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to load");
    }
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  if (error) return <div className="error">{error}</div>;
  if (!finding) return <div className="empty">Loading…</div>;

  const loc = finding.location as Record<string, unknown>;

  return (
    <div>
      <Link to="/findings" className="muted">
        ← All findings
      </Link>
      <h2 style={{ marginBottom: 4 }}>{finding.title}</h2>
      <div className="toolbar">
        <SeverityBadge severity={finding.effective_severity} />
        <StatusBadge status={finding.effective_status} />
        <ClassPill scanClass={finding.scan_class} />
        <span className="muted">{finding.rule_id}</span>
      </div>

      <div className="row">
        <div className="col">
          <div className="card">
            <h3>Details</h3>
            <dl className="kv">
              <dt>Message</dt>
              <dd>{finding.message}</dd>
              <dt>Location</dt>
              <dd>{formatLocation(loc, finding.scan_class)}</dd>
              <dt>Sources</dt>
              <dd>{finding.sources.join(", ")}</dd>
              <dt>Chainability</dt>
              <dd>
                <ChainBar score={finding.chainability_score} />
              </dd>
              <dt>Fingerprint</dt>
              <dd>
                <code>{finding.fingerprint}</code>
              </dd>
              <dt>Scan</dt>
              <dd>
                <Link to={`/findings?scan_id=${finding.scan_id}`}>{finding.scan_id}</Link>
              </dd>
              <dt>First seen</dt>
              <dd>{new Date(finding.first_seen).toLocaleString()}</dd>
            </dl>
          </div>

          <RvdPanel finding={finding} />
          <Comments findingId={finding.id} />
        </div>

        <div className="col" style={{ maxWidth: 360 }}>
          <TriagePanel finding={finding} onChange={load} />
          <HistoryTimeline events={history} />
        </div>
      </div>
    </div>
  );
}

function TriagePanel({ finding, onChange }: { finding: Finding; onChange: () => void }) {
  const [status, setStatus] = useState<TriageStatus>(finding.effective_status);
  const [severity, setSeverity] = useState<Severity | "">("");
  const [reason, setReason] = useState("");
  const [assignee, setAssignee] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const allowed = canTriage();

  async function applyTriage() {
    setBusy(true);
    setError(null);
    try {
      await api.triage(finding.id, status, reason || undefined, severity || undefined);
      setReason("");
      onChange();
    } catch (e) {
      setError(e instanceof Error ? e.message : "triage failed");
    } finally {
      setBusy(false);
    }
  }

  async function applyAssign() {
    setBusy(true);
    setError(null);
    try {
      await api.assign(finding.id, assignee || null);
      onChange();
    } catch (e) {
      setError(e instanceof Error ? e.message : "assign failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card">
      <h3>Triage</h3>
      {!allowed && (
        <div className="muted" style={{ marginBottom: 8 }}>
          Your role is read-only for triage. Findings are immutable; triage is an additive
          record.
        </div>
      )}
      <label>
        Status
        <select
          value={status}
          disabled={!allowed}
          onChange={(e) => setStatus(e.target.value as TriageStatus)}
          style={{ width: "100%" }}
        >
          {STATUSES.map((s) => (
            <option key={s} value={s}>
              {s.replace("_", " ")}
            </option>
          ))}
        </select>
      </label>
      <label>
        Severity override
        <select
          value={severity}
          disabled={!allowed}
          onChange={(e) => setSeverity(e.target.value as Severity | "")}
          style={{ width: "100%" }}
        >
          <option value="">(keep {finding.severity})</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </label>
      <label>
        Reason
        <input
          value={reason}
          disabled={!allowed}
          onChange={(e) => setReason(e.target.value)}
          style={{ width: "100%" }}
          placeholder="why this change"
        />
      </label>
      <button onClick={applyTriage} disabled={!allowed || busy} style={{ marginTop: 10, width: "100%" }}>
        Apply triage
      </button>

      <hr style={{ borderColor: "var(--border)", margin: "16px 0" }} />
      <label>
        Assignee
        <input
          value={assignee}
          disabled={!allowed}
          onChange={(e) => setAssignee(e.target.value)}
          style={{ width: "100%" }}
          placeholder="user id / team"
        />
      </label>
      <button
        className="secondary"
        onClick={applyAssign}
        disabled={!allowed || busy}
        style={{ marginTop: 10, width: "100%" }}
      >
        Assign
      </button>
      {error && <div className="error">{error}</div>}
    </div>
  );
}

function HistoryTimeline({ events }: { events: HistoryEvent[] }) {
  return (
    <div className="card">
      <h3>Status history</h3>
      {events.length === 0 ? (
        <div className="muted">No activity yet.</div>
      ) : (
        events.map((e, i) => (
          <div className="comment" key={i}>
            <div className="meta">
              <strong>{e.action}</strong> by {e.actor_id} · {new Date(e.created_at).toLocaleString()}
            </div>
            {Object.keys(e.detail).length > 0 && (
              <div className="muted" style={{ fontSize: 12 }}>
                {JSON.stringify(e.detail)}
              </div>
            )}
          </div>
        ))
      )}
    </div>
  );
}

function formatLocation(loc: Record<string, unknown>, scanClass: string): string {
  if (scanClass === "DAST") {
    return [loc.url, loc.route, loc.param].filter(Boolean).join(" · ") || "—";
  }
  const file = loc.file as string | undefined;
  const line = loc.start_line as number | undefined;
  const symbol = loc.symbol as string | undefined;
  if (file) return `${file}${line ? `:${line}` : ""}${symbol ? ` (${symbol})` : ""}`;
  if (loc.composition_path) return String(loc.composition_path);
  return "—";
}

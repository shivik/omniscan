import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { api } from "../../api/client";
import type { Finding, FindingFilters, ScanClass, Severity } from "../../api/types";
import { ChainBar, ClassPill, SeverityBadge, StatusBadge } from "../../components/badges";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const CLASSES: ScanClass[] = ["SAST", "DAST", "IAST", "RVD"];

// D.1 Unified findings view across all scan classes + projects, with filters and
// full-text search. Purely renders GET /findings — no logic here.
export function FindingsList() {
  const [params, setParams] = useSearchParams();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  const filters: FindingFilters = {
    scan_id: params.get("scan_id") || undefined,
    project_id: params.get("project_id") || undefined,
    scan_class: (params.get("scan_class") as ScanClass) || undefined,
    min_severity: (params.get("min_severity") as Severity) || undefined,
    chainable_only: params.get("chainable_only") === "1",
    q: params.get("q") || undefined,
  };

  useEffect(() => {
    let live = true;
    setLoading(true);
    api
      .listFindings(filters)
      .then((rows) => live && (setFindings(rows), setError(null)))
      .catch((e) => live && setError(e.message))
      .finally(() => live && setLoading(false));
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [params]);

  function setParam(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next);
  }

  return (
    <div>
      <h2>Findings</h2>
      <div className="toolbar">
        <input
          placeholder="Search title/message…"
          defaultValue={filters.q}
          onKeyDown={(e) => e.key === "Enter" && setParam("q", (e.target as HTMLInputElement).value)}
        />
        <select value={filters.scan_class ?? ""} onChange={(e) => setParam("scan_class", e.target.value)}>
          <option value="">All classes</option>
          {CLASSES.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
        <select value={filters.min_severity ?? ""} onChange={(e) => setParam("min_severity", e.target.value)}>
          <option value="">Any severity</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              ≥ {s}
            </option>
          ))}
        </select>
        <label className="muted" style={{ display: "flex", gap: 6, alignItems: "center" }}>
          <input
            type="checkbox"
            checked={filters.chainable_only}
            onChange={(e) => setParam("chainable_only", e.target.checked ? "1" : "")}
          />
          Chainable only
        </label>
        {filters.scan_id && (
          <span className="pill">
            scan: {filters.scan_id.slice(0, 12)}… <a onClick={() => setParam("scan_id", "")}>✕</a>
          </span>
        )}
      </div>

      {error && <div className="error">{error}</div>}
      {loading ? (
        <div className="empty">Loading…</div>
      ) : findings.length === 0 ? (
        <div className="empty">No findings match these filters.</div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Status</th>
              <th>Class</th>
              <th>Rule</th>
              <th>Title</th>
              <th>Sources</th>
              <th>Chain</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => (
              <tr key={f.id} onClick={() => navigate(`/findings/${f.id}`)}>
                <td>
                  <SeverityBadge severity={f.effective_severity} />
                </td>
                <td>
                  <StatusBadge status={f.effective_status} />
                </td>
                <td>
                  <ClassPill scanClass={f.scan_class} />
                </td>
                <td className="muted">{f.rule_id}</td>
                <td>{f.title}</td>
                <td className="muted">{f.sources.join(", ")}</td>
                <td>
                  <ChainBar score={f.chainability_score} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

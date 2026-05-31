import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../../api/client";
import type { Scan } from "../../api/types";
import { ClassPill } from "../../components/badges";

export function ScansList() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  async function load() {
    try {
      setScans(await api.listScans());
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to load scans");
    }
  }

  useEffect(() => {
    load();
    const t = setInterval(load, 2000); // live-refresh while scans run
    return () => clearInterval(t);
  }, []);

  return (
    <div>
      <div className="toolbar" style={{ justifyContent: "space-between" }}>
        <h2 style={{ margin: 0 }}>Scans</h2>
        <Link to="/scans/new">
          <button>New scan</button>
        </Link>
      </div>
      {error && <div className="error">{error}</div>}
      {scans.length === 0 ? (
        <div className="empty">No scans yet. Start one with “New scan”.</div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Scan</th>
              <th>Class</th>
              <th>Status</th>
              <th>Jobs</th>
              <th>Created</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {scans.map((s) => (
              <tr key={s.id} onClick={() => navigate(`/findings?scan_id=${s.id}`)}>
                <td>
                  <code>{s.id}</code>
                </td>
                <td>
                  <ClassPill scanClass={s.scan_class} />
                </td>
                <td>
                  <StatusText status={s.status} error={s.error} />
                </td>
                <td className="muted">{s.jobs.map((j) => `${j.adapter}:${j.status}`).join(", ")}</td>
                <td className="muted">{new Date(s.created_at).toLocaleString()}</td>
                <td>
                  <Link to={`/findings?scan_id=${s.id}`} onClick={(e) => e.stopPropagation()}>
                    findings →
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function StatusText({ status, error }: { status: string; error: string | null }) {
  const running = !["completed", "failed", "cancelled"].includes(status);
  const color = status === "failed" ? "var(--critical)" : running ? "var(--accent)" : "var(--low)";
  return (
    <span style={{ color }} title={error ?? undefined}>
      {status}
      {running && " …"}
    </span>
  );
}

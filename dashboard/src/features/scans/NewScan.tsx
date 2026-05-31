import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../../api/client";
import type { Project, ScanClass } from "../../api/types";

// New-scan wizard. Issues the same POST /scans the CLI/CI use. The dashboard adds
// no scan logic — it only assembles the request body.
export function NewScan() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectId, setProjectId] = useState("");
  const [scanClass, setScanClass] = useState<ScanClass>("SAST");
  const [repoPath, setRepoPath] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [scopeAllow, setScopeAllow] = useState("");
  const [focus, setFocus] = useState("isolation,deserialization");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    api.listProjects().then((p) => {
      setProjects(p);
      if (p[0]) setProjectId(p[0].id);
    });
  }, []);

  const isSource = scanClass === "SAST" || scanClass === "RVD";
  const isNetwork = scanClass === "DAST" || scanClass === "IAST" || scanClass === "RVD";

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      const payload: Record<string, unknown> = { scan_class: scanClass, project_id: projectId };
      if (isSource && repoPath) payload.source = { type: "path", path: repoPath };
      if (scanClass === "DAST" || scanClass === "IAST")
        payload.target = { base_url: baseUrl };
      if (scopeAllow.trim())
        payload.scope = { allow: scopeAllow.split(",").map((s) => s.trim()).filter(Boolean) };
      if (scanClass === "RVD")
        payload.rvd = { focus: focus.split(",").map((s) => s.trim()).filter(Boolean), budget: "1h" };

      const scan = await api.createScan(payload);
      navigate(`/findings?scan_id=${scan.id}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to create scan");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={{ maxWidth: 560 }}>
      <h2>New scan</h2>
      <div className="card">
        <label>
          Project
          <select value={projectId} onChange={(e) => setProjectId(e.target.value)} style={{ width: "100%" }}>
            {projects.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name} ({p.slug})
              </option>
            ))}
          </select>
        </label>
        <label style={{ display: "block", marginTop: 12 }}>
          Scan class
          <select
            value={scanClass}
            onChange={(e) => setScanClass(e.target.value as ScanClass)}
            style={{ width: "100%" }}
          >
            <option value="SAST">SAST — source analysis</option>
            <option value="DAST">DAST — running app</option>
            <option value="IAST">IAST — instrumented runtime</option>
            <option value="RVD">RVD — residual / compositional discovery (flagship)</option>
          </select>
        </label>

        {isSource && (
          <label style={{ display: "block", marginTop: 12 }}>
            Repo path (local checkout)
            <input
              value={repoPath}
              onChange={(e) => setRepoPath(e.target.value)}
              placeholder="/absolute/path/to/repo"
              style={{ width: "100%" }}
            />
          </label>
        )}
        {(scanClass === "DAST" || scanClass === "IAST") && (
          <label style={{ display: "block", marginTop: 12 }}>
            Target base URL
            <input
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              placeholder="https://staging.acme.test"
              style={{ width: "100%" }}
            />
          </label>
        )}
        {isNetwork && (
          <label style={{ display: "block", marginTop: 12 }}>
            Scope allowlist (comma-separated; required to reach hosts / for RVD ownership)
            <input
              value={scopeAllow}
              onChange={(e) => setScopeAllow(e.target.value)}
              placeholder="*.staging.acme.test"
              style={{ width: "100%" }}
            />
          </label>
        )}
        {scanClass === "RVD" && (
          <label style={{ display: "block", marginTop: 12 }}>
            Focus areas
            <input value={focus} onChange={(e) => setFocus(e.target.value)} style={{ width: "100%" }} />
          </label>
        )}

        <button onClick={submit} disabled={busy || !projectId} style={{ marginTop: 16 }}>
          {busy ? "Creating…" : "Create scan"}
        </button>
        {error && <div className="error">{error}</div>}
        <p className="muted" style={{ fontSize: 12, marginTop: 12 }}>
          scope_guard runs before any job is enqueued — out-of-scope or unverified-ownership
          requests are rejected here.
        </p>
      </div>
    </div>
  );
}

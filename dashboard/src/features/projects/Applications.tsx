import { useEffect, useState } from "react";
import { api } from "../../api/client";
import type { Application, Project } from "../../api/types";

// Applications group projects (the top of the hierarchy, mirroring Mend).
export function Applications() {
  const [apps, setApps] = useState<Application[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function load() {
    try {
      const [a, p] = await Promise.all([api.listApplications(), api.listProjects()]);
      setApps(a);
      setProjects(p);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to load");
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function create() {
    if (!name || !slug) return;
    setBusy(true);
    setError(null);
    try {
      await api.createApplication(name, slug);
      setName("");
      setSlug("");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to create");
    } finally {
      setBusy(false);
    }
  }

  const countFor = (appId: string) => projects.filter((p) => p.application_id === appId).length;

  return (
    <div>
      <h2>Applications</h2>
      <p className="page-sub">Group projects into applications for rolled-up risk.</p>
      <div className="card">
        <div className="toolbar">
          <input placeholder="Application name" value={name} onChange={(e) => setName(e.target.value)} />
          <input
            placeholder="slug"
            value={slug}
            onChange={(e) => setSlug(e.target.value.toLowerCase().replace(/\s+/g, "-"))}
          />
          <button onClick={create} disabled={busy || !name || !slug}>
            Create application
          </button>
        </div>
        {error && <div className="error">{error}</div>}
      </div>

      {apps.length === 0 ? (
        <div className="empty">No applications yet. Create one, then assign projects to it.</div>
      ) : (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Slug</th>
                <th className="num">Projects</th>
                <th>ID</th>
              </tr>
            </thead>
            <tbody>
              {apps.map((a) => (
                <tr key={a.id}>
                  <td>{a.name}</td>
                  <td className="muted">{a.slug}</td>
                  <td className="num">{countFor(a.id)}</td>
                  <td><code>{a.id}</code></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

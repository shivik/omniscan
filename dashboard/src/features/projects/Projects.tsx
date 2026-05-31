import { useEffect, useState } from "react";
import { api } from "../../api/client";
import type { Project } from "../../api/types";

export function Projects() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function load() {
    try {
      setProjects(await api.listProjects());
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
      await api.createProject(name, slug);
      setName("");
      setSlug("");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to create");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <h2>Projects</h2>
      <div className="card">
        <div className="toolbar">
          <input placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} />
          <input
            placeholder="slug"
            value={slug}
            onChange={(e) => setSlug(e.target.value.toLowerCase().replace(/\s+/g, "-"))}
          />
          <button onClick={create} disabled={busy || !name || !slug}>
            Create project
          </button>
        </div>
        {error && <div className="error">{error}</div>}
      </div>

      {projects.length === 0 ? (
        <div className="empty">No projects yet.</div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Slug</th>
              <th>ID</th>
              <th>Created</th>
            </tr>
          </thead>
          <tbody>
            {projects.map((p) => (
              <tr key={p.id}>
                <td>{p.name}</td>
                <td className="muted">{p.slug}</td>
                <td>
                  <code>{p.id}</code>
                </td>
                <td className="muted">{new Date(p.created_at).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

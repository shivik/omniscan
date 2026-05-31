import { useEffect, useState } from "react";
import { api } from "../../api/client";
import type { Comment } from "../../api/types";

// D.3 Threaded comments / collaboration. Markdown body + @mentions are parsed
// server-side; viewers may read + post. This component only calls the comments API.
export function Comments({ findingId }: { findingId: string }) {
  const [comments, setComments] = useState<Comment[]>([]);
  const [body, setBody] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    try {
      setComments(await api.listComments(findingId));
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to load comments");
    }
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [findingId]);

  async function post() {
    if (!body.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const mentions = Array.from(body.matchAll(/@([\w.-]+)/g)).map((m) => m[1]);
      await api.addComment(findingId, body, mentions);
      setBody("");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to post");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card">
      <h3>Discussion</h3>
      {comments.length === 0 && <div className="muted">No comments yet.</div>}
      {comments.map((c) => (
        <div className="comment" key={c.id}>
          <div className="meta">
            <strong>{c.author_id}</strong> · {new Date(c.created_at).toLocaleString()}
            {c.edited && " · edited"}
            {c.mentions.length > 0 && " · mentions: " + c.mentions.map((m) => "@" + m).join(" ")}
          </div>
          <div>{c.deleted ? <em className="muted">[deleted]</em> : c.body}</div>
        </div>
      ))}
      <div style={{ marginTop: 12 }}>
        <textarea
          rows={3}
          placeholder="Add a comment (Markdown, @mention supported)…"
          value={body}
          onChange={(e) => setBody(e.target.value)}
        />
        <div style={{ marginTop: 8 }}>
          <button onClick={post} disabled={busy || !body.trim()}>
            {busy ? "Posting…" : "Comment"}
          </button>
        </div>
        {error && <div className="error">{error}</div>}
      </div>
    </div>
  );
}

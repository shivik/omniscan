import { useState } from "react";
import { api, setSession } from "../../api/client";
import type { Role } from "../../api/types";

// Dev login: issues a token for a chosen role via POST /auth/token. Prod replaces
// this with an IdP redirect — but the dashboard still just stores the bearer token.
export function Login({ onLogin }: { onLogin: () => void }) {
  const [email, setEmail] = useState("triager@omniscan.local");
  const [role, setRole] = useState<Role>("triager");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      const res = await api.issueToken(email, role);
      setSession(res.token, res.role);
      onLogin();
    } catch (e) {
      setError(e instanceof Error ? e.message : "login failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login">
      <h1>OmniScan</h1>
      <p className="muted">Vulnerability-management workspace</p>
      <div className="card">
        <label>
          Email
          <input value={email} onChange={(e) => setEmail(e.target.value)} style={{ width: "100%" }} />
        </label>
        <label>
          Role
          <select value={role} onChange={(e) => setRole(e.target.value as Role)} style={{ width: "100%" }}>
            <option value="viewer">viewer (read + comment)</option>
            <option value="scanner">scanner (+ create scans)</option>
            <option value="triager">triager (+ change state)</option>
            <option value="admin">admin (+ PoC access)</option>
          </select>
        </label>
        <button onClick={submit} disabled={busy}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
        {error && <div className="error">{error}</div>}
      </div>
    </div>
  );
}

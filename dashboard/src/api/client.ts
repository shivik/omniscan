// The single API client. Every dashboard action goes through here — there is no
// scan/triage logic in the UI, only calls to the REST API (the source of truth).

import type {
  Comment,
  Finding,
  FindingFilters,
  HistoryEvent,
  Project,
  Scan,
  Severity,
  TokenResponse,
  TriageStatus,
} from "./types";

const TOKEN_KEY = "omniscan.token";
const ROLE_KEY = "omniscan.role";

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function getRole(): string | null {
  return localStorage.getItem(ROLE_KEY);
}

export function setSession(token: string, role: string): void {
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(ROLE_KEY, role);
}

export function clearSession(): void {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(ROLE_KEY);
}

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  const token = getToken();
  if (token) headers["Authorization"] = `Bearer ${token}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";

  const resp = await fetch(`/api/v1${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  if (!resp.ok) {
    let detail = `HTTP ${resp.status}`;
    try {
      const problem = await resp.json();
      detail = problem.detail || problem.title || detail;
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(detail, resp.status);
  }
  if (resp.status === 204) return undefined as T;
  return (await resp.json()) as T;
}

function qs(params: Record<string, unknown>): string {
  const entries = Object.entries(params).filter(
    ([, v]) => v !== undefined && v !== null && v !== "" && v !== false,
  );
  if (entries.length === 0) return "";
  return "?" + entries.map(([k, v]) => `${k}=${encodeURIComponent(String(v))}`).join("&");
}

export const api = {
  // --- auth ---
  issueToken: (email: string, role: string) =>
    request<TokenResponse>("POST", "/auth/token", { email, role }),

  // --- projects ---
  listProjects: () => request<Project[]>("GET", "/projects"),
  createProject: (name: string, slug: string) =>
    request<Project>("POST", "/projects", { name, slug }),

  // --- scans ---
  listScans: (projectId?: string) =>
    request<Scan[]>("GET", `/scans${qs({ project_id: projectId })}`),
  getScan: (id: string) => request<Scan>("GET", `/scans/${id}`),
  createScan: (payload: Record<string, unknown>) => request<Scan>("POST", "/scans", payload),
  report: (id: string, format: "json" | "sarif") =>
    request<Record<string, unknown>>("GET", `/scans/${id}/report${qs({ format })}`),
  gate: (id: string) => request<Record<string, unknown>>("GET", `/scans/${id}/gate`),

  // --- findings + triage + collaboration ---
  listFindings: (f: FindingFilters) => request<Finding[]>("GET", `/findings${qs({ ...f })}`),
  getFinding: (id: string) => request<Finding>("GET", `/findings/${id}`),
  triage: (id: string, status: TriageStatus, reason?: string, severityOverride?: Severity) =>
    request<unknown>("PATCH", `/findings/${id}/triage`, {
      status,
      reason,
      severity_override: severityOverride,
    }),
  assign: (id: string, assigneeId: string | null) =>
    request<unknown>("PATCH", `/findings/${id}/assignee`, { assignee_id: assigneeId }),
  history: (id: string) => request<HistoryEvent[]>("GET", `/findings/${id}/history`),
  listComments: (id: string) => request<Comment[]>("GET", `/findings/${id}/comments`),
  addComment: (id: string, body: string, mentions: string[] = []) =>
    request<Comment>("POST", `/findings/${id}/comments`, { body, mentions }),

  // --- meta ---
  capabilities: () =>
    request<{ adapters: { name: string; scan_class: string; capabilities: string[] }[] }>(
      "GET",
      "/capabilities",
    ),
};

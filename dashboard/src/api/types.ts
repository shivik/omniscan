// Types mirror the API's Pydantic schemas (api/schemas/models.py). The dashboard
// holds no business logic — these are just the shapes it renders.

export type ScanClass = "SAST" | "DAST" | "IAST" | "RVD";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type TriageStatus =
  | "open"
  | "confirmed"
  | "false_positive"
  | "accepted_risk"
  | "fixed"
  | "embargoed";
export type Role = "viewer" | "scanner" | "triager" | "admin";

export interface Application {
  id: string;
  name: string;
  slug: string;
  created_at: string;
}

export interface Project {
  id: string;
  name: string;
  slug: string;
  application_id: string | null;
  created_at: string;
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface TopApplication extends SeverityCounts {
  id: string;
  name: string;
  projects: number;
  total: number;
}

export interface TopProject extends SeverityCounts {
  id: string;
  name: string;
  application: string | null;
  total: number;
}

export interface TrendPoint {
  date: string;
  open: number;
  resolved: number;
}

export interface DashboardData {
  trend_days: number;
  engines: string[];
  overview: { applications: number; projects: number; scans: number };
  findings_by_severity: SeverityCounts;
  findings_by_engine: Record<string, SeverityCounts>;
  remediation: { remediations: number; suppressions: number };
  trends: TrendPoint[];
  top_applications: TopApplication[];
  top_projects: TopProject[];
  total_findings: number;
}

export interface Job {
  id: string;
  adapter: string;
  scan_class: ScanClass;
  status: string;
}

export interface Scan {
  id: string;
  project_id: string;
  scan_class: ScanClass;
  status: string;
  correlation_id: string;
  error: string | null;
  created_at: string;
  jobs: Job[];
}

export interface Finding {
  id: string;
  scan_id: string;
  project_id: string;
  scan_class: ScanClass;
  fingerprint: string;
  rule_id: string;
  title: string;
  message: string;
  severity: Severity;
  effective_severity: Severity;
  effective_status: TriageStatus;
  location: Record<string, unknown>;
  sources: string[];
  chainability_score: number;
  extra: Record<string, unknown>;
  first_seen: string;
}

export interface Comment {
  id: string;
  finding_id: string;
  parent_id: string | null;
  author_id: string;
  body: string;
  mentions: string[];
  edited: boolean;
  deleted: boolean;
  created_at: string;
}

export interface HistoryEvent {
  action: string;
  actor_id: string;
  detail: Record<string, unknown>;
  created_at: string;
}

export interface TokenResponse {
  token: string;
  user_id: string;
  role: Role;
}

export interface Problem {
  type: string;
  title: string;
  detail: string;
  status: number;
}

export interface FindingFilters {
  project_id?: string;
  scan_id?: string;
  scan_class?: ScanClass;
  min_severity?: Severity;
  chainable_only?: boolean;
  q?: string;
}

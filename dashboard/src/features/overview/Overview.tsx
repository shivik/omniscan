import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Area,
  AreaChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api } from "../../api/client";
import type { DashboardData, SeverityCounts } from "../../api/types";

const ENGINES = ["SAST", "DAST", "IAST", "RVD"];
const TRENDS = [7, 30, 90, 180, 365];
const SEV = [
  { key: "critical", label: "Critical", color: "#e5484d" },
  { key: "high", label: "High", color: "#f76808" },
  { key: "medium", label: "Medium", color: "#e3a008" },
  { key: "low", label: "Low", color: "#3fb950" },
  { key: "info", label: "Info", color: "#8b94a7" },
] as const;

// Mend-style Security Dashboard: engine/trend filters → overview cards → findings-by-
// severity donut + remediation + trend chart → top-10 applications/projects tables.
export function Overview() {
  const [engines, setEngines] = useState<string[]>([...ENGINES]);
  const [trend, setTrend] = useState(30);
  const [data, setData] = useState<DashboardData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    let live = true;
    api
      .dashboard(trend, engines)
      .then((d) => live && (setData(d), setError(null)))
      .catch((e) => live && setError(e.message));
    return () => {
      live = false;
    };
  }, [trend, engines]);

  function toggleEngine(e: string) {
    setEngines((cur) => (cur.includes(e) ? cur.filter((x) => x !== e) : [...cur, e]));
  }

  if (error) return <div className="error">{error}</div>;
  if (!data) return <div className="empty">Loading dashboard…</div>;

  const donut = SEV.map((s) => ({
    ...s,
    value: data.findings_by_severity[s.key as keyof SeverityCounts],
  })).filter((d) => d.value > 0);

  return (
    <div>
      <h2>Security Dashboard</h2>
      <p className="page-sub">Posture across all applications, projects, and scan engines.</p>

      {/* top bar: engine toggles + trend window */}
      <div className="topbar">
        <div className="engine-toggle">
          {ENGINES.map((e) => (
            <button key={e} className={engines.includes(e) ? "on" : ""} onClick={() => toggleEngine(e)}>
              {e}
            </button>
          ))}
        </div>
        <div className="spacer" />
        <div className="trend-select">
          <select value={trend} onChange={(ev) => setTrend(Number(ev.target.value))}>
            {TRENDS.map((t) => (
              <option key={t} value={t}>
                Last {t} days
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* overview KPI cards */}
      <div className="kpi-grid">
        <Kpi label="Applications" value={data.overview.applications} sub="with scanned projects" onClick={() => navigate("/applications")} />
        <Kpi label="Projects" value={data.overview.projects} sub="registered" onClick={() => navigate("/projects")} />
        <Kpi label="Scans" value={data.overview.scans} sub={`in last ${trend} days`} onClick={() => navigate("/scans")} />
      </div>

      {/* findings by severity / remediation / trends */}
      <div className="dash-grid">
        <div className="panel">
          <h3>Total Findings by Severity</h3>
          {donut.length === 0 ? (
            <div className="empty">No findings</div>
          ) : (
            <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
              <ResponsiveContainer width={150} height={150}>
                <PieChart>
                  <Pie data={donut} dataKey="value" nameKey="label" innerRadius={45} outerRadius={70} paddingAngle={2}>
                    {donut.map((d) => (
                      <Cell key={d.key} fill={d.color} stroke="none" />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
              <div className="legend">
                {SEV.map((s) => (
                  <div className="legend-row" key={s.key}>
                    <span className="legend-dot" style={{ background: s.color }} />
                    {s.label}
                    <span className="count">{data.findings_by_severity[s.key as keyof SeverityCounts]}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
          <div className="panel-foot">{data.total_findings} findings total</div>
        </div>

        <div className="panel">
          <h3>Remediation Analysis</h3>
          <div className="remediation">
            <div className="metric">
              <div className="n" style={{ color: "#3fb950" }}>{data.remediation.remediations}</div>
              <div className="l">Remediations</div>
            </div>
            <div className="metric">
              <div className="n" style={{ color: "#8b94a7" }}>{data.remediation.suppressions}</div>
              <div className="l">Suppressions</div>
            </div>
          </div>
          <div className="panel-foot">in the selected {trend}-day window</div>
        </div>

        <div className="panel">
          <h3>Findings Trends</h3>
          <ResponsiveContainer width="100%" height={170}>
            <AreaChart data={data.trends} margin={{ top: 4, right: 8, left: -18, bottom: 0 }}>
              <defs>
                <linearGradient id="gOpen" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#f76808" stopOpacity={0.5} />
                  <stop offset="100%" stopColor="#f76808" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gRes" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#3fb950" stopOpacity={0.5} />
                  <stop offset="100%" stopColor="#3fb950" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="date" tick={{ fontSize: 10, fill: "var(--muted)" }} tickLine={false} />
              <YAxis tick={{ fontSize: 10, fill: "var(--muted)" }} tickLine={false} axisLine={false} width={28} />
              <Tooltip />
              <Area type="monotone" dataKey="open" stroke="#f76808" fill="url(#gOpen)" name="Open" />
              <Area type="monotone" dataKey="resolved" stroke="#3fb950" fill="url(#gRes)" name="Resolved" />
            </AreaChart>
          </ResponsiveContainer>
          <div className="panel-foot">New findings per day, open vs resolved</div>
        </div>
      </div>

      {/* top-10 applications + projects */}
      <div className="dash-grid-2">
        <RiskTable
          title="Top Applications by Risk"
          rows={data.top_applications.map((a) => ({ ...a, extra: `${a.projects} projects` }))}
          onRow={() => navigate("/applications")}
        />
        <RiskTable
          title="Top Projects by Risk"
          rows={data.top_projects.map((p) => ({ ...p, extra: p.application ?? "—" }))}
          onRow={(id) => navigate(`/findings?project_id=${id}`)}
        />
      </div>
    </div>
  );
}

function Kpi({ label, value, sub, onClick }: { label: string; value: number; sub: string; onClick: () => void }) {
  return (
    <div className="kpi" onClick={onClick}>
      <div className="label">{label}</div>
      <div className="value">{value}</div>
      <div className="sub">{sub}</div>
    </div>
  );
}

interface RiskRow extends SeverityCounts {
  id: string;
  name: string;
  total: number;
  extra: string;
}

function RiskTable({ title, rows, onRow }: { title: string; rows: RiskRow[]; onRow: (id: string) => void }) {
  return (
    <div className="panel">
      <h3>{title}</h3>
      {rows.length === 0 ? (
        <div className="empty">No data</div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th></th>
              <th className="num">Total</th>
              <th className="num">C</th>
              <th className="num">H</th>
              <th className="num">M</th>
              <th className="num">L</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id} onClick={() => onRow(r.id)}>
                <td>{r.name}</td>
                <td className="muted">{r.extra}</td>
                <td className="num">{r.total}</td>
                <td className="num"><Sev n={r.critical} c="c" /></td>
                <td className="num"><Sev n={r.high} c="h" /></td>
                <td className="num"><Sev n={r.medium} c="m" /></td>
                <td className="num"><Sev n={r.low} c="l" /></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function Sev({ n, c }: { n: number; c: string }) {
  return <span className={`sevchip ${c}${n === 0 ? " zero" : ""}`}>{n}</span>;
}

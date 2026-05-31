import { useState } from "react";
import { NavLink, Navigate, Route, Routes, useNavigate } from "react-router-dom";
import { clearSession, getRole, getToken } from "./api/client";
import { Login } from "./features/auth/Login";
import { FindingsList } from "./features/vulns/FindingsList";
import { FindingDetail } from "./features/vulns/FindingDetail";
import { ResidualRisk } from "./features/residual/ResidualRisk";
import { ScansList } from "./features/scans/ScansList";
import { NewScan } from "./features/scans/NewScan";
import { Projects } from "./features/projects/Projects";

export function App() {
  const [token, setToken] = useState<string | null>(getToken());

  if (!token) return <Login onLogin={() => setToken(getToken())} />;

  return (
    <div className="app">
      <Sidebar onLogout={() => setToken(null)} />
      <div className="main">
        <Routes>
          <Route path="/" element={<Navigate to="/findings" replace />} />
          <Route path="/findings" element={<FindingsList />} />
          <Route path="/findings/:id" element={<FindingDetail />} />
          <Route path="/residual" element={<ResidualRisk />} />
          <Route path="/scans" element={<ScansList />} />
          <Route path="/scans/new" element={<NewScan />} />
          <Route path="/projects" element={<Projects />} />
          <Route path="*" element={<div className="empty">Not found</div>} />
        </Routes>
      </div>
    </div>
  );
}

function Sidebar({ onLogout }: { onLogout: () => void }) {
  const navigate = useNavigate();
  const role = getRole();
  function logout() {
    clearSession();
    onLogout();
    navigate("/");
  }
  return (
    <nav className="sidebar">
      <h1>OmniScan</h1>
      <span className="brand-rvd">SAST · DAST · IAST · RVD</span>
      <NavLink to="/findings" className="nav-link">
        Findings
      </NavLink>
      <NavLink to="/residual" className="nav-link" style={{ color: "var(--embargo)" }}>
        Residual Risk ✦
      </NavLink>
      <NavLink to="/scans" className="nav-link">
        Scans
      </NavLink>
      <NavLink to="/projects" className="nav-link">
        Projects
      </NavLink>
      <div className="spacer" />
      <div className="session">
        role: <strong>{role}</strong>
        <br />
        <a onClick={logout} style={{ cursor: "pointer" }}>
          Sign out
        </a>
      </div>
    </nav>
  );
}

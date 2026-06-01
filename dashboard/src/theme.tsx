import { createContext, useContext, useEffect, useMemo, useState } from "react";

// Theme modes: "auto" follows the local sunrise→sunset (light during the day, dark at
// night) using the browser's geolocation; "light"/"dark" are explicit user overrides.
// The resolved theme drives a data-theme attribute on <html>, swapping CSS variables.

export type ThemeMode = "auto" | "light" | "dark";
export type ResolvedTheme = "light" | "dark";

const KEY = "omniscan.theme";
const COORDS_KEY = "omniscan.coords";

// ---- sunrise/sunset (NOAA-style solar algorithm; dependency-free public-domain math) ----
const rad = Math.PI / 180;
const J2000 = 2451545;

function toJulian(date: Date): number {
  return date.valueOf() / 86400000 - 0.5 + 2440588;
}
function fromJulian(j: number): Date {
  return new Date((j + 0.5 - 2440588) * 86400000);
}
function solarMeanAnomaly(d: number): number {
  return rad * (357.5291 + 0.98560028 * d);
}
function eclipticLongitude(M: number): number {
  const C = rad * (1.9148 * Math.sin(M) + 0.02 * Math.sin(2 * M) + 0.0003 * Math.sin(3 * M));
  const P = rad * 102.9372;
  return M + C + P + Math.PI;
}

type SunTimes = { sunrise: Date; sunset: Date } | { polar: "day" | "night" };

function sunTimes(date: Date, lat: number, lng: number): SunTimes {
  const lw = rad * -lng;
  const phi = rad * lat;
  const d = toJulian(date) - J2000;
  const n = Math.round(d - 0.0009 - lw / (2 * Math.PI));
  const ds = 0.0009 + lw / (2 * Math.PI) + n;
  const M = solarMeanAnomaly(ds);
  const L = eclipticLongitude(M);
  const dec = Math.asin(Math.sin(rad * 23.4397) * Math.sin(L));
  const Jtransit = J2000 + ds + 0.0053 * Math.sin(M) - 0.0069 * Math.sin(2 * L);
  const h = rad * -0.833; // standard solar altitude at sunrise/sunset (incl. refraction)
  const cosH = (Math.sin(h) - Math.sin(phi) * Math.sin(dec)) / (Math.cos(phi) * Math.cos(dec));
  if (cosH > 1) return { polar: "night" }; // sun never rises today
  if (cosH < -1) return { polar: "day" }; // sun never sets today
  const H = Math.acos(cosH);
  const Jset = J2000 + (0.0009 + (H + lw) / (2 * Math.PI) + n) + 0.0053 * Math.sin(M) - 0.0069 * Math.sin(2 * L);
  const Jrise = Jtransit - (Jset - Jtransit);
  return { sunrise: fromJulian(Jrise), sunset: fromJulian(Jset) };
}

type Coords = { lat: number; lng: number };

function loadCoords(): Coords | null {
  try {
    const raw = localStorage.getItem(COORDS_KEY);
    return raw ? (JSON.parse(raw) as Coords) : null;
  } catch {
    return null;
  }
}

// Fallback when geolocation is unavailable/denied: simple daytime window.
function hourHeuristic(now = new Date()): ResolvedTheme {
  const h = now.getHours();
  return h >= 6 && h < 18 ? "light" : "dark";
}

function autoTheme(coords: Coords | null, now = new Date()): ResolvedTheme {
  if (!coords) return hourHeuristic(now);
  const t = sunTimes(now, coords.lat, coords.lng);
  if ("polar" in t) return t.polar === "day" ? "light" : "dark";
  return now >= t.sunrise && now < t.sunset ? "light" : "dark";
}

export function resolveTheme(mode: ThemeMode, coords: Coords | null): ResolvedTheme {
  if (mode === "light" || mode === "dark") return mode;
  return autoTheme(coords);
}

interface ThemeCtx {
  mode: ThemeMode;
  resolved: ResolvedTheme;
  setMode: (m: ThemeMode) => void;
  geoEnabled: boolean;
}

const Ctx = createContext<ThemeCtx | null>(null);

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [mode, setModeState] = useState<ThemeMode>(
    () => (localStorage.getItem(KEY) as ThemeMode) || "auto",
  );
  const [coords, setCoords] = useState<Coords | null>(() => loadCoords());
  const [resolved, setResolved] = useState<ResolvedTheme>(() => resolveTheme(mode, coords));

  // In auto mode, ask the browser for location once so we can use real sunrise/sunset.
  useEffect(() => {
    if (mode !== "auto" || coords || !("geolocation" in navigator)) return;
    navigator.geolocation.getCurrentPosition(
      (pos) => {
        const c = { lat: pos.coords.latitude, lng: pos.coords.longitude };
        localStorage.setItem(COORDS_KEY, JSON.stringify(c));
        setCoords(c);
      },
      () => {
        /* denied/unavailable → keep the hour-based fallback */
      },
      { maximumAge: 6 * 3600 * 1000, timeout: 8000 },
    );
  }, [mode, coords]);

  useEffect(() => {
    const apply = () => setResolved(resolveTheme(mode, coords));
    apply();
    if (mode !== "auto") return;
    const t = setInterval(apply, 60_000); // flip at sunrise/sunset without a reload
    return () => clearInterval(t);
  }, [mode, coords]);

  useEffect(() => {
    document.documentElement.dataset.theme = resolved;
  }, [resolved]);

  const setMode = (m: ThemeMode) => {
    setModeState(m);
    localStorage.setItem(KEY, m);
  };

  const value = useMemo(
    () => ({ mode, resolved, setMode, geoEnabled: coords !== null }),
    [mode, resolved, coords],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useTheme(): ThemeCtx {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useTheme must be used within ThemeProvider");
  return ctx;
}

export function ThemeSwitcher() {
  const { mode, resolved, setMode, geoEnabled } = useTheme();
  const modes: ThemeMode[] = ["auto", "light", "dark"];
  const icon = { auto: "◑", light: "☀", dark: "☾" } as const;
  const autoHint = mode === "auto" ? (geoEnabled ? " (sun)" : " (clock)") : "";
  return (
    <div
      className="theme-switcher"
      title={`theme: ${mode}${autoHint} — showing ${resolved}`}
    >
      {modes.map((m) => (
        <button
          key={m}
          className={"theme-btn" + (mode === m ? " active" : "")}
          onClick={() => setMode(m)}
          aria-label={`theme ${m}`}
        >
          {icon[m]} {m}
        </button>
      ))}
    </div>
  );
}

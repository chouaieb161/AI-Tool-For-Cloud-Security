import { useEffect, useMemo, useState } from 'react';
import { useLocation } from 'react-router-dom';
import {
  Activity, AlertTriangle, ArrowUpRight, ArrowDownRight, CheckCircle2,
  ChevronLeft, ChevronRight, Minus, Radar, Search,
  ShieldAlert, ShieldCheck, X
} from 'lucide-react';
import { useDashboard } from '../hooks/useDashboard';
import { api } from '../api';
import type { Finding, ScanStatus } from '../api';

/* ─── helpers ─── */
const SEVERITY_TEXT: Record<string, string> = {
  CRITICAL: 'text-red-800 bg-red-100', HIGH: 'text-orange-800 bg-orange-100',
  MEDIUM: 'text-yellow-800 bg-yellow-100', LOW: 'text-blue-800 bg-blue-100',
};
const SEVERITY_ROW = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const PAGE_SIZE = 15;

function shortResourceLabel(f: Finding) {
  if (f.resource_name) return f.resource_name;
  if (f.resource_gcp_uri) return f.resource_gcp_uri.split('/').filter(Boolean).pop() || f.resource_gcp_uri;
  return 'Project/org-level finding';
}

/* ─── SVG Sparkline (pure SVG, no recharts) ─── */
function ScoreTrendChart({ data }: { data: { score: number; scan_id: number }[] }) {
  if (!data || data.length < 2) return <p className="text-sm text-slate-400">Not enough scans yet.</p>;
  const w = 560, h = 140, pad = { top: 10, right: 10, bottom: 24, left: 36 };
  const iw = w - pad.left - pad.right, ih = h - pad.top - pad.bottom;
  const scores = data.map(d => d.score);
  const min = Math.min(...scores), max = Math.max(...scores);
  const range = Math.max(max - min, 10);
  const xScale = (i: number) => pad.left + (i / (data.length - 1)) * iw;
  const yScale = (v: number) => pad.top + ih - ((v - min) / range) * ih;
  const pts = data.map((d, i) => `${xScale(i)},${yScale(d.score)}`).join(' ');
  const prev = data.length >= 2 ? data[data.length - 2].score : data[0].score;
  const curr = data[data.length - 1].score;
  const delta = curr - prev;
  const area = `${pts} ${xScale(data.length - 1)},${pad.top + ih} ${xScale(0)},${pad.top + ih} Z`;

  return (
    <div className="relative">
      <svg viewBox={`0 0 ${w} ${h}`} className="w-full h-auto" preserveAspectRatio="xMidYMid meet">
        {/* grid lines */}
        {[0.25, 0.5, 0.75].map(f => {
          const y = pad.top + ih * (1 - f);
          return <line key={f} x1={pad.left} y1={y} x2={w - pad.right} y2={y} stroke="#e2e8f0" strokeWidth={1} />;
        })}
        {/* area fill */}
        <path d={area} fill="url(#trendGrad)" opacity={0.25} />
        <defs>
          <linearGradient id="trendGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={delta >= 0 ? '#10b981' : '#ef4444'} />
            <stop offset="100%" stopColor={delta >= 0 ? '#10b981' : '#ef4444'} stopOpacity={0.05} />
          </linearGradient>
        </defs>
        {/* line */}
        <polyline points={pts} fill="none" stroke={delta >= 0 ? '#10b981' : '#ef4444'} strokeWidth={2} strokeLinejoin="round" />
        {/* dots */}
        {data.map((d, i) => (
          <circle key={d.scan_id} cx={xScale(i)} cy={yScale(d.score)} r={i === data.length - 1 ? 4 : 2}
            fill={i === data.length - 1 ? (delta >= 0 ? '#10b981' : '#ef4444') : '#94a3b8'} />
        ))}
        {/* y axis labels */}
        {[min, Math.round((min + max) / 2), max].map(v => (
          <text key={v} x={pad.left - 4} y={yScale(v) + 4} textAnchor="end" className="text-[10px] fill-slate-400">{v}</text>
        ))}
      </svg>
      <div className="absolute top-0 right-0 flex items-center gap-1 text-xs font-medium bg-white/80 px-2 py-0.5 rounded">
        {delta >= 0 ? <ArrowUpRight size={14} className="text-emerald-600" /> : <ArrowDownRight size={14} className="text-red-600" />}
        <span className={delta >= 0 ? 'text-emerald-600' : 'text-red-600'}>{delta >= 0 ? '+' : ''}{delta}</span>
      </div>
    </div>
  );
}

/* ─── Heatmap (pure CSS grid) ─── */
function HeatmapGrid({ rows }: { rows: { category: string; critical: number; high: number; medium: number; low: number; total: number }[] }) {
  if (!rows.length) return <p className="text-sm text-slate-400">No matrix data yet.</p>;
  const maxVal = Math.max(...rows.flatMap(r => [r.critical, r.high, r.medium, r.low]), 1);

  function Cell({ val, label }: { val: number; label: string }) {
    if (!val) return <div className="w-8 h-8 rounded bg-slate-50" title={`${label}: 0`} />;
    const intensity = Math.min(val / maxVal, 1);
    const bg = label === 'CRITICAL' ? `rgba(239,68,68,${0.1 + intensity * 0.7})`
           : label === 'HIGH'    ? `rgba(249,115,22,${0.1 + intensity * 0.7})`
           : label === 'MEDIUM'  ? `rgba(250,204,21,${0.1 + intensity * 0.7})`
           :                      `rgba(14,165,233,${0.1 + intensity * 0.7})`;
    return <div className="w-8 h-8 rounded flex items-center justify-center text-[10px] font-semibold" style={{ backgroundColor: bg }} title={`${label}: ${val}`}>{val}</div>;
  }

  return (
    <div className="overflow-x-auto">
      <div className="inline-grid grid-cols-[auto_repeat(4,2rem)] gap-1 text-xs">
        <div />
        {SEVERITY_ROW.map(s => <div key={s} className="text-center text-[10px] text-slate-400 font-medium">{s.slice(0, 3)}</div>)}
        {rows.map(row => (
          <>
            <div key={row.category} className="text-right pr-2 text-[11px] text-slate-600 truncate max-w-[100px]">{row.category}</div>
            <Cell val={row.critical} label="CRITICAL" />
            <Cell val={row.high} label="HIGH" />
            <Cell val={row.medium} label="MEDIUM" />
            <Cell val={row.low} label="LOW" />
          </>
        ))}
      </div>
    </div>
  );
}

/* ─── Findings table with filters + pagination ─── */
function FindingsTable({
  findings,
  selectedFinding,
  onSelect,
  onClose,
}: {
  findings: Finding[];
  selectedFinding: Finding | null;
  onSelect: (f: Finding | null) => void;
  onClose: () => void;
}) {
  const [search, setSearch] = useState('');
  const [sevFilter, setSevFilter] = useState<string[]>([]);
  const [catFilter, setCatFilter] = useState<string[]>([]);
  const [page, setPage] = useState(0);

  const categories = useMemo(() => [...new Set(findings.map(f => f.category).filter(Boolean))], [findings]);

  const filtered = useMemo(() => {
    return findings.filter(f => {
      if (sevFilter.length && !sevFilter.includes(f.severity)) return false;
      if (catFilter.length && !catFilter.includes(f.category)) return false;
      if (search) {
        const q = search.toLowerCase();
        return (
          f.description.toLowerCase().includes(q) ||
          (f.resource_name || '').toLowerCase().includes(q) ||
          f.cis_rule_id.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [findings, sevFilter, catFilter, search]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const safePage = Math.min(page, totalPages - 1);
  const pageItems = filtered.slice(safePage * PAGE_SIZE, (safePage + 1) * PAGE_SIZE);

  function toggleSev(s: string) {
    setSevFilter(p => p.includes(s) ? p.filter(x => x !== s) : [...p, s]);
    setPage(0);
  }
  function toggleCat(c: string) {
    setCatFilter(p => p.includes(c) ? p.filter(x => x !== c) : [...p, c]);
    setPage(0);
  }

  return (
    <div className="bg-white rounded-lg border border-slate-200 shadow-sm overflow-hidden">
      {/* toolbar */}
      <div className="p-4 border-b border-slate-200 bg-slate-50 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h3 className="text-lg font-medium text-slate-800">Recent Findings</h3>
          <span className="text-xs text-slate-400">{filtered.length} of {findings.length} total</span>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative flex-1 min-w-[180px] max-w-xs">
            <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text" placeholder="Search description, resource, CIS rule…"
              value={search} onChange={e => { setSearch(e.target.value); setPage(0); }}
              className="w-full rounded-md border border-slate-300 bg-white py-1.5 pl-8 pr-3 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div className="flex flex-wrap gap-1.5">
            {SEVERITY_ROW.map(s => (
              <button key={s} onClick={() => toggleSev(s)}
                className={`px-2.5 py-1 rounded-md text-xs font-medium border transition-colors ${
                  sevFilter.includes(s)
                    ? `${SEVERITY_TEXT[s]} border-transparent`
                    : 'text-slate-500 border-slate-200 bg-white hover:bg-slate-50'
                }`}>
                {s}
              </button>
            ))}
          </div>
          <select
            multiple
            value={catFilter}
            onChange={e => { setCatFilter(Array.from(e.target.selectedOptions, o => o.value)); setPage(0); }}
            className="hidden lg:block text-xs border border-slate-200 rounded-md px-2 py-1 max-w-[140px]"
          >
            {categories.map(c => <option key={c} value={c}>{c}</option>)}
          </select>
          {catFilter.map(c => (
            <span key={c} className="inline-flex items-center gap-1 rounded-full bg-blue-50 text-blue-700 px-2 py-0.5 text-xs font-medium">
              {c} <button onClick={() => toggleCat(c)}><X size={12} /></button>
            </span>
          ))}
        </div>
      </div>

      {pageItems.length === 0 ? (
        <div className="p-8 text-center text-slate-500">No findings match your filters.</div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full table-fixed text-left text-sm">
            <thead className="uppercase tracking-wider border-b border-slate-200 bg-slate-50 text-slate-500">
              <tr>
                <th className="w-24 px-5 py-3 font-medium">Severity</th>
                <th className="w-28 px-5 py-3 font-medium">Category</th>
                <th className="w-20 px-5 py-3 font-medium">CIS Rule</th>
                <th className="w-44 px-5 py-3 font-medium">Project</th>
                <th className="w-56 px-5 py-3 font-medium">Resource</th>
                <th className="px-5 py-3 font-medium">Finding</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200">
              {pageItems.map(f => (
                <tr key={f.id} tabIndex={0} onClick={() => onSelect(f)}
                  onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect(f); } }}
                  className={`cursor-pointer transition-colors focus:outline-none focus:ring-2 focus:ring-inset focus:ring-blue-500 ${
                    selectedFinding?.id === f.id ? 'bg-blue-50' : 'hover:bg-slate-50'
                  }`}>
                  <td className="px-5 py-4 align-top">
                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${SEVERITY_TEXT[f.severity]}`}>
                      {f.severity}
                    </span>
                  </td>
                  <td className="px-5 py-4 align-top">
                    <span className="inline-flex items-center rounded-md border border-slate-200 bg-slate-50 px-2.5 py-1 text-xs font-medium text-slate-700">
                      {f.category || 'Unknown'}
                    </span>
                  </td>
                  <td className="px-5 py-4 align-top font-medium text-slate-700">{f.cis_rule_id}</td>
                  <td className="px-5 py-4 align-top text-slate-700 truncate" title={f.resource_project_id || undefined}>
                    {f.resource_project_id || 'Scope-level'}
                  </td>
                  <td className="px-5 py-4 align-top">
                    <div className="truncate font-medium text-slate-800" title={f.resource_gcp_uri || f.resource_name || undefined}>
                      {shortResourceLabel(f)}
                    </div>
                    <div className="truncate text-xs text-slate-500">{f.resource_type || 'Unspecified type'}</div>
                  </td>
                  <td className="px-5 py-4 align-top text-slate-600">
                    <p className="line-clamp-2 whitespace-normal break-words" title={f.description}>{f.description}</p>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between px-5 py-3 border-t border-slate-200 bg-slate-50 text-sm">
          <span className="text-slate-500">Page {safePage + 1} of {totalPages}</span>
          <div className="flex gap-1">
            <button disabled={safePage <= 0} onClick={() => setPage(p => p - 1)}
              className="inline-flex items-center rounded-md border border-slate-200 bg-white px-2.5 py-1 text-xs font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-30">
              <ChevronLeft size={14} /> Prev
            </button>
            <button disabled={safePage >= totalPages - 1} onClick={() => setPage(p => p + 1)}
              className="inline-flex items-center rounded-md border border-slate-200 bg-white px-2.5 py-1 text-xs font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-30">
              Next <ChevronRight size={14} />
            </button>
          </div>
        </div>
      )}

      {/* detail modal */}
      {selectedFinding && (
        <div className="fixed inset-0 z-50 flex items-end justify-center bg-slate-950/35 px-4 py-6 backdrop-blur-sm sm:items-center"
          role="dialog" aria-modal="true" onClick={() => onClose()}>
          <div className="max-h-[88vh] w-full max-w-3xl overflow-y-auto rounded-lg border border-slate-200 bg-white shadow-2xl"
            onClick={e => e.stopPropagation()}>
            <div className="sticky top-0 z-10 flex items-start justify-between gap-4 border-b border-slate-200 bg-white px-5 py-4">
              <div>
                <div className="flex flex-wrap items-center gap-2">
                  <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold ${SEVERITY_TEXT[selectedFinding.severity]}`}>
                    {selectedFinding.severity}
                  </span>
                  <span className="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-semibold text-slate-700">CIS {selectedFinding.cis_rule_id}</span>
                  <span className="rounded-full bg-blue-50 px-2.5 py-1 text-xs font-semibold text-blue-700">{selectedFinding.category || 'Unknown'}</span>
                </div>
                <h3 className="mt-3 text-xl font-semibold text-slate-900">{shortResourceLabel(selectedFinding)}</h3>
                <p className="mt-1 text-sm text-slate-500">
                  {selectedFinding.resource_project_id ? `Project: ${selectedFinding.resource_project_id}` : 'Scope-level finding'}
                  {' · '}{selectedFinding.resource_type || 'Unspecified resource type'}
                </p>
              </div>
              <button type="button" onClick={() => onClose()}
                className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-md border border-slate-200 bg-white text-slate-500 hover:bg-slate-50">
                <X size={18} />
              </button>
            </div>
            <div className="space-y-5 px-5 py-5">
              <section>
                <h4 className="text-sm font-semibold uppercase tracking-wide text-slate-500">Description</h4>
                <p className="mt-2 whitespace-pre-wrap break-words rounded-md border border-slate-200 bg-slate-50 p-4 text-sm leading-6 text-slate-800">
                  {selectedFinding.description}
                </p>
              </section>
              <section>
                <h4 className="text-sm font-semibold uppercase tracking-wide text-slate-500">Remediation</h4>
                <p className="mt-2 whitespace-pre-wrap break-words rounded-md border border-emerald-100 bg-emerald-50 p-4 text-sm leading-6 text-slate-800">
                  {selectedFinding.remediation_steps}
                </p>
              </section>
              <dl className="grid gap-3 rounded-md border border-slate-200 bg-white p-4 text-sm sm:grid-cols-2">
                <div><dt className="font-medium text-slate-500">Resource URI</dt><dd className="mt-1 break-words text-slate-800">{selectedFinding.resource_gcp_uri ?? 'N/A'}</dd></div>
                <div><dt className="font-medium text-slate-500">Project</dt><dd className="mt-1 break-words text-slate-800">{selectedFinding.resource_project_id ?? 'Scope-level'}</dd></div>
                <div><dt className="font-medium text-slate-500">Resource DB ID</dt><dd className="mt-1 break-words text-slate-800">{selectedFinding.resource_id ?? 'N/A'}</dd></div>
                <div><dt className="font-medium text-slate-500">Scan ID</dt><dd className="mt-1 break-words text-slate-800">{selectedFinding.scan_id}</dd></div>
              </dl>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ─── Main Dashboard Component ─── */
export default function DashboardPage() {
  const {
    project, dashboard, findings, scanHistory, findingsMatrix, remediationPlan, scanDiff,
    loading, error, reload,
  } = useDashboard();
  const location = useLocation();
  const [scan, setScan] = useState<ScanStatus | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [showDiff, setShowDiff] = useState(false);
  const scanId = useMemo(() => {
    const state = location.state as { scanId?: number } | null;
    return state?.scanId ?? null;
  }, [location.state]);

  useEffect(() => {
    let timer: number | undefined;
    const loadScan = async () => {
      if (!scanId) return;
      try {
        setScanError(null);
        const data = await api.getScan(scanId);
        setScan(data);
        if (data.status !== 'COMPLETED' && data.status !== 'FAILED') {
          timer = window.setTimeout(loadScan, 3000);
        }
      } catch { setScanError('Unable to load scan status.'); }
    };
    loadScan();
    return () => { if (timer) window.clearTimeout(timer); };
  }, [scanId]);

  useEffect(() => {
    if (!scanId || !scan || scan.status !== 'COMPLETED') return;
    if (dashboard?.latest_scan_id === scanId) return;
    reload();
  }, [scanId, scan, dashboard?.latest_scan_id, reload]);

  useEffect(() => {
    if (!selectedFinding) return;
    if (!findings.some(f => f.id === selectedFinding.id)) setSelectedFinding(null);
  }, [findings, selectedFinding]);

  if (loading) return <div className="text-slate-500 p-8 text-center animate-pulse">Loading dashboard...</div>;
  if (error) return <div className="text-red-500 p-8 text-center bg-red-50 rounded-lg">{error}</div>;

  const riskScore = dashboard?.risk_score ?? 0;
  const compliance = dashboard?.compliance_percentage ?? 0;
  const totalResources = dashboard?.total_resources_count ?? 0;
  const criticalCount = dashboard?.findings_by_severity?.CRITICAL ?? 0;
  const highCount = dashboard?.findings_by_severity?.HIGH ?? 0;
  const mediumCount = dashboard?.findings_by_severity?.MEDIUM ?? 0;
  const lowCount = dashboard?.findings_by_severity?.LOW ?? 0;
  const highCritical = criticalCount + highCount;
  const totalFindings = criticalCount + highCount + mediumCount + lowCount;
  const resourceCountBasis = dashboard?.resource_count_basis ?? 'unknown';
  const resourceCountNote = {
    latest_scan_observed: 'Observed in latest scan',
    project_inventory_fallback: 'Fallback: tracked project inventory',
    project_inventory_no_completed_scan: 'Tracked inventory; no completed scan',
  }[resourceCountBasis] || 'No completed scan data';

  const severityBars = [
    { label: 'Critical', value: criticalCount, color: 'bg-red-500' },
    { label: 'High', value: highCount, color: 'bg-orange-500' },
    { label: 'Medium', value: mediumCount, color: 'bg-yellow-400' },
    { label: 'Low', value: lowCount, color: 'bg-sky-500' },
  ];

  const kpis = [
    { label: 'Risk Score', value: riskScore.toString(), note: 'Weighted from stored findings', icon: Radar, tint: 'from-slate-900/10 to-slate-900/5' },
    { label: 'Compliance', value: `${compliance}%`, note: 'Current scoring proxy', icon: ShieldCheck, tint: 'from-emerald-500/15 to-emerald-500/5' },
    { label: 'Observed Resources', value: totalResources.toString(), note: resourceCountNote, icon: Activity, tint: 'from-blue-500/15 to-blue-500/5' },
    { label: 'High/Critical Findings', value: highCritical.toString(), note: 'From latest scan findings', icon: ShieldAlert, tint: 'from-amber-500/20 to-amber-500/5' },
  ];

  return (
    <div className="space-y-6">
      {/* ─── Header ─── */}
      <header className="flex flex-col gap-4 rounded-2xl border border-slate-200 bg-white/80 p-6 shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <p className="text-xs uppercase tracking-[0.2em] text-slate-400">Security Command Center</p>
            <h2 className="text-3xl font-semibold text-slate-900">Security Dashboard</h2>
            <p className="text-slate-500 mt-1">
              {project ? `Project: ${project.name} (${project.gcp_project_id})` : 'Overview of your GCP project security findings.'}
            </p>
          </div>
          <div className="flex items-center gap-2 rounded-full border border-slate-200 bg-white px-4 py-2 text-sm text-slate-600">
            <span className="inline-flex h-2 w-2 rounded-full bg-emerald-500" /> Live telemetry
          </div>
        </div>

        <div className="grid gap-4 lg:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
          <div className="rounded-xl border border-slate-200 bg-gradient-to-br from-slate-900/5 via-white to-emerald-50 p-5">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-500">Risk posture</p>
                <div className="flex items-baseline gap-2">
                  <span className="text-4xl font-semibold text-slate-900">{riskScore}</span>
                  <span className="text-sm text-slate-400">/ 100</span>
                </div>
              </div>
              <div className="rounded-full bg-emerald-100 p-3 text-emerald-700">
                {riskScore >= 75 ? <CheckCircle2 /> : <AlertTriangle />}
              </div>
            </div>
            <div className="mt-4 h-2 rounded-full bg-slate-200">
              <div className="h-2 rounded-full bg-gradient-to-r from-emerald-500 via-amber-400 to-red-500"
                style={{ width: `${Math.min(100, Math.max(0, riskScore))}%` }} />
            </div>
            <p className="mt-2 text-xs text-slate-500">
              Score basé sur les règles CIS uniques par sévérité : CRITICAL -15, HIGH -10, MEDIUM -5, LOW -2 par règle distincte. Pas de double pénalité pour la même règle sur plusieurs ressources.
            </p>
          </div>
          <div className="rounded-xl border border-slate-200 bg-white p-5">
            <p className="text-sm text-slate-500">Findings breakdown</p>
            <div className="mt-3 space-y-2">
              {severityBars.map(row => (
                <div key={row.label} className="space-y-1">
                  <div className="flex items-center justify-between text-xs text-slate-500">
                    <span>{row.label}</span><span>{row.value}</span>
                  </div>
                  <div className="h-2 rounded-full bg-slate-100">
                    <div className={`h-2 rounded-full ${row.color}`}
                      style={{ width: totalFindings ? `${Math.round((row.value / totalFindings) * 100)}%` : '0%' }} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </header>

      {/* ─── Scan status ─── */}
      {scanId && (
        <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
          <div className="flex flex-wrap items-center gap-3 text-sm">
            <span className="inline-flex items-center rounded-full bg-slate-100 px-3 py-1 text-slate-700">Scan ID: {scanId}</span>
            {scan ? (
              <span className={`inline-flex items-center rounded-full px-3 py-1 text-sm font-semibold ${
                scan.status === 'COMPLETED' ? 'bg-emerald-100 text-emerald-700' :
                scan.status === 'FAILED' ? 'bg-red-100 text-red-700' : 'bg-amber-100 text-amber-700'
              }`}>{scan.status}</span>
            ) : <span className="inline-flex items-center rounded-full bg-amber-100 px-3 py-1 text-amber-700">Running</span>}
            {scanError && <span className="text-red-600">{scanError}</span>}
          </div>
        </div>
      )}

      {/* ─── KPI Cards ─── */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        {kpis.map(kpi => {
          const Icon = kpi.icon;
          return (
            <div key={kpi.label} className={`rounded-xl border border-slate-200 bg-gradient-to-br ${kpi.tint} p-5 shadow-sm`}>
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-medium text-slate-500">{kpi.label}</h3>
                <span className="rounded-full bg-white/80 p-2 text-slate-700"><Icon size={18} /></span>
              </div>
              <p className="text-3xl font-semibold text-slate-800 mt-3">{kpi.value}</p>
              <p className="text-xs text-slate-400 mt-2">{kpi.note}</p>
            </div>
          );
        })}
      </div>

      {/* ─── Row 2: Score trend + Heatmap ─── */}
      <div className="grid gap-4 lg:grid-cols-[1.5fr_1fr]">
        {/* Score trend */}
        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <h3 className="text-lg font-medium text-slate-800">Score Trend</h3>
          <p className="text-sm text-slate-500">Evolution across the last {scanHistory.length} scan(s).</p>
          <div className="mt-3">
            <ScoreTrendChart data={scanHistory} />
          </div>
        </div>

        {/* Findings heatmap */}
        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <h3 className="text-lg font-medium text-slate-800">Findings Matrix</h3>
          <p className="text-sm text-slate-500">Category × Severity distribution.</p>
          <div className="mt-4">
            <HeatmapGrid rows={findingsMatrix} />
          </div>
        </div>
      </div>

      {/* ─── Row 3: Scan diff + Remediation plan ─── */}
      <div className="grid gap-4 xl:grid-cols-[1.5fr_1fr]">
        {/* Scan diff */}
        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="flex items-center justify-between mb-2">
            <div>
              <h3 className="text-lg font-medium text-slate-800">Scan Changes</h3>
              <p className="text-sm text-slate-500">New / Fixed / Persistent since last scan.</p>
            </div>
            {scanDiff && (scanDiff.new_findings.length > 0 || scanDiff.fixed_findings.length > 0 || scanDiff.persistent_findings.length > 0) && (
              <button onClick={() => setShowDiff(!showDiff)}
                className="text-xs text-blue-600 hover:underline">{showDiff ? 'Hide' : 'Show details'}</button>
            )}
          </div>
          {!scanDiff || (scanDiff.new_findings.length === 0 && scanDiff.fixed_findings.length === 0 && scanDiff.persistent_findings.length === 0) ? (
            <p className="text-sm text-slate-400">Need at least 2 scans to compare.</p>
          ) : (
            <div className="flex flex-wrap gap-4">
              <div className="flex items-center gap-2">
                <span className="inline-flex items-center gap-1 rounded-full bg-red-50 text-red-700 px-3 py-1 text-sm font-medium">
                  <ArrowUpRight size={14} /> {scanDiff.new_findings.length} new
                </span>
              </div>
              <div className="flex items-center gap-2">
                <span className="inline-flex items-center gap-1 rounded-full bg-emerald-50 text-emerald-700 px-3 py-1 text-sm font-medium">
                  <CheckCircle2 size={14} /> {scanDiff.fixed_findings.length} fixed
                </span>
              </div>
              <div className="flex items-center gap-2">
                <span className="inline-flex items-center gap-1 rounded-full bg-amber-50 text-amber-700 px-3 py-1 text-sm font-medium">
                  <Minus size={14} /> {scanDiff.persistent_findings.length} persistent
                </span>
              </div>
            </div>
          )}
          {showDiff && scanDiff && (
            <div className="mt-4 space-y-3 text-sm max-h-48 overflow-y-auto">
              {scanDiff.new_findings.slice(0, 5).map(f => (
                <div key={`new-${f.id}`} className="flex items-start gap-2 text-red-700">
                  <ArrowUpRight size={14} className="mt-0.5 shrink-0" />
                  <span><strong>CIS {f.cis_rule_id}</strong> — {f.description.slice(0, 120)}</span>
                </div>
              ))}
              {scanDiff.fixed_findings.slice(0, 5).map(f => (
                <div key={`fix-${f.id}`} className="flex items-start gap-2 text-emerald-700">
                  <CheckCircle2 size={14} className="mt-0.5 shrink-0" />
                  <span><strong>CIS {f.cis_rule_id}</strong> — {f.description.slice(0, 120)}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Remediation plan */}
        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <h3 className="text-lg font-medium text-slate-800">Remediation Plan</h3>
          <p className="text-sm text-slate-500">Prioritized by severity × affected resources.</p>
          {remediationPlan.length === 0 ? (
            <p className="text-sm text-slate-400 mt-3">No findings to remediate.</p>
          ) : (
            <div className="mt-4 space-y-3 max-h-60 overflow-y-auto">
              {remediationPlan.map(item => {
                const SevIcon = item.severity === 'CRITICAL' || item.severity === 'HIGH' ? AlertTriangle : Minus;
                return (
                  <div key={item.cis_rule_id} className="flex items-start gap-3 p-3 rounded-lg border border-slate-100 bg-slate-50">
                    <SevIcon size={16} className={`mt-0.5 shrink-0 ${
                      item.severity === 'CRITICAL' ? 'text-red-500' :
                      item.severity === 'HIGH' ? 'text-orange-500' : 'text-yellow-500'
                    }`} />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold ${SEVERITY_TEXT[item.severity]}`}>
                          {item.severity}
                        </span>
                        <span className="text-xs font-semibold text-slate-700">CIS {item.cis_rule_id}</span>
                        <span className="text-[10px] text-slate-400 ml-auto">{item.affected_resources} resource(s)</span>
                      </div>
                      <p className="mt-1 text-xs text-slate-600 line-clamp-2">{item.remediation_steps}</p>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* ─── Findings table ─── */}
      <FindingsTable findings={findings} selectedFinding={selectedFinding}
        onSelect={setSelectedFinding} onClose={() => setSelectedFinding(null)} />
    </div>
  );
}
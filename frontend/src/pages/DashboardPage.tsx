import { useEffect, useMemo, useState } from 'react';
import { useLocation } from 'react-router-dom';
import { Activity, AlertTriangle, CheckCircle2, Radar, ShieldAlert, ShieldCheck, X } from 'lucide-react';
import { useDashboard } from '../hooks/useDashboard';
import { api } from '../api';
import type { Finding, ScanStatus } from '../api';

export default function DashboardPage() {
  const { project, dashboard, findings, loading, error, reload } = useDashboard();
  const location = useLocation();
  const [scan, setScan] = useState<ScanStatus | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
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
      } catch (err) {
        console.error('Failed to load scan status', err);
        setScanError('Unable to load scan status.');
      }
    };

    loadScan();
    return () => {
      if (timer) {
        window.clearTimeout(timer);
      }
    };
  }, [scanId]);

  useEffect(() => {
    if (!scanId || !scan || scan.status !== 'COMPLETED') return;
    if (dashboard?.latest_scan_id === scanId) return;
    reload();
  }, [scanId, scan, dashboard?.latest_scan_id, reload]);

  useEffect(() => {
    if (!selectedFinding) return;
    const stillExists = findings.some((finding) => finding.id === selectedFinding.id);
    if (!stillExists) {
      setSelectedFinding(null);
    }
  }, [findings, selectedFinding]);

  if (loading) {
    return <div className="text-slate-500 p-8 text-center animate-pulse">Loading dashboard...</div>;
  }

  if (error) {
    return <div className="text-red-500 p-8 text-center bg-red-50 rounded-lg">{error}</div>;
  }

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
  const resourceCountNote =
    resourceCountBasis === 'latest_scan_observed'
      ? 'Observed in latest scan'
      : resourceCountBasis === 'project_inventory_fallback'
      ? 'Fallback: tracked project inventory'
      : resourceCountBasis === 'project_inventory_no_completed_scan'
      ? 'Tracked inventory; no completed scan'
      : 'No completed scan data';

  const kpis = [
    { label: 'Risk Score', value: riskScore.toString(), note: 'Weighted from stored findings', icon: Radar, tint: 'from-slate-900/10 to-slate-900/5' },
    { label: 'Compliance', value: `${compliance}%`, note: 'Current scoring proxy', icon: ShieldCheck, tint: 'from-emerald-500/15 to-emerald-500/5' },
    { label: 'Observed Resources', value: totalResources.toString(), note: resourceCountNote, icon: Activity, tint: 'from-blue-500/15 to-blue-500/5' },
    { label: 'High/Critical Findings', value: highCritical.toString(), note: 'From latest scan findings', icon: ShieldAlert, tint: 'from-amber-500/20 to-amber-500/5' }
  ];

  const severityBars = [
    { label: 'Critical', value: criticalCount, color: 'bg-red-500' },
    { label: 'High', value: highCount, color: 'bg-orange-500' },
    { label: 'Medium', value: mediumCount, color: 'bg-yellow-400' },
    { label: 'Low', value: lowCount, color: 'bg-sky-500' }
  ];

  const findingCategoryCounts = findings.reduce<Record<string, number>>((acc, finding) => {
    const category = finding.category || 'Unknown';
    acc[category] = (acc[category] || 0) + 1;
    return acc;
  }, {});

  const categoryData = Object.entries(findingCategoryCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6);

  const maxCategoryCount = categoryData.reduce((max, [, count]) => Math.max(max, count), 1);

  const resourceTypeCounts = findings.reduce<Record<string, number>>((acc, finding) => {
    const type = finding.resource_type || 'Unknown';
    acc[type] = (acc[type] || 0) + 1;
    return acc;
  }, {});

  const topResourceTypes = Object.entries(resourceTypeCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  const auditActions = [
    'Scanned CIS sections 1-8 for GCP controls and live resource inventory.',
    'Mapped findings to exact resources and CIS rule IDs.',
    `Identified ${totalFindings} issue${totalFindings === 1 ? '' : 's'} across ${findings.length ? Object.keys(findingCategoryCounts).length : 0} categories.`,
    'Computed a weighted risk score from severity counts.',
  ];

  const shortResourceLabel = (finding: Finding) => {
    if (finding.resource_name) return finding.resource_name;
    if (finding.resource_gcp_uri) return finding.resource_gcp_uri.split('/').filter(Boolean).pop() || finding.resource_gcp_uri;
    return 'Project/org-level finding';
  };

  return (
    <div className="space-y-6">
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
            <span className="inline-flex h-2 w-2 rounded-full bg-emerald-500" />
            Live telemetry
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
              <div
                className="h-2 rounded-full bg-gradient-to-r from-emerald-500 via-amber-400 to-red-500"
                style={{ width: `${Math.min(100, Math.max(0, riskScore))}%` }}
              />
            </div>
            <p className="mt-2 text-xs text-slate-500">
              Weighted by severity: CRITICAL -15, HIGH -10, MEDIUM -5, LOW -2.
            </p>
          </div>
          <div className="rounded-xl border border-slate-200 bg-white p-5">
            <p className="text-sm text-slate-500">Findings breakdown</p>
            <div className="mt-3 space-y-2">
              {severityBars.map((row) => (
                <div key={row.label} className="space-y-1">
                  <div className="flex items-center justify-between text-xs text-slate-500">
                    <span>{row.label}</span>
                    <span>{row.value}</span>
                  </div>
                  <div className="h-2 rounded-full bg-slate-100">
                    <div
                      className={`h-2 rounded-full ${row.color}`}
                      style={{
                        width: totalFindings ? `${Math.round((row.value / totalFindings) * 100)}%` : '0%'
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </header>

      {scanId && (
        <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
          <div className="flex flex-wrap items-center gap-3 text-sm">
            <span className="inline-flex items-center rounded-full bg-slate-100 px-3 py-1 text-slate-700">
              Scan ID: {scanId}
            </span>
            {scan ? (
              <span className={`inline-flex items-center rounded-full px-3 py-1 text-sm font-semibold ${
                scan.status === 'COMPLETED'
                  ? 'bg-emerald-100 text-emerald-700'
                  : scan.status === 'FAILED'
                  ? 'bg-red-100 text-red-700'
                  : 'bg-amber-100 text-amber-700'
              }`}>
                {scan.status}
              </span>
            ) : (
              <span className="inline-flex items-center rounded-full bg-amber-100 px-3 py-1 text-amber-700">
                Running
              </span>
            )}
            {scanError && <span className="text-red-600">{scanError}</span>}
          </div>
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        {kpis.map((kpi) => {
          const Icon = kpi.icon;
          return (
            <div key={kpi.label} className={`rounded-xl border border-slate-200 bg-gradient-to-br ${kpi.tint} p-5 shadow-sm`}> 
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-medium text-slate-500">{kpi.label}</h3>
                <span className="rounded-full bg-white/80 p-2 text-slate-700">
                  <Icon size={18} />
                </span>
              </div>
              <p className="text-3xl font-semibold text-slate-800 mt-3">{kpi.value}</p>
              <p className="text-xs text-slate-400 mt-2">{kpi.note}</p>
            </div>
          );
        })}
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.5fr_1fr]">
        <div className="grid gap-4 lg:grid-cols-2">
          <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
            <h3 className="text-lg font-medium text-slate-800">Finding category distribution</h3>
            <p className="text-sm text-slate-500">Which CIS domains the agent flagged most often.</p>
            <div className="mt-5 space-y-4">
              {categoryData.length === 0 ? (
                <div className="text-sm text-slate-500">No category findings available yet.</div>
              ) : (
                categoryData.map(([category, count]) => (
                  <div key={category}>
                    <div className="flex items-center justify-between text-sm text-slate-700">
                      <span>{category}</span>
                      <span>{count}</span>
                    </div>
                    <div className="mt-2 h-2 rounded-full bg-slate-100">
                      <div
                        className="h-2 rounded-full bg-slate-800"
                        style={{ width: `${Math.round((count / maxCategoryCount) * 100)}%` }}
                      />
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
            <h3 className="text-lg font-medium text-slate-800">Top resource types</h3>
            <p className="text-sm text-slate-500">Most affected resource families from the latest findings.</p>
            <div className="mt-5 space-y-4">
              {topResourceTypes.length === 0 ? (
                <div className="text-sm text-slate-500">No affected resource types yet.</div>
              ) : (
                topResourceTypes.map(([type, count]) => (
                  <div key={type}>
                    <div className="flex items-center justify-between text-sm text-slate-700">
                      <span>{type}</span>
                      <span>{count}</span>
                    </div>
                    <div className="mt-2 h-2 rounded-full bg-slate-100">
                      <div
                        className="h-2 rounded-full bg-slate-600"
                        style={{ width: `${Math.round((count / Math.max(...topResourceTypes.map(([, v]) => v))) * 100)}%` }}
                      />
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        <div className="rounded-xl border border-slate-200 bg-gradient-to-br from-slate-50 via-slate-100 to-white p-5 shadow-sm">
          <h3 className="text-lg font-medium text-slate-800">Agent audit summary</h3>
          <p className="text-sm text-slate-500">What the scan engine completed during this assessment.</p>
          <div className="mt-5 space-y-3 text-sm text-slate-700">
            {auditActions.map((action) => (
              <div key={action} className="rounded-2xl border border-slate-200 bg-slate-50 p-3">
                <div className="font-medium text-slate-800">{action}</div>
              </div>
            ))}
          </div>
          <div className="mt-6 rounded-2xl bg-slate-900 p-4 text-white">
            <p className="text-xs uppercase tracking-[0.24em] text-slate-400">Agent throughput</p>
            <p className="mt-2 text-3xl font-semibold">{findings.length}</p>
            <p className="mt-1 text-xs text-slate-300">findings extracted from scan evidence</p>
          </div>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <h3 className="text-lg font-medium text-slate-800">Exposure summary</h3>
          <p className="text-sm text-slate-500">Key risk themes based on the latest scan.</p>
          <div className="mt-4 flex flex-wrap gap-3">
            <span className="rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-xs text-slate-600">
              Identity drift: {mediumCount} medium items
            </span>
            <span className="rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-xs text-slate-600">
              Network hardening: {highCritical} high/critical
            </span>
            <span className="rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-xs text-slate-600">
              Logging coverage: {lowCount} low
            </span>
          </div>
        </div>
        <div className="rounded-xl border border-slate-200 bg-gradient-to-br from-white via-amber-50 to-rose-50 p-5 shadow-sm">
          <h3 className="text-lg font-medium text-slate-800">Priority signal</h3>
          <p className="text-sm text-slate-500">Focus first on high-impact items.</p>
          <div className="mt-4 space-y-3">
            <div className="flex items-center justify-between text-sm">
              <span className="text-slate-600">High/Critical</span>
              <span className="font-semibold text-slate-900">{highCritical}</span>
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="text-slate-600">Open findings</span>
              <span className="font-semibold text-slate-900">{totalFindings}</span>
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="text-slate-600">Coverage</span>
              <span className="font-semibold text-slate-900">{compliance}%</span>
            </div>
          </div>
        </div>
      </div>

      {/* Findings Table */}
      <div className="bg-white rounded-lg border border-slate-200 shadow-sm overflow-hidden">
        <div className="p-4 border-b border-slate-200 bg-slate-50 flex items-center justify-between">
          <div>
            <h3 className="text-lg font-medium text-slate-800">Recent Findings</h3>
            <p className="text-xs text-slate-500">Latest controls flagged by the audit.</p>
          </div>
          <span className="text-xs text-slate-400">{totalFindings} total</span>
        </div>
        
        {findings.length === 0 ? (
          <div className="p-8 text-center text-slate-500">
            No findings to display. Run a scan to populate this table.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full table-fixed text-left text-sm">
              <thead className="uppercase tracking-wider border-b border-slate-200 bg-slate-50 text-slate-500">
                <tr>
                  <th className="w-28 px-5 py-3 font-medium">Severity</th>
                  <th className="w-32 px-5 py-3 font-medium">Category</th>
                  <th className="w-24 px-5 py-3 font-medium">CIS Rule</th>
                  <th className="w-48 px-5 py-3 font-medium">Project</th>
                  <th className="w-72 px-5 py-3 font-medium">Resource</th>
                  <th className="px-5 py-3 font-medium">Finding</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200">
                {findings.map((finding) => (
                  <tr
                    key={finding.id}
                    tabIndex={0}
                    onClick={() => setSelectedFinding(finding)}
                    onKeyDown={(event) => {
                      if (event.key === 'Enter' || event.key === ' ') {
                        event.preventDefault();
                        setSelectedFinding(finding);
                      }
                    }}
                    className={`cursor-pointer transition-colors focus:outline-none focus:ring-2 focus:ring-inset focus:ring-blue-500 ${
                      selectedFinding?.id === finding.id ? 'bg-blue-50 hover:bg-blue-50' : 'hover:bg-slate-50'
                    }`}
                  >
                    <td className="px-5 py-4 align-top">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium
                        ${finding.severity === 'CRITICAL' ? 'bg-red-100 text-red-800' :
                          finding.severity === 'HIGH' ? 'bg-orange-100 text-orange-800' :
                          finding.severity === 'MEDIUM' ? 'bg-yellow-100 text-yellow-800' :
                          'bg-blue-100 text-blue-800'}`}>
                        {finding.severity}
                      </span>
                    </td>
                    <td className="px-5 py-4 align-top">
                      <span className="inline-flex max-w-full items-center rounded-md border border-slate-200 bg-slate-50 px-2.5 py-1 text-xs font-medium text-slate-700">
                        {finding.category || 'Unknown'}
                      </span>
                    </td>
                    <td className="px-5 py-4 align-top font-medium text-slate-700">{finding.cis_rule_id}</td>
                    <td className="px-5 py-4 align-top text-slate-700">
                      <span className="block truncate" title={finding.resource_project_id || undefined}>
                        {finding.resource_project_id || 'Scope-level'}
                      </span>
                    </td>
                    <td className="px-5 py-4 align-top">
                      <div className="min-w-0">
                        <div className="truncate font-medium text-slate-800" title={finding.resource_gcp_uri || finding.resource_name || undefined}>
                          {shortResourceLabel(finding)}
                        </div>
                        <div className="mt-1 truncate text-xs text-slate-500">
                          {finding.resource_type || 'Unspecified type'}
                        </div>
                      </div>
                    </td>
                    <td className="px-5 py-4 align-top text-slate-600">
                      <p className="line-clamp-2 whitespace-normal break-words" title={finding.description}>
                        {finding.description}
                      </p>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {selectedFinding && (
        <div
          className="fixed inset-0 z-50 flex items-end justify-center bg-slate-950/35 px-4 py-6 backdrop-blur-sm sm:items-center"
          role="dialog"
          aria-modal="true"
          aria-labelledby="finding-detail-title"
          onClick={() => setSelectedFinding(null)}
        >
          <div
            className="max-h-[88vh] w-full max-w-3xl overflow-y-auto rounded-lg border border-slate-200 bg-white shadow-2xl"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="sticky top-0 z-10 flex items-start justify-between gap-4 border-b border-slate-200 bg-white px-5 py-4">
              <div>
                <div className="flex flex-wrap items-center gap-2">
                  <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold
                    ${selectedFinding.severity === 'CRITICAL' ? 'bg-red-100 text-red-800' :
                      selectedFinding.severity === 'HIGH' ? 'bg-orange-100 text-orange-800' :
                      selectedFinding.severity === 'MEDIUM' ? 'bg-yellow-100 text-yellow-800' :
                      'bg-blue-100 text-blue-800'}`}>
                    {selectedFinding.severity}
                  </span>
                  <span className="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-semibold text-slate-700">
                    CIS {selectedFinding.cis_rule_id}
                  </span>
                  <span className="rounded-full bg-blue-50 px-2.5 py-1 text-xs font-semibold text-blue-700">
                    {selectedFinding.category || 'Unknown'}
                  </span>
                </div>
                <h3 id="finding-detail-title" className="mt-3 text-xl font-semibold text-slate-900">
                  {shortResourceLabel(selectedFinding)}
                </h3>
                <p className="mt-1 text-sm text-slate-500">
                  {selectedFinding.resource_project_id ? `Project: ${selectedFinding.resource_project_id}` : 'Scope-level finding'}
                  {' · '}
                  {selectedFinding.resource_type || 'Unspecified resource type'}
                </p>
              </div>
              <button
                type="button"
                onClick={() => setSelectedFinding(null)}
                className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-md border border-slate-200 bg-white text-slate-500 hover:bg-slate-50 hover:text-slate-900"
                aria-label="Close finding details"
              >
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
                <div>
                  <dt className="font-medium text-slate-500">Resource URI</dt>
                  <dd className="mt-1 break-words text-slate-800">{selectedFinding.resource_gcp_uri ?? 'N/A'}</dd>
                </div>
                <div>
                  <dt className="font-medium text-slate-500">Project</dt>
                  <dd className="mt-1 break-words text-slate-800">{selectedFinding.resource_project_id ?? 'Scope-level'}</dd>
                </div>
                <div>
                  <dt className="font-medium text-slate-500">Resource DB ID</dt>
                  <dd className="mt-1 break-words text-slate-800">{selectedFinding.resource_id ?? 'N/A'}</dd>
                </div>
                <div>
                  <dt className="font-medium text-slate-500">Scan ID</dt>
                  <dd className="mt-1 break-words text-slate-800">{selectedFinding.scan_id}</dd>
                </div>
              </dl>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

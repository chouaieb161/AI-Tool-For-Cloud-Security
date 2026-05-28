import { useEffect, useMemo, useState } from 'react';
import { useLocation } from 'react-router-dom';
import { useDashboard } from '../hooks/useDashboard';
import { api } from '../api';
import type { ScanStatus } from '../api';

export default function DashboardPage() {
  const { project, dashboard, findings, loading, error } = useDashboard();
  const location = useLocation();
  const [scan, setScan] = useState<ScanStatus | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
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

  if (loading) {
    return <div className="text-slate-500 p-8 text-center animate-pulse">Loading dashboard...</div>;
  }

  if (error) {
    return <div className="text-red-500 p-8 text-center bg-red-50 rounded-lg">{error}</div>;
  }

  const kpis = [
    { label: 'Risk Score', value: dashboard?.risk_score.toString() || '0' },
    { label: 'Compliance', value: `${dashboard?.compliance_percentage || 0}%` },
    { label: 'Total Resources', value: dashboard?.total_resources_count.toString() || '0' },
    { label: 'High/Critical Findings', value: ((dashboard?.findings_by_severity?.CRITICAL || 0) + (dashboard?.findings_by_severity?.HIGH || 0)).toString() }
  ];

  return (
    <div className="space-y-6">
      <header className="flex justify-between items-end">
        <div>
          <h2 className="text-2xl font-bold text-slate-800">Security Dashboard</h2>
          <p className="text-slate-500">
            {project ? `Project: ${project.name} (${project.gcp_project_id})` : 'Overview of your GCP project security findings.'}
          </p>
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
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {kpis.map(kpi => (
          <div key={kpi.label} className="bg-white p-6 rounded-lg border border-slate-200 shadow-sm">
            <h3 className="text-sm font-medium text-slate-500">{kpi.label}</h3>
            <p className="text-2xl font-semibold text-slate-800 mt-2">{kpi.value}</p>
          </div>
        ))}
      </div>

      {/* Findings Table */}
      <div className="bg-white rounded-lg border border-slate-200 shadow-sm overflow-hidden">
        <div className="p-4 border-b border-slate-200 bg-slate-50">
          <h3 className="text-lg font-medium text-slate-800">Recent Findings</h3>
        </div>
        
        {findings.length === 0 ? (
          <div className="p-8 text-center text-slate-500">
            No findings to display. Run a scan to populate this table.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm whitespace-nowrap">
              <thead className="uppercase tracking-wider border-b border-slate-200 bg-slate-50 text-slate-500">
                <tr>
                  <th className="px-6 py-3 font-medium">Severity</th>
                  <th className="px-6 py-3 font-medium">CIS Rule</th>
                  <th className="px-6 py-3 font-medium">Resource</th>
                  <th className="px-6 py-3 font-medium">Description</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200">
                {findings.map((finding) => (
                  <tr key={finding.id} className="hover:bg-slate-50 transition-colors">
                    <td className="px-6 py-4">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium
                        ${finding.severity === 'CRITICAL' ? 'bg-red-100 text-red-800' :
                          finding.severity === 'HIGH' ? 'bg-orange-100 text-orange-800' :
                          finding.severity === 'MEDIUM' ? 'bg-yellow-100 text-yellow-800' :
                          'bg-blue-100 text-blue-800'}`}>
                        {finding.severity}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-slate-700">{finding.cis_rule_id}</td>
                    <td className="px-6 py-4 text-slate-700">{finding.resource_name || 'N/A'}</td>
                    <td className="px-6 py-4 text-slate-600 truncate max-w-xs" title={finding.description}>
                      {finding.description}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

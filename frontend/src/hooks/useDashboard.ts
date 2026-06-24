import { useCallback, useEffect, useState } from 'react';
import { api } from '../api';
import type {
  Project,
  DashboardData,
  Finding,
  ScanHistoryItem,
  FindingsMatrixItem,
  RemediationPlanItem,
  ScanDiffData,
} from '../api';

export function useDashboard() {
  const [project, setProject] = useState<Project | null>(null);
  const [dashboard, setDashboard] = useState<DashboardData | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // New state for enhanced dashboard features
  const [scanHistory, setScanHistory] = useState<ScanHistoryItem[]>([]);
  const [findingsMatrix, setFindingsMatrix] = useState<FindingsMatrixItem[]>([]);
  const [remediationPlan, setRemediationPlan] = useState<RemediationPlanItem[]>([]);
  const [scanDiff, setScanDiff] = useState<ScanDiffData | null>(null);

  const loadData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      // 1. Get or create project
      let projects = await api.getProjects();
      if (projects.length === 0) {
        // Create demo project if tracking is empty
        const newProj = await api.createProject("Demo GCP Project", "demo-gcp-001");
        projects = [newProj];
      }

      const activeProject = projects[0];
      setProject(activeProject);

      // 2. Load dashboard KPIs
      const dashboardData = await api.getDashboard(activeProject.id);
      setDashboard(dashboardData);

      // 3. Load enhanced data in parallel (non-blocking, errors are caught silently)
      api.getScanHistory(activeProject.id).then(setScanHistory).catch(() => {});
      api.getFindingsMatrix(activeProject.id).then(setFindingsMatrix).catch(() => {});
      api.getRemediationPlan(activeProject.id).then(setRemediationPlan).catch(() => {});
    } catch (err) {
      console.error(err);
      setError("Failed to load dashboard data. Ensure backend is running and mock_agent_run.py script was executed.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  useEffect(() => {
    const loadFindings = async () => {
      if (!dashboard?.latest_scan_id) {
        setFindings([]);
        return;
      }
      try {
        const scanFindings = await api.getFindings(dashboard.latest_scan_id);
        setFindings(scanFindings);
      } catch (err) {
        console.error('Failed to load findings for dashboard', err);
      }
    };

    loadFindings();
  }, [dashboard?.latest_scan_id]);

  // Load scan diff when we have at least 2 scans in history
  useEffect(() => {
    const loadDiff = async () => {
      if (!project || scanHistory.length < 2) return;
      const fromScanId = scanHistory[scanHistory.length - 2].scan_id;
      const toScanId = scanHistory[scanHistory.length - 1].scan_id;
      try {
        const diff = await api.getScanDiff(project.id, fromScanId, toScanId);
        setScanDiff(diff);
      } catch {
        setScanDiff(null);
      }
    };
    loadDiff();
  }, [scanHistory, project]);

  return {
    project,
    dashboard,
    findings,
    scanHistory,
    findingsMatrix,
    remediationPlan,
    scanDiff,
    loading,
    error,
    reload: loadData,
  };
}
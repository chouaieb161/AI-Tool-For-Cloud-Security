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
  CloudProvider,
  OCIDashboardData,
} from '../api';

export function useDashboard(cloudProvider: CloudProvider = 'GCP') {
  const [project, setProject] = useState<Project | null>(null);
  const [dashboard, setDashboard] = useState<DashboardData | OCIDashboardData | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // New state for enhanced dashboard features
  const [scanHistory, setScanHistory] = useState<ScanHistoryItem[]>([]);
  const [findingsMatrix, setFindingsMatrix] = useState<FindingsMatrixItem[]>([]);
  const [remediationPlan, setRemediationPlan] = useState<RemediationPlanItem[]>([]);
  const [scanDiff, setScanDiff] = useState<ScanDiffData | null>(null);

  const isOCI = cloudProvider === 'OCI';

  const loadData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      // 1. Get or create project
      let projects = await api.getProjects();
      const matchingProjects = projects.filter((project) => (project.cloud_provider ?? 'GCP') === cloudProvider);
      let activeProject = matchingProjects[0] ?? projects[0];
      if (!activeProject) {
        const projName = isOCI ? 'Demo OCI Project' : 'Demo GCP Project';
        const projId = isOCI ? 'demo-oci-001' : 'demo-gcp-001';
        const newProj = await api.createProject(projName, projId, cloudProvider);
        activeProject = newProj;
        projects = [newProj];
      }

      setProject(activeProject);

      // 2. Load dashboard KPIs (GCP or OCI)
      if (isOCI) {
        const dashboardData = await api.getOCIDashboard(activeProject.id);
        setDashboard(dashboardData);
      } else {
        const dashboardData = await api.getDashboard(activeProject.id);
        setDashboard(dashboardData);
      }

      // 3. Load enhanced data in parallel
      api.getScanHistory(activeProject.id).then(setScanHistory).catch(() => {});
      api.getFindingsMatrix(activeProject.id).then(setFindingsMatrix).catch(() => {});
      api.getRemediationPlan(activeProject.id).then(setRemediationPlan).catch(() => {});
    } catch (err) {
      console.error(err);
      setError(`Failed to load ${cloudProvider} dashboard data. Ensure backend is running.`);
    } finally {
      setLoading(false);
    }
  }, [isOCI, cloudProvider]);

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
        if (isOCI) {
          const scanResult = await api.getOCIScanFindings(dashboard.latest_scan_id);
          // Convert OCI findings to the standard Finding format
          const converted: Finding[] = scanResult.findings.map((f, idx) => ({
            id: idx,
            scan_id: dashboard.latest_scan_id!,
            resource_id: null,
            resource_name: null,
            resource_type: null,
            resource_gcp_uri: f.resource_ocid,
            resource_project_id: null,
            category: f.cis_rule_id.split('.')[0] || 'Unknown',
            cis_rule_id: f.cis_rule_id,
            severity: f.severity as Finding['severity'],
            description: f.description,
            remediation_steps: f.remediation_steps,
          }));
          setFindings(converted);
        } else {
          const scanFindings = await api.getFindings(dashboard.latest_scan_id);
          setFindings(scanFindings);
        }
      } catch (err) {
        console.error('Failed to load findings for dashboard', err);
      }
    };

    loadFindings();
  }, [dashboard?.latest_scan_id, isOCI]);

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
    cloudProvider,
  };
}
import { useCallback, useEffect, useState } from 'react';
import { api } from '../api';
import type { Project, DashboardData, Finding } from '../api';

export function useDashboard() {
  const [project, setProject] = useState<Project | null>(null);
  const [dashboard, setDashboard] = useState<DashboardData | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

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

  return { project, dashboard, findings, loading, error, reload: loadData };
}

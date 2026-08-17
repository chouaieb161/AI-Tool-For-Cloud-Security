import axios from 'axios';

const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_URL ?? '/api'
});

export interface DashboardData {
  total_resources_count: number;
  resource_count_basis: string;
  risk_score: number;
  findings_by_severity: Record<string, number>;
  compliance_percentage: number;
  latest_scan_id: number | null;
  latest_completed_scan_id: number | null;
}

export interface Finding {
  id: number;
  scan_id: number;
  resource_id: number | null;
  resource_name: string | null;
  resource_type: string | null;
  resource_gcp_uri: string | null;
  resource_project_id: string | null;
  category: string;
  cis_rule_id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  remediation_steps: string;
}

export interface Project {
  id: number;
  name: string;
  gcp_project_id: string;
  created_at: string;
  cloud_provider?: 'GCP' | 'OCI';
  tenant_provider_id?: number;
  organisation_id?: number;
}

export interface ChatSession {
  id: number;
  project_id: number;
  title: string | null;
  created_at: string;
}

export interface ChatMessage {
  id: number;
  session_id: number;
  role: 'user' | 'assistant';
  content: string;
  created_at: string;
  citations?: { cis_id: string }[];
  steps?: string[];
}

export interface MemoryNote {
  id: number;
  project_id: number;
  session_id: number | null;
  kind: string;
  source: string | null;
  content: string;
  pinned: boolean;
  created_at: string;
}

export interface ScanStatus {
  id: number;
  project_id: number;
  timestamp: string;
  score: number;
  status: 'COMPLETED' | 'FAILED' | 'RUNNING' | 'PENDING';
}

export interface CredentialStatus {
  configured: boolean;
  project_id: string | null;
  credentials_path: string | null;
  provider?: 'GCP' | 'OCI' | null;
}

export interface ScanHistoryItem {
  scan_id: number;
  score: number;
  findings_count: number;
  timestamp: string;
}

export interface FindingsMatrixItem {
  category: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

export interface RemediationPlanItem {
  cis_rule_id: string;
  severity: string;
  description: string;
  remediation_steps: string;
  affected_resources: number;
}

export interface ScanDiffData {
  new_findings: Finding[];
  fixed_findings: Finding[];
  persistent_findings: Finding[];
}

// ---- OCI-specific types ----
export interface OCIScanResult {
  score: number;
  status: string;
  resources: { type: string; name: string; ocid: string }[];
  findings: {
    cis_rule_id: string;
    severity: string;
    description: string;
    remediation_steps: string;
    resource_ocid: string | null;
  }[];
}

export interface OCIDashboardData {
  total_resources_count: number;
  resource_count_basis: string;
  risk_score: number;
  findings_by_severity: Record<string, number>;
  compliance_percentage: number;
  latest_scan_id: number | null;
  latest_completed_scan_id: number | null;
}

export type CloudProvider = 'GCP' | 'OCI';

export interface TenantProvider {
  id: number;
  organisation_id: number;
  provider_type: CloudProvider;
  provider_label: string;
  enabled: boolean;
  focus_version: string;
  config: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export const api = {
  // ─── Projects ───
  getProjects: async () => {
    const res = await apiClient.get<Project[]>('/projects');
    return res.data;
  },
  
  createProject: async (name: string, gcp_project_id: string, cloudProvider: CloudProvider = 'GCP') => {
    const res = await apiClient.post<Project>('/projects', { name, gcp_project_id, cloud_provider: cloudProvider });
    return res.data;
  },

  // ─── GCP Dashboard ───
  getDashboard: async (projectId: number) => {
    const res = await apiClient.get<DashboardData>(`/projects/${projectId}/dashboard`);
    return res.data;
  },

  getFindings: async (scanId: number) => {
    const res = await apiClient.get<Finding[]>(`/scans/${scanId}/findings`);
    return res.data;
  },

  triggerScan: async (projectId: number) => {
    const res = await apiClient.post<{ scan_id: number }>(`/projects/${projectId}/scan`);
    return res.data;
  },

  getScan: async (scanId: number) => {
    const res = await apiClient.get<ScanStatus>(`/scans/${scanId}`);
    return res.data;
  },

  // ─── OCI Scans ───
  triggerOCIScan: async (projectId: number) => {
    const res = await apiClient.post<{ scan_id: number }>(`/oci/scans/trigger?project_id=${projectId}`);
    return res.data;
  },

  freeformOCIScan: async (projectId: number, query: string) => {
    const res = await apiClient.post<OCIScanResult>('/oci/scans/freeform', { project_id: projectId, query });
    return res.data;
  },

  getOCIDashboard: async (projectId: number) => {
    const res = await apiClient.get<OCIDashboardData>(`/oci/dashboard?project_id=${projectId}`);
    return res.data;
  },

  getOCIScanFindings: async (scanId: number) => {
    const res = await apiClient.get<OCIScanResult>(`/oci/scans/${scanId}/findings`);
    return res.data;
  },

  // ─── Chat ───
  getChatSessions: async (projectId: number) => {
    const res = await apiClient.get<ChatSession[]>(`/chat/sessions`, { params: { project_id: projectId } });
    return res.data;
  },

  createChatSession: async (projectId: number, title?: string) => {
    const res = await apiClient.post<ChatSession>('/chat/sessions', { project_id: projectId, title });
    return res.data;
  },

  deleteChatSession: async (sessionId: number) => {
    await apiClient.delete(`/chat/sessions/${sessionId}`);
  },

  getChatMessages: async (sessionId: number) => {
    const res = await apiClient.get<ChatMessage[]>(`/chat/sessions/${sessionId}/messages`);
    return res.data;
  },

  updateChatMessage: async (sessionId: number, messageId: number, content: string) => {
    const res = await apiClient.patch<ChatMessage>(`/chat/sessions/${sessionId}/messages/${messageId}`, { content });
    return res.data;
  },

  deleteChatMessage: async (sessionId: number, messageId: number) => {
    await apiClient.delete(`/chat/sessions/${sessionId}/messages/${messageId}`);
  },

  // ─── Memory ───
  getMemoryNotes: async (projectId: number, params?: { kind?: string; limit?: number }) => {
    const res = await apiClient.get<MemoryNote[]>(`/projects/${projectId}/memory`, { params });
    return res.data;
  },

  updateMemoryNote: async (projectId: number, noteId: number, pinned: boolean) => {
    const res = await apiClient.patch<MemoryNote>(`/projects/${projectId}/memory/${noteId}`, { pinned });
    return res.data;
  },

  deleteMemoryNote: async (projectId: number, noteId: number) => {
    await apiClient.delete(`/projects/${projectId}/memory/${noteId}`);
  },

  // ─── Credentials ───
  getCredentialStatus: async () => {
    const res = await apiClient.get<CredentialStatus>('/credentials/status');
    return res.data;
  },

  uploadCredentials: async (file: File, provider: CloudProvider = 'GCP') => {
    const form = new FormData();
    form.append('file', file);
    const res = await apiClient.post<CredentialStatus>(`/credentials/upload?provider=${provider}`, form, {
      headers: { 'Content-Type': 'multipart/form-data' }
    });
    return res.data;
  },

  // ─── Tenant Provider Management (multi-tenant) ───
  getTenantProviders: async (params?: { organisation_id?: number; provider_type?: CloudProvider }) => {
    const res = await apiClient.get<TenantProvider[]>('/admin/tenant-providers', { params });
    return res.data;
  },

  createTenantProvider: async (data: {
    organisation_id: number;
    provider_type: CloudProvider;
    provider_label: string;
    focus_version: string;
    enabled?: boolean;
  }) => {
    const res = await apiClient.post<TenantProvider>('/admin/tenant-providers', data);
    return res.data;
  },

  storeProviderCredentials: async (providerId: number, data: {
    credentials_json?: string;
    config_content?: string;
    private_key?: string;
  }) => {
    const res = await apiClient.put(`/admin/tenant-providers/${providerId}/credentials`, data);
    return res.data;
  },

  triggerScheduler: async (providerId?: number) => {
    const params = providerId ? { provider_id: providerId } : {};
    const res = await apiClient.post<{ status: string; scan_ids: number[]; count: number }>('/admin/scheduler/run', null, { params });
    return res.data;
  },

  // ─── Enhanced Dashboard Endpoints ───
  getScanHistory: async (projectId: number, limit: number = 20) => {
    const res = await apiClient.get<ScanHistoryItem[]>(`/scans/history/${projectId}`, { params: { limit } });
    return res.data;
  },

  getFindingsMatrix: async (projectId: number) => {
    const res = await apiClient.get<FindingsMatrixItem[]>(`/scans/matrix/${projectId}`);
    return res.data;
  },

  getRemediationPlan: async (projectId: number) => {
    const res = await apiClient.get<RemediationPlanItem[]>(`/scans/remediation-plan/${projectId}`);
    return res.data;
  },

  getScanDiff: async (projectId: number, fromScanId: number, toScanId: number) => {
    const res = await apiClient.get<ScanDiffData>(`/scans/diff/${projectId}`, {
      params: { from_scan_id: fromScanId, to_scan_id: toScanId }
    });
    return res.data;
  }
};
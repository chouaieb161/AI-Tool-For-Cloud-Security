import axios from 'axios';

const apiClient = axios.create({
  baseURL: '/api'
});

export interface DashboardData {
  total_resources_count: number;
  resource_count_basis: string;
  risk_score: number;
  findings_by_severity: Record<string, number>;
  compliance_percentage: number;
  latest_scan_id: number | null;
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
  status: 'COMPLETED' | 'FAILED';
}

export interface CredentialStatus {
  configured: boolean;
  project_id: string | null;
  credentials_path: string | null;
}

export const api = {
  getProjects: async () => {
    const res = await apiClient.get<Project[]>('/projects');
    return res.data;
  },
  
  createProject: async (name: string, gcp_project_id: string) => {
    const res = await apiClient.post<Project>('/projects', { name, gcp_project_id });
    return res.data;
  },

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

  getCredentialStatus: async () => {
    const res = await apiClient.get<CredentialStatus>('/credentials/status');
    return res.data;
  },

  uploadCredentials: async (file: File) => {
    const form = new FormData();
    form.append('file', file);
    const res = await apiClient.post<CredentialStatus>('/credentials/upload', form, {
      headers: { 'Content-Type': 'multipart/form-data' }
    });
    return res.data;
  }
};

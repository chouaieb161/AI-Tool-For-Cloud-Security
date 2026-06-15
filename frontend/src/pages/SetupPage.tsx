import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { UploadCloud, ShieldCheck, PlayCircle } from 'lucide-react';
import { useCredentials } from '../hooks/useCredentials';
import { api } from '../api';
import type { Project } from '../api';

export default function SetupPage() {
  const navigate = useNavigate();
  const { status, loading, error, upload, reload } = useCredentials();
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [project, setProject] = useState<Project | null>(null);
  const [scanStatus, setScanStatus] = useState<string | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [scanLoading, setScanLoading] = useState(false);
  const isConfigured = Boolean(status?.configured || success);
  const activeProjectId = status?.project_id ?? project?.gcp_project_id ?? 'Unknown';

  const ensureProject = async (projectId: string | null) => {
    if (!projectId) return null;
    const projects = await api.getProjects();
    const existing = projects.find((p) => p.gcp_project_id === projectId);
    if (existing) {
      setProject(existing);
      return existing;
    }
    const created = await api.createProject(`GCP Project ${projectId}`, projectId);
    setProject(created);
    return created;
  };

  const handleUpload = async () => {
    if (!selectedFile) return;
    setSuccess(null);
    setScanStatus(null);
    setScanError(null);
    try {
      const data = await upload(selectedFile);
      setSuccess(`Credentials loaded for project ${data.project_id}.`);
      await ensureProject(data.project_id);
      await reload();
    } catch {
      // handled by hook
    }
  };

  const handleScan = async () => {
    if (!status?.project_id) return;
    setScanStatus(null);
    setScanError(null);
    setScanLoading(true);
    try {
      const active = project ?? (await ensureProject(status.project_id));
      if (!active) throw new Error('Project not available');
      const result = await api.triggerScan(active.id);
      setScanStatus(`Scan started. Scan ID: ${result.scan_id}.`);
      navigate('/', { state: { scanId: result.scan_id } });
    } catch (err) {
      console.error('Failed to trigger scan', err);
      setScanError('Failed to start scan. Please try again.');
    } finally {
      setScanLoading(false);
    }
  };

  return (
    <div className="max-w-2xl">
      <header className="mb-6">
        <h2 className="text-2xl font-bold text-slate-800">Connect GCP Credentials</h2>
        <p className="text-slate-500">
          Upload a service account JSON to enable scanning, dashboard insights, and agent chat.
        </p>
      </header>

      <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
        <div className="flex items-center gap-3 text-slate-700">
          <ShieldCheck className="text-emerald-500" />
          <div className="text-sm">
            This key is stored on your backend server. Only upload read-only service accounts.
          </div>
        </div>

        <div className="border-2 border-dashed border-slate-200 rounded-lg p-6 text-center">
          <UploadCloud className="mx-auto text-slate-400" />
          <p className="text-sm text-slate-500 mt-2">Drop your service account JSON here, or browse.</p>
          <input
            type="file"
            accept="application/json"
            className="mt-4 block w-full text-sm text-slate-500 file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-sm file:font-semibold file:bg-slate-100 file:text-slate-700 hover:file:bg-slate-200"
            onChange={(event) => setSelectedFile(event.target.files?.[0] ?? null)}
          />
        </div>

        <button
          onClick={handleUpload}
          disabled={!selectedFile || loading}
          className="w-full rounded-md bg-emerald-600 px-4 py-2 text-white font-semibold hover:bg-emerald-700 disabled:opacity-50"
        >
          {loading ? 'Uploading...' : 'Upload Credentials'}
        </button>

        {error && (
          <div className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-600">
            {error}
          </div>
        )}
        {success && (
          <div className="rounded-md border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-700">
            {success}
          </div>
        )}

        {scanStatus && (
          <div className="rounded-md border border-blue-200 bg-blue-50 p-3 text-sm text-blue-700">
            {scanStatus}
          </div>
        )}
        {scanError && (
          <div className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-600">
            {scanError}
          </div>
        )}

        {isConfigured && (
          <div className="rounded-md border border-slate-200 bg-slate-50 p-3 text-sm text-slate-600">
            Credentials active for project: <span className="font-semibold">{activeProjectId}</span>
          </div>
        )}

        {isConfigured && (
          <button
            onClick={handleScan}
            disabled={scanLoading}
            className="w-full inline-flex items-center justify-center gap-2 rounded-md bg-slate-900 px-4 py-2 text-white font-semibold hover:bg-slate-800 disabled:opacity-50"
          >
            <PlayCircle size={18} />
            {scanLoading ? 'Starting scan...' : 'Trigger Scan'}
          </button>
        )}
      </div>
    </div>
  );
}

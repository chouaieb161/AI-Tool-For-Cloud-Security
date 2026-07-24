import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { UploadCloud, ShieldCheck, PlayCircle, Cloud, Server } from 'lucide-react';
import { useCredentials } from '../hooks/useCredentials';
import { api } from '../api';
import type { CloudProvider, Project } from '../api';

export default function SetupPage() {
  const navigate = useNavigate();
  const { status, loading, error, upload, reload } = useCredentials();
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [project, setProject] = useState<Project | null>(null);
  const [scanStatus, setScanStatus] = useState<string | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [scanLoading, setScanLoading] = useState(false);
  const [provider, setProvider] = useState<CloudProvider>('GCP');
  const [postScanTarget, setPostScanTarget] = useState<'dashboard' | 'chat'>('dashboard');
  const [pendingScanId, setPendingScanId] = useState<number | null>(null);
  const isConfigured = Boolean(status?.configured || success);
  const activeProjectId = status?.project_id ?? project?.gcp_project_id ?? 'Unknown';

  useEffect(() => {
    if (status?.provider) {
      setProvider(status.provider);
    }
  }, [status?.provider]);

  useEffect(() => {
    if (pendingScanId == null) return;

    let cancelled = false;
    let timeoutId: number | undefined;

    const pollScan = async () => {
      try {
        const scan = await api.getScan(pendingScanId);
        if (cancelled) return;

        if (scan.status === 'COMPLETED') {
          setScanStatus(`Scan completed. Opening ${postScanTarget === 'chat' ? 'chat' : 'dashboard'}...`);
          setPendingScanId(null);
          navigate(postScanTarget === 'chat' ? '/chat' : '/', { state: { scanId: pendingScanId, provider } });
          return;
        }

        if (scan.status === 'FAILED') {
          setScanError('The scan failed. Please review the backend logs and try again.');
          setPendingScanId(null);
          return;
        }

        timeoutId = window.setTimeout(pollScan, 2000);
      } catch (err) {
        console.error('Failed to check scan status', err);
        if (!cancelled) {
          setScanError('The scan is still running or the status check failed. Please wait a moment and refresh.');
          setPendingScanId(null);
        }
      }
    };

    timeoutId = window.setTimeout(pollScan, 1500);

    return () => {
      cancelled = true;
      if (timeoutId) {
        window.clearTimeout(timeoutId);
      }
    };
  }, [navigate, pendingScanId, postScanTarget, provider]);

  const ensureProject = async (projectId: string | null) => {
    if (!projectId) return null;
    const projects = await api.getProjects();
    const existing = projects.find((p) => p.gcp_project_id === projectId && (p.cloud_provider ?? 'GCP') === provider);
    if (existing) {
      setProject(existing);
      return existing;
    }
    const label = provider === 'OCI' ? `OCI Project ${projectId}` : `GCP Project ${projectId}`;
    const created = await api.createProject(label, projectId, provider);
    setProject(created);
    return created;
  };

  const handleUpload = async () => {
    if (!selectedFile) return;
    setSuccess(null);
    setScanStatus(null);
    setScanError(null);
    try {
      const data = await upload(selectedFile, provider);
      setSuccess(`Credentials loaded for ${provider} project ${data.project_id}.`);
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
      const result = provider === 'OCI'
        ? await api.triggerOCIScan(active.id)
        : await api.triggerScan(active.id);
      setPendingScanId(result.scan_id);
      setScanStatus(`Scan started. Waiting for completion and opening ${postScanTarget === 'chat' ? 'chat' : 'dashboard'}...`);
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
        <h2 className="text-2xl font-bold text-slate-800">Connect Cloud Credentials</h2>
        <p className="text-slate-500">
          Choose your provider, upload the matching credentials, and start a scan that opens the dashboard and chat automatically.
        </p>
      </header>

      <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
        <div className="flex items-center gap-3 text-slate-700">
          <ShieldCheck className="text-emerald-500" />
          <div className="text-sm">
            These credentials are stored on your backend server. Only upload read-only credentials for the selected provider.
          </div>
        </div>

        <div className="grid gap-2 sm:grid-cols-2">
          <button
            type="button"
            onClick={() => setProvider('GCP')}
            className={`flex items-center justify-center gap-2 rounded-lg border px-3 py-2 text-sm font-medium ${provider === 'GCP' ? 'border-blue-200 bg-blue-50 text-blue-700' : 'border-slate-200 bg-white text-slate-600'}`}
          >
            <Cloud size={16} /> GCP service account
          </button>
          <button
            type="button"
            onClick={() => setProvider('OCI')}
            className={`flex items-center justify-center gap-2 rounded-lg border px-3 py-2 text-sm font-medium ${provider === 'OCI' ? 'border-red-200 bg-red-50 text-red-700' : 'border-slate-200 bg-white text-slate-600'}`}
          >
            <Server size={16} /> OCI config file
          </button>
        </div>

        <div className="border-2 border-dashed border-slate-200 rounded-lg p-6 text-center">
          <UploadCloud className="mx-auto text-slate-400" />
          <p className="text-sm text-slate-500 mt-2">{provider === 'OCI' ? 'Drop your OCI config file here, or browse.' : 'Drop your service account JSON here, or browse.'}</p>
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
          {loading ? 'Uploading...' : `Upload ${provider} Credentials`}
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
          <div className="space-y-3">
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => setPostScanTarget('dashboard')}
                className={`flex-1 rounded-md border px-3 py-2 text-sm font-medium ${postScanTarget === 'dashboard' ? 'border-blue-200 bg-blue-50 text-blue-700' : 'border-slate-200 bg-white text-slate-600'}`}
              >
                Open Dashboard
              </button>
              <button
                type="button"
                onClick={() => setPostScanTarget('chat')}
                className={`flex-1 rounded-md border px-3 py-2 text-sm font-medium ${postScanTarget === 'chat' ? 'border-emerald-200 bg-emerald-50 text-emerald-700' : 'border-slate-200 bg-white text-slate-600'}`}
              >
                Open Chat
              </button>
            </div>
            <button
              onClick={handleScan}
              disabled={scanLoading}
              className="w-full inline-flex items-center justify-center gap-2 rounded-md bg-slate-900 px-4 py-2 text-white font-semibold hover:bg-slate-800 disabled:opacity-50"
            >
              <PlayCircle size={18} />
              {scanLoading ? 'Starting scan...' : 'Trigger Scan'}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { UploadCloud, ShieldCheck, PlayCircle, Cloud, Server, Plus } from 'lucide-react';
import { api } from '../api';
import type { CloudProvider, TenantProvider } from '../api';

export default function SetupPage() {
  const navigate = useNavigate();
  const [providers, setProviders] = useState<TenantProvider[]>([]);
  const [loadingProviders, setLoadingProviders] = useState(true);

  // Form state
  const [providerType, setProviderType] = useState<CloudProvider>('GCP');
  const [providerLabel, setProviderLabel] = useState('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [ociConfigText, setOciConfigText] = useState('');
  const [ociPrivateKeyText, setOciPrivateKeyText] = useState('');

  // Feedback
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [scanLoading, setScanLoading] = useState<number | null>(null);

  const loadData = async () => {
    setLoadingProviders(true);
    try {
      const provs = await api.getTenantProviders();
      setProviders(provs);
    } catch (err) {
      console.error('Failed to load providers', err);
      setError('Failed to load providers. Is the server running?');
    } finally {
      setLoadingProviders(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleSave = async () => {
    setError(null);
    setSuccess(null);
    if (!providerLabel.trim()) {
      setError('Enter a provider label (e.g. "My OCI Production").');
      return;
    }
    if (providerType === 'GCP') {
      if (!selectedFile) {
        setError('Select a GCP service account JSON file.');
        return;
      }
    }
    if (providerType === 'OCI') {
      if (!ociConfigText.trim()) {
        setError('Paste the OCI config file content.');
        return;
      }
    }

    setSaving(true);
    try {
      const tp = await api.createTenantProvider({
        organisation_id: 1,
        provider_type: providerType,
        provider_label: providerLabel.trim(),
        focus_version: providerType === 'OCI' ? 'CIS_OCI_3.0' : 'CIS_GCP_3.0',
      });

      if (providerType === 'GCP' && selectedFile) {
        const text = await selectedFile.text();
        await api.storeProviderCredentials(tp.id, { credentials_json: text });
      } else if (providerType === 'OCI') {
        await api.storeProviderCredentials(tp.id, {
          config_content: ociConfigText,
          private_key: ociPrivateKeyText || undefined,
        });
      }

      setSuccess(`Provider "${providerLabel}" created and credentials stored.`);
      setProviderLabel('');
      setSelectedFile(null);
      setOciConfigText('');
      setOciPrivateKeyText('');
      await loadData();
    } catch (err: any) {
      const msg = err?.response?.data?.detail || err?.message || 'Failed to save provider.';
      setError(msg);
    } finally {
      setSaving(false);
    }
  };

  const handleScan = async (tp: TenantProvider) => {
    setScanLoading(tp.id);
    setError(null);
    setSuccess(null);
    try {
      const result = await api.triggerScheduler(tp.id);
      if (result.count > 0) {
        setSuccess(`Scan triggered (ID: ${result.scan_ids[0]}). Opening dashboard...`);
        setTimeout(() => navigate('/', { state: { providerType: tp.provider_type } }), 1500);
      } else {
        setError('No scan was created. Check the provider has credentials stored.');
      }
    } catch (err: any) {
      const msg = err?.response?.data?.detail || err?.message || 'Failed to trigger scan.';
      setError(msg);
    } finally {
      setScanLoading(null);
    }
  };

  const hasCredentials = (tp: TenantProvider): boolean => {
    const c = tp.config;
    return Boolean(c?.credentials_json || c?.config_content);
  };

  return (
    <div className="max-w-3xl">
      <header className="mb-6">
        <h2 className="text-2xl font-bold text-slate-800">Cloud Providers</h2>
        <p className="text-slate-500">Register a cloud provider, upload credentials, and trigger a security scan.</p>
      </header>

      {/* Existing providers */}
      <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm mb-6">
        <h3 className="text-lg font-semibold text-slate-700 mb-3">Registered Providers</h3>
        {loadingProviders ? (
          <p className="text-sm text-slate-400">Loading...</p>
        ) : providers.length === 0 ? (
          <p className="text-sm text-slate-400">No providers registered yet. Add one below.</p>
        ) : (
          <div className="space-y-3">
            {providers.map((tp) => (
              <div key={tp.id} className="flex items-center justify-between rounded-lg border border-slate-100 bg-slate-50 p-3">
                <div className="flex items-center gap-3">
                  {tp.provider_type === 'OCI' ? <Server size={16} className="text-red-500" /> : <Cloud size={16} className="text-blue-500" />}
                  <div>
                    <span className="font-medium text-slate-700">{tp.provider_label}</span>
                    <span className="ml-2 text-xs text-slate-400">{tp.provider_type}</span>
                    {hasCredentials(tp) && <span className="ml-2 text-xs text-emerald-600">✓ credentials</span>}
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {hasCredentials(tp) && (
                    <button
                      onClick={() => handleScan(tp)}
                      disabled={scanLoading === tp.id}
                      className="inline-flex items-center gap-1 rounded-md bg-slate-900 px-3 py-1.5 text-xs font-semibold text-white hover:bg-slate-800 disabled:opacity-50"
                    >
                      <PlayCircle size={14} />
                      {scanLoading === tp.id ? 'Scanning...' : 'Scan'}
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Add new provider */}
      <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
        <h3 className="flex items-center gap-2 text-lg font-semibold text-slate-700">
          <Plus size={18} /> Add New Provider
        </h3>

        <div className="flex items-center gap-3 text-slate-700">
          <ShieldCheck className="text-emerald-500 shrink-0" />
          <div className="text-sm">
            Credentials are stored in the database and used only for read-only cloud API access.
          </div>
        </div>

        {/* Provider type toggle */}
        <div className="grid gap-2 sm:grid-cols-2">
          <button
            type="button"
            onClick={() => setProviderType('GCP')}
            className={`flex items-center justify-center gap-2 rounded-lg border px-3 py-2 text-sm font-medium ${providerType === 'GCP' ? 'border-blue-200 bg-blue-50 text-blue-700' : 'border-slate-200 bg-white text-slate-600'}`}
          >
            <Cloud size={16} /> GCP
          </button>
          <button
            type="button"
            onClick={() => setProviderType('OCI')}
            className={`flex items-center justify-center gap-2 rounded-lg border px-3 py-2 text-sm font-medium ${providerType === 'OCI' ? 'border-red-200 bg-red-50 text-red-700' : 'border-slate-200 bg-white text-slate-600'}`}
          >
            <Server size={16} /> OCI
          </button>
        </div>

        {/* Provider label */}
        <div>
          <label className="block text-sm font-medium text-slate-600 mb-1">Provider label</label>
          <input
            type="text"
            value={providerLabel}
            onChange={(e) => setProviderLabel(e.target.value)}
            placeholder={providerType === 'OCI' ? 'My OCI Production' : 'My GCP Production'}
            className="w-full rounded-md border border-slate-200 px-3 py-2 text-sm"
          />
        </div>

        {/* GCP: file upload */}
        {providerType === 'GCP' && (
          <div className="border-2 border-dashed border-slate-200 rounded-lg p-6 text-center">
            <UploadCloud className="mx-auto text-slate-400" />
            <p className="text-sm text-slate-500 mt-2">Drop your service account JSON file here, or browse.</p>
            <input
              type="file"
              accept=".json"
              className="mt-4 block w-full text-sm text-slate-500 file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-sm file:font-semibold file:bg-slate-100 file:text-slate-700 hover:file:bg-slate-200"
              onChange={(e) => setSelectedFile(e.target.files?.[0] ?? null)}
            />
          </div>
        )}

        {/* OCI: text areas */}
        {providerType === 'OCI' && (
          <div className="space-y-3">
            <div>
              <label className="block text-sm font-medium text-slate-600 mb-1">OCI config content</label>
              <textarea
                value={ociConfigText}
                onChange={(e) => setOciConfigText(e.target.value)}
                rows={6}
                placeholder="[DEFAULT]&#10;user=ocid1.user.oc1..&#10;fingerprint=...&#10;tenancy=ocid1.tenancy.oc1..&#10;region=...&#10;key_file=/path/to/key.pem"
                className="w-full rounded-md border border-slate-200 px-3 py-2 text-sm font-mono"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-600 mb-1">Private key (PEM)</label>
              <textarea
                value={ociPrivateKeyText}
                onChange={(e) => setOciPrivateKeyText(e.target.value)}
                rows={4}
                placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;...&#10;-----END RSA PRIVATE KEY-----"
                className="w-full rounded-md border border-slate-200 px-3 py-2 text-sm font-mono"
              />
            </div>
          </div>
        )}

        {/* Save button */}
        <button
          onClick={handleSave}
          disabled={saving}
          className="w-full rounded-md bg-emerald-600 px-4 py-2 text-white font-semibold hover:bg-emerald-700 disabled:opacity-50"
        >
          {saving ? 'Saving...' : `Save ${providerType} Provider`}
        </button>

        {error && (
          <div className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-600">{error}</div>
        )}
        {success && (
          <div className="rounded-md border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-700">{success}</div>
        )}
      </div>
    </div>
  );
}

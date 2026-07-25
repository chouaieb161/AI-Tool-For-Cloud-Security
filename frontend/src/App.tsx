import { useEffect, useState } from 'react';
import { Routes, Route, NavLink, Navigate } from 'react-router-dom';
import { LayoutDashboard, MessageSquare, KeyRound, Cloud, Server } from 'lucide-react';
import DashboardPage from './pages/DashboardPage';
import ChatPage from './pages/ChatPage';
import SetupPage from './pages/SetupPage';
import { api } from './api';
import type { CloudProvider, TenantProvider } from './api';

function App() {
  const [providers, setProviders] = useState<TenantProvider[]>([]);
  const [selectedProviderId, setSelectedProviderId] = useState<number | null>(null);

  useEffect(() => {
    api.getTenantProviders().then((list) => {
      setProviders(list);
      if (list.length > 0 && selectedProviderId === null) {
        setSelectedProviderId(list[0].id);
      }
    }).catch(() => {});
  }, []);

  const selectedProvider = providers.find((p) => p.id === selectedProviderId);
  const cloudProvider: CloudProvider = selectedProvider?.provider_type ?? 'GCP';

  return (
    <div className="flex h-screen bg-slate-50">
      <aside className="w-64 bg-white border-r border-slate-200 flex flex-col">
        <div className="p-4 border-b border-slate-200">
          <h1 className="text-xl font-semibold text-slate-800">Cloud Security</h1>
        </div>

        <div className="p-4 border-b border-slate-200">
          <select
            value={selectedProviderId ?? ''}
            onChange={(e) => setSelectedProviderId(Number(e.target.value))}
            className="w-full rounded-md border border-slate-200 px-2 py-1.5 text-sm"
          >
            {providers.length === 0 && <option value="">No providers</option>}
            {providers.map((tp) => (
              <option key={tp.id} value={tp.id}>
                {tp.provider_label} ({tp.provider_type})
              </option>
            ))}
          </select>
        </div>

        <nav className="p-4 space-y-2 flex-1">
          <NavLink
            to="/"
            end
            className={({ isActive }) =>
              `flex items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
                isActive ? 'bg-slate-100 text-slate-900' : 'text-slate-500 hover:bg-slate-50'
              }`
            }
          >
            <LayoutDashboard size={16} />
            Dashboard
          </NavLink>

          <NavLink
            to="/chat"
            className={({ isActive }) =>
              `flex items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
                isActive ? 'bg-slate-100 text-slate-900' : 'text-slate-500 hover:bg-slate-50'
              }`
            }
          >
            <MessageSquare size={16} />
            Chat
          </NavLink>

          <NavLink
            to="/setup"
            className={({ isActive }) =>
              `flex items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
                isActive ? 'bg-slate-100 text-slate-900' : 'text-slate-500 hover:bg-slate-50'
              }`
            }
          >
            <KeyRound size={16} />
            Setup
          </NavLink>
        </nav>

        <div className="p-4 border-t border-slate-200 text-xs text-slate-400">
          {selectedProvider && (
            <span className="flex items-center gap-1">
              {selectedProvider.provider_type === 'OCI' ? <Server size={12} className="text-red-400" /> : <Cloud size={12} className="text-blue-400" />}
              {selectedProvider.provider_label}
            </span>
          )}
        </div>
      </aside>

      <main className="flex-1 overflow-y-auto p-6">
        <Routes>
          <Route path="/" element={<DashboardPage cloudProvider={cloudProvider} />} />
          <Route path="/chat" element={<ChatPage cloudProvider={cloudProvider} />} />
          <Route path="/setup" element={<SetupPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  );
}

export default App;

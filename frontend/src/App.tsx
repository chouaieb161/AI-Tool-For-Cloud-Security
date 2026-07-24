import { useEffect, useState } from 'react';
import { Routes, Route, NavLink, Navigate } from 'react-router-dom';
import { LayoutDashboard, MessageSquare, KeyRound, Cloud, Server } from 'lucide-react';
import DashboardPage from './pages/DashboardPage';
import ChatPage from './pages/ChatPage';
import SetupPage from './pages/SetupPage';
import { useCredentials } from './hooks/useCredentials';
import type { CloudProvider } from './api';

function App() {
  const { status, loading } = useCredentials();
  const isConfigured = Boolean(status?.configured);
  const [cloudProvider, setCloudProvider] = useState<CloudProvider>('GCP');

  useEffect(() => {
    if (status?.provider) {
      setCloudProvider(status.provider);
    }
  }, [status?.provider]);

  return (
    <div className="flex h-screen bg-slate-50">
      {/* Sidebar */}
      <aside className="w-64 bg-white border-r border-slate-200 flex flex-col">
        <div className="p-4 border-b border-slate-200">
          <h1 className="text-xl font-semibold text-slate-800">Cloud Security</h1>
        </div>

        {/* Cloud Provider Toggle */}
        <div className="p-4 border-b border-slate-200">
          <div className="flex rounded-lg border border-slate-200 overflow-hidden">
            <button
              onClick={() => setCloudProvider('GCP')}
              className={`flex-1 flex items-center justify-center gap-1.5 py-2 text-xs font-medium transition-colors ${
                cloudProvider === 'GCP'
                  ? 'bg-blue-50 text-blue-700'
                  : 'bg-white text-slate-500 hover:bg-slate-50'
              }`}
            >
              <Cloud size={14} />
              GCP
            </button>
            <button
              onClick={() => setCloudProvider('OCI')}
              className={`flex-1 flex items-center justify-center gap-1.5 py-2 text-xs font-medium transition-colors ${
                cloudProvider === 'OCI'
                  ? 'bg-red-50 text-red-700'
                  : 'bg-white text-slate-500 hover:bg-slate-50'
              }`}
            >
              <Server size={14} />
              OCI
            </button>
          </div>
        </div>

        <nav className="p-4 space-y-2 flex-1">
          <NavLink
            to="/setup"
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-md transition-colors ${
                isActive ? 'bg-emerald-50 text-emerald-700' : 'text-slate-600 hover:bg-slate-100'
              }`
            }
          >
            <KeyRound size={20} />
            Credentials
          </NavLink>
          <NavLink
            to="/"
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-md transition-colors ${
                isActive ? 'bg-blue-50 text-blue-700' : 'text-slate-600 hover:bg-slate-100'
              }`
            }
          >
            <LayoutDashboard size={20} />
            Dashboard
          </NavLink>
          <NavLink
            to="/chat"
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-md transition-colors ${
                isActive ? 'bg-blue-50 text-blue-700' : 'text-slate-600 hover:bg-slate-100'
              }`
            }
          >
            <MessageSquare size={20} />
            Agent Chat
          </NavLink>
        </nav>

        {/* Provider indicator at bottom */}
        <div className="p-4 border-t border-slate-200">
          <div className={`flex items-center gap-2 text-xs font-medium ${
            cloudProvider === 'OCI' ? 'text-red-600' : 'text-blue-600'
          }`}>
            {cloudProvider === 'OCI' ? <Server size={14} /> : <Cloud size={14} />}
            Active provider: {cloudProvider}
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-auto">
        <div className="p-8">
          {loading ? (
            <div className="text-slate-500 p-8 text-center animate-pulse">Checking credentials...</div>
          ) : (
            <Routes>
              <Route path="/setup" element={<SetupPage />} />
              <Route
                path="/"
                element={
                  isConfigured ? (
                    <DashboardPage cloudProvider={cloudProvider} />
                  ) : (
                    <Navigate to="/setup" replace />
                  )
                }
              />
              <Route
                path="/chat"
                element={
                  isConfigured ? (
                    <ChatPage cloudProvider={cloudProvider} />
                  ) : (
                    <Navigate to="/setup" replace />
                  )
                }
              />
              <Route path="*" element={<Navigate to={isConfigured ? '/' : '/setup'} replace />} />
            </Routes>
          )}
        </div>
      </main>
    </div>
  );
}

export default App;
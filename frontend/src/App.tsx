import { Routes, Route, NavLink, Navigate } from 'react-router-dom';
import { LayoutDashboard, MessageSquare, KeyRound } from 'lucide-react';
import DashboardPage from './pages/DashboardPage';
import ChatPage from './pages/ChatPage';
import SetupPage from './pages/SetupPage';
import { useCredentials } from './hooks/useCredentials';

function App() {
  const { status, loading } = useCredentials();
  const isConfigured = Boolean(status?.configured);

  return (
    <div className="flex h-screen bg-slate-50">
      {/* Sidebar */}
      <aside className="w-64 bg-white border-r border-slate-200">
        <div className="p-4 border-b border-slate-200">
          <h1 className="text-xl font-semibold text-slate-800">Cloud Security</h1>
        </div>
        <nav className="p-4 space-y-2">
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
                element={isConfigured ? <DashboardPage /> : <Navigate to="/setup" replace />}
              />
              <Route
                path="/chat"
                element={isConfigured ? <ChatPage /> : <Navigate to="/setup" replace />}
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

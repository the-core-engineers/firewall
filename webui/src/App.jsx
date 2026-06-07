import React from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { AppProvider, useAppContext } from './context/AppContext';
import AppShell from './components/AppShell';

import Login from './pages/Login';
import DashboardPage from './pages/Dashboard';
import LiveCapturePage from './pages/LiveCapture';
import RulesPage from './pages/Rules';
import BlocklistPage from './pages/Blocklist';
import LogsPage from './pages/Logs';
import PacketTesterPage from './pages/PacketTester';
import SettingsPage from './pages/Settings';

function AppRouter() {
  const { token } = useAuth();
  const { currentView } = useAppContext();

  if (!token) {
    return <Login />;
  }

  const renderView = () => {
    switch (currentView) {
      case 'dashboard': return <DashboardPage />;
      case 'live': return <LiveCapturePage />;
      case 'rules': return <RulesPage />;
      case 'blocklist': return <BlocklistPage />;
      case 'logs': return <LogsPage />;
      case 'tester': return <PacketTesterPage />;
      case 'settings': return <SettingsPage />;
      default: return <DashboardPage />;
    }
  };

  return (
    <AppShell>
      {renderView()}
    </AppShell>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <AppProvider>
        <AppRouter />
      </AppProvider>
    </AuthProvider>
  );
}

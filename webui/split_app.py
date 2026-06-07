import os

files = {
    "src/context/AuthContext.jsx": """import React, { createContext, useContext, useState, useCallback } from 'react';

const AuthContext = createContext();

export function AuthProvider({ children }) {
  const [token, setToken] = useState(localStorage.getItem('fw_token'));
  const [loginError, setLoginError] = useState('');

  const login = async (username, password) => {
    try {
      const formData = new URLSearchParams();
      formData.append('username', username);
      formData.append('password', password);
      
      const res = await fetch('http://localhost:8000/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formData.toString()
      });
      if (res.ok) {
        const data = await res.json();
        localStorage.setItem('fw_token', data.access_token);
        setToken(data.access_token);
        setLoginError('');
      } else {
        const errorData = await res.json();
        setLoginError(errorData.detail || 'Invalid credentials');
      }
    } catch (e) {
      setLoginError('Could not connect to server');
    }
  };

  const logout = () => {
    localStorage.removeItem('fw_token');
    setToken(null);
  };

  const authFetch = useCallback(async (path, options = {}) => {
    const headers = {
      'Authorization': `Bearer ${token}`,
      ...options.headers
    };
    const res = await fetch(`http://localhost:8000${path}`, { ...options, headers });
    if (res.status === 401) {
      logout();
    }
    return res;
  }, [token]);

  return (
    <AuthContext.Provider value={{ token, login, logout, authFetch, loginError, setLoginError }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
""",
    "src/context/AppContext.jsx": """import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { useAuth } from './AuthContext';

const AppContext = createContext();

export function AppProvider({ children }) {
  const { token, authFetch } = useAuth();

  const initialTraffic = Array.from({ length: 60 }).map((_, i) => ({
    group: 'Packets/sec',
    index: i,
    value: 0
  }));

  const [currentView, setCurrentView] = useState('dashboard');
  const [isSideNavExpanded, setIsSideNavExpanded] = useState(true);
  const [packets, setPackets] = useState([]);
  const [isCapturing, setIsCapturing] = useState(false);
  const [status, setStatus] = useState('stopped');
  const [rules, setRules] = useState([]);
  const [logs, setLogs] = useState([]);
  const [blocklist, setBlocklist] = useState([]);
  const [stats, setStats] = useState({ analyzed: 0, allowed: 0, dropped: 0, blocked: 0, traffic: initialTraffic });
  const [settings, setSettings] = useState({ rate_limit: '1000', theme: 'g100', default_policy: 'ALLOW' });

  const fetchStatus = useCallback(async () => {
    try {
      const res = await authFetch('/capture/status');
      if (res.ok) {
        const data = await res.json();
        setIsCapturing(data.is_capturing);
        setStatus(data.is_capturing ? 'capturing' : 'stopped');
      }
    } catch (_) {}
  }, [authFetch]);

  const fetchRules = useCallback(async () => {
    try {
      const res = await authFetch('/rules');
      if (res.ok) setRules(await res.json());
    } catch (_) {}
  }, [authFetch]);

  const fetchLogs = useCallback(async () => {
    try {
      const res = await authFetch('/logs');
      if (res.ok) setLogs(await res.json());
    } catch (_) {}
  }, [authFetch]);

  const fetchBlocklist = useCallback(async () => {
    try {
      const res = await authFetch('/blocklist');
      if (res.ok) setBlocklist(await res.json());
    } catch (_) {}
  }, [authFetch]);

  const fetchSettings = useCallback(async () => {
    try {
      const res = await authFetch('/settings');
      if (res.ok) {
        const data = await res.json();
        setSettings(prev => ({ ...prev, ...data }));
      }
    } catch (_) {}
  }, [authFetch]);

  const fetchStats = useCallback(async (isInitialLoad = false) => {
    try {
      const res = await authFetch('/capture/stats');
      if (res.ok) {
        const newStats = await res.json();
        setStats(prev => {
          if (isInitialLoad) return { ...newStats, traffic: prev.traffic };
          const delta = Math.max(0, newStats.analyzed - prev.analyzed);
          let newTraffic = [...prev.traffic];
          newTraffic.push({ group: 'Packets/sec', value: delta });
          if (newTraffic.length > 60) newTraffic = newTraffic.slice(-60);
          newTraffic = newTraffic.map((pt, i) => ({ ...pt, index: i }));
          return { ...newStats, traffic: newTraffic };
        });
      }
    } catch (_) {}
  }, [authFetch]);

  useEffect(() => {
    if (!token) return;
    fetchStatus();
    fetchRules();
    fetchLogs();
    fetchBlocklist();
    fetchSettings();
    fetchStats(true);
  }, [token, fetchStatus, fetchRules, fetchLogs, fetchBlocklist, fetchSettings, fetchStats]);

  useEffect(() => {
    if (!token || !isCapturing) return;
    const interval = setInterval(async () => {
      try {
        const resPackets = await authFetch('/capture/packets');
        if (resPackets.ok) setPackets(await resPackets.json());
        fetchStats(false);
      } catch (_) {}
    }, 1000);
    return () => clearInterval(interval);
  }, [token, isCapturing, authFetch, fetchStats]);

  const value = {
    currentView, setCurrentView,
    isSideNavExpanded, setIsSideNavExpanded,
    packets, setPackets,
    isCapturing, setIsCapturing,
    status, setStatus,
    rules, setRules, fetchRules,
    logs, setLogs, fetchLogs,
    blocklist, setBlocklist, fetchBlocklist,
    stats, setStats, fetchStats,
    settings, setSettings, fetchSettings,
    fetchStatus
  };

  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
}

export const useAppContext = () => useContext(AppContext);
""",
    "src/pages/Login.jsx": """import React, { useState } from 'react';
import { Theme, Tile, Stack, InlineNotification, FluidForm, TextInput, PasswordInput, Button, Header, HeaderName, HeaderNavigation, HeaderMenuItem } from '@carbon/react';
import { Login as LoginIcon } from '@carbon/icons-react';
import { useAuth } from '../context/AuthContext';

export default function Login() {
  const { login, loginError, setLoginError } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  const handleLogin = (e) => {
    e.preventDefault();
    login(username, password);
  };

  return (
    <Theme theme="g100" className="login-page-container">
      <Header aria-label="Firewall Header">
        <HeaderName href="#" prefix="">Firewall</HeaderName>
        <HeaderNavigation aria-label="Header Navigation" style={{ marginLeft: 'auto' }}>
          <HeaderMenuItem href="#">Terms of Conditions</HeaderMenuItem>
        </HeaderNavigation>
      </Header>
      <Tile className="login-box">
        <Stack gap={7}>
          <h2 className="cds--type-productive-heading-04">Login to Firewall</h2>
          {loginError && (
            <InlineNotification kind="error" title="Error" subtitle={loginError} onCloseButtonClick={() => setLoginError('')} lowContrast />
          )}
          <FluidForm onSubmit={handleLogin}>
            <Stack gap={6}>
              <TextInput id="login-username" labelText="Username" placeholder="Enter your username" value={username} onChange={(e) => setUsername(e.target.value)} required />
              <PasswordInput id="login-password" labelText="Password" placeholder="Enter your password" value={password} onChange={(e) => setPassword(e.target.value)} required />
              <Button type="submit" size="lg" renderIcon={LoginIcon}>Sign in</Button>
            </Stack>
          </FluidForm>
          <InlineNotification kind="info" lowContrast hideCloseButton title="Notice" subtitle="This web application was made for authorized network security administration." style={{ marginTop: 'var(--cds-spacing-05)', maxWidth: '100%' }} />
        </Stack>
      </Tile>
    </Theme>
  );
}
"""
}

for filepath, content in files.items():
    with open(filepath, 'w') as f:
        f.write(content)


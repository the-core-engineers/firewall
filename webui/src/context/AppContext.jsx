import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
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
  const [stats, setStats] = useState({
    analyzed: 0,
    allowed: 0,
    dropped: 0,
    blocked: 0,
    traffic: [],
    packetsPerSec: initialTraffic
  });
  const [settings, setSettings] = useState({ rate_limit: '1000', theme: 'g100', default_policy: 'ALLOW' });

  const fetchStatus = useCallback(async () => {
    try {
      const res = await authFetch('/capture/status');
      if (res.ok) {
        const data = await res.json();
        const capturing = data.status === 'working';
        setIsCapturing(capturing);
        setStatus(capturing ? 'capturing' : 'stopped');
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
          if (isInitialLoad) return { ...newStats, packetsPerSec: prev.packetsPerSec };
          const delta = Math.max(0, newStats.analyzed - prev.analyzed);
          let newPps = [...prev.packetsPerSec];
          newPps.push({ group: 'Packets/sec', value: delta });
          if (newPps.length > 60) newPps = newPps.slice(-60);
          newPps = newPps.map((pt, i) => ({ ...pt, index: i }));

          return { ...newStats, traffic: newStats.traffic || [], packetsPerSec: newPps };
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

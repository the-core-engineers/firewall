import os

files = {
    "src/components/AppShell.jsx": """import React from 'react';
import { Theme, Header, HeaderMenuButton, HeaderName, HeaderGlobalBar, HeaderGlobalAction, SideNav, SideNavItems, SideNavLink, Content } from '@carbon/react';
import { Dashboard, Activity, Network_4, Locked, Document, Task, Settings as SettingsIcon, Logout } from '@carbon/icons-react';
import { useAuth } from '../context/AuthContext';
import { useAppContext } from '../context/AppContext';

export default function AppShell({ children }) {
  const { logout } = useAuth();
  const { currentView, setCurrentView, isSideNavExpanded, setIsSideNavExpanded, settings } = useAppContext();

  const activeTheme = settings.theme || 'white';

  return (
    <Theme theme="g100">
      <Header aria-label="Firewall Header">
        <HeaderMenuButton aria-label="Open menu" isCollapsible onClick={() => setIsSideNavExpanded(!isSideNavExpanded)} isActive={isSideNavExpanded} />
        <HeaderName href="#" prefix="">Firewall</HeaderName>
        <HeaderGlobalBar>
          <HeaderGlobalAction aria-label="Logout" tooltipAlignment="end" onClick={logout}>
            <Logout size={20} />
          </HeaderGlobalAction>
        </HeaderGlobalBar>
      </Header>
      <SideNav aria-label="Side navigation" expanded={isSideNavExpanded} isRail>
        <SideNavItems>
          <SideNavLink renderIcon={Dashboard} isActive={currentView === 'dashboard'} onClick={() => setCurrentView('dashboard')}>Dashboard</SideNavLink>
          <SideNavLink renderIcon={Activity} isActive={currentView === 'live'} onClick={() => setCurrentView('live')}>Live Capture</SideNavLink>
          <SideNavLink renderIcon={Network_4} isActive={currentView === 'rules'} onClick={() => setCurrentView('rules')}>Firewall Rules</SideNavLink>
          <SideNavLink renderIcon={Locked} isActive={currentView === 'blocklist'} onClick={() => setCurrentView('blocklist')}>Blocklist</SideNavLink>
          <SideNavLink renderIcon={Document} isActive={currentView === 'logs'} onClick={() => setCurrentView('logs')}>Logs</SideNavLink>
          <SideNavLink renderIcon={Task} isActive={currentView === 'tester'} onClick={() => setCurrentView('tester')}>Packet Tester</SideNavLink>
          <SideNavLink renderIcon={SettingsIcon} isActive={currentView === 'settings'} onClick={() => setCurrentView('settings')}>Settings</SideNavLink>
        </SideNavItems>
      </SideNav>
      <Theme theme={activeTheme}>
        <Content style={{ minHeight: '100vh', padding: 0, margin: 0 }}>
          <div style={{ padding: '3rem 2rem 2rem 2rem', marginLeft: isSideNavExpanded ? '16rem' : '3rem', transition: 'margin-left 0.11s cubic-bezier(0.2, 0, 0.38, 0.9)' }}>
            {children}
          </div>
        </Content>
      </Theme>
    </Theme>
  );
}
""",
    "src/pages/Dashboard.jsx": """import React from 'react';
import { Stack, Tile, Grid, Column } from '@carbon/react';
import { AreaChart } from '@carbon/charts-react';
import { useAppContext } from '../context/AppContext';

export default function DashboardPage() {
  const { stats, status } = useAppContext();

  const chartOptions = {
    title: 'Live Traffic (Pkts/sec)',
    axes: {
      bottom: { visible: false, mapsTo: 'index', scaleType: 'linear' },
      left: { visible: false, mapsTo: 'value', scaleType: 'linear' }
    },
    curve: 'curveMonotoneX',
    height: '250px',
    points: { enabled: false, radius: 0 },
    legend: { enabled: false },
    grid: { x: { enabled: false }, y: { enabled: false } },
    animations: false
  };

  return (
    <Stack gap={7}>
      <Stack gap={3}>
        <h2 className="cds--type-productive-heading-04">Security Dashboard</h2>
      </Stack>
      <Grid fullWidth style={{ padding: 0, margin: 0 }}>
        <Column sm={4} md={2} lg={4}>
          <Tile>
            <Stack gap={3}>
              <h5>Total Analyzed</h5>
              <h2>{stats.analyzed}</h2>
            </Stack>
          </Tile>
        </Column>
        <Column sm={4} md={2} lg={4}>
          <Tile>
            <Stack gap={3}>
              <h5>Packets Allowed</h5>
              <h2 className="success-text">{stats.allowed}</h2>
            </Stack>
          </Tile>
        </Column>
        <Column sm={4} md={2} lg={4}>
          <Tile>
            <Stack gap={3}>
              <h5>Packets Dropped</h5>
              <h2 className="warning-text">{stats.dropped}</h2>
            </Stack>
          </Tile>
        </Column>
        <Column sm={4} md={2} lg={4}>
          <Tile>
            <Stack gap={3}>
              <h5>Packets Blocked</h5>
              <h2 className="error-text">{stats.blocked}</h2>
            </Stack>
          </Tile>
        </Column>
      </Grid>
      <Tile>
        <AreaChart data={stats.traffic} options={chartOptions} />
      </Tile>
    </Stack>
  );
}
"""
}

for filepath, content in files.items():
    with open(filepath, 'w') as f:
        f.write(content)


import React from 'react';
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
        <Content id="main-content">
          <div style={{ padding: '2rem', marginLeft: isSideNavExpanded ? '16rem' : '3rem', transition: 'margin-left 0.11s cubic-bezier(0.2, 0, 0.38, 0.9)' }}>
            {children}
          </div>
        </Content>
      </Theme>
    </Theme>
  );
}

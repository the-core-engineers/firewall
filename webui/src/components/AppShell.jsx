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
    <>
      <Theme theme="g100">
        <Header aria-label="BASTION Header">
          <HeaderName href="#" prefix="">BASTION</HeaderName>
          <HeaderGlobalBar>
            <HeaderGlobalAction aria-label="Logout" tooltipAlignment="end" onClick={logout}>
              <Logout size={20} />
            </HeaderGlobalAction>
          </HeaderGlobalBar>
        </Header>
      </Theme>
      <Theme theme={activeTheme} className="app-shell">
        <SideNav aria-label="Side navigation" expanded={true}>
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
        <Content id="main-content">
          <div style={{ padding: '2rem' }}>
            {children}
          </div>
        </Content>
      </Theme>
    </>
  );
}

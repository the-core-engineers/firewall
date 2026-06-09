import React, { useState } from 'react';
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
      <Header aria-label="BASTION Header">
        <HeaderName href="#" prefix="">BASTION</HeaderName>
        {/* THIS IS COMMENTED OUT <HeaderNavigation aria-label="Header Navigation" style={{ marginLeft: 'auto' }}>
          <HeaderMenuItem href="#">Terms of Conditions</HeaderMenuItem>
        </HeaderNavigation> */}
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
          <InlineNotification kind="warning" lowContrast hideCloseButton title="Notice" subtitle="The webui interface is under development and is subject to change." style={{ marginTop: 'var(--cds-spacing-05)', maxWidth: '100%' }} />
          <InlineNotification kind="info" lowContrast title="Version" subtitle="Codename: Alpha X" style={{ marginTop: 'var(--cds-spacing-05)', maxWidth: '100%' }} />
        </Stack>
      </Tile>
    </Theme>
  );
}

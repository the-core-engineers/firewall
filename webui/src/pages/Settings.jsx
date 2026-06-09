import React from 'react';
import { Stack, Button, Form, FormGroup, Select, SelectItem, TextInput } from '@carbon/react';
import { Save } from '@carbon/icons-react';
import { useAuth } from '../context/AuthContext';
import { useAppContext } from '../context/AppContext';
import { useNotification } from '../context/NotificationContext';

export default function SettingsPage() {
  const { authFetch } = useAuth();
  const { settings, setSettings, fetchSettings } = useAppContext();
  const { addNotification } = useNotification();

  const handleSaveSettings = async (e) => {
    e.preventDefault();
    
    // The backend expects individual POST requests for each setting
    const settingKeys = ['rate_limit', 'theme', 'default_policy'];
    
    let hasError = false;
    for (const key of settingKeys) {
      if (settings[key] !== undefined) {
        const res = await authFetch('/settings', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            key: key,
            value: settings[key].toString()
          })
        });
        if (!res.ok) hasError = true;
      }
    }
    
    if (!hasError) {
      addNotification('success', 'Settings Saved', 'Engine configuration applied successfully.');
    } else {
      addNotification('error', 'Action Failed', 'Failed to save one or more settings.');
    }
    fetchSettings();
  };

  return (
    <Stack gap={7}>
      <Stack gap={3}>
        <h2 className="cds--type-productive-heading-04">Engine Settings</h2>
      </Stack>

      <div style={{ maxWidth: '600px', padding: '1rem', backgroundColor: 'var(--cds-layer)', border: '1px solid var(--cds-border-subtle)' }}>
        <Form onSubmit={handleSaveSettings}>
          <Stack gap={6}>
            <FormGroup legendText="Security Policy">
              <Select id="settings-policy" labelText="Default Firewall Policy" helperText="Action taken when no rules match a packet." value={settings.default_policy} onChange={e => setSettings({...settings, default_policy: e.target.value})}>
                <SelectItem value="ALLOW" text="ALLOW ALL" />
                <SelectItem value="DROP" text="DROP ALL" />
              </Select>
            </FormGroup>
            <FormGroup legendText="Rate Limiting">
              <TextInput id="settings-rate" labelText="Max Packets Per Second" helperText="Automatically drops packets exceeding this limit to prevent DoS attacks." value={settings.rate_limit} onChange={e => setSettings({...settings, rate_limit: e.target.value})} type="number" />
            </FormGroup>
            <FormGroup legendText="Appearance">
              <Select id="settings-theme" labelText="UI Theme" helperText="Changes the content area theme (shell remains dark)." value={settings.theme} onChange={e => setSettings({...settings, theme: e.target.value})}>
                <SelectItem value="white" text="White" />
                <SelectItem value="g10" text="Gray 10" />
                <SelectItem value="g90" text="Gray 90" />
                <SelectItem value="g100" text="Gray 100" />
              </Select>
            </FormGroup>
            <Button type="submit" renderIcon={Save}>Save Settings</Button>
          </Stack>
        </Form>
      </div>
    </Stack>
  );
}

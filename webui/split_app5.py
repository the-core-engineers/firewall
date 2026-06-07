import os

files = {
    "src/pages/Blocklist.jsx": """import React, { useState } from 'react';
import { Stack, Button, DataTable, TableContainer, Table, TableHead, TableRow, TableHeader, TableBody, TableCell, Form, FormGroup, TextInput } from '@carbon/react';
import { TrashCan } from '@carbon/icons-react';
import { useAuth } from '../context/AuthContext';
import { useAppContext } from '../context/AppContext';

export default function BlocklistPage() {
  const { authFetch } = useAuth();
  const { blocklist, fetchBlocklist } = useAppContext();
  const [newBlockIp, setNewBlockIp] = useState('');
  const [newBlockReason, setNewBlockReason] = useState('');

  const handleAddBlocklist = async (e) => {
    e.preventDefault();
    await authFetch('/blocklist', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip_address: newBlockIp, reason: newBlockReason || 'Manual block' })
    });
    setNewBlockIp('');
    setNewBlockReason('');
    fetchBlocklist();
  };

  const handleRemoveBlocklist = async (ip) => {
    await authFetch(`/blocklist/${ip}`, { method: 'DELETE' });
    fetchBlocklist();
  };

  const blocklistHeaders = [
    { key: 'ip', header: 'IP Address' },
    { key: 'reason', header: 'Reason' },
    { key: 'timestamp', header: 'Added At' },
    { key: 'delete', header: '' },
  ];

  const mappedBlocklist = blocklist.map(b => ({
    id: b.ip_address,
    ip: b.ip_address,
    reason: b.reason,
    timestamp: new Date(b.timestamp).toLocaleString(),
    delete: b.ip_address
  }));

  return (
    <Stack gap={7}>
      <Stack gap={3}>
        <h2 className="cds--type-productive-heading-04">Dynamic Blocklist</h2>
      </Stack>
      <div style={{ padding: '1rem', backgroundColor: 'var(--cds-layer)', border: '1px solid var(--cds-border-subtle)' }}>
        <h4 style={{ marginBottom: '1rem' }}>Manually Block IP</h4>
        <Form onSubmit={handleAddBlocklist}>
          <Stack orientation="horizontal" gap={4}>
            <FormGroup legendText="">
              <TextInput id="block-ip" labelText="IP Address" placeholder="e.g. 192.168.1.100" value={newBlockIp} onChange={e => setNewBlockIp(e.target.value)} required />
            </FormGroup>
            <FormGroup legendText="" style={{ flexGrow: 1 }}>
              <TextInput id="block-reason" labelText="Reason (optional)" placeholder="Malicious actor..." value={newBlockReason} onChange={e => setNewBlockReason(e.target.value)} />
            </FormGroup>
            <FormGroup legendText="">
              <Button type="submit" style={{ marginTop: '1.5rem' }}>Block IP</Button>
            </FormGroup>
          </Stack>
        </Form>
      </div>

      <DataTable rows={mappedBlocklist} headers={blocklistHeaders}>
        {({ rows, headers, getTableProps, getHeaderProps, getRowProps }) => (
          <TableContainer title="Blocked IPs">
            <Table {...getTableProps()}>
              <TableHead>
                <TableRow>
                  {headers.map((header) => (
                    <TableHeader {...getHeaderProps({ header })} key={header.key}>{header.header}</TableHeader>
                  ))}
                </TableRow>
              </TableHead>
              <TableBody>
                {rows.length === 0 ? (
                  <TableRow><TableCell colSpan={headers.length} style={{ textAlign: 'center' }}>No IPs currently blocked.</TableCell></TableRow>
                ) : (
                  rows.map((row) => (
                    <TableRow {...getRowProps({ row })} key={row.id}>
                      {row.cells.map((cell) => {
                        if (cell.info.header === 'delete') {
                          return <TableCell key={cell.id}><Button kind="ghost" size="sm" renderIcon={TrashCan} iconDescription="Unblock IP" hasIconOnly onClick={() => handleRemoveBlocklist(cell.value)} /></TableCell>;
                        }
                        return <TableCell key={cell.id}>{cell.value}</TableCell>;
                      })}
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </DataTable>
    </Stack>
  );
}
""",
    "src/pages/Logs.jsx": """import React from 'react';
import { Stack, Button, DataTable, TableContainer, Table, TableHead, TableRow, TableHeader, TableBody, TableCell, Tag } from '@carbon/react';
import { TrashCan } from '@carbon/icons-react';
import { useAuth } from '../context/AuthContext';
import { useAppContext } from '../context/AppContext';

export default function LogsPage() {
  const { authFetch } = useAuth();
  const { logs, fetchLogs } = useAppContext();

  const handleClearLogs = async () => {
    await authFetch('/logs', { method: 'DELETE' });
    fetchLogs();
  };

  const logHeaders = [
    { key: 'timestamp', header: 'Time' },
    { key: 'protocol', header: 'Protocol' },
    { key: 'srcIp', header: 'Source IP' },
    { key: 'dstIp', header: 'Dest IP' },
    { key: 'srcPort', header: 'Src Port' },
    { key: 'dstPort', header: 'Dest Port' },
    { key: 'action', header: 'Action' },
    { key: 'reason', header: 'Reason' },
  ];

  const mappedLogs = logs.map(log => ({
    id: log.id.toString(),
    timestamp: new Date(log.timestamp).toLocaleString(),
    protocol: log.protocol,
    srcIp: log.src_ip,
    dstIp: log.dst_ip,
    srcPort: log.src_port,
    dstPort: log.dst_port,
    action: log.action,
    reason: log.reason || '-'
  }));

  return (
    <Stack gap={7}>
      <Stack gap={3}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h2 className="cds--type-productive-heading-04">Security Logs</h2>
          <Button kind="ghost" renderIcon={TrashCan} onClick={handleClearLogs}>Clear Logs</Button>
        </div>
      </Stack>

      <DataTable rows={mappedLogs} headers={logHeaders}>
        {({ rows, headers, getTableProps, getHeaderProps, getRowProps }) => (
          <TableContainer title="Event History">
            <Table {...getTableProps()}>
              <TableHead>
                <TableRow>
                  {headers.map((header) => (
                    <TableHeader {...getHeaderProps({ header })} key={header.key}>{header.header}</TableHeader>
                  ))}
                </TableRow>
              </TableHead>
              <TableBody>
                {rows.length === 0 ? (
                  <TableRow><TableCell colSpan={headers.length} style={{ textAlign: 'center' }}>No logs available.</TableCell></TableRow>
                ) : (
                  rows.map((row) => (
                    <TableRow {...getRowProps({ row })} key={row.id}>
                      {row.cells.map((cell) => {
                        if (cell.info.header === 'action') {
                          return <TableCell key={cell.id}><Tag type={cell.value === 'ALLOW' ? 'green' : 'red'}>{cell.value}</Tag></TableCell>;
                        }
                        return <TableCell key={cell.id}>{cell.value}</TableCell>;
                      })}
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </DataTable>
    </Stack>
  );
}
""",
    "src/pages/PacketTester.jsx": """import React, { useState } from 'react';
import { Stack, Button, Form, FormGroup, Select, SelectItem, TextInput, Tile } from '@carbon/react';
import { useAuth } from '../context/AuthContext';

export default function PacketTesterPage() {
  const { authFetch } = useAuth();
  const [testPacket, setTestPacket] = useState({
    protocol: 'TCP',
    src_ip: '',
    dst_ip: '',
    src_port: '',
    dst_port: ''
  });
  const [testResult, setTestResult] = useState(null);

  const handleTestPacket = async (e) => {
    e.preventDefault();
    const payload = {
      protocol: testPacket.protocol,
      src_ip: testPacket.src_ip || '192.168.1.100',
      dst_ip: testPacket.dst_ip || '8.8.8.8',
      src_port: testPacket.src_port ? parseInt(testPacket.src_port) : 12345,
      dst_port: testPacket.dst_port ? parseInt(testPacket.dst_port) : 80,
    };
    const res = await authFetch('/capture/test_packet', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (res.ok) {
      setTestResult(await res.json());
    }
  };

  return (
    <Stack gap={7}>
      <Stack gap={3}>
        <h2 className="cds--type-productive-heading-04">Packet Tester</h2>
        <p>Simulate a packet traversing the firewall engine to see if it would be allowed or dropped.</p>
      </Stack>

      <div style={{ padding: '1rem', backgroundColor: 'var(--cds-layer)', border: '1px solid var(--cds-border-subtle)' }}>
        <Form onSubmit={handleTestPacket}>
          <Stack orientation="horizontal" gap={4}>
            <FormGroup legendText="">
              <Select id="test-protocol" labelText="Protocol" value={testPacket.protocol} onChange={e => setTestPacket({...testPacket, protocol: e.target.value})}>
                <SelectItem value="TCP" text="TCP" />
                <SelectItem value="UDP" text="UDP" />
                <SelectItem value="ICMP" text="ICMP" />
              </Select>
            </FormGroup>
            <FormGroup legendText="">
              <TextInput id="test-src-ip" labelText="Source IP" placeholder="192.168.1.100" value={testPacket.src_ip} onChange={e => setTestPacket({...testPacket, src_ip: e.target.value})} />
            </FormGroup>
            <FormGroup legendText="">
              <TextInput id="test-dst-ip" labelText="Dest IP" placeholder="8.8.8.8" value={testPacket.dst_ip} onChange={e => setTestPacket({...testPacket, dst_ip: e.target.value})} />
            </FormGroup>
            <FormGroup legendText="">
              <TextInput id="test-src-port" labelText="Src Port" placeholder="12345" value={testPacket.src_port} onChange={e => setTestPacket({...testPacket, src_port: e.target.value})} style={{ width: '80px' }} />
            </FormGroup>
            <FormGroup legendText="">
              <TextInput id="test-dst-port" labelText="Dest Port" placeholder="80" value={testPacket.dst_port} onChange={e => setTestPacket({...testPacket, dst_port: e.target.value})} style={{ width: '80px' }} />
            </FormGroup>
            <FormGroup legendText="">
              <Button type="submit" style={{ marginTop: '1.5rem' }}>Test Packet</Button>
            </FormGroup>
          </Stack>
        </Form>
      </div>

      {testResult && (
        <Tile style={{ borderLeft: `4px solid ${testResult.action === 'ALLOW' ? '#24a148' : '#da1e28'}` }}>
          <Stack gap={4}>
            <h4 style={{ color: testResult.action === 'ALLOW' ? '#24a148' : '#da1e28' }}>
              {testResult.action === 'ALLOW' ? 'PACKET ALLOWED' : 'PACKET DROPPED'}
            </h4>
            <div><strong>Reason:</strong> {testResult.reason}</div>
            <div><strong>Matched Rule ID:</strong> {testResult.matched_rule_id || 'None'}</div>
          </Stack>
        </Tile>
      )}
    </Stack>
  );
}
""",
    "src/pages/Settings.jsx": """import React from 'react';
import { Stack, Button, Form, FormGroup, Select, SelectItem, TextInput } from '@carbon/react';
import { Save } from '@carbon/icons-react';
import { useAuth } from '../context/AuthContext';
import { useAppContext } from '../context/AppContext';

export default function SettingsPage() {
  const { authFetch } = useAuth();
  const { settings, setSettings, fetchSettings } = useAppContext();

  const handleSaveSettings = async (e) => {
    e.preventDefault();
    await authFetch('/settings', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        rate_limit: parseInt(settings.rate_limit),
        theme: settings.theme,
        default_policy: settings.default_policy
      })
    });
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
"""
}

for filepath, content in files.items():
    with open(filepath, 'w') as f:
        f.write(content)


import React, { useState } from 'react';
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
      srcIp: testPacket.src_ip || '192.168.1.100',
      dstIp: testPacket.dst_ip || '8.8.8.8',
      srcPort: testPacket.src_port || '12345',
      dstPort: testPacket.dst_port || '80',
    };
    const res = await authFetch('/test', {
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

import React, { useState } from 'react';
import { Stack, Button, DataTable, TableContainer, Table, TableHead, TableRow, TableHeader, TableBody, TableCell, Tag, Form, FormGroup, Select, SelectItem, TextInput } from '@carbon/react';
import { TrashCan } from '@carbon/icons-react';
import { useAuth } from '../context/AuthContext';
import { useAppContext } from '../context/AppContext';
import { useNotification } from '../context/NotificationContext';

export default function RulesPage() {
  const { authFetch } = useAuth();
  const { rules, fetchRules } = useAppContext();
  const { addNotification } = useNotification();
  const [newRule, setNewRule] = useState({
    action: 'ALLOW',
    protocol: 'ANY',
    src_ip: '',
    dst_ip: '',
    src_port: '',
    dst_port: '',
    description: ''
  });

  const handleAddRule = async (e) => {
    e.preventDefault();
    const payload = {
      action: newRule.action,
      protocol: newRule.protocol,
      srcIp: newRule.src_ip || null,
      dstIp: newRule.dst_ip || null,
      srcPort: newRule.src_port ? newRule.src_port : null,
      dstPort: newRule.dst_port ? newRule.dst_port : null,
      description: newRule.description || null
    };
    const res = await authFetch('/rules', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (res.ok) {
      addNotification('success', 'Rule Created', 'Firewall rule has been created successfully.');
      setNewRule({ action: 'ALLOW', protocol: 'ANY', src_ip: '', dst_ip: '', src_port: '', dst_port: '', description: '' });
      fetchRules();
    } else {
      addNotification('error', 'Action Failed', 'Failed to create firewall rule.');
    }
  };

  const handleDeleteRule = async (ruleId) => {
    const res = await authFetch(`/rules/${ruleId}`, { method: 'DELETE' });
    if (res.ok) {
      addNotification('info', 'Rule Deleted', 'Firewall rule has been removed.');
      fetchRules();
    } else {
      addNotification('error', 'Action Failed', 'Failed to delete firewall rule.');
    }
  };

  const ruleHeaders = [
    { key: 'action', header: 'Action' },
    { key: 'protocol', header: 'Protocol' },
    { key: 'srcIp', header: 'Src IP' },
    { key: 'dstIp', header: 'Dest IP' },
    { key: 'srcPort', header: 'Src Port' },
    { key: 'dstPort', header: 'Dest Port' },
    { key: 'description', header: 'Description' },
    { key: 'delete', header: '' },
  ];

  const mappedRules = rules.map(rule => ({
    id: rule.id,
    action: rule.action,
    protocol: rule.protocol,
    srcIp: rule.srcIp || 'ANY',
    dstIp: rule.dstIp || 'ANY',
    srcPort: rule.srcPort || 'ANY',
    dstPort: rule.dstPort || 'ANY',
    description: rule.description || '-',
    delete: rule.id
  }));

  const getTagColor = (action) => {
    if (action === 'ALLOW') return 'green';
    if (action === 'BLOCK') return 'red';
    if (action === 'DROP') return 'magenta';
    return 'gray';
  };

  return (
    <Stack gap={7}>
      <Stack gap={3}>
        <h2 className="cds--type-productive-heading-04">Firewall Rules</h2>
      </Stack>
      <div style={{ padding: '1rem', backgroundColor: 'var(--cds-layer)', border: '1px solid var(--cds-border-subtle)' }}>
        <h4 style={{ marginBottom: '1rem' }}>Add New Rule</h4>
        <Form onSubmit={handleAddRule}>
          <Stack orientation="horizontal" gap={4}>
            <FormGroup legendText="">
              <Select id="rule-action" labelText="Action" value={newRule.action} onChange={e => setNewRule({...newRule, action: e.target.value})}>
                <SelectItem value="ALLOW" text="ALLOW" />
                <SelectItem value="DENY" text="DENY" />
                <SelectItem value="DROP" text="DROP" />
              </Select>
            </FormGroup>
            <FormGroup legendText="">
              <Select id="rule-protocol" labelText="Protocol" value={newRule.protocol} onChange={e => setNewRule({...newRule, protocol: e.target.value})}>
                <SelectItem value="ANY" text="ANY" />
                <SelectItem value="TCP" text="TCP" />
                <SelectItem value="UDP" text="UDP" />
                <SelectItem value="ICMP" text="ICMP" />
              </Select>
            </FormGroup>
            <FormGroup legendText="">
              <TextInput id="rule-src-ip" labelText="Source IP (optional)" placeholder="e.g. 192.168.1.5" value={newRule.src_ip} onChange={e => setNewRule({...newRule, src_ip: e.target.value})} />
            </FormGroup>
            <FormGroup legendText="">
              <TextInput id="rule-dst-ip" labelText="Dest IP (optional)" placeholder="e.g. 10.0.0.1" value={newRule.dst_ip} onChange={e => setNewRule({...newRule, dst_ip: e.target.value})} />
            </FormGroup>
            <FormGroup legendText="">
              <TextInput id="rule-src-port" labelText="Src Port" placeholder="ANY" value={newRule.src_port} onChange={e => setNewRule({...newRule, src_port: e.target.value})} style={{ width: '80px' }} />
            </FormGroup>
            <FormGroup legendText="">
              <TextInput id="rule-dst-port" labelText="Dest Port" placeholder="ANY" value={newRule.dst_port} onChange={e => setNewRule({...newRule, dst_port: e.target.value})} style={{ width: '80px' }} />
            </FormGroup>
          </Stack>
          <Stack orientation="horizontal" gap={4} style={{ marginTop: '1rem', alignItems: 'flex-end' }}>
            <FormGroup legendText="" style={{ flexGrow: 1 }}>
              <TextInput id="rule-desc" labelText="Description (optional)" placeholder="Rule description..." value={newRule.description} onChange={e => setNewRule({...newRule, description: e.target.value})} />
            </FormGroup>
            <Button type="submit">Add Rule</Button>
          </Stack>
        </Form>
      </div>

      <DataTable rows={mappedRules} headers={ruleHeaders}>
        {({ rows, headers, getTableProps, getHeaderProps, getRowProps }) => (
          <TableContainer title="Active Rules">
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
                  <TableRow><TableCell colSpan={headers.length} style={{ textAlign: 'center' }}>No rules defined.</TableCell></TableRow>
                ) : (
                  rows.map((row) => (
                    <TableRow {...getRowProps({ row })} key={row.id}>
                      {row.cells.map((cell) => {
                        if (cell.info.header === 'action') {
                          return <TableCell key={cell.id}><Tag type={getTagColor(cell.value)}>{cell.value}</Tag></TableCell>;
                        }
                        if (cell.info.header === 'delete') {
                          return <TableCell key={cell.id}><Button kind="ghost" size="sm" renderIcon={TrashCan} iconDescription="Delete rule" hasIconOnly onClick={() => handleDeleteRule(cell.value)} /></TableCell>;
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

import React, { useState } from 'react';
import { Stack, Button, DataTable, TableContainer, Table, TableHead, TableRow, TableHeader, TableBody, TableCell, Form, FormGroup, TextInput } from '@carbon/react';
import { TrashCan } from '@carbon/icons-react';
import { useAuth } from '../context/AuthContext';
import { useAppContext } from '../context/AppContext';
import { useNotification } from '../context/NotificationContext';

export default function BlocklistPage() {
  const { authFetch } = useAuth();
  const { blocklist, fetchBlocklist } = useAppContext();
  const { addNotification } = useNotification();
  const [newBlockIp, setNewBlockIp] = useState('');
  const [newBlockReason, setNewBlockReason] = useState('');

  const handleAddBlocklist = async (e) => {
    e.preventDefault();
    const res = await authFetch('/blocklist', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip: newBlockIp, reason: newBlockReason || 'Manual block' })
    });
    if (res.ok) {
      addNotification('success', 'IP Blocked', `Successfully added ${newBlockIp} to the blocklist.`);
      setNewBlockIp('');
      setNewBlockReason('');
      fetchBlocklist();
    } else {
      addNotification('error', 'Action Failed', 'Failed to add IP to blocklist.');
    }
  };

  const handleRemoveBlocklist = async (ip) => {
    const res = await authFetch(`/blocklist/${ip}`, { method: 'DELETE' });
    if (res.ok) {
      addNotification('info', 'IP Unblocked', 'Successfully removed IP from the blocklist.');
      fetchBlocklist();
    } else {
      addNotification('error', 'Action Failed', 'Failed to remove IP from blocklist.');
    }
  };

  const blocklistHeaders = [
    { key: 'ip', header: 'IP Address' },
    { key: 'reason', header: 'Reason' },
    { key: 'timestamp', header: 'Added At' },
    { key: 'delete', header: '' },
  ];

  const mappedBlocklist = blocklist.map(b => ({
    id: b.id,
    ip: b.ip,
    reason: b.reason,
    timestamp: new Date(b.timestamp).toLocaleString(),
    delete: b.id
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

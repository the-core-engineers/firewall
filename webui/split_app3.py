import os

files = {
    "src/pages/LiveCapture.jsx": """import React from 'react';
import { Stack, Button, DataTable, TableContainer, Table, TableHead, TableRow, TableHeader, TableBody, TableCell, Tag } from '@carbon/react';
import { Play, Stop, TrashCan } from '@carbon/icons-react';
import { useAuth } from '../context/AuthContext';
import { useAppContext } from '../context/AppContext';

export default function LiveCapturePage() {
  const { authFetch } = useAuth();
  const { status, fetchStatus, packets, setPackets } = useAppContext();

  const handleStartCapture = async () => {
    await authFetch('/capture/start', { method: 'POST' });
    fetchStatus();
  };

  const handleStopCapture = async () => {
    await authFetch('/capture/stop', { method: 'POST' });
    fetchStatus();
  };

  const handleClearCapture = async () => {
    await authFetch('/capture/clear', { method: 'POST' });
    setPackets([]);
  };

  const isCapturing = status === 'capturing';

  const packetHeaders = [
    { key: 'timestamp', header: 'Time' },
    { key: 'protocol', header: 'Protocol' },
    { key: 'src', header: 'Source' },
    { key: 'dst', header: 'Destination' },
    { key: 'status', header: 'Status' },
    { key: 'reason', header: 'Reason' },
  ];

  return (
    <Stack gap={7}>
      <Stack gap={3}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h2 className="cds--type-productive-heading-04">Live Traffic Capture</h2>
          <Stack orientation="horizontal" gap={3}>
            {isCapturing ? (
              <Button kind="danger" renderIcon={Stop} onClick={handleStopCapture}>Stop Capture</Button>
            ) : (
              <Button kind="primary" renderIcon={Play} onClick={handleStartCapture}>Start Capture</Button>
            )}
            <Button kind="ghost" renderIcon={TrashCan} onClick={handleClearCapture}>Clear</Button>
          </Stack>
        </div>
      </Stack>
      <DataTable rows={packets} headers={packetHeaders}>
        {({ rows, headers, getTableProps, getHeaderProps, getRowProps }) => (
          <TableContainer title="Captured Packets">
            <Table {...getTableProps()}>
              <TableHead>
                <TableRow>
                  {headers.map((header) => (
                    <TableHeader {...getHeaderProps({ header })} key={header.key}>
                      {header.header}
                    </TableHeader>
                  ))}
                </TableRow>
              </TableHead>
              <TableBody>
                {rows.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={headers.length} style={{ textAlign: 'center' }}>No packets captured yet.</TableCell>
                  </TableRow>
                ) : (
                  rows.map((row) => (
                    <TableRow {...getRowProps({ row })} key={row.id}>
                      {row.cells.map((cell) => {
                        if (cell.info.header === 'status') {
                          return (
                            <TableCell key={cell.id}>
                              <Tag type={cell.value === 'allowed' ? 'green' : 'red'}>
                                {cell.value.toUpperCase()}
                              </Tag>
                            </TableCell>
                          );
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
"""
}

for filepath, content in files.items():
    with open(filepath, 'w') as f:
        f.write(content)


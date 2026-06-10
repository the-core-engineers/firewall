import React, { useState } from 'react';
import { Stack, Button, DataTable, TableContainer, Table, TableHead, TableRow, TableHeader, TableBody, TableCell, Tag, Pagination } from '@carbon/react';
import { TrashCan, Renew } from '@carbon/icons-react';
import { useAuth } from '../context/AuthContext';
import { useAppContext } from '../context/AppContext';
import { useNotification } from '../context/NotificationContext';

export default function LogsPage() {
  const { authFetch } = useAuth();
  const { logs, fetchLogs } = useAppContext();
  const { addNotification } = useNotification();

  const [firstRowIndex, setFirstRowIndex] = useState(0);
  const [currentPageSize, setCurrentPageSize] = useState(100);

  const handleClearLogs = async () => {
    const res = await authFetch('/logs', { method: 'DELETE' });
    if (res.ok) {
      addNotification('info', 'Logs Cleared', 'Historical security event logs have been permanently deleted.');
      fetchLogs();
    } else {
      addNotification('error', 'Action Failed', 'Failed to clear security logs.');
    }
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
    srcIp: log.srcIp,
    dstIp: log.dstIp,
    srcPort: log.srcPort,
    dstPort: log.dstPort,
    action: log.action,
    reason: log.reason || '-'
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
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h2 className="cds--type-productive-heading-04">Security Logs</h2>
          <Stack orientation="horizontal" gap={3}>
            <Button kind="ghost" renderIcon={Renew} onClick={fetchLogs}>Refresh Logs</Button>
            <Button kind="ghost" renderIcon={TrashCan} onClick={handleClearLogs}>Clear Logs</Button>
          </Stack>
        </div>
      </Stack>

      <DataTable rows={mappedLogs.slice(firstRowIndex, firstRowIndex + currentPageSize)} headers={logHeaders}>
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
                          return <TableCell key={cell.id}><Tag type={getTagColor(cell.value)}>{cell.value}</Tag></TableCell>;
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
      <Pagination
        totalItems={mappedLogs.length}
        backwardText="Previous page"
        forwardText="Next page"
        page={Math.floor(firstRowIndex / currentPageSize) + 1}
        pageSize={currentPageSize}
        pageSizes={[20, 50, 100, 1000]}
        itemsPerPageText="Items per page:"
        onChange={({ page, pageSize }) => {
          if (pageSize !== currentPageSize) {
            setCurrentPageSize(pageSize);
            setFirstRowIndex(0);
          } else {
            setFirstRowIndex((page - 1) * pageSize);
          }
        }}
      />
    </Stack>
  );
}

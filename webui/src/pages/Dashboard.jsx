import React from 'react';
import { Stack, Tile, Grid, Column } from '@carbon/react';
import { useAppContext } from '../context/AppContext';

export default function DashboardPage() {
  const { stats, status } = useAppContext();

  return (
    <Stack gap={7}>
      <Stack gap={3}>
        <h2 className="cds--type-productive-heading-04">Security Dashboard</h2>
      </Stack>
      <Grid fullWidth style={{ padding: 0, margin: 0 }}>
        <Column sm={4} md={2} lg={4}>
          <Tile>
            <Stack gap={3}>
              <h5>Total Analyzed</h5>
              <h2>{stats.analyzed}</h2>
            </Stack>
          </Tile>
        </Column>
        <Column sm={4} md={2} lg={4}>
          <Tile>
            <Stack gap={3}>
              <h5>Packets Allowed</h5>
              <h2 className="success-text">{stats.allowed}</h2>
            </Stack>
          </Tile>
        </Column>
        <Column sm={4} md={2} lg={4}>
          <Tile>
            <Stack gap={3}>
              <h5>Packets Dropped</h5>
              <h2 className="warning-text">{stats.dropped}</h2>
            </Stack>
          </Tile>
        </Column>
        <Column sm={4} md={2} lg={4}>
          <Tile>
            <Stack gap={3}>
              <h5>Packets Blocked</h5>
              <h2 className="error-text">{stats.blocked}</h2>
            </Stack>
          </Tile>
        </Column>
      </Grid>
    </Stack>
  );
}

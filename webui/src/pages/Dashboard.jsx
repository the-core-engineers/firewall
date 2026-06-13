import React from 'react';
import { Stack, Tile, Grid, Column } from '@carbon/react';
import { LineChart } from '@carbon/charts-react';
import '@carbon/charts/styles.css';
import { useAppContext } from '../context/AppContext';

export default function DashboardPage() {
  const { stats, status } = useAppContext();

  const sparklineOptions = {
    title: 'Allowed Packets/sec',
    axes: {
      bottom: {
        title: 'Time (s)',
        mapsTo: 'index',
        scaleType: 'linear'
      },
      left: {
        mapsTo: 'value',
        title: 'Packets',
        scaleType: 'linear'
      }
    },
    curve: 'curveMonotoneX',
    height: '250px',
    legend: {
      enabled: false
    },
    grid: {
      x: {
        enabled: false
      },
      y: {
        enabled: false
      }
    },
    points: {
      enabled: false
    }
  };

  return (
    <Stack gap={7}>
      <Stack gap={3}>
        <h2 className="cds--type-productive-heading-04">Security Dashboard</h2>
      </Stack>
      <Grid fullWidth style={{ padding: 0, margin: 0 }}>
        <Column sm={4} md={4} lg={8}>
          <Tile>
            <Stack gap={3}>
              <h5>Total Analyzed</h5>
              <h2>{stats.analyzed}</h2>
            </Stack>
          </Tile>
        </Column>
        <Column sm={4} md={4} lg={8}>
          <Tile>
            <Stack gap={3}>
              <h5>Packets Allowed</h5>
              <h2 className="success-text">{stats.allowed}</h2>
            </Stack>
          </Tile>
        </Column>
      </Grid>

      <Grid fullWidth style={{ padding: 0, margin: 0 }}>
        <Column sm={4} md={8} lg={16}>
          <Tile style={{ padding: '1rem', width: '100%' }}>
            <LineChart
              data={stats.packetsPerSec}
              options={sparklineOptions}
            />
          </Tile>
        </Column>
      </Grid>
    </Stack>
  );
}

# webUI

**Location:** `webui/`  
**Stack:** React 18 · Vite 5 · IBM Carbon Design System · JavaScript (ESM)  
**Last updated:** 2026-06-09

**Author:** `Bikesh`

---

## Table of Contents

1. [Overview](#1-overview)
2. [Directory Structure](#2-directory-structure)
3. [Setup & Running](#3-setup--running)
4. [Dependencies](#4-dependencies)
5. [Architecture](#5-architecture)
6. [State Management — Context API](#6-state-management--context-api)
   - 6.1 [AuthContext](#61-authcontext)
   - 6.2 [AppContext](#62-appcontext)
7. [Application Shell — `AppShell.jsx`](#7-application-shell--appshell-jsx)
8. [Routing — `App.jsx`](#8-routing--appjsx)
9. [Pages](#9-pages)
   - 9.1 [Login](#91-login)
   - 9.2 [Dashboard](#92-dashboard)
   - 9.3 [Live Capture](#93-live-capture)
   - 9.4 [Firewall Rules](#94-firewall-rules)
   - 9.5 [Blocklist](#95-blocklist)
   - 9.6 [Logs](#96-logs)
   - 9.7 [Packet Tester](#97-packet-tester)
   - 9.8 [Settings](#98-settings)
10. [Design System — IBM Carbon](#10-design-system--ibm-carbon)
11. [API Communication Pattern](#11-api-communication-pattern)
12. [Known Limitations & TODOs](#12-known-limitations--todos)

---

## 1. Overview

The `webui/` package is a single-page React application (SPA) that serves as the operator interface for the firewall. It connects exclusively to the `core/` backend REST API at `http://localhost:8000`.

Key characteristics:

- **No page navigation** — all views are rendered inside a single shell; navigation changes only the `currentView` state value.
- **JWT authentication** — the token is stored in `localStorage` under the key `fw_token` and injected into every API call automatically via the `authFetch` wrapper.
- **Live polling** — when capture is active, the UI polls `/capture/packets` and `/capture/stats` every second using `setInterval`.
- **IBM Carbon Design System** — all components (tables, forms, buttons, navigation) use the `@carbon/react` component library.

---

## 2. Directory Structure

```
webui/
├── package.json            # npm metadata and dependency declarations
├── vite.config.js          # Vite build configuration
├── index.html              # HTML entry point
├── public/
│   └── login-background.png
├── src/
│   ├── main.jsx            # React DOM root mount
│   ├── App.jsx             # Root component; wraps providers and router
│   ├── index.scss          # Global styles (Carbon overrides)
│   ├── context/
│   │   ├── AuthContext.jsx # JWT state, login/logout, authFetch wrapper
│   │   └── AppContext.jsx  # All application data, polling, fetch helpers
│   ├── components/
│   │   └── AppShell.jsx    # Persistent header, side-nav, content wrapper
│   └── pages/
│       ├── Login.jsx
│       ├── Dashboard.jsx
│       ├── LiveCapture.jsx
│       ├── Rules.jsx
│       ├── Blocklist.jsx
│       ├── Logs.jsx
│       ├── PacketTester.jsx
│       └── Settings.jsx
└── split_app*.py           # (Legacy scaffolding scripts — not used at runtime)
```

---

## 3. Setup & Running

### Prerequisites

- Node.js 18+
- The `core/` backend must be running on `http://localhost:8000`

### Install and start

```bash
cd webui
npm install
npm run dev
```

Vite starts the dev server on `http://localhost:5173` by default.

### Build for production

```bash
npm run build
# Output in webui/dist/
```

Serve `dist/` with any static file server (e.g. nginx, `serve`).

---

## 4. Dependencies

### Runtime

| Package | Version | Purpose |
|---|---|---|
| `react` | ^18.2 | UI framework |
| `react-dom` | ^18.2 | DOM rendering |
| `@carbon/react` | ^1.65 | IBM Carbon component library |
| `@carbon/icons-react` | ^11.53 | Carbon SVG icon set |
| `@carbon/charts-react` | ^1.27 | Carbon chart components (D3-backed) |
| `@carbon/charts` | ^1.27 | Chart core (peer dep of charts-react) |
| `d3` | ^7.9 | Underlying chart rendering (transitive) |

### Dev

| Package | Version | Purpose |
|---|---|---|
| `vite` | ^5.1 | Build tool and dev server |
| `@vitejs/plugin-react` | ^4.2 | JSX transform for Vite |
| `sass` | ^1.71 | SCSS compilation for Carbon styles |

---

## 5. Architecture

```
main.jsx
  └─ App.jsx
       ├─ <AuthProvider>          (AuthContext — JWT, login, authFetch)
       └─ <AppProvider>           (AppContext — data, polling, fetchers)
            └─ <AppRouter>
                 ├─ if !token  →  <Login />
                 └─ if token   →  <AppShell>
                                       └─ {renderView()}   ← switches on currentView
                                            ├─ <DashboardPage />
                                            ├─ <LiveCapturePage />
                                            ├─ <RulesPage />
                                            ├─ <BlocklistPage />
                                            ├─ <LogsPage />
                                            ├─ <PacketTesterPage />
                                            └─ <SettingsPage />
```

Context nesting order matters: `AuthProvider` is outermost so `AppProvider` can call `useAuth()` to access `authFetch`.

---

## 6. State Management — Context API

The application uses two React contexts instead of a third-party state library.

### 6.1 AuthContext

**File:** `src/context/AuthContext.jsx`

Manages authentication state for the entire application.

#### State

| Value | Type | Description |
|---|---|---|
| `token` | `string \| null` | JWT stored in / read from `localStorage` |
| `loginError` | `string` | Error message shown on the login form |

#### Exposed values

| Value | Type | Description |
|---|---|---|
| `token` | string | Current JWT (null if not logged in) |
| `login(username, password)` | async fn | POSTs to `/login`, stores token |
| `logout()` | fn | Clears `localStorage` and token state |
| `authFetch(path, options)` | async fn | Authenticated wrapper around `fetch` |
| `loginError` | string | Current error string |
| `setLoginError` | fn | Clears the error after user dismisses it |

#### `authFetch` detail

```js
const authFetch = async (path, options = {}) => {
  // Automatically injects Authorization header
  const headers = { 'Authorization': `Bearer ${token}`, ...options.headers };
  const res = await fetch(`http://localhost:8000${path}`, { ...options, headers });
  // Auto-logout on 401 (expired / invalid token)
  if (res.status === 401) logout();
  return res;
};
```

All pages use `authFetch` instead of bare `fetch` — this ensures the JWT is always present and expired sessions are handled consistently.

---

### 6.2 AppContext

**File:** `src/context/AppContext.jsx`

Single source of truth for all application data. Manages background polling when capture is active.

#### State

| State | Type | Initial Value | Description |
|---|---|---|---|
| `currentView` | string | `'dashboard'` | Which page the shell renders |
| `isSideNavExpanded` | bool | `true` | Side-nav open/collapsed |
| `packets` | array | `[]` | Last 50 captured packets |
| `isCapturing` | bool | `false` | Whether the sniffer is running |
| `status` | string | `'stopped'` | `'capturing'` or `'stopped'` |
| `rules` | array | `[]` | All firewall rules from backend |
| `logs` | array | `[]` | Last 100 log entries |
| `blocklist` | array | `[]` | All blocklist entries |
| `stats` | object | zeros | Packet counters + traffic history |
| `settings` | object | defaults | Engine settings key-value pairs |

#### Fetch helpers

Each data type has a dedicated `useCallback` fetcher that pages can call to trigger a refresh:

| Function | Endpoint | When called |
|---|---|---|
| `fetchStatus()` | `GET /capture/status` | On mount; after start/stop |
| `fetchRules()` | `GET /rules` | On mount; after add/delete |
| `fetchLogs()` | `GET /logs` | On mount; on manual refresh |
| `fetchBlocklist()` | `GET /blocklist` | On mount; after add/delete |
| `fetchSettings()` | `GET /settings` | On mount; after save |
| `fetchStats(isInitialLoad)` | `GET /capture/stats` | On mount; every 1s when capturing |

#### Polling behaviour

```
useEffect: when isCapturing === true
  setInterval(1000ms):
    → GET /capture/packets  →  setPackets()
    → fetchStats(false)     →  compute delta, push to traffic array
```

When `isCapturing` becomes `false`, the interval is cleared by the effect cleanup function.

#### Traffic history derivation

```
Backend sends:   { analyzed: 1500, allowed: 1200, dropped: 250, blocked: 50, traffic: [...] }

Frontend keeps:  60-point rolling array of { group: 'Packets/sec', value: delta }

delta = max(0, newStats.analyzed - prev.analyzed)
```

The delta approach ensures the sparkline shows **rate** (packets per second) rather than cumulative totals, which would always increase monotonically.

---

## 7. Application Shell — `AppShell.jsx`

**File:** `src/components/AppShell.jsx`

The persistent layout wrapper rendered for every authenticated view.

```
┌─────────────────────────────────────────────────────────┐
│  <Header>   "Firewall"                    [Logout icon]  │
├────────────┬────────────────────────────────────────────┤
│ <SideNav>  │                                            │
│            │  <Content>                                 │
│  Dashboard │    <Theme theme={settings.theme}>          │
│  Live Cap  │      {children}   ← page rendered here     │
│  Rules     │    </Theme>                                │
│  Blocklist │                                            │
│  Logs      │                                            │
│  Tester    │                                            │
│  Settings  │                                            │
└────────────┴────────────────────────────────────────────┘
```

### Theme layering

The shell uses a fixed dark theme (`g100`) for the header and nav, while the content area uses the user-selected theme from `settings.theme`. This means operators can set a light or dark content theme without the navigation chrome changing.

### Side-nav rail mode

The side-nav uses Carbon's `isRail` property. When collapsed, it condenses to a narrow icon strip (~48px wide) rather than disappearing entirely, keeping navigation always accessible.

### Margin animation

The content `<div>` transitions its left margin (`3rem` collapsed ↔ `16rem` expanded) using the same cubic-bezier curve as Carbon's native shell animation for a seamless feel.

---

## 8. Routing — `App.jsx`

There is no React Router. Navigation is implemented entirely via the `currentView` string in `AppContext`.

```jsx
const renderView = () => {
  switch (currentView) {
    case 'dashboard': return <DashboardPage />;
    case 'live':      return <LiveCapturePage />;
    case 'rules':     return <RulesPage />;
    case 'blocklist': return <BlocklistPage />;
    case 'logs':      return <LogsPage />;
    case 'tester':    return <PacketTesterPage />;
    case 'settings':  return <SettingsPage />;
    default:          return <DashboardPage />;
  }
};
```

Clicking a side-nav link calls `setCurrentView('target')` — the shell re-renders the content area without any browser navigation. The URL never changes.

---

## 9. Pages

### 9.1 Login

**File:** `src/pages/Login.jsx`

Renders when `token` is null. Uses `AuthContext.login()` on form submit.

- Shows an `InlineNotification` error banner if `loginError` is set.
- Clears the error when the user dismisses it via `setLoginError('')`.
- Displays an informational notice that the app is for authorised administrators.

---

### 9.2 Dashboard

**File:** `src/pages/Dashboard.jsx`

Read-only statistics view. Pulls `stats` and `status` from `AppContext`.

**Metric tiles:**

| Tile | Value | CSS class |
|---|---|---|
| Total Analyzed | `stats.analyzed` | — |
| Packets Allowed | `stats.allowed` | `success-text` |
| Packets Dropped | `stats.dropped` | `warning-text` |
| Packets Blocked | `stats.blocked` | `error-text` |

Values update in real time when capture is active via the AppContext polling interval.

---

### 9.3 Live Capture

**File:** `src/pages/LiveCapture.jsx`

Real-time packet table. Shows the last 50 packets returned by `GET /capture/packets`.

**Controls:**

| Button | Action |
|---|---|
| Start Capture | `POST /capture/start` then `fetchStatus()` |
| Stop Capture | `POST /capture/stop` then `fetchStatus()` |
| Clear | `POST /capture/clear` then `setPackets([])` |

**Colour coding (Carbon `<Tag>` types):**

| Action | Colour |
|---|---|
| ALLOW | `green` |
| BLOCK | `red` |
| DROP | `magenta` |

**Table columns:** Time · Protocol · Source · Destination · Status · Reason

---

### 9.4 Firewall Rules

**File:** `src/pages/Rules.jsx`

Displays all rules and provides an add-rule form.

#### Field name mapping

The form uses `snake_case` internally (`src_ip`, `dst_port`, etc.) and converts to `camelCase` for the API payload on submit:

```js
// Local state
{ action: 'ALLOW', protocol: 'TCP', src_ip: '', dst_port: '443', ... }

// API payload
{ action: 'ALLOW', protocol: 'TCP', srcIp: null, dstPort: '443', ... }
```

Empty string fields are sent as `null` (converted before the POST).

#### Port field behaviour

The `Src Port` and `Dest Port` inputs accept any valid `port_matches` format:
- Single: `443`
- Range: `49152-65535`
- Comma list: `80,443,8080`

The backend validates and stores the value as-is.

#### Rule actions available in the form

`ALLOW` · `DENY` · `DROP`

> **Note:** `DENY` is offered as a UI option but the backend engine only handles `ALLOW`, `BLOCK`, and `DROP`. `DENY` values are stored and returned but have no defined engine behaviour.

#### Delete

Calls `DELETE /rules/{rule.id}` where `id` is the 8-character UUID.

---

### 9.5 Blocklist

**File:** `src/pages/Blocklist.jsx`

Manual IP block management.

**Add form fields:** IP Address (required) · Reason (optional, defaults to `"Manual block"`)

**Delete:** calls `DELETE /blocklist/{entry.id}` by the blocklist entry UUID.

> Auto-blocked IPs (from flood detection) appear here too — operators can unblock them manually.

---

### 9.6 Logs

**File:** `src/pages/Logs.jsx`

Read-only historical log table. Returns the most recent 100 entries from the database, newest first.

**Controls:** Refresh · Clear All (permanent, calls `DELETE /logs`)

**Columns:** Time · Protocol · Source IP · Dest IP · Src Port · Dest Port · Action · Reason

Same colour-coding as Live Capture (`green` / `red` / `magenta`).

---

### 9.7 Packet Tester

**File:** `src/pages/PacketTester.jsx`

Sends a simulated packet through the engine without touching the network.

**Fields:** Protocol · Source IP · Dest IP · Src Port · Dest Port

**Defaults applied by the component** if fields are left blank:

| Field | Default |
|---|---|
| srcIp | `192.168.1.100` |
| dstIp | `8.8.8.8` |
| srcPort | `12345` |
| dstPort | `80` |

**Result tile:**

Shows ALLOWED (green left border) or DROPPED (red left border), the reason string, and the matched rule ID.

> The result tile uses the `action` field from the backend response, not the `allowed` boolean, for the colour decision.

---

### 9.8 Settings

**File:** `src/pages/Settings.jsx`

Editable engine configuration. Sends each changed setting as a separate `POST /settings` call.

**Settings managed:**

| Setting | UI Label | Type | Description |
|---|---|---|---|
| `default_policy` | Default Firewall Policy | Select | `ALLOW` or `DROP` |
| `rate_limit` | Max Packets Per Second | Number input | Packets/min before DROP |
| `theme` | UI Theme | Select | `white` / `g10` / `g90` / `g100` |

> `default_policy` is stored in the backend `settings` table but is **not currently read by the engine** — the engine always defaults to ALLOW. This is a known TODO.

---

## 10. Design System — IBM Carbon

All UI components come from `@carbon/react`. Key components used:

| Component | Used in |
|---|---|
| `Header`, `HeaderName`, `HeaderGlobalBar` | AppShell |
| `SideNav`, `SideNavItems`, `SideNavLink` | AppShell |
| `Theme` | AppShell (dual-layer theming) |
| `Content` | AppShell |
| `DataTable`, `Table`, `TableHead`, `TableBody`, `TableCell`, `TableHeader`, `TableRow` | All data pages |
| `Tag` | LiveCapture, Rules, Logs (status badges) |
| `Button` | All interactive pages |
| `Form`, `FormGroup`, `TextInput`, `Select`, `SelectItem` | Rules, Blocklist, Tester, Settings |
| `Tile`, `Stack`, `Grid`, `Column` | Dashboard, PacketTester |
| `InlineNotification` | Login |
| `FluidForm`, `PasswordInput` | Login |

### Status colour convention

This colour mapping is applied consistently across all pages that display packet actions:

```
ALLOW  →  Carbon 'green'   tag
BLOCK  →  Carbon 'red'     tag
DROP   →  Carbon 'magenta' tag
```

### Theme tokens

Carbon exposes theme tokens as CSS custom properties under `--cds-*`. Custom inline styles in the pages use these tokens to stay theme-aware:

```jsx
backgroundColor: 'var(--cds-layer)'
border: '1px solid var(--cds-border-subtle)'
```

---

## 11. API Communication Pattern

### Request flow

```
User action (click / form submit)
       │
       ▼
Page component calls authFetch(path, options)
       │
       ▼
AuthContext injects Authorization header
       │
       ▼
fetch('http://localhost:8000' + path, { headers: { Authorization: 'Bearer <token>' }, ...options })
       │
       ├─ 200 OK   →  component updates local state or calls fetchXxx()
       ├─ 400/4xx  →  component may show error (currently silent in most pages)
       └─ 401      →  AuthContext calls logout() → redirect to Login
```

### Polling flow (when capturing)

```
AppContext useEffect (dep: isCapturing)
       │
       └─ setInterval(1000ms)
               │
               ├─ GET /capture/packets  →  setPackets(data)
               └─ fetchStats(false)
                       │
                       └─ compute delta
                          push to traffic rolling window
                          setStats(newStats)
```

---

## 12. Known Limitations & TODOs

| # | Area | Issue | Suggested Fix |
|---|---|---|---|
| 1 | Config | API base URL (`http://localhost:8000`) is hardcoded in two places (`AuthContext`, `PacketTester`) | Move to `import.meta.env.VITE_API_URL` |
| 2 | Error handling | Most `authFetch` calls are silent on non-2xx responses | Add toast/notification feedback for failed operations |
| 3 | Routing | URL never changes; browser back/forward and bookmarks don't work | Adopt React Router with hash or history routing |
| 4 | Rules form | `DENY` action is offered but has no engine behaviour | Remove from dropdown or implement in engine |
| 5 | Settings | `default_policy` setting is saved but never read by the engine | Wire `default_policy` into `evaluate_packet()` fallback return |
| 6 | Live Capture | Packets are fetched only while `isCapturing === true`; new packets captured just before stop may be missed | Fetch once more after stop |
| 7 | Performance | Full rule list is re-fetched after every add/delete | Optimistic update local state; revalidate in background |
| 8 | Accessibility | Side-nav `SideNavLink` items use `onClick` with no `href`; keyboard navigation may not announce page change | Add `aria-current="page"` and role announcements |
| 9 | Security | JWT stored in `localStorage` is vulnerable to XSS | Consider `httpOnly` cookie with CSRF protection |
| 10 | Charts | Dashboard traffic chart placeholder exists in AppContext state but no chart component is rendered on the Dashboard page | Add Carbon `AreaChart` to `Dashboard.jsx` using `stats.traffic` |

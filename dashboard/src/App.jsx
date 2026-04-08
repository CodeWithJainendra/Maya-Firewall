import { useEffect, useMemo, useState } from 'react'
import {
  Activity,
  AlertTriangle,
  Binary,
  Cpu,
  Globe,
  LayoutDashboard,
  Lock,
  MapPinned,
  Radar,
  Server,
  Shield,
  Skull,
  Terminal,
  Waves,
  Zap,
} from 'lucide-react'
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'

const tabs = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'network', label: 'Network', icon: Waves },
  { id: 'decoys', label: 'Decoys', icon: Server },
  { id: 'intel', label: 'Threat Intel', icon: Skull },
]

const defaultAttackSeries = []

const serviceHeatmap = [
  { service: 'SSH', hits: 1240 },
  { service: 'HTTP', hits: 920 },
  { service: 'HTTPS', hits: 860 },
  { service: 'RDP', hits: 410 },
  { service: 'MySQL', hits: 365 },
  { service: 'SMB', hits: 298 },
]

const decoyFleet = [
  { name: 'Linux SSH Bastions', count: 144, health: 'Stable', response: '24 ms' },
  { name: 'Windows AD Mirrors', count: 36, health: 'Elevated', response: '42 ms' },
  { name: 'Database Replicas', count: 61, health: 'Stable', response: '31 ms' },
  { name: 'OT/SCADA Nodes', count: 18, health: 'Critical Watch', response: '57 ms' },
]

const initialLiveSessions = []

const malwareQueue = [
  { name: 'ransom_x.elf', family: 'locker', severity: 'critical', age: '12 sec' },
  { name: 'backdoor_v4.bin', family: 'rat', severity: 'high', age: '5 min' },
  { name: 'scan_script.py', family: 'recon', severity: 'medium', age: '12 min' },
  { name: 'dropper.ps1', family: 'loader', severity: 'high', age: '19 min' },
]

const geoIngress = [
  { region: 'IN-Kanpur', hits: 34, color: '#00e5ff' },
  { region: 'SG-Singapore', hits: 19, color: '#34d399' },
  { region: 'DE-Frankfurt', hits: 11, color: '#f59e0b' },
  { region: 'NL-Amsterdam', hits: 8, color: '#f43f5e' },
]

const aptRankings = [
  { name: 'APT41 (Winnti)', confidence: 88, ttps: 19 },
  { name: 'Lazarus Group', confidence: 62, ttps: 14 },
  { name: 'SideWinder', confidence: 45, ttps: 11 },
  { name: 'Unknown Cluster-7', confidence: 23, ttps: 6 },
]

const severityPalette = {
  critical: '#ff4d6d',
  high: '#ff8a00',
  medium: '#00d4ff',
}

async function apiFetch(url, options = {}) {
  const headers = {
    ...(options.body ? { 'Content-Type': 'application/json' } : {}),
    ...(options.headers || {}),
  }

  return fetch(url, {
    credentials: 'include',
    ...options,
    headers,
  })
}

function formatAuthError(error) {
  const message = error?.message || ''
  const isNetworkFailure =
    error instanceof TypeError || /networkerror|failed to fetch|fetch resource/i.test(message)

  if (isNetworkFailure) {
    return 'Dashboard backend unreachable on 127.0.0.1:8900. Start: cargo run -p maya-cli -- dashboard --port 8900'
  }

  return message || 'Authentication failed'
}

function StatCard({ title, value, subtitle, icon, tone = 'cyan' }) {
  const Icon = icon

  return (
    <article className={`panel stat-card tone-${tone}`}>
      <div className="stat-card__header">
        <div>
          <p className="eyebrow">{title}</p>
          <h3 className="stat-card__value">{value}</h3>
        </div>
        <span className="stat-card__icon"><Icon size={18} /></span>
      </div>
      <p className="stat-card__subtitle">{subtitle}</p>
    </article>
  )
}

function PanelTitle({ icon, title, meta }) {
  const Icon = icon

  return (
    <div className="panel-title">
      <div className="panel-title__main">
        <span className="panel-title__icon"><Icon size={16} /></span>
        <div>
          <h3>{title}</h3>
          {meta ? <p>{meta}</p> : null}
        </div>
      </div>
    </div>
  )
}

function HealthPill({ label, value }) {
  return (
    <div className="health-pill">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  )
}

function App() {
  const [activeTab, setActiveTab] = useState('overview')
  const [health, setHealth] = useState(null)
  const [stats, setStats] = useState(null)
  const [liveFeed, setLiveFeed] = useState(initialLiveSessions)
  const [attackSeries, setAttackSeries] = useState(defaultAttackSeries)
  const [authState, setAuthState] = useState('checking')
  const [loginToken, setLoginToken] = useState('')
  const [authError, setAuthError] = useState('')
  const [authLoading, setAuthLoading] = useState(false)

  useEffect(() => {
    let active = true

    const checkSession = async () => {
      try {
        const sessionRes = await apiFetch('/api/auth/session')
        if (!active) return
        setAuthState(sessionRes.ok ? 'authenticated' : 'unauthenticated')
      } catch {
        if (!active) return
        setAuthState('unauthenticated')
      }
    }

    checkSession()
    return () => {
      active = false
    }
  }, [authState])

  useEffect(() => {
    if (authState !== 'authenticated') {
      return undefined
    }

    let cancelled = false

    const load = async () => {
      try {
        const [healthRes, statsRes] = await Promise.all([
          apiFetch('/api/health'),
          apiFetch('/api/stats'),
        ])

        if (!cancelled && (healthRes.status === 401 || statsRes.status === 401)) {
          setAuthState('unauthenticated')
          return
        }

        if (!cancelled && healthRes.ok) {
          setHealth(await healthRes.json())
        }

        if (!cancelled && statsRes.ok) {
          setStats(await statsRes.json())
        }
      } catch {
        // fallback to local static data during frontend-only dev
      }
    }

    load()
    const timer = setInterval(load, 15000)

    return () => {
      cancelled = true
      clearInterval(timer)
    }
  }, [authState])

  useEffect(() => {
    if (authState !== 'authenticated') {
      return undefined
    }

    let cancelled = false
    let reconnectTimer
    let socket

    const connect = () => {
      const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      socket = new WebSocket(`${wsProtocol}//${window.location.host}/ws/feed`)

      socket.onmessage = (message) => {
        try {
          const parsed = JSON.parse(message.data)
          if (cancelled) {
            return
          }

          const feed = parsed?.feed ?? parsed

          if (feed?.id) {
            setLiveFeed((prev) => {
              const deduped = prev.filter((entry) => entry.id !== feed.id)
              return [feed, ...deduped].slice(0, 20)
            })
          }

          if (parsed?.stats) {
            setStats(parsed.stats)
          }

          if (Array.isArray(parsed?.series) && parsed.series.length > 0) {
            setAttackSeries(parsed.series)
          }
        } catch {
          // ignore malformed payloads
        }
      }

      socket.onclose = () => {
        if (!cancelled) {
          reconnectTimer = window.setTimeout(connect, 1500)
        }
      }

      socket.onerror = () => {
        socket.close()
      }
    }

    connect()

    return () => {
      cancelled = true
      if (reconnectTimer) {
        window.clearTimeout(reconnectTimer)
      }
      if (socket && socket.readyState <= WebSocket.OPEN) {
        socket.close()
      }
    }
  }, [authState])

  const handleLogin = async (event) => {
    event.preventDefault()
    setAuthLoading(true)
    setAuthError('')

    try {
      const response = await apiFetch('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ token: loginToken }),
      })

      if (!response.ok) {
        throw new Error('Invalid dashboard token')
      }

      setLoginToken('')
      setAuthState('authenticated')
    } catch (error) {
      setAuthError(formatAuthError(error))
      setAuthState('unauthenticated')
    } finally {
      setAuthLoading(false)
    }
  }

  const handleLogout = async () => {
    await apiFetch('/api/auth/logout', { method: 'POST' })
    setAuthState('unauthenticated')
    setHealth(null)
    setStats(null)
  }

  const overviewStats = useMemo(
    () => ({
      activeDecoys: stats?.active_decoys ?? 'N/A',
      trappedAttackers: stats?.trapped_attackers ?? 'N/A',
      scansDetected:
        stats?.scans_detected !== undefined && stats?.scans_detected !== null
          ? stats.scans_detected.toLocaleString()
          : 'N/A',
      malwareCaptured: stats?.malware_captured ?? 'N/A',
      activeSessions: stats?.active_sessions ?? 'N/A',
      alertsGenerated: stats?.alerts_generated ?? 'N/A',
    }),
    [stats],
  )

  const telemetryAvailable = Boolean(stats && health)

  const componentHealth = health?.components
    ? Object.entries(health.components).map(([key, value]) => ({
        key: key.replaceAll('_', ' '),
        value,
      }))
    : [
        { key: 'network engine', value: 'unavailable' },
        { key: 'deception engine', value: 'unavailable' },
        { key: 'ai brain', value: 'unavailable' },
        { key: 'sandbox', value: 'unavailable' },
        { key: 'crypto', value: 'unavailable' },
      ]

  return (
    <div className="app-shell">
      <div className="app-shell__grid" />
      <div className="app-shell__scanline" />

      <header className="topbar panel">
        <div className="brand">
          <div className="brand__mark">
            <Shield size={22} />
          </div>
          <div>
            <p className="eyebrow">Westworld active deception</p>
            <h1>MAYA SOC GRID</h1>
          </div>
        </div>

        <nav className="topbar__nav">
          {tabs.map(({ id, label, icon }) => {
            const Icon = icon

            return (
              <button
                key={id}
                type="button"
                className={`nav-tab ${activeTab === id ? 'nav-tab--active' : ''}`}
                onClick={() => setActiveTab(id)}
              >
                <Icon size={15} />
                <span>{label}</span>
              </button>
            )
          })}
        </nav>

        <div className="topbar__status">
          <div>
            <p className="eyebrow">Grid identity</p>
            <strong>maya-node-001@cdis-iitk</strong>
          </div>
          {authState === 'authenticated' ? (
            <button type="button" className="ghost-button" onClick={handleLogout}>Logout</button>
          ) : null}
          <span className="status-dot" aria-hidden="true" />
        </div>
      </header>

      {authState !== 'authenticated' ? (
        <section className="auth-overlay">
          <form className="auth-card panel" onSubmit={handleLogin}>
            <div className="auth-card__header">
              <Shield size={18} />
              <div>
                <p className="eyebrow">Secure access</p>
                <h2>Authenticate dashboard operator</h2>
              </div>
            </div>
            <p className="auth-card__copy">
              Enter the MAYA dashboard access token. A secure session cookie will be issued after verification.
            </p>
            <p className="auth-help">Dev token: <strong>maya-dev-token</strong></p>
            <input
              className="auth-input"
              type="password"
              value={loginToken}
              onChange={(event) => setLoginToken(event.target.value)}
              placeholder="Dashboard access token"
              autoComplete="current-password"
            />
            {authError ? <p className="auth-error">{authError}</p> : null}
            <button type="submit" className="primary-button" disabled={authLoading || !loginToken.trim()}>
              {authLoading ? 'Authorizing…' : 'Establish secure session'}
            </button>
          </form>
        </section>
      ) : null}

      <main className={`dashboard-layout ${authState !== 'authenticated' ? 'dashboard-layout--locked' : ''}`}>
        <section className="stats-grid">
          <StatCard
            title="Active Decoys"
            value={overviewStats.activeDecoys}
            subtitle={telemetryAvailable ? '+12 spawned in last hour' : 'Telemetry unavailable'}
            icon={Server}
            tone="cyan"
          />
          <StatCard
            title="Trapped Attackers"
            value={overviewStats.trappedAttackers}
            subtitle={
              telemetryAvailable
                ? `${overviewStats.activeSessions} live sessions in deception fabric`
                : 'Telemetry unavailable'
            }
            icon={Skull}
            tone="rose"
          />
          <StatCard
            title="Scans Blocked"
            value={overviewStats.scansDetected}
            subtitle={telemetryAvailable ? 'XDP ingress filter armed' : 'Telemetry unavailable'}
            icon={Zap}
            tone="amber"
          />
          <StatCard
            title="Malware Samples"
            value={overviewStats.malwareCaptured}
            subtitle={telemetryAvailable ? '3 waiting for sandbox execution' : 'Telemetry unavailable'}
            icon={Binary}
            tone="mint"
          />
        </section>

        <section className="hero-grid">
          <article className="panel hero-chart">
            <PanelTitle icon={Activity} title="Attack intensity timeline" meta="Probe-to-exploit transition over the last 90 minutes" />
            <div className="chart-wrap chart-wrap--large">
              {attackSeries.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={attackSeries}>
                    <defs>
                      <linearGradient id="mayaIntensity" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#00e5ff" stopOpacity={0.35} />
                        <stop offset="100%" stopColor="#00e5ff" stopOpacity={0.02} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid stroke="rgba(255,255,255,0.06)" vertical={false} />
                    <XAxis dataKey="time" stroke="rgba(214,228,255,0.55)" tickLine={false} axisLine={false} />
                    <YAxis stroke="rgba(214,228,255,0.55)" tickLine={false} axisLine={false} />
                    <Tooltip
                      contentStyle={{
                        background: '#07111a',
                        border: '1px solid rgba(0, 229, 255, 0.15)',
                        borderRadius: '14px',
                      }}
                    />
                    <Area type="monotone" dataKey="intensity" stroke="#00e5ff" strokeWidth={2} fill="url(#mayaIntensity)" />
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <div className="empty-telemetry">No live telemetry available for attack timeline.</div>
              )}
            </div>
          </article>

          <article className="panel live-feed">
            <PanelTitle icon={Terminal} title="Live deception feed" meta="Current attacker interactions across the decoy mesh" />
            <div className="feed-list">
              {liveFeed.length > 0 ? (
                liveFeed.map((session) => (
                  <div key={session.id} className="feed-item">
                    <div className="feed-item__head">
                      <strong>@{session.actor}</strong>
                      <span>{session.time}</span>
                    </div>
                    <code>{session.command}</code>
                    <div className="feed-item__label-row">
                      <span className="feed-item__label">{session.command_label || 'command_execution'}</span>
                      <span className={`severity severity--${session.severity || 'medium'}`}>{session.severity || 'medium'}</span>
                    </div>
                    <div className="feed-item__meta">
                      <span>{session.decoy}</span>
                      <span className={`badge badge--${session.state}`}>{session.state}</span>
                    </div>
                  </div>
                ))
              ) : (
                <div className="empty-telemetry">No live telemetry available for deception feed.</div>
              )}
            </div>
            <button type="button" className="primary-button">Launch full grid shell</button>
          </article>
        </section>

        {activeTab === 'overview' && (
          <section className="content-grid">
            <article className="panel">
              <PanelTitle icon={Radar} title="APT attribution likelihood" meta="Behavioral similarity from session telemetry and TTP overlap" />
              <div className="rank-list">
                {aptRankings.map((apt) => (
                  <div key={apt.name} className="rank-item">
                    <div className="rank-item__labels">
                      <strong>{apt.name}</strong>
                      <span>{apt.ttps} TTP matches</span>
                    </div>
                    <div className="progress-row">
                      <div className="progress-track">
                        <div className="progress-bar" style={{ width: `${apt.confidence}%` }} />
                      </div>
                      <em>{apt.confidence}%</em>
                    </div>
                  </div>
                ))}
              </div>
            </article>

            <article className="panel">
              <PanelTitle icon={Binary} title="Malware sandbox queue" meta="Pending artifacts prioritized by behavioral severity" />
              <div className="list-table">
                {malwareQueue.map((item) => (
                  <div key={item.name} className="list-row">
                    <div>
                      <strong>{item.name}</strong>
                      <span>{item.family}</span>
                    </div>
                    <div className="list-row__end">
                      <span>{item.age}</span>
                      <span className={`severity severity--${item.severity}`}>{item.severity}</span>
                    </div>
                  </div>
                ))}
              </div>
            </article>

            <article className="panel">
              <PanelTitle icon={MapPinned} title="Geographical ingress" meta="Observed entry clusters across monitored edges" />
              <div className="geo-layout">
                <div className="geo-radar">
                  <div className="geo-radar__ring geo-radar__ring--one" />
                  <div className="geo-radar__ring geo-radar__ring--two" />
                  <div className="geo-radar__ring geo-radar__ring--three" />
                  {geoIngress.map((point, index) => (
                    <span
                      key={point.region}
                      className="geo-radar__point"
                      style={{
                        left: `${22 + index * 18}%`,
                        top: `${28 + (index % 2) * 22}%`,
                        background: point.color,
                      }}
                    />
                  ))}
                  <div className="geo-radar__label">IND / PRIMARY SENSOR</div>
                </div>
                <div className="geo-list">
                  {geoIngress.map((point) => (
                    <div key={point.region} className="geo-list__item">
                      <span>{point.region}</span>
                      <strong>{point.hits} hits</strong>
                    </div>
                  ))}
                </div>
              </div>
            </article>

            <article className="panel health-panel">
              <PanelTitle icon={Cpu} title="System posture" meta="Control-plane health and deception runtime state" />
              <div className="health-grid">
                {componentHealth.map((entry) => (
                  <HealthPill key={entry.key} label={entry.key} value={entry.value} />
                ))}
              </div>
              <div className="system-note">
                <Lock size={14} />
                <span>PQ hybrid mode armed · Kyber768 tunnel profile · HotStuff quorum healthy</span>
              </div>
            </article>
          </section>
        )}

        {activeTab === 'network' && (
          <section className="content-grid content-grid--network">
            <article className="panel">
              <PanelTitle icon={Globe} title="Ingress service pressure" meta="Top targeted services across the XDP edge" />
              <div className="chart-wrap">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={serviceHeatmap}>
                    <CartesianGrid stroke="rgba(255,255,255,0.06)" vertical={false} />
                    <XAxis dataKey="service" stroke="rgba(214,228,255,0.55)" tickLine={false} axisLine={false} />
                    <YAxis stroke="rgba(214,228,255,0.55)" tickLine={false} axisLine={false} />
                    <Tooltip
                      contentStyle={{
                        background: '#07111a',
                        border: '1px solid rgba(0, 229, 255, 0.15)',
                        borderRadius: '14px',
                      }}
                    />
                    <Bar dataKey="hits" radius={[8, 8, 0, 0]} fill="#00e5ff" />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </article>

            <article className="panel">
              <PanelTitle icon={Zap} title="Probe versus exploit split" meta="Traffic blend observed during current burst window" />
              <div className="chart-wrap">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={[
                        { name: 'Probe traffic', value: 81 },
                        { name: 'Exploit traffic', value: 19 },
                      ]}
                      dataKey="value"
                      innerRadius={68}
                      outerRadius={94}
                      paddingAngle={4}
                    >
                      <Cell fill="#00e5ff" />
                      <Cell fill="#ff4d6d" />
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        background: '#07111a',
                        border: '1px solid rgba(0, 229, 255, 0.15)',
                        borderRadius: '14px',
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </article>

            <article className="panel network-metrics">
              <PanelTitle icon={Waves} title="Edge telemetry" meta="Kernel-to-userspace deception path" />
              <div className="metric-stack">
                <HealthPill label="xdp mode" value="armed" />
                <HealthPill label="packet path" value="kernel first" />
                <HealthPill label="avg redirect latency" value="31 ms" />
                <HealthPill label="active watch ports" value="8" />
                <HealthPill label="pps budget" value="100k" />
                <HealthPill label="dns intercept" value="enabled" />
              </div>
            </article>
          </section>
        )}

        {activeTab === 'decoys' && (
          <section className="content-grid content-grid--decoys">
            <article className="panel fleet-panel">
              <PanelTitle icon={Server} title="Decoy fleet status" meta="Current isolation tiers and response timing" />
              <div className="list-table">
                {decoyFleet.map((fleet) => (
                  <div key={fleet.name} className="list-row">
                    <div>
                      <strong>{fleet.name}</strong>
                      <span>{fleet.count} instances</span>
                    </div>
                    <div className="list-row__end">
                      <span>{fleet.response}</span>
                      <span className={`severity severity--${fleet.health === 'Critical Watch' ? 'critical' : fleet.health === 'Elevated' ? 'high' : 'medium'}`}>
                        {fleet.health}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </article>

            <article className="panel">
              <PanelTitle icon={Shield} title="Isolation posture" meta="Runtime distribution across sandbox classes" />
              <div className="health-grid">
                <HealthPill label="gVisor lanes" value="312" />
                <HealthPill label="Kata lanes" value="64" />
                <HealthPill label="bare decoys" value="0" />
                <HealthPill label="average ttl" value="58 min" />
                <HealthPill label="spawn budget" value="50 ms" />
                <HealthPill label="auto pruning" value="enabled" />
              </div>
            </article>
          </section>
        )}

        {activeTab === 'intel' && (
          <section className="content-grid content-grid--intel">
            <article className="panel">
              <PanelTitle icon={AlertTriangle} title="Threat intelligence board" meta="High-confidence signals extracted from deception interactions" />
              <div className="list-table">
                {[
                  'C2 beaconing pattern matches SideWinder cluster transport framing',
                  'Privilege escalation attempts indicate Impacket-style operator workflow',
                  'Observed staging cadence aligns with long-dwell reconnaissance actor',
                  'Fake ledger exfiltration path successfully delayed by 114 seconds',
                ].map((item) => (
                  <div key={item} className="intel-note">
                    <AlertTriangle size={16} />
                    <span>{item}</span>
                  </div>
                ))}
              </div>
            </article>

            <article className="panel">
              <PanelTitle icon={Radar} title="Malware severity distribution" meta="Queued artifacts by current triage priority" />
              <div className="severity-grid">
                {Object.entries(severityPalette).map(([severity, color]) => {
                  const count = malwareQueue.filter((item) => item.severity === severity).length
                  return (
                    <div key={severity} className="severity-card">
                      <span className="severity-card__swatch" style={{ background: color }} />
                      <strong>{count}</strong>
                      <span>{severity}</span>
                    </div>
                  )
                })}
              </div>
            </article>
          </section>
        )}
      </main>

      <footer className="footer-bar">
        <span>MAYA CORE v0.1.0 · BUILD 2026.04.08.1728</span>
        <span>PQ-encrypted fabric · formal consensus ready · active deception posture nominal</span>
      </footer>
    </div>
  )
}

export default App

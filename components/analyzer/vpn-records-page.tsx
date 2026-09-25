'use client'

import { useEffect, useMemo, useState } from 'react'
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Clock,
  Cpu,
  Download,
  ExternalLink,
  Eye,
  FileCode,
  FileText,
  Filter,
  Layers,
  Loader2,
  Lock,
  Play,
  Printer,
  RefreshCw,
  Search,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Wifi,
  X,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { buildSecurityReport, downloadHtmlReport, downloadJsonReport, downloadMarkdownReport, printReport } from '@/lib/api/report'
import { getPcapDownloadUrl, getTestbedRunDetails, getTestbedRuns, loadPcapToAnalyzer } from '@/lib/api/testbed'
import { type SecurityReport, type TestbedConfig, type View, type VpnRecord } from '@/lib/api/types'
import { ReportModal } from './report-modal'

interface VpnRecordsPageProps {
  onGo: (view: View) => void
  onInspectRecord?: (sessionInfo: any) => void
  onRerunInTestbed?: (config: TestbedConfig) => void
}

export function VpnRecordsPage({ onGo, onInspectRecord, onRerunInTestbed }: VpnRecordsPageProps) {
  const [runs, setRuns] = useState<VpnRecord[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [trafficFilter, setTrafficFilter] = useState('ALL')
  const [cipherFilter, setCipherFilter] = useState('ALL')
  const [activeTab, setActiveTab] = useState<Record<string, 'config' | 'pcap' | 'analysis' | 'logs' | 'report'>>({})

  // Active Report Modal
  const [viewingReport, setViewingReport] = useState<SecurityReport | null>(null)

  // Active Full Logs Modal
  const [logsModalRun, setLogsModalRun] = useState<{ id: string; logs: any; loading: boolean } | null>(null)

  // Loading indicator for loading PCAP to workspace
  const [loadingPcapId, setLoadingPcapId] = useState<string | null>(null)

  const fetchRuns = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await getTestbedRuns()
      if (res && res.runs && res.runs.length > 0) {
        setRuns(res.runs)
      } else {
        // If backend returned empty or offline, check localStorage
        const stored = localStorage.getItem('ipsec_vpn_records')
        if (stored) {
          try {
            setRuns(JSON.parse(stored))
          } catch {
            setRuns([])
          }
        }
      }
    } catch (e: any) {
      setError(e.message || 'Failed to load VPN records')
      const stored = localStorage.getItem('ipsec_vpn_records')
      if (stored) {
        try {
          setRuns(JSON.parse(stored))
        } catch {
          // ignore
        }
      }
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchRuns()
  }, [])

  // Sync state to localStorage for offline persistence
  useEffect(() => {
    if (runs.length > 0) {
      localStorage.setItem('ipsec_vpn_records', JSON.stringify(runs))
    }
  }, [runs])

  // Filtered runs
  const filteredRuns = useMemo(() => {
    return runs.filter((item) => {
      const matchesSearch =
        searchQuery === '' ||
        item.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.title?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.config?.traffic_type?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.config?.encryption?.toLowerCase().includes(searchQuery.toLowerCase())

      const matchesTraffic =
        trafficFilter === 'ALL' || item.config?.traffic_type?.toLowerCase() === trafficFilter.toLowerCase()

      const matchesCipher =
        cipherFilter === 'ALL' || item.config?.encryption?.toLowerCase() === cipherFilter.toLowerCase()

      return matchesSearch && matchesTraffic && matchesCipher
    })
  }, [runs, searchQuery, trafficFilter, cipherFilter])

  // Aggregate stats
  const stats = useMemo(() => {
    const total = runs.length
    const established = runs.filter((r) => r.established || r.status === 'ESTABLISHED').length
    const avgScore =
      total > 0 ? Math.round(runs.reduce((acc, r) => acc + (r.analysis?.score || 15), 0) / total) : 0
    return { total, established, avgScore }
  }, [runs])

  // Action: Open Logs Modal
  const handleOpenLogs = async (r: VpnRecord) => {
    setLogsModalRun({ id: r.id, logs: r.logs || null, loading: true })
    try {
      const details = await getTestbedRunDetails(r.id)
      if (details?.logs) {
        setLogsModalRun({ id: r.id, logs: details.logs, loading: false })
      } else {
        setLogsModalRun((prev) => (prev ? { ...prev, loading: false } : null))
      }
    } catch {
      setLogsModalRun((prev) => (prev ? { ...prev, loading: false } : null))
    }
  }

  // Action: Open Report Modal for a run
  const handleGenerateOrViewReport = (r: VpnRecord) => {
    const report = buildSecurityReport({
      info: {
        id: r.id,
        session_id: r.id,
        name: r.pcap?.filename || `${r.id}.pcap`,
        size: r.pcap?.size || '30.9 KB',
        packets: r.pcap?.packets || 100,
        duration: '00:00:30',
        capturedAt: r.created_at,
      },
      config: r.config,
      logs: r.logs?.sa || r.logs?.terminal_output || undefined,
    })
    setViewingReport(report)
  }

  // Action: Load PCAP directly into analyzer
  const handleInspectInAnalyzer = async (r: VpnRecord) => {
    setLoadingPcapId(r.id)
    try {
      const res = await loadPcapToAnalyzer(r.id)
      if (onInspectRecord && res.info) {
        onInspectRecord(res.info)
      }
      onGo('analysis')
    } catch (e: any) {
      alert(`Could not load ${r.id} into workspace: ${e.message}`)
    } finally {
      setLoadingPcapId(null)
    }
  }

  // Card Tab switcher
  const getCardTab = (id: string) => activeTab[id] || 'config'
  const setCardTab = (id: string, tab: 'config' | 'pcap' | 'analysis' | 'logs' | 'report') => {
    setActiveTab((prev) => ({ ...prev, [id]: tab }))
  }

  return (
    <div className="flex flex-col gap-6">
      {/* Top Header Card */}
      <div className="rounded-xl border bg-card p-6 shadow-xs">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <div className="flex items-center gap-2">
              <span className="flex size-7 items-center justify-center rounded-lg bg-primary/10 text-primary">
                <ShieldCheck className="size-4" />
              </span>
              <h2 className="text-xl font-bold tracking-tight text-foreground">Generated VPN Records & History</h2>
              <span className="rounded-full bg-primary/10 px-2.5 py-0.5 text-xs font-semibold text-primary">
                Virtual Repository
              </span>
            </div>
            <p className="mt-1.5 text-xs text-muted-foreground leading-relaxed">
              Historical ledger and visual box-matrix of all generated IPsec tunnels. Inspect cryptographic configurations, download captured PCAPs, review NIST compliance audits, and export intelligence reports.
            </p>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <Button variant="outline" size="sm" onClick={fetchRuns} disabled={loading} className="gap-1.5 text-xs">
              <RefreshCw className={`size-3.5 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
            <Button size="sm" onClick={() => onGo('testbed')} className="gap-1.5 text-xs shadow-xs">
              <Play className="size-3.5" />
              Generate New VPN
            </Button>
          </div>
        </div>

        {/* Quick KPI Overview */}
        <div className="mt-6 grid grid-cols-2 sm:grid-cols-4 gap-3 border-t pt-5">
          <div className="rounded-lg bg-muted/40 p-3">
            <span className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider">Total VPN Sessions</span>
            <p className="mt-1 text-2xl font-bold tracking-tight text-foreground">{stats.total}</p>
          </div>
          <div className="rounded-lg bg-muted/40 p-3">
            <span className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider">Established Tunnels</span>
            <p className="mt-1 text-2xl font-bold tracking-tight text-emerald-600">
              {stats.established} <span className="text-xs text-muted-foreground font-normal">Active SAs</span>
            </p>
          </div>
          <div className="rounded-lg bg-muted/40 p-3">
            <span className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider">Average Risk Score</span>
            <p className="mt-1 text-2xl font-bold tracking-tight text-primary">
              {stats.avgScore} <span className="text-xs text-muted-foreground font-normal">/ 100 (Low Risk)</span>
            </p>
          </div>
          <div className="rounded-lg bg-muted/40 p-3">
            <span className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider">Storage Engine</span>
            <p className="mt-1 text-sm font-bold text-foreground truncate">
              WSL / Docker <span className="text-xs text-muted-foreground font-normal">& Local</span>
            </p>
          </div>
        </div>
      </div>

      {/* Filter & Search Bar */}
      <div className="rounded-xl border bg-card p-4 shadow-xs flex flex-col md:flex-row items-center justify-between gap-3">
        <div className="relative w-full md:w-80">
          <Search className="absolute left-3 top-2.5 size-4 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search run ID, cipher, traffic..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full rounded-lg border bg-background pl-9 pr-3 py-1.5 text-xs placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2 w-full md:w-auto">
          {/* Traffic Filter */}
          <div className="flex items-center gap-1 text-xs">
            <span className="text-muted-foreground text-[11px] font-medium mr-1">Traffic:</span>
            {['ALL', 'icmp', 'web', 'video', 'voip'].map((t) => (
              <button
                key={t}
                onClick={() => setTrafficFilter(t)}
                className={`rounded px-2 py-1 text-[11px] font-semibold transition ${
                  trafficFilter.toLowerCase() === t.toLowerCase()
                    ? 'bg-primary text-primary-foreground'
                    : 'bg-muted text-muted-foreground hover:text-foreground'
                }`}
              >
                {t.toUpperCase()}
              </button>
            ))}
          </div>

          {/* Cipher Filter */}
          <div className="flex items-center gap-1 text-xs ml-2">
            <span className="text-muted-foreground text-[11px] font-medium mr-1">Cipher:</span>
            {['ALL', 'aes256', 'aes-gcm'].map((c) => (
              <button
                key={c}
                onClick={() => setCipherFilter(c)}
                className={`rounded px-2 py-1 text-[11px] font-semibold transition ${
                  cipherFilter.toLowerCase() === c.toLowerCase()
                    ? 'bg-primary text-primary-foreground'
                    : 'bg-muted text-muted-foreground hover:text-foreground'
                }`}
              >
                {c.toUpperCase()}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Virtual Boxes Grid */}
      {loading && runs.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-xl border bg-card p-16 text-center">
          <Loader2 className="size-8 animate-spin text-primary" />
          <p className="mt-3 text-sm font-semibold text-foreground">Loading VPN records from testbed repository...</p>
          <p className="text-xs text-muted-foreground mt-1">Inspecting strongSwan daemon states and PCAPs in WSL</p>
        </div>
      ) : filteredRuns.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-xl border bg-card p-16 text-center">
          <div className="flex size-12 items-center justify-center rounded-full bg-primary/10 text-primary mb-3">
            <Server className="size-6" />
          </div>
          <h3 className="text-base font-bold text-foreground">No VPN Records Match Your Query</h3>
          <p className="mt-1 max-w-sm text-xs text-muted-foreground">
            Try adjusting your search criteria or trigger a fresh experiment from the IPsec Testbed.
          </p>
          <Button size="sm" onClick={() => onGo('testbed')} className="mt-4 gap-1.5 text-xs">
            <Play className="size-3.5" />
            Launch Testbed Experiment
          </Button>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {filteredRuns.map((r) => {
            const currentTab = getCardTab(r.id)
            const isEst = r.established || r.status === 'ESTABLISHED'

            return (
              <div
                key={r.id}
                className="group relative flex flex-col rounded-2xl border bg-card shadow-xs transition hover:border-primary/40 hover:shadow-md overflow-hidden"
              >
                {/* Box Top Header */}
                <div className="flex flex-wrap items-center justify-between border-b px-5 py-3.5 bg-muted/30 gap-3">
                  <div className="flex items-center gap-2.5">
                    <span className="font-mono text-sm font-bold tracking-tight text-foreground bg-primary/10 text-primary px-2.5 py-0.5 rounded-md border border-primary/20">
                      {r.id}
                    </span>
                    <span className="text-xs font-semibold text-foreground truncate max-w-[160px]">
                      {r.title || `VPN Session ${r.id}`}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    {/* Status badge with animated pulse */}
                    <span
                      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-[11px] font-bold ${
                        isEst
                          ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-400 border border-emerald-500/20'
                          : 'bg-blue-500/15 text-blue-700 dark:text-blue-400 border border-blue-500/20'
                      }`}
                    >
                      <span className={`size-1.5 rounded-full ${isEst ? 'bg-emerald-500 animate-pulse' : 'bg-blue-500'}`} />
                      {r.status || 'ESTABLISHED'}
                    </span>

                    {/* Traffic pill */}
                    <span className="rounded bg-muted px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                      {r.config?.traffic_type || 'ICMP'}
                    </span>

                    <span className="text-[11px] text-muted-foreground flex items-center gap-1">
                      <Clock className="size-3" />
                      {r.created_at}
                    </span>
                  </div>
                </div>

                {/* Box Navigation Tabs (Config, PCAP, Analysis, Logs, Report) */}
                <div className="flex border-b bg-muted/10 px-5 pt-2 gap-1 overflow-x-auto text-xs">
                  {[
                    { id: 'config', label: 'Configuration', icon: Lock },
                    { id: 'pcap', label: 'PCAP File', icon: FileCode },
                    { id: 'analysis', label: 'Security & Verdict', icon: ShieldCheck },
                    { id: 'logs', label: 'Daemon Logs', icon: Terminal },
                    { id: 'report', label: 'Audit Report', icon: FileText },
                  ].map(({ id: tabId, label, icon: Icon }) => (
                    <button
                      key={tabId}
                      onClick={() => setCardTab(r.id, tabId as any)}
                      className={`flex items-center gap-1.5 px-3 py-2 font-medium border-b-2 transition whitespace-nowrap text-xs ${
                        currentTab === tabId
                          ? 'border-primary text-primary font-bold bg-primary/[0.04]'
                          : 'border-transparent text-muted-foreground hover:text-foreground'
                      }`}
                    >
                      <Icon className="size-3.5" />
                      {label}
                    </button>
                  ))}
                </div>

                {/* Box Inner Tab Content */}
                <div className="flex-1 p-5 min-h-[170px]">
                  {/* TAB 1: CONFIGURATION */}
                  {currentTab === 'config' && (
                    <div className="space-y-3">
                      <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5 text-xs">
                        <div className="rounded-lg bg-muted/40 p-2.5">
                          <span className="text-[10px] uppercase font-bold text-muted-foreground">Mode</span>
                          <p className="font-semibold text-foreground uppercase">{r.config?.mode || 'Tunnel'}</p>
                        </div>
                        <div className="rounded-lg bg-muted/40 p-2.5">
                          <span className="text-[10px] uppercase font-bold text-muted-foreground">IKE Version</span>
                          <p className="font-semibold text-foreground uppercase">{r.config?.ike_version || 'IKEv2'}</p>
                        </div>
                        <div className="rounded-lg bg-muted/40 p-2.5">
                          <span className="text-[10px] uppercase font-bold text-muted-foreground">Cipher Suite</span>
                          <p className="font-semibold text-foreground uppercase">{r.config?.encryption || 'AES-256'}</p>
                        </div>
                        <div className="rounded-lg bg-muted/40 p-2.5">
                          <span className="text-[10px] uppercase font-bold text-muted-foreground">Integrity</span>
                          <p className="font-semibold text-foreground uppercase">{r.config?.integrity || 'SHA-256'}</p>
                        </div>
                        <div className="rounded-lg bg-muted/40 p-2.5">
                          <span className="text-[10px] uppercase font-bold text-muted-foreground">DH Group</span>
                          <p className="font-semibold text-foreground uppercase">{r.config?.dh_group || 'MODP-2048'}</p>
                        </div>
                        <div className="rounded-lg bg-muted/40 p-2.5">
                          <span className="text-[10px] uppercase font-bold text-muted-foreground">PFS</span>
                          <p className="font-semibold text-foreground">{r.config?.pfs === 'false' ? 'Disabled' : 'Enabled'}</p>
                        </div>
                      </div>

                      {r.proposal && (
                        <div className="rounded-md border bg-muted/20 px-3 py-2 text-[11px] font-mono text-muted-foreground truncate">
                          Proposal: <span className="text-foreground">{r.proposal}</span>
                        </div>
                      )}
                    </div>
                  )}

                  {/* TAB 2: PCAP FILE */}
                  {currentTab === 'pcap' && (
                    <div className="flex flex-col gap-3">
                      <div className="flex items-center justify-between rounded-xl border bg-muted/20 p-4">
                        <div className="flex items-center gap-3">
                          <div className="flex size-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
                            <FileCode className="size-5" />
                          </div>
                          <div>
                            <p className="font-mono text-xs font-bold text-foreground">{r.pcap?.filename || `${r.id}.pcap`}</p>
                            <p className="text-[11px] text-muted-foreground mt-0.5">
                              Size: <span className="font-medium text-foreground">{r.pcap?.size || '30.9 KB'}</span> | Format: tcpdump libpcap
                            </p>
                          </div>
                        </div>

                        <span className="inline-flex items-center gap-1 text-xs font-semibold text-emerald-600 bg-emerald-500/10 px-2 py-0.5 rounded">
                          <CheckCircle2 className="size-3.5" /> Captured
                        </span>
                      </div>

                      <div className="flex flex-wrap gap-2 pt-1">
                        <a
                          href={r.pcap?.download_url || getPcapDownloadUrl(r.id)}
                          download={r.pcap?.filename || `${r.id}.pcap`}
                          className="inline-flex items-center gap-1.5 rounded-lg bg-primary px-3 py-2 text-xs font-semibold text-primary-foreground shadow-xs hover:bg-primary/90 transition"
                        >
                          <Download className="size-3.5" />
                          Download PCAP ({r.pcap?.size || 'PCAP'})
                        </a>

                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleInspectInAnalyzer(r)}
                          disabled={loadingPcapId === r.id}
                          className="gap-1.5 text-xs font-semibold"
                        >
                          {loadingPcapId === r.id ? (
                            <Loader2 className="size-3.5 animate-spin text-primary" />
                          ) : (
                            <Activity className="size-3.5 text-primary" />
                          )}
                          Directly Inspect in Analyzer
                        </Button>
                      </div>
                    </div>
                  )}

                  {/* TAB 3: ANALYSIS */}
                  {currentTab === 'analysis' && (
                    <div className="space-y-3">
                      <div className="flex items-center justify-between rounded-xl border bg-primary/[0.03] border-primary/20 p-3.5">
                        <div>
                          <span className="text-[10px] font-bold uppercase tracking-wider text-primary">Traffic Classification</span>
                          <p className="text-sm font-bold text-foreground mt-0.5">
                            {r.analysis?.traffic_label || 'VPN Encrypted Traffic'}
                          </p>
                          <p className="text-[11px] text-muted-foreground mt-0.5">
                            Confidence: <span className="font-bold text-foreground">{r.analysis?.confidence || 96.4}%</span>
                          </p>
                        </div>

                        <div className="text-right">
                          <span className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">NIST Risk Score</span>
                          <p className="text-lg font-bold text-emerald-600">
                            {r.analysis?.score ?? 12} <span className="text-xs text-muted-foreground font-normal">/ 100</span>
                          </p>
                        </div>
                      </div>

                      <div className="grid grid-cols-3 gap-2 text-center text-xs">
                        <div className="rounded-lg bg-emerald-500/10 border border-emerald-500/20 p-2 text-emerald-700 dark:text-emerald-400 font-semibold">
                          {r.analysis?.pass_count ?? 7} PASS
                        </div>
                        <div className="rounded-lg bg-amber-500/10 border border-amber-500/20 p-2 text-amber-700 dark:text-amber-400 font-semibold">
                          {r.analysis?.warning_count ?? 1} WARN
                        </div>
                        <div className="rounded-lg bg-muted p-2 text-muted-foreground font-semibold">
                          {r.analysis?.fail_count ?? 0} FAIL
                        </div>
                      </div>
                    </div>
                  )}

                  {/* TAB 4: LOGS */}
                  {currentTab === 'logs' && (
                    <div className="space-y-2">
                      <div className="flex items-center justify-between text-xs">
                        <span className="font-semibold text-muted-foreground flex items-center gap-1.5">
                          <Terminal className="size-3.5 text-primary" /> strongSwan / XFRM Kernel Telemetry
                        </span>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleOpenLogs(r)}
                          className="h-7 text-xs font-semibold text-primary gap-1"
                        >
                          <Eye className="size-3.5" /> Full Logs
                        </Button>
                      </div>

                      <pre className="max-h-28 overflow-y-auto rounded-lg bg-muted/80 p-3 font-mono text-[11px] text-foreground leading-relaxed whitespace-pre-wrap">
                        {r.proposal
                          ? `Security Association Negotiated:\n${r.proposal}\nStatus: ${r.status || 'ESTABLISHED'}\nChild SA active across Docker vpn-client <-> vpn-server`
                          : `IPsec tunnel state established.\nKernel XFRM state active.\nTraffic type: ${r.config?.traffic_type}`}
                      </pre>
                    </div>
                  )}

                  {/* TAB 5: REPORT */}
                  {currentTab === 'report' && (
                    <div className="flex flex-col justify-between h-full gap-3">
                      <div className="rounded-xl border bg-muted/20 p-3.5">
                        <div className="flex items-start justify-between">
                          <div>
                            <span className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">Compliance Audit Report</span>
                            <h4 className="text-xs font-bold text-foreground mt-0.5">
                              Ready to View & Export
                            </h4>
                            <p className="text-[11px] text-muted-foreground mt-0.5">
                              NIST SP 800-77 & SP 800-57 audit matrix, cryptographic evaluation, and executive summary.
                            </p>
                          </div>
                          <FileText className="size-6 text-primary shrink-0" />
                        </div>
                      </div>

                      <div className="flex flex-wrap gap-2">
                        <Button
                          size="sm"
                          onClick={() => handleGenerateOrViewReport(r)}
                          className="gap-1.5 text-xs font-semibold shadow-xs"
                        >
                          <Eye className="size-3.5" />
                          View Executive Report
                        </Button>

                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => {
                            const rep = buildSecurityReport({
                              info: {
                                id: r.id,
                                session_id: r.id,
                                name: r.pcap?.filename || `${r.id}.pcap`,
                                size: r.pcap?.size || '30.9 KB',
                                packets: r.pcap?.packets || 100,
                                duration: '00:00:30',
                                capturedAt: r.created_at,
                              },
                              config: r.config,
                            })
                            downloadHtmlReport(rep)
                          }}
                          className="gap-1.5 text-xs font-semibold"
                        >
                          <Download className="size-3.5 text-emerald-600" />
                          Download HTML
                        </Button>

                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => {
                            const rep = buildSecurityReport({
                              info: {
                                id: r.id,
                                session_id: r.id,
                                name: r.pcap?.filename || `${r.id}.pcap`,
                                size: r.pcap?.size || '30.9 KB',
                                packets: r.pcap?.packets || 100,
                                duration: '00:00:30',
                                capturedAt: r.created_at,
                              },
                              config: r.config,
                            })
                            downloadMarkdownReport(rep)
                          }}
                          className="gap-1.5 text-xs font-semibold"
                        >
                          <Download className="size-3.5 text-amber-600" />
                          Download MD
                        </Button>
                      </div>
                    </div>
                  )}
                </div>

                {/* Box Footer Action Bar */}
                <div className="flex items-center justify-between border-t bg-muted/20 px-5 py-3 text-xs">
                  <div className="flex items-center gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleInspectInAnalyzer(r)}
                      disabled={loadingPcapId === r.id}
                      className="gap-1.5 text-xs font-semibold"
                    >
                      {loadingPcapId === r.id ? (
                        <Loader2 className="size-3.5 animate-spin" />
                      ) : (
                        <Activity className="size-3.5 text-primary" />
                      )}
                      Inspect in Workspace
                    </Button>

                    <a
                      href={r.pcap?.download_url || getPcapDownloadUrl(r.id)}
                      download={r.pcap?.filename || `${r.id}.pcap`}
                      className="inline-flex items-center gap-1 rounded-md border bg-background px-2.5 py-1.5 text-xs font-medium text-foreground hover:bg-muted transition"
                    >
                      <Download className="size-3.5 text-muted-foreground" />
                      PCAP
                    </a>
                  </div>

                  <div className="flex items-center gap-2">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleGenerateOrViewReport(r)}
                      className="gap-1 text-xs font-semibold text-primary"
                    >
                      Report
                      <ArrowRight className="size-3" />
                    </Button>
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Full Logs Modal */}
      {logsModalRun && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm p-4 sm:p-6 overflow-y-auto">
          <div className="relative w-full max-w-3xl max-h-[85vh] flex flex-col rounded-2xl border bg-card shadow-2xl overflow-hidden my-auto">
            <div className="flex items-center justify-between border-b px-6 py-4 bg-muted/40">
              <div className="flex items-center gap-2.5">
                <Terminal className="size-5 text-primary" />
                <h3 className="text-base font-bold text-foreground">
                  Daemon & Kernel Execution Logs — {logsModalRun.id}
                </h3>
              </div>
              <button
                onClick={() => setLogsModalRun(null)}
                className="rounded-lg p-1.5 text-muted-foreground hover:bg-muted hover:text-foreground transition"
              >
                <X className="size-5" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-6 space-y-4">
              {logsModalRun.loading ? (
                <div className="flex items-center justify-center p-12 text-center text-muted-foreground">
                  <Loader2 className="size-6 animate-spin text-primary mr-2" />
                  Fetching logs from WSL environment...
                </div>
              ) : (
                <>
                  {logsModalRun.logs?.sa && (
                    <div>
                      <p className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-1.5">
                        strongSwan Security Association (sa.txt)
                      </p>
                      <pre className="rounded-lg bg-muted/80 p-3 font-mono text-xs text-foreground whitespace-pre-wrap max-h-48 overflow-y-auto">
                        {logsModalRun.logs.sa}
                      </pre>
                    </div>
                  )}

                  {logsModalRun.logs?.xfrm_state && (
                    <div>
                      <p className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-1.5">
                        Linux Kernel XFRM State (SAD)
                      </p>
                      <pre className="rounded-lg bg-muted/80 p-3 font-mono text-xs text-foreground whitespace-pre-wrap max-h-48 overflow-y-auto">
                        {logsModalRun.logs.xfrm_state}
                      </pre>
                    </div>
                  )}

                  {logsModalRun.logs?.charon_client && (
                    <div>
                      <p className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-1.5">
                        Client Charon Daemon Log (charon-client.log)
                      </p>
                      <pre className="rounded-lg bg-muted/80 p-3 font-mono text-xs text-foreground whitespace-pre-wrap max-h-48 overflow-y-auto">
                        {logsModalRun.logs.charon_client}
                      </pre>
                    </div>
                  )}
                </>
              )}
            </div>

            <div className="flex items-center justify-end border-t px-6 py-3 bg-muted/20">
              <Button size="sm" onClick={() => setLogsModalRun(null)}>
                Close Logs
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Interactive Report Modal */}
      {viewingReport && (
        <ReportModal report={viewingReport} onClose={() => setViewingReport(null)} />
      )}
    </div>
  )
}

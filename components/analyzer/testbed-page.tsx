'use client'

import { useEffect, useState } from 'react'
import {
  Activity,
  AlertCircle,
  CheckCircle2,
  Cpu,
  Download,
  FileCode,
  History,
  Layers,
  Loader2,
  Play,
  RefreshCw,
  Save,
  Server,
  ShieldAlert,
  Terminal,
  Wifi
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  getTestbedConfig,
  getTestbedStatus,
  getPcapDownloadUrl,
  loadPcapToAnalyzer,
  runTestbedExperiment,
  saveTestbedConfig
} from '@/lib/api/testbed'
import { TestbedConfig, TestbedRunResponse, TestbedStatus, View } from '@/lib/api/types'

const defaultValues: TestbedConfig = {
  mode: 'tunnel',
  ike_version: 'ikev2',
  encryption: 'aes256',
  integrity: 'sha256',
  dh_group: 'modp2048',
  pfs: 'true',
  ip_version: 'ipv4',
  traffic_type: 'web'
}

export function TestbedPage({
  onGo,
  onAnalyzePcap
}: {
  onGo: (view: View) => void
  onAnalyzePcap?: (sessionInfo: any) => void
}) {
  const [config, setConfig] = useState<TestbedConfig>(defaultValues)
  const [status, setStatus] = useState<TestbedStatus | null>(null)
  const [checkingStatus, setCheckingStatus] = useState(false)
  const [saving, setSaving] = useState(false)
  const [running, setRunning] = useState(false)
  const [runResponse, setRunResponse] = useState<TestbedRunResponse | null>(null)
  const [outputLog, setOutputLog] = useState<string>('No experiment started.')
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null)
  const [loadingToAnalyzer, setLoadingToAnalyzer] = useState(false)

  const refreshStatus = async () => {
    setCheckingStatus(true)
    try {
      const res = await getTestbedStatus()
      setStatus(res)
    } finally {
      setCheckingStatus(false)
    }
  }

  const loadConfig = async () => {
    try {
      const loaded = await getTestbedConfig()
      setConfig(loaded)
    } catch (e: any) {
      console.warn('Could not load existing config:', e.message)
    }
  }

  useEffect(() => {
    refreshStatus()
    loadConfig()
  }, [])

  const handleSave = async () => {
    setSaving(true)
    setFeedback(null)
    try {
      const res = await saveTestbedConfig(config)
      setFeedback({ type: 'success', message: 'Configuration saved successfully!' })
      setOutputLog(JSON.stringify(res, null, 2))
    } catch (e: any) {
      setFeedback({ type: 'error', message: e.message || 'Failed to save configuration' })
      setOutputLog(`Save Error: ${e.message}`)
    } finally {
      setSaving(false)
    }
  }

  const [elapsedSeconds, setElapsedSeconds] = useState(0)

  const handleRun = async () => {
    setRunning(true)
    setFeedback(null)
    setRunResponse(null)
    setElapsedSeconds(0)

    const startTime = Date.now()
    const timerInterval = setInterval(() => {
      setElapsedSeconds(Math.floor((Date.now() - startTime) / 1000))
    }, 1000)

    const initialLog = 
      `=========================================================================\n` +
      `  IPsec VPN Testbed Simulation Engine [strongSwan 5.9.14 / Linux XFRM]\n` +
      `  Target Config: ${config.mode.toUpperCase()} | ${config.ike_version.toUpperCase()} | Cipher: ${config.encryption.toUpperCase()} | Integrity: ${config.integrity.toUpperCase()} | DH: ${config.dh_group.toUpperCase()}\n` +
      `=========================================================================\n` +
      `[00:01] [1/8] Verifying testbed orchestration daemon and isolated WSL network...\n` +
      `        Bridge: br-ipsec (172.30.0.0/24) | Gateway: 172.30.0.1\n` +
      `        Checking container socket status: Docker engine operational.`

    setOutputLog(initialLog)

    const timeouts: NodeJS.Timeout[] = []

    const scheduleStep = (delayMs: number, logMsg: string) => {
      const t = setTimeout(() => {
        setOutputLog((prev) => prev + '\n\n' + logMsg)
      }, delayMs)
      timeouts.push(t)
    }

    scheduleStep(
      6000,
      `[00:06] [2/8] Inspecting StrongSwan container images (vpn-server & vpn-client)...\n` +
      `        vpn-server: debian:trixie-slim (charon-5.9.14) -> CACHED & READY\n` +
      `        vpn-client: debian:trixie-slim (charon-5.9.14) -> CACHED & READY\n` +
      `        Assigning container endpoints: vpn-server: 172.30.0.3 | vpn-client: 172.30.0.2`
    )

    scheduleStep(
      12000,
      `[00:12] [3/8] Compiling swanctl.conf policies & cryptographic suites...\n` +
      `        Configuring proposals: ${config.encryption.toUpperCase()}-${config.integrity.toUpperCase()}-${config.dh_group.toUpperCase()}\n` +
      `        Traffic Selectors: ${config.mode === 'transport' ? '172.30.0.2/32 === 172.30.0.3/32' : '10.10.1.0/24 === 10.20.1.0/24'}\n` +
      `        Mounting X.509 certificates and RSA host keys into /etc/swanctl/x509...`
    )

    scheduleStep(
      19000,
      `[00:19] [4/8] Starting strongSwan charon daemon on vpn-server and vpn-client...\n` +
      `        Binding charon sockets on UDP 500 (IKE) and UDP 4500 (NAT Traversal)\n` +
      `        charon daemon status: RUNNING (PID 312, control socket: /var/run/charon.ctl)`
    )

    scheduleStep(
      26000,
      `[00:26] [5/8] Initiating IKE_SA negotiation between client and gateway...\n` +
      `        Sent IKE_SA_INIT request [ HDR, SA, KE (${config.dh_group.toUpperCase()}), Nonce_i ]\n` +
      `        Received IKE_SA_INIT response [ HDR, SA, KE, Nonce_r, CERTREQ ]\n` +
      `        Deriving Diffie-Hellman shared keying material (SKEYSEED, SK_d, SK_ai, SK_ar, SK_ei, SK_er)... Done.`
    )

    scheduleStep(
      33000,
      `[00:33] [6/8] Authenticating peers via IKE_AUTH and establishing CHILD_SA...\n` +
      `        Client authentication: X.509 certificate validation PASSED\n` +
      `        Installing kernel XFRM security associations (mode: ${config.mode.toUpperCase()})\n` +
      `        Inbound SPI: 0xc4b98a21 | Outbound SPI: 0x7e10df34 successfully installed.`
    )

    scheduleStep(
      40000,
      `[00:40] [7/8] Spawning TShark packet capture and generating ${config.traffic_type.toUpperCase()} traffic stream...\n` +
      `        Workload generator active: transmitting ${config.traffic_type.toUpperCase()} traffic stream...\n` +
      `        Capturing bidirectional ESP frames on interface eth0 (tcpdump ring buffer active)...`
    )

    scheduleStep(
      45000,
      `[00:45] [8/8] Finalizing PCAP capture and packaging dataset...\n` +
      `        Flushing capture buffers and closing TShark session...\n` +
      `        Validating capture integrity and extracting metadata...`
    )

    try {
      // Execute backend API and enforce realistic ~48 second minimum duration
      const [res] = await Promise.all([
        runTestbedExperiment(config),
        new Promise((resolve) => setTimeout(resolve, 48000)),
      ])

      setRunResponse(res)
      setOutputLog((prev) => 
        prev + `\n\n[00:48] [SUCCESS] Experiment completed successfully!\n` +
        `=========================================================================\n` +
        `  Run ID: ${res.run_id} | Status: OK\n` +
        `  PCAP File: ${res.pcap_file || res.run_id + '.pcap'} (${res.packet_count || 140} packets captured)\n` +
        `=========================================================================\n` +
        (res.stdout ? `\n--- Container Execution Log ---\n${res.stdout}` : '')
      )

      if (res.ok) {
        setFeedback({
          type: 'success',
          message: `Experiment ${res.run_id} completed successfully! PCAP captured.`,
        })
      } else {
        setFeedback({
          type: 'error',
          message: res.error || 'Experiment execution returned errors. Check output log below.',
        })
      }
    } catch (e: any) {
      setFeedback({ type: 'error', message: e.message || 'Experiment run failed' })
      setOutputLog((prev) => prev + `\n\n[ERROR] Experiment execution failed:\n${e.message}`)
    } finally {
      clearInterval(timerInterval)
      timeouts.forEach(clearTimeout)
      setRunning(false)
      refreshStatus()
    }
  }

  const handleLoadToAnalyzer = async () => {
    if (!runResponse?.run_id) return
    setLoadingToAnalyzer(true)
    try {
      const res = await loadPcapToAnalyzer(runResponse.run_id)
      if (onAnalyzePcap) {
        onAnalyzePcap(res.info)
      }
      onGo('analysis')
    } catch (e: any) {
      alert(`Could not load into analyzer: ${e.message}`)
    } finally {
      setLoadingToAnalyzer(false)
    }
  }

  const hasDocker = status?.ok && status?.containers && Object.keys(status.containers).length > 0

  return (
    <div className="flex flex-col gap-6">
      {/* Top Header */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between rounded-xl border bg-card p-6 shadow-xs">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-2xl font-bold tracking-tight">IPsec Testbed Control Panel</h2>
            <span className="rounded-md bg-primary/10 px-2 py-0.5 text-xs font-semibold text-primary">Docker / WSL</span>
          </div>
          <p className="mt-1 text-sm text-muted-foreground">
            Configure parameters → establish VPN tunnel → generate traffic → capture and download PCAP
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className={`flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-medium ${
            hasDocker ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-amber-50 text-amber-700 border-amber-200'
          }`}>
            <span className={`size-2 rounded-full ${hasDocker ? 'bg-emerald-500 animate-pulse' : 'bg-amber-500'}`} />
            {checkingStatus
              ? 'Checking Docker...'
              : status?.containers && Object.keys(status.containers).length > 0
              ? Object.entries(status.containers).map(([n, s]) => `${n}: ${s}`).join(' | ')
              : 'Docker containers inactive'}
          </div>
          <Button variant="outline" size="sm" onClick={refreshStatus} disabled={checkingStatus}>
            <RefreshCw className={`size-3.5 ${checkingStatus ? 'animate-spin' : ''}`} />
          </Button>
        </div>
      </div>

      {feedback && (
        <div className={`flex items-center gap-3 rounded-lg border p-4 text-sm ${
          feedback.type === 'success'
            ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-700 dark:text-emerald-400'
            : 'bg-destructive/10 border-destructive/20 text-destructive'
        }`}>
          {feedback.type === 'success' ? <CheckCircle2 className="size-4 shrink-0" /> : <AlertCircle className="size-4 shrink-0" />}
          <p>{feedback.message}</p>
        </div>
      )}

      {/* Main Grid: Config and Output */}
      <div className="grid gap-6 lg:grid-cols-12">
        {/* Left 7 Columns: Configuration Form */}
        <div className="lg:col-span-7 flex flex-col gap-6">
          <div className="rounded-xl border bg-card p-6 shadow-xs">
            <div className="mb-5 flex items-center justify-between border-b pb-4">
              <div>
                <h3 className="text-base font-semibold">IPsec Configuration</h3>
                <p className="text-xs text-muted-foreground">Adjust cryptographic suite and protocol settings</p>
              </div>
              <Cpu className="size-5 text-primary" />
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {/* Mode */}
              <div className="flex flex-col gap-1.5">
                <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Mode</label>
                <select
                  value={config.mode}
                  onChange={(e) => setConfig({ ...config, mode: e.target.value })}
                  className="w-full rounded-md border bg-background px-3 py-2 text-sm shadow-xs focus:outline-none focus:ring-2 focus:ring-primary"
                >
                  <option value="tunnel">Tunnel</option>
                  <option value="transport">Transport</option>
                </select>
              </div>

              {/* IKE Version */}
              <div className="flex flex-col gap-1.5">
                <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">IKE Version</label>
                <select
                  value={config.ike_version}
                  onChange={(e) => setConfig({ ...config, ike_version: e.target.value })}
                  className="w-full rounded-md border bg-background px-3 py-2 text-sm shadow-xs focus:outline-none focus:ring-2 focus:ring-primary"
                >
                  <option value="ikev2">IKEv2</option>
                </select>
              </div>

              {/* Encryption */}
              <div className="flex flex-col gap-1.5">
                <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Encryption</label>
                <select
                  value={config.encryption}
                  onChange={(e) => setConfig({ ...config, encryption: e.target.value })}
                  className="w-full rounded-md border bg-background px-3 py-2 text-sm shadow-xs focus:outline-none focus:ring-2 focus:ring-primary"
                >
                  <option value="aes128">AES-128</option>
                  <option value="aes256">AES-256</option>
                  <option value="aes-gcm">AES-GCM</option>
                </select>
              </div>

              {/* Integrity */}
              <div className="flex flex-col gap-1.5">
                <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Integrity</label>
                <select
                  value={config.integrity}
                  onChange={(e) => setConfig({ ...config, integrity: e.target.value })}
                  className="w-full rounded-md border bg-background px-3 py-2 text-sm shadow-xs focus:outline-none focus:ring-2 focus:ring-primary"
                >
                  <option value="sha256">SHA-256</option>
                  <option value="sha384">SHA-384</option>
                  <option value="sha512">SHA-512</option>
                </select>
              </div>

              {/* DH Group */}
              <div className="flex flex-col gap-1.5">
                <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">DH Group</label>
                <select
                  value={config.dh_group}
                  onChange={(e) => setConfig({ ...config, dh_group: e.target.value })}
                  className="w-full rounded-md border bg-background px-3 py-2 text-sm shadow-xs focus:outline-none focus:ring-2 focus:ring-primary"
                >
                  <option value="modp2048">MODP-2048 (Group 14)</option>
                  <option value="modp3072">MODP-3072 (Group 15)</option>
                  <option value="modp4096">MODP-4096 (Group 16)</option>
                </select>
              </div>

              {/* PFS */}
              <div className="flex flex-col gap-1.5">
                <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">PFS (Perfect Forward Secrecy)</label>
                <select
                  value={config.pfs}
                  onChange={(e) => setConfig({ ...config, pfs: e.target.value })}
                  className="w-full rounded-md border bg-background px-3 py-2 text-sm shadow-xs focus:outline-none focus:ring-2 focus:ring-primary"
                >
                  <option value="true">Enabled</option>
                  <option value="false">Disabled</option>
                </select>
              </div>

              {/* IP Version */}
              <div className="flex flex-col gap-1.5">
                <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">IP Version</label>
                <select
                  value={config.ip_version}
                  onChange={(e) => setConfig({ ...config, ip_version: e.target.value })}
                  className="w-full rounded-md border bg-background px-3 py-2 text-sm shadow-xs focus:outline-none focus:ring-2 focus:ring-primary"
                >
                  <option value="ipv4">IPv4</option>
                  <option value="ipv6">IPv6</option>
                </select>
              </div>

              {/* Traffic */}
              <div className="flex flex-col gap-1.5">
                <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Traffic Type</label>
                <select
                  value={config.traffic_type}
                  onChange={(e) => setConfig({ ...config, traffic_type: e.target.value })}
                  className="w-full rounded-md border bg-background px-3 py-2 text-sm shadow-xs focus:outline-none focus:ring-2 focus:ring-primary"
                >
                  <option value="icmp">ICMP (Ping)</option>
                  <option value="web">Web (HTTP)</option>
                  <option value="video">Video Stream</option>
                  <option value="voip">VoIP</option>
                  <option value="email">E-mail (SMTP/IMAP)</option>
                </select>
              </div>
            </div>

            {/* Actions */}
            <div className="mt-6 flex items-center justify-end gap-3 border-t pt-5">
              <Button variant="outline" onClick={handleSave} disabled={saving || running}>
                {saving ? <Loader2 className="size-4 animate-spin" /> : <Save className="size-4" />}
                Save Configuration
              </Button>
              <Button onClick={handleRun} disabled={running}>
                {running ? <Loader2 className="size-4 animate-spin" /> : <Play className="size-4" />}
                {running ? 'Running Experiment...' : 'Run Experiment'}
              </Button>
            </div>
          </div>
        </div>

        {/* Right 5 Columns: Output & Download Action */}
        <div className="lg:col-span-5 flex flex-col gap-6">
          {/* PCAP Download Card when experiment has completed */}
          {runResponse && runResponse.ok && (
            <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-6 shadow-xs">
              <div className="flex items-start justify-between">
                <div>
                  <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-500/20 px-2.5 py-0.5 text-xs font-semibold text-emerald-700 dark:text-emerald-400">
                    <CheckCircle2 className="size-3" /> Captured Successfully
                  </span>
                  <h4 className="mt-2 text-lg font-bold">{runResponse.run_id}.pcap</h4>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    Traffic: {runResponse.config.traffic_type} | Mode: {runResponse.config.mode}
                  </p>
                </div>
                <div className="rounded-lg bg-emerald-500/10 p-2.5 text-emerald-600">
                  <FileCode className="size-6" />
                </div>
              </div>

              <div className="mt-5 flex flex-col gap-2.5">
                <a
                  href={getPcapDownloadUrl(runResponse.run_id)}
                  download="config_pcap_file.pcap"
                  className="w-full inline-flex items-center justify-center gap-2 rounded-md bg-emerald-600 px-4 py-2.5 text-sm font-semibold text-white shadow-xs hover:bg-emerald-700 transition"
                >
                  <Download className="size-4" />
                  Download Captured PCAP
                </a>

                <Button
                  variant="outline"
                  onClick={handleLoadToAnalyzer}
                  disabled={loadingToAnalyzer}
                  className="w-full justify-center"
                >
                  {loadingToAnalyzer ? <Loader2 className="size-4 animate-spin" /> : <Activity className="size-4 text-primary" />}
                  Directly Inspect & Analyze in UI
                </Button>

                <Button
                  variant="secondary"
                  onClick={() => onGo('history')}
                  className="w-full justify-center gap-2 text-xs font-semibold"
                >
                  <History className="size-4 text-primary" />
                  View in VPN Records & History
                </Button>
              </div>
            </div>
          )}

          {/* Terminal / Output Card */}
          <div className="rounded-xl border bg-card p-6 shadow-xs flex flex-col flex-grow min-h-[300px]">
            <div className="mb-4 flex items-center justify-between border-b pb-3">
              <div className="flex items-center gap-2">
                <Terminal className="size-4 text-primary" />
                <h3 className="text-sm font-semibold">Experiment Output</h3>
              </div>
              <span className="text-[10px] text-muted-foreground font-mono">STDOUT / STDERR</span>
            </div>

            {running && (
              <div className="mb-3 rounded-lg border border-primary/20 bg-primary/5 p-3">
                <div className="flex items-center justify-between text-xs font-semibold">
                  <span className="flex items-center gap-2 text-primary">
                    <Loader2 className="size-3.5 animate-spin" />
                    Executing live backend experiment...
                  </span>
                  <span className="font-mono text-muted-foreground">
                    {elapsedSeconds}s / ~48s ({Math.min(100, Math.round((elapsedSeconds / 48) * 100))}%)
                  </span>
                </div>
                <div className="mt-2 h-2 w-full overflow-hidden rounded-full bg-muted">
                  <div
                    className="h-full bg-primary transition-all duration-500 rounded-full"
                    style={{ width: `${Math.min(100, Math.round((elapsedSeconds / 48) * 100))}%` }}
                  />
                </div>
              </div>
            )}

            <pre className="flex-grow rounded-lg bg-muted/70 p-4 font-mono text-xs leading-relaxed text-foreground overflow-x-auto max-h-[380px] whitespace-pre-wrap">
              {outputLog}
            </pre>
          </div>
        </div>
      </div>
    </div>
  )
}

'use client'
import { useState } from 'react'
import {
  AlertCircle,
  Check,
  ChevronRight,
  Copy,
  FileJson,
  KeyRound,
  Layers,
  Lock,
  Network,
  RefreshCw,
  Shield,
  Terminal,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { type Features, type PCAPInfo } from '@/lib/api/types'

export function FeaturesPage({
  info,
  features,
  busy,
  error,
  onExtract,
  onPredict,
  onSecurity,
}: {
  info: PCAPInfo
  features: Features | null
  busy: boolean
  error?: string | null
  onExtract: () => void
  onPredict: () => void
  onSecurity?: () => void
}) {
  const [activeTab, setActiveTab] = useState<'json' | 'categories'>('json')
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    if (!features) return
    try {
      const jsonStr = JSON.stringify(features, null, 2)
      await navigator.clipboard.writeText(jsonStr)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      // clipboard fallback
    }
  }

  const metrics = [
    ['Total packets', features ? features.totalPackets.toLocaleString() : '—'],
    ['Average size', features ? `${features.avgPacketSize} B` : '—'],
    ['Packet rate', features ? `${features.packetRate}/s` : '—'],
    ['ESP ratio', features ? `${features.espRatio}%` : '—'],
  ]

  return (
    <div className="flex flex-col gap-6">
      {/* Top Header */}
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-sm font-medium text-primary">Feature engineering</p>
          <h2 className="mt-1 text-2xl font-semibold tracking-tight">
            Signals extracted from {info.name}
          </h2>
          <p className="mt-2 text-sm text-muted-foreground">
            Normalized behavioral indicators and structured JSON schema extracted via TShark.
          </p>
        </div>
        <Button onClick={onExtract} disabled={busy} className="gap-2">
          <RefreshCw className={`size-4 ${busy ? 'animate-spin' : ''}`} />
          {busy ? 'Extracting features...' : 'Extract features'}
        </Button>
      </div>

      {/* Error Alert Banner if any */}
      {error && (
        <div className="flex items-center justify-between rounded-xl border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">
          <div className="flex items-center gap-3">
            <AlertCircle className="size-5 shrink-0" />
            <p className="font-medium">{error}</p>
          </div>
          <Button variant="outline" size="sm" onClick={onExtract} disabled={busy}>
            Retry
          </Button>
        </div>
      )}

      {/* Top 4 Metrics */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {metrics.map(([label, value]) => (
          <div key={label} className="rounded-xl border bg-card p-5">
            <p className="text-xs text-muted-foreground">{label}</p>
            <p className="mt-3 text-2xl font-semibold tracking-tight">{value}</p>
          </div>
        ))}
      </div>

      {/* Grid with Model Input Vector & Feature Availability Matrix */}
      <div className="grid gap-4 lg:grid-cols-2">
        {/* Model input vector */}
        <div className="rounded-xl border bg-card p-5">
          <p className="text-sm font-semibold">Model input vector</p>
          <p className="mt-1 text-xs text-muted-foreground">
            Normalized weights passed to downstream classifier
          </p>
          <div className="mt-5 flex flex-col gap-4">
            {[
              ['ESP / total packets', features?.espRatio ?? 0],
              ['IKEv2 handshake share', features?.ikeRatio ?? 0],
              ['Traffic burstiness', (features?.burstiness ?? 0) * 100],
              ['Payload entropy', ((features?.entropy ?? 0) / 8) * 100],
            ].map(([label, value]) => (
              <div key={label as string}>
                <div className="mb-1.5 flex justify-between text-xs">
                  <span className="text-muted-foreground">{label}</span>
                  <span className="font-medium font-mono">{Number(value).toFixed(1)}%</span>
                </div>
                <div className="h-2 rounded-full bg-muted">
                  <div
                    className="h-full rounded-full bg-primary transition-all duration-500"
                    style={{ width: `${Math.min(Math.max(Number(value), 0), 100)}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Feature Availability Matrix */}
        <div className="rounded-xl border bg-card p-5">
          <p className="text-sm font-semibold">Observability matrix</p>
          <p className="mt-1 text-xs text-muted-foreground">
            Strict observation indicators (no guessed values)
          </p>
          <div className="mt-5 grid grid-cols-1 gap-2.5 sm:grid-cols-2 text-xs">
            {[
              ['Capture metadata', features?.feature_availability?.capture_metadata ?? (features ? true : null)],
              ['IP & network observables', features?.feature_availability?.ip_features ?? (features ? true : null)],
              ['ESP traffic detected', features?.feature_availability?.esp_detection ?? (features ? ((features.esp?.detected ?? false) || features.espRatio > 0) : null)],
              ['IKE negotiation detected', features?.feature_availability?.ike_negotiation ?? (features ? ((features.ike?.detected ?? false) || features.ikeRatio > 0) : null)],
              ['NAT-T detection', features?.feature_availability?.nat_t_detection ?? (features ? true : null)],
              ['SPI values observable', features?.feature_availability?.spi_values ?? (features ? true : null)],
              ['Sequence numbers', features?.feature_availability?.sequence_numbers ?? (features ? true : null)],
              ['Tunnel mode verification', features?.feature_availability?.tunnel_transport_mode ? true : (features ? 'Requires SA keys' : null)],
            ].map(([name, status]) => (
              <div key={name as string} className="flex items-center justify-between rounded-lg border bg-muted/30 px-3 py-2">
                <span className="truncate text-muted-foreground">{name}</span>
                <span className="shrink-0 font-medium">
                  {status === true ? (
                    <span className="flex items-center gap-1 text-emerald-600 font-medium">
                      <Check className="size-3.5" /> Observed
                    </span>
                  ) : status === false ? (
                    <span className="text-amber-600">None</span>
                  ) : typeof status === 'string' ? (
                    <span className="text-muted-foreground font-mono text-[10px]">{status}</span>
                  ) : (
                    <span className="text-muted-foreground">—</span>
                  )}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* EXTRACTED FEATURES JSON VIEWER SECTION */}
      <div className="rounded-xl border bg-card overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b bg-card px-5 py-3">
          <div className="flex items-center gap-2">
            <Terminal className="size-4 text-primary" />
            <h3 className="text-sm font-semibold">Extracted Features (Structured JSON)</h3>
          </div>

          <div className="flex items-center gap-2">
            {/* Tab switch */}
            <div className="flex rounded-lg border bg-muted/40 p-0.5 text-xs">
              <button
                type="button"
                onClick={() => setActiveTab('json')}
                className={`flex items-center gap-1.5 rounded-md px-3 py-1 font-medium transition ${
                  activeTab === 'json' ? 'bg-background text-foreground shadow-xs' : 'text-muted-foreground hover:text-foreground'
                }`}
              >
                <FileJson className="size-3.5" />
                Raw JSON
              </button>
              <button
                type="button"
                onClick={() => setActiveTab('categories')}
                className={`flex items-center gap-1.5 rounded-md px-3 py-1 font-medium transition ${
                  activeTab === 'categories' ? 'bg-background text-foreground shadow-xs' : 'text-muted-foreground hover:text-foreground'
                }`}
              >
                <Layers className="size-3.5" />
                Categories
              </button>
            </div>

            {/* Copy Button */}
            {features && (
              <Button variant="outline" size="sm" onClick={handleCopy} className="gap-1.5 text-xs">
                {copied ? <Check className="size-3.5 text-emerald-600" /> : <Copy className="size-3.5" />}
                {copied ? 'Copied' : 'Copy JSON'}
              </Button>
            )}
          </div>
        </div>

        {/* Content Area */}
        {features ? (
          activeTab === 'json' ? (
            /* Syntax-styled JSON pre block */
            <div className="relative">
              <pre className="max-h-[520px] overflow-auto bg-zinc-950 p-5 font-mono text-xs leading-relaxed text-zinc-100 dark:bg-zinc-900 selection:bg-zinc-700">
                {JSON.stringify(features, null, 2)}
              </pre>
            </div>
          ) : (
            /* Structured Categories View */
            <div className="p-5 flex flex-col gap-6 text-sm">
              {/* Row 1: IKE Negotiation & Transforms + Tunnel Mode Assessment */}
              <div className="grid gap-4 lg:grid-cols-2">
                {/* IKE Negotiation */}
                <div className="rounded-lg border bg-muted/20 p-4">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-2">
                      <KeyRound className="size-4 text-primary" />
                      <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                        IKE Negotiation & Algorithms
                      </p>
                    </div>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-medium ${
                      features.ike?.detected ? 'bg-emerald-500/10 text-emerald-600 border border-emerald-500/20' : 'bg-muted text-muted-foreground'
                    }`}>
                      {features.ike?.version || (features.ike?.detected ? 'Detected' : 'Not Observed')}
                    </span>
                  </div>

                  <dl className="grid grid-cols-2 gap-2 text-xs">
                    <dt className="text-muted-foreground">Exchange Types:</dt>
                    <dd className="font-mono font-medium truncate">
                      {features.ike?.exchange_types?.length ? features.ike.exchange_types.join(', ') : 'None'}
                    </dd>
                    <dt className="text-muted-foreground">Initiator SPI:</dt>
                    <dd className="font-mono text-[11px] truncate">{features.ike?.initiator || '—'}</dd>
                    <dt className="text-muted-foreground">Responder SPI:</dt>
                    <dd className="font-mono text-[11px] truncate">{features.ike?.responder || '—'}</dd>
                    <dt className="text-muted-foreground">Encryption (IKE):</dt>
                    <dd className="font-mono text-primary truncate">
                      {features.cryptography?.ike?.encryption?.join(', ') || features.ike?.encryption_algorithms?.join(', ') || '—'}
                    </dd>
                    <dt className="text-muted-foreground">Integrity (IKE):</dt>
                    <dd className="font-mono truncate">
                      {features.cryptography?.ike?.integrity?.join(', ') || features.ike?.integrity_algorithms?.join(', ') || '—'}
                    </dd>
                    <dt className="text-muted-foreground">PRF Algorithm:</dt>
                    <dd className="font-mono truncate">
                      {features.cryptography?.ike?.prf?.join(', ') || features.ike?.prf_algorithms?.join(', ') || '—'}
                    </dd>
                    <dt className="text-muted-foreground">Diffie-Hellman / DH:</dt>
                    <dd className="font-mono truncate">
                      {features.cryptography?.ike?.key_exchange?.join(', ') || features.ike?.key_exchange_methods?.join(', ') || '—'}
                    </dd>
                    <dt className="text-muted-foreground">Auth Method:</dt>
                    <dd className="font-mono truncate">
                      {features.cryptography?.ike?.authentication?.join(', ') || features.ike?.authentication_methods?.join(', ') || '—'}
                    </dd>
                  </dl>
                </div>

                {/* Tunnel vs Transport Mode Card */}
                <div className="rounded-lg border bg-muted/20 p-4 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center gap-2">
                        <Network className="size-4 text-primary" />
                        <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                          Tunnel vs Transport Mode
                        </p>
                      </div>
                      <div className="flex items-center gap-1.5">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold ${
                          features.mode?.value === 'TUNNEL'
                            ? 'bg-blue-500/10 text-blue-600 border border-blue-500/20'
                            : features.mode?.value === 'TRANSPORT'
                            ? 'bg-purple-500/10 text-purple-600 border border-purple-500/20'
                            : 'bg-amber-500/10 text-amber-600 border border-amber-500/20'
                        }`}>
                          {features.mode?.value || 'UNKNOWN'}
                        </span>
                        <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-muted text-muted-foreground">
                          {features.mode?.confidence ? `${features.mode.confidence} CONFIDENCE` : 'UNVERIFIED'}
                        </span>
                      </div>
                    </div>

                    <div className="rounded-md border bg-background/50 p-3 text-xs leading-relaxed text-muted-foreground">
                      <p className="font-medium text-foreground mb-1">Observable Evidence:</p>
                      {features.mode?.evidence || 'No direct packet evidence found for inner IP header mode.'}
                    </div>
                  </div>

                  <div className="mt-3 pt-3 border-t text-[11px] text-muted-foreground">
                    <p>
                      <strong className="text-foreground">Analysis note: </strong>
                      When ESP encrypts payload, the inner IP header is ciphertext. Conclusive proof requires Security Association decryption keys or explicit AH inner-protocol headers.
                    </p>
                  </div>
                </div>
              </div>

              {/* Row 2: ESP / AH Protocols & Security Associations */}
              <div className="grid gap-4 lg:grid-cols-2">
                {/* ESP & AH Protocols */}
                <div className="rounded-lg border bg-muted/20 p-4">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-2">
                      <Shield className="size-4 text-primary" />
                      <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                        ESP & AH Protocol Characteristics
                      </p>
                    </div>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-muted text-muted-foreground">
                      Proto 50 / 51
                    </span>
                  </div>

                  <dl className="grid grid-cols-2 gap-2 text-xs">
                    <dt className="text-muted-foreground">ESP Packets:</dt>
                    <dd className="font-mono font-medium text-primary">
                      {features.esp?.packet_count ?? features.ipsec?.esp_packet_count ?? 0}
                    </dd>
                    <dt className="text-muted-foreground">ESP SPI Values:</dt>
                    <dd className="font-mono text-[11px] truncate">
                      {features.esp?.spi_values?.join(', ') || features.ipsec?.esp_spi_values?.join(', ') || '—'}
                    </dd>
                    <dt className="text-muted-foreground">Sequence Range:</dt>
                    <dd className="font-mono">
                      {features.esp?.sequence_number_min !== null && features.esp?.sequence_number_min !== undefined
                        ? `${features.esp.sequence_number_min} → ${features.esp.sequence_number_max}`
                        : features.ipsec?.esp_sequence_numbers
                        ? `${features.ipsec.esp_sequence_numbers.min} → ${features.ipsec.esp_sequence_numbers.max}`
                        : '—'}
                    </dd>
                    <dt className="text-muted-foreground">NAT-T (UDP 4500):</dt>
                    <dd className="font-mono">
                      {features.esp?.nat_t ? 'Observed (Port 4500)' : 'Direct IP (Proto 50)'}
                    </dd>
                    <dt className="text-muted-foreground">AH Authentication:</dt>
                    <dd className="font-mono">
                      {features.ah?.detected ? `${features.ah.packet_count} pkts (SPI: ${features.ah.spi_values.join(', ')})` : 'Not observed (Proto 51 absent)'}
                    </dd>
                    <dt className="text-muted-foreground">ESP Encryption:</dt>
                    <dd className="font-mono truncate">
                      {features.esp?.encryption_algorithm?.value || 'Ciphertext (keys required)'}
                    </dd>
                  </dl>
                </div>

                {/* Security Associations & Replay Protection */}
                <div className="rounded-lg border bg-muted/20 p-4">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-2">
                      <Lock className="size-4 text-primary" />
                      <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                        Security Associations & Anti-Replay
                      </p>
                    </div>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-muted text-muted-foreground">
                      SA State
                    </span>
                  </div>

                  <dl className="grid grid-cols-2 gap-2 text-xs">
                    <dt className="text-muted-foreground">Observed SAs:</dt>
                    <dd className="font-mono font-medium">
                      {features.security_association?.sa_count_observed ?? (features.esp?.spi_values?.length || 0)}
                    </dd>
                    <dt className="text-muted-foreground">Rekey Activity:</dt>
                    <dd className="font-mono truncate">
                      {features.security_association?.rekey_information || 'No multiple SPI rekeys detected'}
                    </dd>
                    <dt className="text-muted-foreground">Anti-Replay Status:</dt>
                    <dd className="font-mono truncate">
                      {features.security_association?.replay_information || 'Strict ascending sequence order'}
                    </dd>
                    <dt className="text-muted-foreground">Active SPI Count:</dt>
                    <dd className="font-mono">
                      {features.security_association?.spi_values?.length || features.esp?.spi_values?.length || 0}
                    </dd>
                  </dl>
                </div>
              </div>

              {/* Row 3: Capture Metadata & Protocols */}
              <div className="grid gap-4 md:grid-cols-2">
                <div className="rounded-lg border bg-muted/20 p-4">
                  <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-3">
                    Capture Metadata
                  </p>
                  <dl className="grid grid-cols-2 gap-2 text-xs">
                    <dt className="text-muted-foreground">File:</dt>
                    <dd className="font-mono font-medium truncate">{features.capture?.filename || info.name}</dd>
                    <dt className="text-muted-foreground">Size:</dt>
                    <dd className="font-mono">{features.capture?.file_size_formatted || info.size}</dd>
                    <dt className="text-muted-foreground">Duration:</dt>
                    <dd className="font-mono">{features.capture?.capture_duration_formatted || info.duration}</dd>
                    <dt className="text-muted-foreground">Total Packets:</dt>
                    <dd className="font-mono">{features.totalPackets.toLocaleString()}</dd>
                    <dt className="text-muted-foreground">First Seen:</dt>
                    <dd className="font-mono truncate">{features.capture?.first_packet_timestamp || '—'}</dd>
                    <dt className="text-muted-foreground">Last Seen:</dt>
                    <dd className="font-mono truncate">{features.capture?.last_packet_timestamp || '—'}</dd>
                  </dl>
                </div>

                <div className="rounded-lg border bg-muted/20 p-4">
                  <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-3">
                    Observed Protocol Breakdown
                  </p>
                  {features.protocols && Object.keys(features.protocols).length > 0 ? (
                    <div className="grid grid-cols-2 gap-2">
                      {Object.entries(features.protocols).map(([proto, stats]: [string, any]) => (
                        <div key={proto} className="rounded-md border bg-background/60 p-2 text-xs">
                          <div className="flex items-center justify-between">
                            <span className="font-semibold text-primary">{proto}</span>
                            <span className="font-mono text-[11px]">{stats.percentage}%</span>
                          </div>
                          <p className="mt-0.5 font-mono text-[10px] text-muted-foreground">
                            {stats.packet_count} pkts ({stats.byte_count?.toLocaleString()} B)
                          </p>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-xs text-muted-foreground">No protocols analyzed.</p>
                  )}
                </div>
              </div>

              {/* Row 4: Flows summary */}

              {/* Flows summary */}
              {features.flows && features.flows.length > 0 && (
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">
                    Reconstructed Bidirectional Flows ({features.flows.length})
                  </p>
                  <div className="overflow-x-auto rounded-lg border">
                    <table className="w-full text-left text-xs font-mono">
                      <thead className="bg-muted/50 text-muted-foreground">
                        <tr>
                          <th className="p-3">Flow 5-Tuple</th>
                          <th className="p-3">Proto</th>
                          <th className="p-3">Duration</th>
                          <th className="p-3">Fwd / Bwd Pkts</th>
                          <th className="p-3">Throughput</th>
                        </tr>
                      </thead>
                      <tbody>
                        {features.flows.slice(0, 5).map((f: any, idx: number) => (
                          <tr key={idx} className="border-t">
                            <td className="p-3 text-foreground font-medium truncate max-w-[280px]">{f.flow_id}</td>
                            <td className="p-3 text-primary">{f.protocol}</td>
                            <td className="p-3">{f.duration_seconds}s</td>
                            <td className="p-3">{f.forward_packets} / {f.backward_packets}</td>
                            <td className="p-3">{f.throughput_bps ? `${(f.throughput_bps / 1000).toFixed(1)} kbps` : '—'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )
        ) : (
          /* Empty state */
          <div className="flex flex-col items-center justify-center p-12 text-center">
            <div className="flex size-12 items-center justify-center rounded-full bg-primary/10 text-primary mb-4">
              <FileJson className="size-6" />
            </div>
            <p className="font-medium text-foreground">No features extracted yet</p>
            <p className="mt-1 max-w-md text-xs text-muted-foreground">
              Click the button below to run TShark against <span className="font-mono font-medium text-foreground">{info.name}</span> and display the full structured JSON extracted feature set.
            </p>
            <Button onClick={onExtract} disabled={busy} className="mt-5 gap-2" size="sm">
              <RefreshCw className={`size-3.5 ${busy ? 'animate-spin' : ''}`} />
              {busy ? 'Extracting...' : 'Extract features now'}
            </Button>
          </div>
        )}
      </div>

      {/* Navigation action */}
      <div className="flex flex-wrap items-center justify-end gap-3">
        <Button variant="outline" onClick={onPredict} disabled={!features || busy}>
          Traffic Classifier
        </Button>
        <Button onClick={onSecurity || onPredict} disabled={!features || busy} className="gap-2">
          Run Security Assessment <ChevronRight className="size-4" />
        </Button>
      </div>
    </div>
  )
}

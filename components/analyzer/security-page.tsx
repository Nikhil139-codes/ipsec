'use client'

import { useState } from 'react'
import {
  AlertCircle,
  AlertTriangle,
  ArrowRight,
  Bot,
  Check,
  CheckCircle2,
  Copy,
  ExternalLink,
  FileCode2,
  FileText,
  Flame,
  HelpCircle,
  KeyRound,
  Layers,
  Lock,
  Network,
  Printer,
  RefreshCw,
  Repeat,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  XCircle,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { buildSecurityReport } from '@/lib/api/report'
import {
  type PCAPInfo,
  type SecurityAnalysisResult,
  type SecurityCheckFinding,
  type SecurityCheckStatus,
  type SecurityCheckSeverity,
  type View,
} from '@/lib/api/types'
import { ReportModal } from './report-modal'
import { ReportChat } from './report-chat'

interface SecurityPageProps {
  info: PCAPInfo
  securityAssessment: SecurityAnalysisResult | null
  busy: boolean
  error?: string | null
  onAnalyze: () => void
  onGo?: (view: View) => void
}

export function SecurityPage({
  info,
  securityAssessment,
  busy,
  error,
  onAnalyze,
  onGo,
}: SecurityPageProps) {
  const [copied, setCopied] = useState(false)
  const [expandedCheck, setExpandedCheck] = useState<string | null>(null)
  const [modalReport, setModalReport] = useState<any>(null)

  const handleOpenReport = () => {
    const rep = buildSecurityReport({
      info,
      securityAssessment,
    })
    setModalReport(rep)
  }

  const handleCopyJson = async () => {
    if (!securityAssessment) return
    try {
      await navigator.clipboard.writeText(JSON.stringify(securityAssessment, null, 2))
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      // fallback
    }
  }

  const nist = securityAssessment?.nist_assessment
  const risk = securityAssessment?.risk_assessment
  const ai = securityAssessment?.ai_analysis

  // Helper for Status Badge
  const renderStatusBadge = (status: SecurityCheckStatus) => {
    switch (status) {
      case 'PASS':
        return (
          <span className="inline-flex items-center gap-1.5 rounded-md border border-emerald-200 bg-emerald-50 px-2.5 py-1 text-xs font-semibold text-emerald-700">
            <CheckCircle2 className="size-3.5" />
            PASS
          </span>
        )
      case 'WARNING':
        return (
          <span className="inline-flex items-center gap-1.5 rounded-md border border-amber-200 bg-amber-50 px-2.5 py-1 text-xs font-semibold text-amber-700">
            <AlertTriangle className="size-3.5" />
            WARNING
          </span>
        )
      case 'FAIL':
        return (
          <span className="inline-flex items-center gap-1.5 rounded-md border border-rose-200 bg-rose-50 px-2.5 py-1 text-xs font-semibold text-rose-700">
            <XCircle className="size-3.5" />
            FAIL
          </span>
        )
      case 'NOT_OBSERVABLE':
      default:
        return (
          <span className="inline-flex items-center gap-1.5 rounded-md border border-slate-200 bg-slate-100 px-2.5 py-1 text-xs font-medium text-slate-600">
            <HelpCircle className="size-3.5" />
            NOT OBSERVABLE
          </span>
        )
    }
  }

  // Helper for Severity Badge
  const renderSeverityBadge = (severity: SecurityCheckSeverity) => {
    const colors: Record<SecurityCheckSeverity, string> = {
      LOW: 'bg-muted text-muted-foreground border-transparent',
      MEDIUM: 'bg-amber-100/60 text-amber-800 border-amber-200',
      HIGH: 'bg-orange-100/60 text-orange-800 border-orange-200',
      CRITICAL: 'bg-rose-100/60 text-rose-800 border-rose-200',
    }
    return (
      <span className={`inline-flex items-center rounded border px-2 py-0.5 text-[11px] font-medium uppercase tracking-wider ${colors[severity] || colors.LOW}`}>
        {severity}
      </span>
    )
  }

  // Helper for Risk Level styling
  const getRiskLevelColor = (level: string) => {
    switch (level) {
      case 'LOW':
        return 'text-emerald-700 bg-emerald-50 border-emerald-200'
      case 'MODERATE':
        return 'text-amber-700 bg-amber-50 border-amber-200'
      case 'HIGH':
        return 'text-orange-700 bg-orange-50 border-orange-200'
      case 'CRITICAL':
      default:
        return 'text-rose-700 bg-rose-50 border-rose-200'
    }
  }

  // Helper for Category Icon
  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'Cryptographic Strength':
        return <Lock className="size-4 text-primary" />
      case 'Configuration Compliance':
        return <Layers className="size-4 text-primary" />
      case 'Security Association Parameters':
      case 'Security Association (SA) Parameters':
        return <Network className="size-4 text-primary" />
      case 'Key Lifetime':
        return <KeyRound className="size-4 text-primary" />
      case 'Replay Protection':
        return <Repeat className="size-4 text-primary" />
      case 'Forward Secrecy (PFS) Configuration':
      case 'Forward Secrecy / PFS':
        return <ShieldCheck className="size-4 text-primary" />
      case 'Cipher Suite Strength':
        return <Shield className="size-4 text-primary" />
      case 'Metadata Exposure':
        return <AlertTriangle className="size-4 text-primary" />
      default:
        return <Shield className="size-4 text-primary" />
    }
  }

  return (
    <div className="flex flex-col gap-6">
      {/* Top Header */}
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-sm font-medium text-primary">Compliance &amp; Threat Intelligence</p>
          <h2 className="mt-1 text-2xl font-semibold tracking-tight">
            Security Assessment for {info.name}
          </h2>
          <p className="mt-2 text-sm text-muted-foreground">
            Server-side NIST SP 800-77 / SP 800-57 deterministic evaluation &amp; Groq AI analysis.
          </p>
        </div>
        <div className="flex items-center gap-3">
          {securityAssessment ? (
            <>
              <Button
                variant="default"
                size="sm"
                onClick={handleOpenReport}
                className="gap-2 text-xs font-semibold shadow-xs"
              >
                <FileText className="size-4" />
                Generate Security Report
              </Button>
              <Button variant="outline" size="sm" onClick={handleCopyJson} className="gap-2">
                {copied ? <Check className="size-4 text-emerald-600" /> : <Copy className="size-4" />}
                {copied ? 'Copied JSON' : 'Copy JSON'}
              </Button>
            </>
          ) : (
            <Button onClick={onAnalyze} disabled={busy} className="gap-2">
              <RefreshCw className={`size-4 ${busy ? 'animate-spin' : ''}`} />
              {busy ? 'Evaluating rules...' : 'Run Security Assessment'}
            </Button>
          )}
        </div>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="flex items-center justify-between rounded-xl border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">
          <div className="flex items-center gap-3">
            <AlertCircle className="size-5 shrink-0" />
            <p className="font-medium">{error}</p>
          </div>
          <Button variant="outline" size="sm" onClick={onAnalyze} disabled={busy}>
            Retry
          </Button>
        </div>
      )}

      {securityAssessment ? (
        <>
          {/* ========================================================================= */}
          {/* SECTION 1: PROMINENT RISK SCORE & OVERVIEW */}
          {/* ========================================================================= */}
          <div className="grid gap-5 md:grid-cols-3">
            {/* Risk Score Card */}
            <div className="rounded-xl border bg-card p-6 md:col-span-2">
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    Deterministic Risk Score
                  </p>
                  <div className="mt-3 flex items-baseline gap-3">
                    <span className="text-5xl font-extrabold tracking-tight text-foreground">
                      {risk?.score ?? 0}
                    </span>
                    <span className="text-xl font-medium text-muted-foreground">/ 100</span>
                    <span
                      className={`ml-2 inline-flex items-center rounded-lg border px-3 py-1 text-sm font-semibold uppercase tracking-wide ${getRiskLevelColor(
                        risk?.level || 'LOW'
                      )}`}
                    >
                      {risk?.level || 'LOW'} RISK
                    </span>
                  </div>
                </div>

                <div className="text-right text-xs text-muted-foreground">
                  <p className="font-medium text-foreground">Scoring Method</p>
                  <p className="mt-0.5 font-mono">{risk?.method || 'project_policy_v1'}</p>
                  <p className="mt-2 text-[11px]">Server-side deterministic formula</p>
                </div>
              </div>

              {/* Visual Score Meter */}
              <div className="mt-6">
                <div className="relative h-3 w-full overflow-hidden rounded-full bg-muted">
                  <div
                    className={`h-full transition-all duration-500 ${(risk?.score ?? 0) >= 70
                      ? 'bg-rose-500'
                      : (risk?.score ?? 0) >= 40
                        ? 'bg-orange-500'
                        : (risk?.score ?? 0) >= 20
                          ? 'bg-amber-500'
                          : 'bg-emerald-500'
                      }`}
                    style={{ width: `${Math.min(100, Math.max(5, risk?.score ?? 0))}%` }}
                  />
                </div>
                <div className="mt-2 flex justify-between text-[11px] font-medium text-muted-foreground">
                  <span>0 (Low)</span>
                  <span>20 (Moderate)</span>
                  <span>40 (High)</span>
                  <span>70+ (Critical)</span>
                </div>
              </div>

              {/* Scoring Factors Breakdown */}
              {risk?.factors && risk.factors.length > 0 ? (
                <div className="mt-6 border-t pt-4">
                  <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    Risk Assessment Factors ({risk.factors.length})
                  </p>
                  <div className="mt-3 space-y-2">
                    {risk.factors.map((f, i) => (
                      <div
                        key={i}
                        className="flex items-start justify-between gap-4 rounded-lg bg-muted/40 p-2.5 text-xs"
                      >
                        <div className="flex items-center gap-2">
                          <span className="font-semibold text-foreground">{f.category}:</span>
                          <span className="text-muted-foreground">{f.reason}</span>
                        </div>
                        <span className="shrink-0 font-mono font-bold text-amber-600">
                          +{f.points} pts
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="mt-5 border-t pt-4 text-xs text-muted-foreground">
                  <p>No risk points accumulated. Capture adheres to standard baseline requirements.</p>
                </div>
              )}
            </div>

            {/* Overall NIST Status Card */}
            <div className="flex flex-col justify-between rounded-xl border bg-card p-6">
              <div>
                <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  Overall NIST Status
                </p>
                <div className="mt-3">
                  {nist?.overall_status === 'PASS' && (
                    <div className="flex items-center gap-2 text-2xl font-bold text-emerald-600">
                      <ShieldCheck className="size-7" /> PASS
                    </div>
                  )}
                  {nist?.overall_status === 'WARNING' && (
                    <div className="flex items-center gap-2 text-2xl font-bold text-amber-600">
                      <AlertTriangle className="size-7" /> WARNING
                    </div>
                  )}
                  {nist?.overall_status === 'FAIL' && (
                    <div className="flex items-center gap-2 text-2xl font-bold text-rose-600">
                      <ShieldAlert className="size-7" /> FAIL
                    </div>
                  )}
                </div>
                <p className="mt-2 text-xs leading-5 text-muted-foreground">
                  Derived from NIST SP 800-77 Rev. 1 (Guide to IPsec VPNs) and SP 800-57 Part 1 Rev. 5.
                </p>
              </div>

              <div className="mt-6 border-t pt-4">
                <p className="text-xs font-medium text-foreground">Assessment Summary</p>
                <div className="mt-3 grid grid-cols-2 gap-2 text-center text-xs">
                  <div className="rounded-lg bg-emerald-50 p-2 text-emerald-700">
                    <p className="font-bold text-base">
                      {nist?.checks.filter((c) => c.status === 'PASS').length ?? 0}
                    </p>
                    <p className="text-[10px] uppercase tracking-wider">Passed</p>
                  </div>
                  <div className="rounded-lg bg-amber-50 p-2 text-amber-700">
                    <p className="font-bold text-base">
                      {nist?.checks.filter((c) => c.status === 'WARNING').length ?? 0}
                    </p>
                    <p className="text-[10px] uppercase tracking-wider">Warnings</p>
                  </div>
                  <div className="rounded-lg bg-rose-50 p-2 text-rose-700">
                    <p className="font-bold text-base">
                      {nist?.checks.filter((c) => c.status === 'FAIL').length ?? 0}
                    </p>
                    <p className="text-[10px] uppercase tracking-wider">Failed</p>
                  </div>
                  <div className="rounded-lg bg-slate-100 p-2 text-slate-700">
                    <p className="font-bold text-base">
                      {nist?.checks.filter((c) => c.status === 'NOT_OBSERVABLE').length ?? 0}
                    </p>
                    <p className="text-[10px] uppercase tracking-wider">Unobserved</p>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* ========================================================================= */}
          {/* ATTACK MODEL TEST CALLOUT OPTION                                          */}
          {/* ========================================================================= */}
          <div className="rounded-xl border-2 border-rose-500/30 bg-rose-50/50 dark:bg-rose-950/20 p-5 shadow-sm">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
              <div className="flex items-start gap-3.5">
                <div className="flex size-10 shrink-0 items-center justify-center rounded-xl bg-rose-500/10 text-rose-600">
                  <Flame className="size-5" />
                </div>
                <div>
                  <h4 className="text-sm font-bold text-foreground">
                    Would you like to test your VPN configuration using an attack model?

                  </h4>
                  <p className="text-xs text-muted-foreground mt-0.5 max-w-2xl leading-relaxed">
                    Simulate automated adversarial validation tests in an authorized testbed environment based on the discovered NIST security findings and risk parameters.

                  </p>
                </div>
              </div>
              {onGo && (
                <Button
                  onClick={() => onGo('attacker')}
                  className="bg-rose-600 hover:bg-rose-700 text-white font-semibold text-xs shadow-sm gap-2 shrink-0 transition-transform active:scale-95"
                >
                  <Flame className="size-4" />
                  Launch Attacker Simulation
                  <ArrowRight className="size-3.5" />
                </Button>
              )}
            </div>
          </div>

          {/* ========================================================================= */}
          {/* SECTION 2: NIST SECURITY ASSESSMENT (8 CATEGORIES) */}
          {/* ========================================================================= */}
          <div className="rounded-xl border bg-card">
            <div className="border-b p-5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <h3 className="text-base font-semibold tracking-tight text-foreground">
                    NIST Security Assessment Findings
                  </h3>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    Strictly evaluated from observed packet evidence. Unobservable parameters are explicitly noted.
                  </p>
                </div>
                <span className="text-xs font-mono text-muted-foreground">8 Categories Evaluated</span>
              </div>
            </div>

            <div className="divide-y">
              {nist?.checks.map((check, idx) => {
                const isExpanded = expandedCheck === check.category || expandedCheck === null
                return (
                  <div key={idx} className="p-5 transition-colors hover:bg-muted/20">
                    {/* Category Header Row */}
                    <div className="flex flex-wrap items-center justify-between gap-4">
                      <div className="flex items-center gap-3">
                        <div className="flex size-8 items-center justify-center rounded-lg bg-primary/10">
                          {getCategoryIcon(check.category)}
                        </div>
                        <div>
                          <p className="text-sm font-semibold text-foreground">{check.category}</p>
                          <p className="text-xs text-muted-foreground">
                            Severity: {renderSeverityBadge(check.severity)}
                          </p>
                        </div>
                      </div>
                      <div>{renderStatusBadge(check.status)}</div>
                    </div>

                    {/* Detailed Fields */}
                    <div className="mt-4 grid gap-3 rounded-lg bg-muted/30 p-4 text-xs">
                      {/* Observed Value */}
                      <div>
                        <span className="font-semibold text-foreground">Observed Value: </span>
                        {check.observed_value ? (
                          <span className="font-mono text-foreground font-medium bg-background px-2 py-0.5 rounded border">
                            {check.observed_value}
                          </span>
                        ) : (
                          <span className="font-mono text-muted-foreground italic">
                            null (Not observable from captured frames)
                          </span>
                        )}
                      </div>

                      {/* Expected / Policy */}
                      <div>
                        <span className="font-semibold text-foreground">Expected / Policy: </span>
                        <span className="text-muted-foreground">{check.expected_or_policy}</span>
                      </div>

                      {/* Technical Reason */}
                      <div>
                        <span className="font-semibold text-foreground">Reason: </span>
                        <span className="text-muted-foreground leading-relaxed">{check.reason}</span>
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>

          {/* ========================================================================= */}
          {/* SECTION 3: GROK AI ANALYSIS */}
          {/* ========================================================================= */}
          <div className="rounded-xl border bg-card">
            <div className="border-b p-5">
              <div className="flex flex-wrap items-center justify-between gap-4">
                <div className="flex items-center gap-2.5">
                  <div className="flex size-8 items-center justify-center rounded-lg bg-primary text-primary-foreground">
                    <Bot className="size-4" />
                  </div>
                  <div>
                    <h3 className="text-base font-semibold tracking-tight text-foreground">
                      Groq AI Security &amp; Traffic Analysis
                    </h3>
                    <p className="text-xs text-muted-foreground">
                      Probabilistic traffic classification and threat modeling powered by server-side Groq LPU inference.
                    </p>
                  </div>
                </div>

                {ai?.available && (
                  <div className="flex items-center gap-3">
                    <div className="rounded-md border bg-muted/50 px-3 py-1 text-xs">
                      <span className="text-muted-foreground">Traffic Type: </span>
                      <span className="font-semibold text-foreground">{ai.traffic_class}</span>
                    </div>
                    <div className="rounded-md border bg-muted/50 px-3 py-1 text-xs">
                      <span className="text-muted-foreground">Confidence: </span>
                      <span className="font-bold text-primary">
                        {Math.round((ai.confidence ?? 0.95) * 100)}%
                      </span>
                    </div>
                  </div>
                )}
              </div>
            </div>

            <div className="p-6">
              {ai && ai.available !== false ? (
                <div className="space-y-6">
                  {/* Traffic Classification Banner */}
                  <div className="rounded-lg border bg-primary/5 p-4">
                    <div className="flex flex-wrap items-center justify-between gap-4">
                      <div>
                        <p className="text-xs font-semibold uppercase tracking-wider text-primary">
                          Traffic Classification (Probabilistic)
                        </p>
                        <p className="mt-1 text-xl font-bold text-foreground">{ai.traffic_class}</p>
                      </div>
                      <div className="flex items-center gap-3">
                        <div className="text-right">
                          <p className="text-xs text-muted-foreground">Confidence</p>
                          <p className="text-lg font-bold text-primary">
                            {Math.round((ai.confidence ?? 0.95) * 100)}%
                          </p>
                        </div>
                        <div className="h-3 w-28 overflow-hidden rounded-full bg-muted">
                          <div
                            className="h-full rounded-full bg-primary"
                            style={{ width: `${Math.round((ai.confidence ?? 0.95) * 100)}%` }}
                          />
                        </div>
                      </div>
                    </div>
                    <p className="mt-3 text-xs leading-relaxed text-muted-foreground">{ai.summary}</p>
                  </div>

                  {/* Security Interpretation */}
                  <div>
                    <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                      Security Interpretation
                    </h4>
                    <div className="mt-2 rounded-lg border bg-muted/30 p-4 text-xs leading-relaxed text-foreground">
                      {ai.security_interpretation}
                    </div>
                  </div>

                  {/* Grid: Key Observations & Recommendations */}
                  <div className="grid gap-6 md:grid-cols-2">
                    {/* Key Observations */}
                    <div className="rounded-lg border p-4">
                      <p className="text-xs font-semibold uppercase tracking-wider text-foreground">
                        Key Observations
                      </p>
                      <ul className="mt-3 space-y-2 text-xs text-muted-foreground">
                        {ai.key_observations && ai.key_observations.length > 0 ? (
                          ai.key_observations.map((obs, i) => (
                            <li key={i} className="flex items-start gap-2">
                              <span className="text-primary font-bold">•</span>
                              <span className="leading-relaxed">{obs}</span>
                            </li>
                          ))
                        ) : (
                          <li className="italic">No specific observations reported.</li>
                        )}
                      </ul>
                    </div>

                    {/* Recommendations */}
                    <div className="rounded-lg border p-4">
                      <p className="text-xs font-semibold uppercase tracking-wider text-foreground">
                        Actionable Recommendations
                      </p>
                      <ul className="mt-3 space-y-2 text-xs text-muted-foreground">
                        {ai.recommendations && ai.recommendations.length > 0 ? (
                          ai.recommendations.map((rec, i) => (
                            <li key={i} className="flex items-start gap-2">
                              <span className="text-emerald-600 font-bold">•</span>
                              <span className="leading-relaxed">{rec}</span>
                            </li>
                          ))
                        ) : (
                          <li className="italic">No additional recommendations required.</li>
                        )}
                      </ul>
                    </div>
                  </div>
                </div>
              ) : (
                /* AI Unavailable Fallback Banner */
                <div className="rounded-lg border border-amber-200 bg-amber-50/70 p-5 text-amber-900">
                  <div className="flex items-start gap-3">
                    <AlertTriangle className="size-5 shrink-0 text-amber-600 mt-0.5" />
                    <div>
                      <p className="font-semibold text-sm">
                        AI analysis unavailable — NIST assessment completed.
                      </p>
                      <p className="mt-1 text-xs text-amber-800 leading-relaxed">
                        The NIST deterministic security rule engine evaluated all 8 security categories and calculated your risk score ({risk?.score}/100 - {risk?.level}). Groq AI narrative analysis was skipped because <code className="rounded bg-amber-100 px-1 py-0.5 font-mono text-[11px]">GROQ_API_KEY</code> is not configured on the server.
                      </p>
                      <p className="mt-3 text-[11px] text-amber-700">
                        To enable deep Groq traffic classification and narrative threat interpretation, set <code className="rounded bg-amber-100 px-1 py-0.5 font-mono">GROQ_API_KEY</code> in your server environment file (<code className="rounded bg-amber-100 px-1 py-0.5 font-mono">.env.local</code>).
                      </p>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* ========================================================================= */}
          {/* SECTION 4: ASK ABOUT THIS REPORT (RAG ASSISTANT)                          */}
          {/* ========================================================================= */}
          <ReportChat
            sessionId={securityAssessment.session_id}
            reportId={securityAssessment.report_id || securityAssessment.session_id}
            reportName={info.name}
          />
        </>
      ) : (
        /* Empty State */
        <div className="flex flex-col items-center justify-center rounded-xl border bg-card p-12 text-center">
          <div className="flex size-14 items-center justify-center rounded-full bg-primary/10 text-primary mb-4">
            <ShieldCheck className="size-7" />
          </div>
          <h3 className="text-lg font-semibold text-foreground">No Security Assessment Run Yet</h3>
          <p className="mt-1 max-w-md text-xs text-muted-foreground">
            Execute the NIST SP 800-77 / SP 800-57 security engine and Grok AI analysis against{' '}
            <span className="font-mono font-medium text-foreground">{info.name}</span> to generate the full security report.
          </p>
          <Button onClick={onAnalyze} disabled={busy} className="mt-6 gap-2">
            <RefreshCw className={`size-4 ${busy ? 'animate-spin' : ''}`} />
            {busy ? 'Evaluating security rules...' : 'Run Security Assessment now'}
          </Button>
        </div>
      )}

      {modalReport && (
        <ReportModal
          report={modalReport}
          onClose={() => setModalReport(null)}
          onLaunchAttacker={() => {
            setModalReport(null)
            onGo?.('attacker')
          }}
        />
      )}
    </div>
  )
}

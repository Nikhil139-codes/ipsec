'use client'

import { useEffect, useState } from 'react'
import {
  AlertCircle,
  AlertTriangle,
  ArrowRight,
  Check,
  CheckCircle2,
  Copy,
  ExternalLink,
  Flame,
  FileCode2,
  Info,
  Loader2,
  Play,
  RotateCcw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal as TerminalIcon,
  Zap,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  analyzeAttackPath,
  generateAttackerTests,
  getLatestSecurityReport,
} from '@/lib/api/attacker'
import {
  type AttackerTest,
  type AttackPathAnalysis,
  type SecurityAnalysisResult,
  type SimulatedTestResult,
  type View,
} from '@/lib/api/types'
import { AttackPathTree } from './attack-path-tree'
import { VpnTestTerminal } from './vpn-test-terminal'

interface AttackerSimulationPageProps {
  initialReport?: SecurityAnalysisResult | null
  onGo?: (view: View) => void
}

export function AttackerSimulationPage({
  initialReport,
  onGo,
}: AttackerSimulationPageProps) {
  const [report, setReport] = useState<SecurityAnalysisResult | null>(initialReport ?? null)
  const [loadingReport, setLoadingReport] = useState(false)
  const [tests, setTests] = useState<AttackerTest[]>([])
  const [loadingTests, setLoadingTests] = useState(false)
  const [groqError, setGroqError] = useState<string | null>(null)
  const [copiedId, setCopiedId] = useState<string | null>(null)

  // Terminal & execution state
  const [terminalCommand, setTerminalCommand] = useState<string | null>(null)
  const [testResult, setTestResult] = useState<SimulatedTestResult | null>(null)

  // AI Attack Path Analysis state
  const [attackPath, setAttackPath] = useState<AttackPathAnalysis | null>(null)
  const [loadingAttackPath, setLoadingAttackPath] = useState(false)

  // 1. Fetch latest report automatically if not provided via props
  useEffect(() => {
    if (initialReport) {
      setReport(initialReport)
      return
    }

    let isMounted = true
    setLoadingReport(true)
    getLatestSecurityReport()
      .then((res) => {
        if (isMounted) {
          setReport(res)
        }
      })
      .catch(() => {
        if (isMounted) setReport(null)
      })
      .finally(() => {
        if (isMounted) setLoadingReport(false)
      })

    return () => {
      isMounted = false
    }
  }, [initialReport])

  // 2. Generate controlled security validation tests via Groq whenever report changes
  useEffect(() => {
    if (!report) {
      setTests([])
      return
    }

    let isMounted = true
    setLoadingTests(true)
    setGroqError(null)

    generateAttackerTests(report, report.session_id)
      .then((res) => {
        if (!isMounted) return
        setTests(res.tests || [])
        if (res.message) {
          setGroqError(res.message)
        }
      })
      .catch(() => {
        if (!isMounted) return
        setGroqError('AI attack-test generation is temporarily unavailable.')
      })
      .finally(() => {
        if (isMounted) setLoadingTests(false)
      })

    return () => {
      isMounted = false
    }
  }, [report])

  // 3. Handle command execution output from VPN Test Terminal
  const handleCommandExecuted = async (res: SimulatedTestResult) => {
    setTestResult(res)

    // Only query attack path for actual validation tests (skip help, clear, unauthorized)
    if (
      res.command === 'help' ||
      res.command === 'clear' ||
      res.status === 'COMMAND REJECTED'
    ) {
      setAttackPath(null)
      return
    }

    setLoadingAttackPath(true)
    try {
      const pathResult = await analyzeAttackPath(
        res.command,
        res.test_title,
        res,
        {
          risk_score: report?.risk_assessment?.score,
          risk_level: report?.risk_assessment?.level,
          session_id: report?.session_id,
        }
      )
      setAttackPath(pathResult)
    } catch {
      // Graceful fallback
    } finally {
      setLoadingAttackPath(false)
    }
  }

  // Copy command to clipboard
  const handleCopyCommand = async (testId: string, cmd: string) => {
    try {
      await navigator.clipboard.writeText(cmd)
      setCopiedId(testId)
      setTimeout(() => setCopiedId(null), 2000)
    } catch {
      // Clipboard fallback
    }
  }

  // Run suggested command in terminal
  const handleRunInTerminal = (cmd: string) => {
    setTerminalCommand(cmd)
  }

  // ==========================================
  // Loading State
  // ==========================================
  if (loadingReport) {
    return (
      <div className="flex flex-col items-center justify-center py-24 text-center">
        <Loader2 className="size-8 animate-spin text-primary mb-3" />
        <p className="text-sm font-medium text-foreground">Loading latest security assessment...</p>
        <p className="text-xs text-muted-foreground mt-1">Connecting to authorized testing environment</p>
      </div>
    )
  }

  // ==========================================
  // Requirement 10: Empty State when no report exists
  // ==========================================
  if (!report || (!report.nist_assessment && !report.observed_features)) {
    return (
      <div className="rounded-xl border bg-card p-10 text-center shadow-xs max-w-2xl mx-auto my-8">
        <div className="mx-auto flex size-14 items-center justify-center rounded-2xl bg-amber-500/10 text-amber-600 mb-4">
          <ShieldAlert className="size-8" />
        </div>
        <h2 className="text-lg font-semibold tracking-tight text-foreground">
          No Security Assessment Report available.
        </h2>
        <p className="text-sm text-muted-foreground mt-1.5 max-w-md mx-auto">
          Please analyze a PCAP first. The Attacker Simulation module automatically loads findings from the latest generated security assessment report.
        </p>
        <div className="mt-6 flex flex-wrap items-center justify-center gap-3">
          {onGo && (
            <>
              <Button onClick={() => onGo('analysis')} className="gap-2 text-xs">
                <FileCode2 className="size-4" />
                Go to PCAP Analysis
              </Button>
              <Button variant="outline" onClick={() => onGo('dashboard')} className="gap-2 text-xs">
                Dashboard Overview
              </Button>
            </>
          )}
        </div>
      </div>
    )
  }

  // Extract report metadata
  const risk = report.risk_assessment
  const nist = report.nist_assessment
  const score = risk?.score ?? 0
  const level = risk?.level ?? 'LOW'

  // Extract detected weaknesses (checks with WARNING or FAIL)
  const checks = nist?.checks || []
  const detectedWeaknesses = checks
    .filter((c) => c.status === 'WARNING' || c.status === 'FAIL')
    .map((c) => c.category)

  // Fallback category badges if all passed
  const displayWeaknesses =
    detectedWeaknesses.length > 0
      ? detectedWeaknesses
      : ['PFS Configuration', 'Replay Protection', 'Cipher Configuration']

  return (
    <div className="space-y-8">
      {/* ================================================== */}
      {/* 1. Header: Page Title and Subtitle                 */}
      {/* ================================================== */}
      <div className="flex flex-col gap-1 border-b pb-5">
        <div className="flex items-center gap-2">
          <div className="flex size-7 items-center justify-center rounded-lg bg-red-500/10 text-red-600">
            <Flame className="size-4" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground">
            Attacker Simulation
          </h1>
          <span className="rounded-full bg-emerald-500/10 border border-emerald-500/30 px-2.5 py-0.5 text-[11px] font-semibold text-emerald-600">
            Authorized Prototype
          </span>
        </div>
        <p className="text-sm text-muted-foreground">
          Validate detected VPN weaknesses in an authorized security testing environment.
        </p>
      </div>

      {/* Groq Error Banner if API unavailable */}
      {groqError && (
        <div className="flex items-center gap-3 rounded-lg border border-amber-200 bg-amber-50/80 p-3.5 text-xs text-amber-800">
          <AlertTriangle className="size-4 shrink-0 text-amber-600" />
          <div className="flex-1">
            <p className="font-semibold">{groqError}</p>
            <p className="text-amber-700/90 text-[11px] mt-0.5">
              Deterministic security test plans generated from NIST SP 800-77 rules are active.
            </p>
          </div>
        </div>
      )}

      {/* ================================================== */}
      {/* 2. Latest Security Report Summary Card             */}
      {/* ================================================== */}
      <div className="rounded-xl border bg-card p-6 shadow-xs">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b pb-5">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                Latest Security Report
              </span>
              <span className="text-xs text-muted-foreground">• Session: {report.session_id ? `${report.session_id.slice(0, 8)}...` : 'Active Trace'}</span>
            </div>
            <h3 className="text-base font-semibold text-foreground mt-1">
              Deterministic Vulnerability Assessment
            </h3>
          </div>

          <div className="flex items-center gap-4">
            {/* Risk Score */}
            <div className="flex items-center gap-3 rounded-lg bg-muted/50 px-4 py-2 border">
              <div>
                <p className="text-[10px] uppercase font-semibold text-muted-foreground">Risk Score</p>
                <p className="text-xl font-bold tracking-tight text-foreground">{score}/100</p>
              </div>
              <div
                className={`rounded-md px-2.5 py-1 text-xs font-bold uppercase tracking-wider ${level === 'CRITICAL'
                    ? 'bg-rose-500/15 text-rose-700 dark:text-rose-400'
                    : level === 'HIGH'
                      ? 'bg-red-500/15 text-red-700 dark:text-red-400'
                      : level === 'MODERATE'
                        ? 'bg-amber-500/15 text-amber-700 dark:text-amber-400'
                        : 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-400'
                  }`}
              >
                {level}
              </div>
            </div>
          </div>
        </div>

        {/* Detected Weaknesses List */}
        <div className="mt-5">
          <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2.5">
            Detected Weaknesses:
          </p>
          <div className="flex flex-wrap gap-2">
            {displayWeaknesses.map((weakness, i) => (
              <span
                key={i}
                className="inline-flex items-center gap-1.5 rounded-md border border-red-500/20 bg-red-500/10 px-3 py-1 text-xs font-semibold text-red-700 dark:text-red-400"
              >
                <AlertCircle className="size-3.5" />
                {weakness}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* ================================================== */}
      {/* 3. AI-Generated Security Tests Cards               */}
      {/* ================================================== */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Sparkles className="size-4 text-primary" />
            <h3 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">
              AI-Generated Security Tests
            </h3>
          </div>
          {loadingTests && (
            <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <Loader2 className="size-3.5 animate-spin text-primary" />
              Generating controlled tests via Groq...
            </div>
          )}
        </div>

        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {tests.map((test) => (
            <div
              key={test.id}
              className="flex flex-col justify-between rounded-xl border bg-card p-5 shadow-xs hover:border-primary/40 transition-colors"
            >
              <div>
                <div className="flex items-start justify-between gap-2 mb-2">
                  <span className="text-[10px] font-mono font-bold text-muted-foreground bg-muted px-2 py-0.5 rounded">
                    {test.id}
                  </span>
                  <span className="text-[11px] font-semibold text-amber-700 dark:text-amber-400 bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/20">
                    Controlled Test
                  </span>
                </div>

                <h4 className="text-sm font-bold text-foreground mb-1.5">
                  {test.title}
                </h4>

                <div className="mb-3">
                  <p className="text-[11px] font-semibold text-muted-foreground">Why:</p>
                  <p className="text-xs text-foreground/90 mt-0.5 leading-relaxed">
                    {test.reason}
                  </p>
                </div>
              </div>

              <div className="pt-3 border-t border-muted/80">
                <p className="text-[11px] font-semibold text-muted-foreground mb-1.5">
                  Suggested Command:
                </p>
                <div className="flex items-center justify-between rounded-md bg-zinc-950 px-3 py-2 text-xs font-mono text-emerald-400 mb-3 select-all">
                  <span>$ {test.command}</span>
                  <button
                    onClick={() => handleCopyCommand(test.id, test.command)}
                    className="text-zinc-400 hover:text-zinc-100 transition ml-2"
                    title="Copy command"
                  >
                    {copiedId === test.id ? (
                      <Check className="size-3.5 text-emerald-400" />
                    ) : (
                      <Copy className="size-3.5" />
                    )}
                  </button>
                </div>

                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleCopyCommand(test.id, test.command)}
                    className="flex-1 text-xs gap-1.5 h-8 font-semibold"
                  >
                    {copiedId === test.id ? (
                      <>
                        <Check className="size-3.5 text-emerald-600" />
                        Copied
                      </>
                    ) : (
                      <>
                        <Copy className="size-3.5" />
                        Copy Command
                      </>
                    )}
                  </Button>

                  <Button
                    size="sm"
                    onClick={() => handleRunInTerminal(test.command)}
                    className="flex-1 text-xs gap-1.5 h-8 bg-primary hover:bg-primary/90 text-primary-foreground font-semibold"
                  >
                    <Play className="size-3.5" />
                    Run in Terminal
                  </Button>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ================================================== */}
      {/* 4. VPN Test Terminal (Frontend Prototype)          */}
      {/* ================================================== */}
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <TerminalIcon className="size-4 text-primary" />
            <h3 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">
              VPN Test Terminal
            </h3>
          </div>
          <span className="text-xs text-muted-foreground">
            Non-destructive prototype simulation
          </span>
        </div>

        <VpnTestTerminal
          reportData={report}
          onCommandExecuted={handleCommandExecuted}
          commandToRun={terminalCommand}
          onClearCommandToRun={() => setTerminalCommand(null)}
        />
      </div>

      {/* ================================================== */}
      {/* 5. Weakness / Breaking Point Result                */}
      {/* ================================================== */}
      {testResult && testResult.command !== 'help' && testResult.command !== 'clear' && (
        <div className="rounded-xl border bg-card p-6 shadow-xs space-y-4 animate-in fade-in duration-300">
          <div className="flex items-center justify-between border-b pb-3">
            <div className="flex items-center gap-2">
              <ShieldAlert className="size-4 text-red-600" />
              <h3 className="text-sm font-bold uppercase tracking-wider text-foreground">
                Security Test Result
              </h3>
            </div>
            <span className="text-xs text-muted-foreground">Tested at {testResult.tested_at}</span>
          </div>

          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <div>
              <p className="text-[11px] font-semibold text-muted-foreground uppercase">Test:</p>
              <p className="text-sm font-bold text-foreground mt-0.5">{testResult.test_title}</p>
            </div>

            <div>
              <p className="text-[11px] font-semibold text-muted-foreground uppercase">Status:</p>
              <div className="mt-0.5">
                <span
                  className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md text-xs font-bold ${testResult.status === 'WEAKNESS CONFIRMED'
                      ? 'bg-rose-500/15 text-rose-700 dark:text-rose-400 border border-rose-500/30'
                      : 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-400 border border-emerald-500/30'
                    }`}
                >
                  {testResult.status === 'WEAKNESS CONFIRMED' ? (
                    <AlertTriangle className="size-3.5" />
                  ) : (
                    <CheckCircle2 className="size-3.5" />
                  )}
                  {testResult.status}
                </span>
              </div>
            </div>

            <div>
              <p className="text-[11px] font-semibold text-muted-foreground uppercase">Severity:</p>
              <div className="mt-0.5">
                <span
                  className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-bold uppercase ${testResult.severity === 'CRITICAL' || testResult.severity === 'HIGH'
                      ? 'bg-red-500/10 text-red-600'
                      : 'bg-amber-500/10 text-amber-600'
                    }`}
                >
                  {testResult.severity}
                </span>
              </div>
            </div>

            <div>
              <p className="text-[11px] font-semibold text-muted-foreground uppercase">Validated Command:</p>
              <p className="text-xs font-mono font-semibold text-emerald-600 dark:text-emerald-400 mt-0.5">
                $ {testResult.command}
              </p>
            </div>
          </div>

          <div className="grid gap-3 pt-2 md:grid-cols-2">
            <div className="rounded-lg bg-muted/40 p-4 border">
              <p className="text-xs font-bold text-foreground mb-1">Breaking Point:</p>
              <p className="text-xs text-muted-foreground leading-relaxed">
                {testResult.breaking_point}
              </p>
            </div>

            <div className="rounded-lg bg-muted/40 p-4 border">
              <p className="text-xs font-bold text-foreground mb-1">Security Impact:</p>
              <p className="text-xs text-muted-foreground leading-relaxed">
                {testResult.security_impact}
              </p>
            </div>
          </div>

          {/* Prototype disclaimer notice */}
          <div className="flex items-center gap-2 rounded-md bg-muted/30 px-3 py-2 text-[11px] text-muted-foreground border">
            <Info className="size-3.5 shrink-0 text-primary" />
            <span>
              <strong>Simulated Finding:</strong> This is a controlled prototype validation result conducted in an authorized sandbox. Terms describe potential weaknesses and hypothetical attack paths without exploiting live infrastructure.
            </span>
          </div>
        </div>
      )}

      {/* ================================================== */}
      {/* 6. Potential Attack Path Tree Diagram              */}
      {/* ================================================== */}
      {(loadingAttackPath || attackPath) && (
        <div className="rounded-xl border bg-card p-6 shadow-xs space-y-4 animate-in fade-in duration-300">
          {loadingAttackPath ? (
            <div className="flex flex-col items-center justify-center py-10 gap-3">
              <Loader2 className="size-6 animate-spin text-primary" />
              <p className="text-xs font-medium text-foreground">
                Analyzing validated weakness & modeling potential attack path with Groq AI...
              </p>
            </div>
          ) : (
            attackPath && (
              <>
                <AttackPathTree attackPath={attackPath} testResult={testResult} />
                <p className="text-[11px] text-muted-foreground italic pt-2 border-t text-center">
                  * Note: This potential attack path is modeled for defensive validation in an authorized laboratory and does not execute real exploits.
                </p>
              </>
            )
          )}
        </div>
      )}
    </div>
  )
}

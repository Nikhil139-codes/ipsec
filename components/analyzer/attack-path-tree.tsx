'use client'

import {
  AlertCircle,
  AlertTriangle,
  ArrowDown,
  CheckCircle2,
  ChevronDown,
  CornerDownRight,
  Flame,
  GitBranch,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  XCircle,
  Zap,
} from 'lucide-react'
import { type AttackPathAnalysis, type SimulatedTestResult } from '@/lib/api/types'

interface AttackPathTreeProps {
  attackPath: AttackPathAnalysis
  testResult?: SimulatedTestResult | null
}

export function AttackPathTree({ attackPath, testResult }: AttackPathTreeProps) {
  const cmd = (testResult?.command || '').toLowerCase()
  const isPfs = cmd.includes('pfs')
  const isReplay = cmd.includes('replay')
  const isCipher = cmd.includes('cipher')

  // Dynamic values based on current test result and report
  const weaknessTitle =
    attackPath.validated_weakness ||
    (isPfs
      ? 'Weak PFS Configuration'
      : isReplay
      ? 'Replay Protection Weakness'
      : isCipher
      ? 'Cipher Configuration Weakness'
      : 'Detected Configuration Weakness')

  const testTitle =
    testResult?.test_title ||
    (isPfs
      ? 'PFS Security Test'
      : isReplay
      ? 'Replay Validation Test'
      : isCipher
      ? 'Cipher Validation Test'
      : 'Security Validation Test')

  const confirmedOutcome =
    attackPath.test_result ||
    (isPfs
      ? 'Weakness Confirmed'
      : isReplay
      ? 'Potential Replay Acceptance'
      : isCipher
      ? 'Weak/Legacy Configuration Confirmed'
      : 'Successful Validation')

  const attackerAction =
    attackPath.potential_attacker_action ||
    attackPath.attacker_next_step ||
    (isPfs
      ? 'Attempt Weaker Negotiation'
      : isReplay
      ? 'Attempt Duplicate Sequence Frame Injection'
      : isCipher
      ? 'Attempt Bit-Flipping Integrity Probing'
      : 'Attempt Weaker Negotiation')

  const potentialImpact = attackPath.potential_impact
  const recommendedHardening = attackPath.recommended_hardening

  return (
    <div className="space-y-6">
      {/* Title */}
      <div className="border-b pb-3 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <GitBranch className="size-4 text-primary" />
          <h3 className="text-base font-bold text-foreground">
            Potential Attack Path
          </h3>
        </div>
        <span className="text-xs font-mono text-muted-foreground bg-muted/60 px-2 py-0.5 rounded">
          Dynamic Threat Progression Tree
        </span>
      </div>

      {/* Visual Tree Graph Container */}
      <div className="relative mx-auto max-w-3xl flex flex-col items-center">
        {/* ========================================================================= */}
        {/* NODE 1: DETECTED WEAKNESS                                                 */}
        {/* ========================================================================= */}
        <div className="w-full max-w-md rounded-xl border border-rose-500/30 bg-rose-500/5 p-4 shadow-2xs transition hover:border-rose-500/50">
          <div className="flex items-center justify-between gap-2 mb-1.5">
            <span className="inline-flex items-center gap-1 text-[11px] font-bold uppercase tracking-wider text-rose-700 dark:text-rose-400">
              <Flame className="size-3.5" />
              Detected Weakness
            </span>
            <span className="rounded bg-rose-500/15 px-2 py-0.5 text-[10px] font-bold text-rose-700">
              ENTRY POINT
            </span>
          </div>
          <h4 className="text-sm font-bold text-foreground">{weaknessTitle}</h4>
        </div>

        {/* Connector 1 -> 2 */}
        <div className="flex flex-col items-center my-1">
          <div className="h-6 w-0.5 bg-border" />
          <div className="text-muted-foreground -mt-1">
            <ChevronDown className="size-4 text-muted-foreground/70" />
          </div>
        </div>

        {/* ========================================================================= */}
        {/* NODE 2: SECURITY TEST                                                     */}
        {/* ========================================================================= */}
        <div className="w-full max-w-md rounded-xl border border-blue-500/30 bg-blue-500/5 p-4 shadow-2xs transition hover:border-blue-500/50">
          <div className="flex items-center justify-between gap-2 mb-1.5">
            <span className="inline-flex items-center gap-1 text-[11px] font-bold uppercase tracking-wider text-blue-700 dark:text-blue-400">
              <Terminal className="size-3.5" />
              Security Validation Test
            </span>
            <span className="rounded bg-blue-500/15 px-2 py-0.5 text-[10px] font-mono font-bold text-blue-700">
              $ {testResult?.command || 'test'}
            </span>
          </div>
          <h4 className="text-sm font-bold text-foreground">{testTitle}</h4>
          <p className="text-xs text-muted-foreground mt-0.5">
            Controlled probe executed in authorized prototype sandbox
          </p>
        </div>

        {/* Connector 2 -> 3 (Branching Split) */}
        <div className="flex flex-col items-center my-1 w-full max-w-md">
          <div className="h-4 w-0.5 bg-border" />
        </div>

        {/* Branching Crossbar */}
        <div className="w-full max-w-xl grid grid-cols-2 gap-4 relative">
          {/* Horizontal connecting bar */}
          <div className="absolute top-0 left-1/4 right-1/4 h-0.5 bg-border" />

          {/* Left Branch (Active / Confirmed Weakness Path) */}
          <div className="flex flex-col items-center">
            <div className="h-4 w-0.5 bg-border" />
            <div className="-mt-1 mb-1">
              <ChevronDown className="size-4 text-rose-500" />
            </div>

            <div className="w-full rounded-xl border-2 border-rose-500/40 bg-card p-3.5 shadow-xs">
              <div className="flex items-center justify-between gap-1 mb-1">
                <span className="text-[10px] font-bold uppercase tracking-wider text-rose-700 flex items-center gap-1">
                  <AlertTriangle className="size-3" />
                  Successful Validation
                </span>
                <span className="rounded bg-rose-500/15 px-1.5 py-0.2 text-[9px] font-bold text-rose-700">
                  CONFIRMED
                </span>
              </div>
              <h5 className="text-xs font-bold text-foreground">{confirmedOutcome}</h5>
              <p className="text-[11px] text-muted-foreground mt-0.5">
                Vulnerable condition successfully reproduced in testbed.
              </p>
            </div>
          </div>

          {/* Right Branch (Blocked / Mitigated Alternative Path) */}
          <div className="flex flex-col items-center opacity-70">
            <div className="h-4 w-0.5 bg-border" />
            <div className="-mt-1 mb-1">
              <ChevronDown className="size-4 text-muted-foreground" />
            </div>

            <div className="w-full rounded-xl border border-dashed border-border bg-muted/30 p-3.5 shadow-2xs">
              <div className="flex items-center justify-between gap-1 mb-1">
                <span className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-1">
                  <ShieldCheck className="size-3 text-emerald-600" />
                  Blocked by VPN Policy
                </span>
                <span className="rounded bg-muted px-1.5 py-0.2 text-[9px] font-bold text-muted-foreground">
                  CONTROL EFFECTIVE
                </span>
              </div>
              <h5 className="text-xs font-bold text-foreground">Defensive Control Drops Probe</h5>
              <p className="text-[11px] text-muted-foreground mt-0.5">
                Policy rejects anomalous frames; attack path ends.
              </p>
              <div className="mt-2 text-[10px] font-bold text-emerald-700 bg-emerald-500/10 px-2 py-0.5 rounded text-center">
                Attack Path Ends
              </div>
            </div>
          </div>
        </div>

        {/* Connector from Left Branch Downward */}
        <div className="w-full max-w-xl grid grid-cols-2 gap-4">
          <div className="flex flex-col items-center my-1">
            <div className="h-6 w-0.5 bg-rose-500/40" />
            <div className="text-rose-500 -mt-1">
              <ChevronDown className="size-4" />
            </div>
          </div>
          <div />
        </div>

        {/* ========================================================================= */}
        {/* NODE 4: POTENTIAL ATTACKER ACTION                                         */}
        {/* ========================================================================= */}
        <div className="w-full max-w-md rounded-xl border border-purple-500/30 bg-purple-500/5 p-4 shadow-2xs transition hover:border-purple-500/50">
          <div className="flex items-center justify-between gap-2 mb-1.5">
            <span className="inline-flex items-center gap-1 text-[11px] font-bold uppercase tracking-wider text-purple-700 dark:text-purple-400">
              <Zap className="size-3.5" />
              Potential Attacker Action
            </span>
            <span className="rounded bg-purple-500/15 px-2 py-0.5 text-[10px] font-bold text-purple-700">
              FURTHER ANALYSIS
            </span>
          </div>
          <h4 className="text-sm font-bold text-foreground">{attackerAction}</h4>
          <p className="text-xs text-muted-foreground mt-1 leading-relaxed">
            Hypothetical progression an adversary could attempt following confirmation of the weakness.
          </p>
        </div>

        {/* Connector 4 -> 5 */}
        <div className="flex flex-col items-center my-1">
          <div className="h-6 w-0.5 bg-border" />
          <div className="text-muted-foreground -mt-1">
            <ChevronDown className="size-4 text-muted-foreground/70" />
          </div>
        </div>

        {/* ========================================================================= */}
        {/* NODE 5: POTENTIAL IMPACT                                                  */}
        {/* ========================================================================= */}
        <div className="w-full max-w-md rounded-xl border border-amber-500/30 bg-amber-500/5 p-4 shadow-2xs transition hover:border-amber-500/50">
          <div className="flex items-center justify-between gap-2 mb-1.5">
            <span className="inline-flex items-center gap-1 text-[11px] font-bold uppercase tracking-wider text-amber-700 dark:text-amber-400">
              <AlertCircle className="size-3.5" />
              Potential Impact
            </span>
            <span className="rounded bg-amber-500/15 px-2 py-0.5 text-[10px] font-bold text-amber-700">
              RISK EXPOSURE
            </span>
          </div>
          <p className="text-xs text-foreground/90 font-medium leading-relaxed">
            {potentialImpact}
          </p>
        </div>

        {/* Connector 5 -> 6 */}
        <div className="flex flex-col items-center my-1">
          <div className="h-6 w-0.5 bg-border" />
          <div className="text-emerald-600 -mt-1">
            <ChevronDown className="size-4" />
          </div>
        </div>

        {/* ========================================================================= */}
        {/* NODE 6: RECOMMENDED HARDENING                                             */}
        {/* ========================================================================= */}
        <div className="w-full max-w-md rounded-xl border-2 border-emerald-500/40 bg-emerald-500/10 p-4 shadow-xs transition hover:border-emerald-500/60">
          <div className="flex items-center justify-between gap-2 mb-1.5">
            <span className="inline-flex items-center gap-1 text-[11px] font-bold uppercase tracking-wider text-emerald-800 dark:text-emerald-400">
              <ShieldCheck className="size-4 text-emerald-600" />
              Recommended Hardening
            </span>
            <span className="rounded bg-emerald-600 px-2 py-0.5 text-[10px] font-bold text-white">
              MITIGATION
            </span>
          </div>
          <p className="text-xs text-foreground font-semibold leading-relaxed">
            {recommendedHardening}
          </p>
          <div className="mt-2 flex items-center gap-1.5 text-[11px] text-emerald-700">
            <CheckCircle2 className="size-3.5 shrink-0" />
            <span>Remediates attack path and enforces NIST SP 800-77 compliance.</span>
          </div>
        </div>
      </div>
    </div>
  )
}

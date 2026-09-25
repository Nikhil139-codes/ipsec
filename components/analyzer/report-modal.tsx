'use client'

import { useState } from 'react'
import {
  AlertCircle,
  AlertTriangle,
  CheckCircle2,
  Download,
  FileCode,
  FileText,
  HelpCircle,
  Printer,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  X,
  XCircle,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  downloadHtmlReport,
  downloadJsonReport,
  downloadMarkdownReport,
  printReport,
} from '@/lib/api/report'
import { type SecurityReport } from '@/lib/api/types'

interface ReportModalProps {
  report: SecurityReport | null
  onClose: () => void
}

export function ReportModal({ report, onClose }: ReportModalProps) {
  if (!report) return null

  const getRiskBadge = (level: string, score: number) => {
    switch (level) {
      case 'LOW':
        return (
          <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-500/10 px-3 py-1 text-xs font-bold text-emerald-600 border border-emerald-500/20">
            <ShieldCheck className="size-3.5" />
            {level} RISK ({score}/100)
          </span>
        )
      case 'MODERATE':
        return (
          <span className="inline-flex items-center gap-1.5 rounded-full bg-amber-500/10 px-3 py-1 text-xs font-bold text-amber-600 border border-amber-500/20">
            <AlertTriangle className="size-3.5" />
            {level} RISK ({score}/100)
          </span>
        )
      case 'HIGH':
      case 'CRITICAL':
      default:
        return (
          <span className="inline-flex items-center gap-1.5 rounded-full bg-rose-500/10 px-3 py-1 text-xs font-bold text-rose-600 border border-rose-500/20">
            <ShieldAlert className="size-3.5" />
            {level} RISK ({score}/100)
          </span>
        )
    }
  }

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'PASS':
        return (
          <span className="inline-flex items-center gap-1 rounded bg-emerald-500/15 px-2 py-0.5 text-[11px] font-semibold text-emerald-600">
            <CheckCircle2 className="size-3" /> PASS
          </span>
        )
      case 'WARNING':
        return (
          <span className="inline-flex items-center gap-1 rounded bg-amber-500/15 px-2 py-0.5 text-[11px] font-semibold text-amber-600">
            <AlertTriangle className="size-3" /> WARN
          </span>
        )
      case 'FAIL':
        return (
          <span className="inline-flex items-center gap-1 rounded bg-rose-500/15 px-2 py-0.5 text-[11px] font-semibold text-rose-600">
            <XCircle className="size-3" /> FAIL
          </span>
        )
      default:
        return (
          <span className="inline-flex items-center gap-1 rounded bg-slate-500/15 px-2 py-0.5 text-[11px] font-medium text-slate-500">
            <HelpCircle className="size-3" /> N/A
          </span>
        )
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm p-4 sm:p-6 overflow-y-auto">
      <div className="relative w-full max-w-4xl max-h-[90vh] flex flex-col rounded-2xl border bg-card shadow-2xl overflow-hidden my-auto">
        {/* Header */}
        <div className="flex flex-wrap items-center justify-between border-b px-6 py-4 bg-muted/40 gap-4">
          <div className="flex items-center gap-3">
            <div className="flex size-10 items-center justify-center rounded-xl bg-primary text-primary-foreground shadow-sm">
              <ShieldCheck className="size-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold tracking-tight text-foreground">{report.report_title}</h3>
                <span className="rounded bg-primary/10 px-2 py-0.5 text-[10px] font-mono font-medium text-primary">
                  {report.id}
                </span>
              </div>
              <p className="text-xs text-muted-foreground mt-0.5">
                Target: <span className="font-mono font-semibold text-foreground">{report.target_file}</span> | Generated: {report.generated_at}
              </p>
            </div>
          </div>

          {/* Action Export Buttons */}
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => printReport(report)}
              className="gap-1.5 text-xs font-semibold shadow-2xs"
            >
              <Printer className="size-3.5 text-primary" />
              Print / PDF
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => downloadHtmlReport(report)}
              className="gap-1.5 text-xs font-semibold shadow-2xs"
            >
              <FileCode className="size-3.5 text-emerald-600" />
              HTML
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => downloadMarkdownReport(report)}
              className="gap-1.5 text-xs font-semibold shadow-2xs"
            >
              <FileText className="size-3.5 text-amber-600" />
              Markdown
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => downloadJsonReport(report)}
              className="gap-1.5 text-xs font-semibold shadow-2xs"
            >
              <Download className="size-3.5 text-primary" />
              JSON
            </Button>
            <button
              onClick={onClose}
              className="ml-2 rounded-lg p-1.5 text-muted-foreground hover:bg-muted hover:text-foreground transition"
              aria-label="Close modal"
            >
              <X className="size-5" />
            </button>
          </div>
        </div>

        {/* Modal Scrollable Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Executive Summary Card */}
          <div className="rounded-xl border bg-primary/[0.03] border-primary/20 p-5 shadow-xs">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-primary/15 pb-3.5">
              <div>
                <span className="text-[11px] font-bold uppercase tracking-widest text-primary">Executive Summary</span>
                <h4 className="text-lg font-bold text-foreground mt-0.5">
                  Traffic Verdict: {report.traffic_verdict}
                </h4>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-xs text-muted-foreground font-medium">
                  Confidence: <span className="text-foreground font-bold">{report.traffic_confidence}%</span>
                </span>
                {getRiskBadge(report.risk_level, report.risk_score)}
              </div>
            </div>
            <p className="mt-3 text-xs leading-relaxed text-muted-foreground">
              {report.explanation}
            </p>
          </div>

          {/* Quick Stats Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="rounded-xl border bg-muted/30 p-3.5">
              <span className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider">NIST Compliance</span>
              <p className="mt-1 text-xl font-bold text-emerald-600">
                {report.nist_compliance.pass_count} <span className="text-xs text-muted-foreground font-normal">/ {report.nist_compliance.total_checks} Pass</span>
              </p>
            </div>
            <div className="rounded-xl border bg-muted/30 p-3.5">
              <span className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider">ESP Encapsulation</span>
              <p className="mt-1 text-xl font-bold text-primary">
                {report.cryptographic_profile.esp_ratio}%
              </p>
            </div>
            <div className="rounded-xl border bg-muted/30 p-3.5">
              <span className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider">Encryption Cipher</span>
              <p className="mt-1 text-sm font-bold uppercase truncate text-foreground">
                {report.cryptographic_profile.encryption}
              </p>
            </div>
            <div className="rounded-xl border bg-muted/30 p-3.5">
              <span className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider">Diffie-Hellman</span>
              <p className="mt-1 text-sm font-bold uppercase truncate text-foreground">
                {report.cryptographic_profile.dh_group}
              </p>
            </div>
          </div>

          {/* Cryptographic Profile Table */}
          <div className="rounded-xl border bg-card p-5 shadow-xs">
            <h5 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-3">
              Cryptographic Suite Specifications
            </h5>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-y-3 gap-x-4 text-xs">
              <div>
                <span className="text-muted-foreground">Mode:</span>
                <p className="font-semibold text-foreground">{report.cryptographic_profile.mode}</p>
              </div>
              <div>
                <span className="text-muted-foreground">IKE Version:</span>
                <p className="font-semibold text-foreground">{report.cryptographic_profile.ike_version}</p>
              </div>
              <div>
                <span className="text-muted-foreground">Integrity / Hash:</span>
                <p className="font-semibold uppercase text-foreground">{report.cryptographic_profile.integrity}</p>
              </div>
              <div>
                <span className="text-muted-foreground">Forward Secrecy (PFS):</span>
                <p className="font-semibold text-foreground">{report.cryptographic_profile.pfs}</p>
              </div>
            </div>
          </div>

          {/* NIST Compliance Matrix */}
          <div className="rounded-xl border bg-card p-5 shadow-xs">
            <h5 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-3">
              NIST SP 800-77 & SP 800-57 Rule Evaluation
            </h5>
            <div className="divide-y text-xs">
              {report.nist_compliance.checks.map((c) => (
                <div key={c.id} className="py-2.5 flex items-start justify-between gap-4">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-foreground">{c.id}</span>
                      <span className="font-semibold text-foreground">{c.name}</span>
                      <span className="text-[10px] text-muted-foreground">({c.standard})</span>
                    </div>
                    <p className="mt-1 text-muted-foreground leading-normal">{c.observation}</p>
                  </div>
                  <div className="shrink-0">{getStatusBadge(c.status)}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Findings & Recommendations */}
          <div className="grid sm:grid-cols-2 gap-4">
            <div className="rounded-xl border bg-card p-4 shadow-xs">
              <h5 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-2.5">
                Key Observations
              </h5>
              <ul className="space-y-1.5 text-xs text-muted-foreground list-disc pl-4">
                {report.key_findings.map((f, i) => (
                  <li key={i}>{f}</li>
                ))}
              </ul>
            </div>
            <div className="rounded-xl border bg-card p-4 shadow-xs">
              <h5 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-2.5">
                Actionable Recommendations
              </h5>
              <ul className="space-y-1.5 text-xs text-muted-foreground list-decimal pl-4">
                {report.recommendations.map((r, i) => (
                  <li key={i} className="font-medium text-foreground">
                    {r}
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {/* Execution Logs preview if present */}
          {report.logs_summary && (
            <div className="rounded-xl border bg-card p-4 shadow-xs">
              <div className="flex items-center gap-2 mb-2">
                <Terminal className="size-4 text-primary" />
                <h5 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
                  strongSwan / Kernel SAD/SPD Logs
                </h5>
              </div>
              <pre className="max-h-44 overflow-y-auto rounded-lg bg-muted/80 p-3 font-mono text-[11px] text-foreground leading-relaxed whitespace-pre-wrap">
                {report.logs_summary}
              </pre>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between border-t px-6 py-3.5 bg-muted/20">
          <p className="text-xs text-muted-foreground">
            Complete security intelligence report is compiled and ready for audit export.
          </p>
          <Button size="sm" onClick={onClose}>
            Close Report
          </Button>
        </div>
      </div>
    </div>
  )
}

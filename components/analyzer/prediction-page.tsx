'use client'

import { useState } from 'react'
import {
  CheckCircle2,
  Download,
  FileCode,
  FileText,
  Loader2,
  Printer,
  RefreshCw,
  Sparkles,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  buildSecurityReport,
  downloadHtmlReport,
  downloadJsonReport,
  downloadMarkdownReport,
  printReport,
} from '@/lib/api/report'
import { type PCAPInfo, type Prediction, type SecurityAnalysisResult } from '@/lib/api/types'
import { ReportModal } from './report-modal'

interface PredictionPageProps {
  info: PCAPInfo
  prediction: Prediction | null
  securityAssessment?: SecurityAnalysisResult | null
  busy: boolean
  onPredict: () => void
}

export function PredictionPage({
  info,
  prediction,
  securityAssessment,
  busy,
  onPredict,
}: PredictionPageProps) {
  const [activeModalReport, setActiveModalReport] = useState<any>(null)

  const handleGenerateAndOpenReport = async () => {
    if (!prediction) {
      await onPredict()
    }
    const report = buildSecurityReport({
      info,
      prediction,
      securityAssessment,
    })
    setActiveModalReport(report)
  }

  const handleDownloadHtml = () => {
    const report = buildSecurityReport({ info, prediction, securityAssessment })
    downloadHtmlReport(report)
  }

  const handleDownloadMarkdown = () => {
    const report = buildSecurityReport({ info, prediction, securityAssessment })
    downloadMarkdownReport(report)
  }

  const handlePrintPdf = () => {
    const report = buildSecurityReport({ info, prediction, securityAssessment })
    printReport(report)
  }

  return (
    <div className="flex flex-col gap-6">
      {/* Top Header */}
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-sm font-medium text-primary flex items-center gap-1.5">
            <Sparkles className="size-4" /> AI Classification & Threat Intelligence
          </p>
          <h2 className="mt-1 text-2xl font-semibold tracking-tight">Traffic Verdict for {info.name}</h2>
          <p className="mt-1.5 text-sm text-muted-foreground">
            Explainable neural output and cryptographic heuristics from the IPsec traffic classifier.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {prediction && (
            <Button
              variant="default"
              size="sm"
              onClick={handleGenerateAndOpenReport}
              className="gap-1.5 text-xs font-semibold shadow-xs"
            >
              <FileText className="size-3.5" />
              Generate Security Report
            </Button>
          )}
          <Button variant="outline" size="sm" onClick={onPredict} disabled={busy} className="gap-1.5 text-xs">
            <RefreshCw className={`size-3.5 ${busy ? 'animate-spin' : ''}`} />
            {busy ? 'Classifying...' : 'Run Again'}
          </Button>
        </div>
      </div>

      {prediction ? (
        <>
          {/* Main Grid: Classification verdict and Probability distribution */}
          <div className="grid gap-4 lg:grid-cols-[1.1fr_0.9fr]">
            {/* Verdict Card */}
            <div className="rounded-xl border bg-card p-6 shadow-xs">
              <div className="flex items-start justify-between">
                <div>
                  <p className="text-xs font-semibold uppercase tracking-[0.16em] text-muted-foreground">
                    Final Classification
                  </p>
                  <h3 className="mt-2 text-3xl font-bold tracking-tight text-primary">
                    {prediction.label}
                  </h3>
                </div>
                <div className="flex size-12 items-center justify-center rounded-full bg-emerald-500/10 text-emerald-600 border border-emerald-500/20">
                  <CheckCircle2 className="size-6" />
                </div>
              </div>

              <div className="mt-8">
                <div className="mb-2 flex justify-between text-xs font-medium">
                  <span className="text-muted-foreground">Confidence Score</span>
                  <span className="font-bold text-foreground">{prediction.confidence}%</span>
                </div>
                <div className="h-3 overflow-hidden rounded-full bg-muted">
                  <div
                    className="h-full rounded-full bg-primary transition-all duration-500"
                    style={{ width: `${prediction.confidence}%` }}
                  />
                </div>
              </div>

              <p className="mt-6 text-xs leading-relaxed text-muted-foreground">
                {prediction.explanation}
              </p>
            </div>

            {/* Probability Distribution Card */}
            <div className="rounded-xl border bg-card p-6 shadow-xs flex flex-col justify-between">
              <div>
                <p className="text-sm font-semibold">Probability Distribution</p>
                <div className="mt-5 flex flex-col gap-4">
                  {prediction.probabilities.map((item) => (
                    <div key={item.label}>
                      <div className="mb-1.5 flex justify-between text-xs">
                        <span className="font-medium text-foreground">{item.label}</span>
                        <span className="font-bold text-primary">{item.value}%</span>
                      </div>
                      <div className="h-2 rounded-full bg-muted overflow-hidden">
                        <div
                          className="h-full rounded-full bg-primary transition-all duration-500"
                          style={{ width: `${item.value}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Quick Report Download Strip */}
              <div className="mt-6 border-t pt-4">
                <p className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground mb-2.5">
                  Export Downloadable Report
                </p>
                <div className="flex flex-wrap items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handleDownloadHtml}
                    className="gap-1.5 text-xs font-medium h-8"
                  >
                    <FileCode className="size-3.5 text-emerald-600" />
                    HTML
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handleDownloadMarkdown}
                    className="gap-1.5 text-xs font-medium h-8"
                  >
                    <FileText className="size-3.5 text-amber-600" />
                    Markdown
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handlePrintPdf}
                    className="gap-1.5 text-xs font-medium h-8"
                  >
                    <Printer className="size-3.5 text-primary" />
                    Print / PDF
                  </Button>
                </div>
              </div>
            </div>
          </div>
        </>
      ) : (
        /* Empty State */
        <div className="flex flex-col items-center justify-center rounded-xl border bg-card p-12 text-center shadow-xs">
          <div className="flex size-14 items-center justify-center rounded-full bg-primary/10 text-primary mb-4">
            <Sparkles className="size-7" />
          </div>
          <h3 className="text-lg font-semibold text-foreground">No Prediction Generated Yet</h3>
          <p className="mt-1.5 max-w-sm text-xs text-muted-foreground">
            Execute the explainable AI classifier to inspect protocol encapsulation and generate the complete intelligence report.
          </p>
          <Button
            className="mt-6 gap-2 text-xs font-semibold"
            onClick={handleGenerateAndOpenReport}
            disabled={busy}
          >
            {busy ? <Loader2 className="size-4 animate-spin" /> : <FileText className="size-4" />}
            {busy ? 'Analyzing traffic...' : 'Generate & Download Report'}
          </Button>
        </div>
      )}

      {/* Report Modal */}
      {activeModalReport && (
        <ReportModal report={activeModalReport} onClose={() => setActiveModalReport(null)} />
      )}
    </div>
  )
}

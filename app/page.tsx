'use client'

import { useState } from 'react'
import { AnalysisPage } from '@/components/analyzer/analysis-page'
import { AnalyzerShell } from '@/components/analyzer/analyzer-shell'
import { AttackerSimulationPage } from '@/components/analyzer/attacker-simulation-page'
import { DashboardPage } from '@/components/analyzer/dashboard-page'
import { FeaturesPage } from '@/components/analyzer/features-page'
import { PredictionPage } from '@/components/analyzer/prediction-page'
import { ReportModal } from '@/components/analyzer/report-modal'
import { SecurityPage } from '@/components/analyzer/security-page'
import { TestbedPage } from '@/components/analyzer/testbed-page'
import { UserGuidePage } from '@/components/analyzer/user-guide-page'
import { VpnRecordsPage } from '@/components/analyzer/vpn-records-page'
import { useAnalyzer } from '@/hooks/use-analyzer'
import { buildSecurityReport } from '@/lib/api/report'
import { initialInfo, type SecurityReport, type View } from '@/lib/api/types'

export default function Page() {
  const [view, setView] = useState<View>('dashboard')
  const [live, setLive] = useState(false)
  const [globalReport, setGlobalReport] = useState<SecurityReport | null>(null)
  const analyzer = useAnalyzer()
  const info = analyzer.info ?? initialInfo

  const upload = async (file?: File) => {
    await analyzer.upload(file)
    if (file) setView('analysis')
  }

  const inspect = async () => {
    await analyzer.inspect()
  }

  const extract = async () => {
    await analyzer.extract()
    setView('features')
  }

  const analyzeSecurity = async () => {
    await analyzer.analyzeSecurity()
    setView('security')
  }

  const predict = async () => {
    await analyzer.predict()
    setView('prediction')
  }

  const handleTriggerGlobalReport = () => {
    const report = buildSecurityReport({
      info,
      features: analyzer.features,
      securityAssessment: analyzer.securityAssessment,
      prediction: analyzer.prediction,
    })
    setGlobalReport(report)
  }

  return (
    <>
      <AnalyzerShell
        view={view}
        live={live}
        prediction={analyzer.prediction}
        securityAssessment={analyzer.securityAssessment}
        sourceName={analyzer.file?.name ?? analyzer.info?.name ?? 'No capture loaded'}
        onView={setView}
        onLive={() => setLive((value) => !value)}
        onGenerateReport={handleTriggerGlobalReport}
      >
        {view === 'dashboard' && (
          <DashboardPage info={analyzer.info} live={live} onUpload={upload} onGo={setView} />
        )}
        {view === 'analysis' && (
          <AnalysisPage
            info={info}
            packets={analyzer.packets}
            busy={analyzer.busy}
            onInspect={inspect}
            onFeatures={extract}
          />
        )}
        {view === 'features' && (
          <FeaturesPage
            info={info}
            features={analyzer.features}
            busy={analyzer.busy}
            error={analyzer.error}
            onExtract={analyzer.extract}
            onPredict={predict}
            onSecurity={analyzeSecurity}
          />
        )}
        {view === 'security' && (
          <SecurityPage
            info={info}
            securityAssessment={analyzer.securityAssessment}
            busy={analyzer.busy}
            error={analyzer.error}
            onAnalyze={analyzer.analyzeSecurity}
            onGo={setView}
          />
        )}
        {view === 'attacker' && (
          <AttackerSimulationPage
            initialReport={analyzer.securityAssessment}
            onGo={setView}
          />
        )}
        {view === 'prediction' && (
          <PredictionPage
            info={info}
            prediction={analyzer.prediction}
            securityAssessment={analyzer.securityAssessment}
            busy={analyzer.busy}
            onPredict={analyzer.predict}
          />
        )}
        {view === 'testbed' && (
          <TestbedPage
            onGo={setView}
            onAnalyzePcap={(newInfo) => {
              if (newInfo) {
                analyzer.extract(newInfo.id || newInfo.session_id)
                analyzer.inspect(newInfo.id || newInfo.session_id)
              }
            }}
          />
        )}
        {view === 'history' && (
          <VpnRecordsPage
            onGo={setView}
            onInspectRecord={(sessionInfo) => {
              if (sessionInfo) {
                analyzer.extract(sessionInfo.id || sessionInfo.session_id)
                analyzer.inspect(sessionInfo.id || sessionInfo.session_id)
              }
            }}
          />
        )}
        {view === 'guide' && <UserGuidePage />}
      </AnalyzerShell>

      {/* Top-level global report modal */}
      {globalReport && (
        <ReportModal
          report={globalReport}
          onClose={() => setGlobalReport(null)}
          onLaunchAttacker={() => {
            setGlobalReport(null)
            setView('attacker')
          }}
        />
      )}
    </>
  )
}

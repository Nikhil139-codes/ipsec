import {
  BarChart3,
  BookOpen,
  CheckCircle2,
  ChevronRight,
  CircleDot,
  FileCode2,
  FileText,
  Flame,
  History,
  LayoutDashboard,
  RefreshCw,
  Server,
  ShieldCheck,
  Sparkles,
  Wifi,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { type Prediction, type SecurityAnalysisResult, type View } from '@/lib/api/types'

const items: { id: View; label: string; icon: any }[] = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'analysis', label: 'PCAP Analysis', icon: FileCode2 },
  { id: 'features', label: 'Feature Extraction', icon: BarChart3 },
  { id: 'security', label: 'Security Assessment', icon: ShieldCheck },
  { id: 'attacker', label: 'Attacker Simulation', icon: Flame },
  { id: 'prediction', label: 'Traffic Classifier', icon: Sparkles },
  { id: 'testbed', label: 'IPsec Testbed', icon: Server },
  { id: 'history', label: 'VPN Records & History', icon: History },
  { id: 'guide', label: 'User Guide', icon: BookOpen },
]

export function AnalyzerShell({
  view,
  live,
  prediction,
  securityAssessment,
  sourceName,
  onView,
  onLive,
  onGenerateReport,
  children,
}: {
  view: View
  live: boolean
  prediction: Prediction | null
  securityAssessment?: SecurityAnalysisResult | null
  sourceName: string
  onView: (view: View) => void
  onLive: () => void
  onGenerateReport?: () => void
  children: React.ReactNode
}) {
  const title = items.find((item) => item.id === view)?.label

  return (
    <main className="min-h-screen bg-background text-foreground">
      <header className="flex h-16 items-center justify-between border-b bg-card px-5 lg:px-8">
        <div className="flex items-center gap-3">
          <div className="flex size-9 items-center justify-center rounded-lg bg-primary text-primary-foreground">
            <ShieldCheck className="size-5" />
          </div>
          <div>
            <p className="text-sm font-semibold tracking-tight">IPsec Analyzer</p>
            <p className="text-xs text-muted-foreground">Secure traffic intelligence</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <div className="hidden items-center gap-2 rounded-full border bg-muted/40 px-3 py-1.5 text-xs text-muted-foreground sm:flex">
            <CircleDot className="size-3 fill-emerald-500 text-emerald-500" /> Analyzer API online
          </div>
          {onGenerateReport && (
            <Button variant="outline" size="sm" onClick={onGenerateReport} className="gap-1.5 text-xs font-semibold shadow-2xs">
              <FileText className="size-3.5 text-primary" />
              Generate Security Report
            </Button>
          )}
          <Button variant="outline" size="sm" onClick={onLive}>
            <Wifi data-icon="inline-start" className={live ? 'text-emerald-600' : ''} />
            {live ? 'Live stream on' : 'Live stream'}
          </Button>
        </div>
      </header>

      <div className="flex min-h-[calc(100vh-4rem)]">
        <aside className="hidden w-60 shrink-0 border-r bg-card p-4 md:block">
          <p className="mb-3 px-3 text-[11px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
            Workspace
          </p>
          <nav className="flex flex-col gap-1">
            {items.map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                onClick={() => onView(id)}
                className={`flex items-center gap-3 rounded-md px-3 py-2.5 text-left text-sm transition-colors ${view === id
                    ? 'bg-primary/10 font-medium text-primary'
                    : 'text-muted-foreground hover:bg-muted hover:text-foreground'
                  }`}
              >
                <Icon className="size-4" />
                {label}
                {id === 'security' && securityAssessment && (
                  <CheckCircle2 className="ml-auto size-3.5 text-emerald-600" />
                )}
                {id === 'prediction' && prediction && (
                  <CheckCircle2 className="ml-auto size-3.5 text-emerald-600" />
                )}
              </button>
            ))}
          </nav>
          <div className="mt-8 border-t pt-5">
            <p className="mb-3 px-3 text-[11px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
              Capture status
            </p>
            <div className="rounded-lg bg-muted/50 p-3">
              <div className="mb-2 flex items-center gap-2 text-xs font-medium">
                <span className="size-2 rounded-full bg-emerald-500" />
                Ready to analyze
              </div>
              <p className="truncate text-xs text-muted-foreground">{sourceName}</p>
            </div>
          </div>
          <div className="flex items-center gap-2 px-3 pt-8 text-xs text-muted-foreground">
            <Server className="size-3.5" /> Docker backend connected
          </div>
        </aside>

        <section className="min-w-0 flex-1">
          <div className="border-b bg-card px-5 py-4 lg:px-8">
            <div className="mx-auto flex max-w-6xl items-center justify-between">
              <div>
                <div className="mb-1 flex items-center gap-2 text-xs text-muted-foreground">
                  <span>Workspace</span>
                  <ChevronRight className="size-3" />
                  <span className="text-foreground">{title}</span>
                </div>
                <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
              </div>
              <Button variant="ghost" size="icon" aria-label="Refresh status">
                <RefreshCw className="size-4" />
              </Button>
            </div>
          </div>
          <div className="mx-auto max-w-6xl p-5 lg:p-8">{children}</div>
        </section>
      </div>
    </main>
  )
}


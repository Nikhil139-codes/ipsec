'use client'

import {
  Upload,
  FileCode2,
  BarChart3,
  ShieldCheck,
  FileText,
  MessageSquare,
  Flame,
  Terminal,
  Brain,
  Lock,
  ArrowRight,
  CheckCircle2,
} from 'lucide-react'

export function UserGuidePage() {
  const steps = [
    {
      num: 1,
      title: 'STEP 1 — UPLOAD PCAP',
      icon: Upload,
      action: 'Upload a .pcap or .pcapng file containing IPsec traffic.',
      whatHappens: 'The system accepts the capture, initializes the parser, and creates an active analysis session.',
      output: 'Uploaded PCAP file details and metadata overview.',
    },
    {
      num: 2,
      title: 'STEP 2 — PCAP ANALYSIS',
      icon: FileCode2,
      action: 'Open PCAP Analysis and inspect the captured packets.',
      whatHappens: 'The system parses the PCAP and identifies observable network and IPsec packets such as IKE, ESP and AH.',
      output: 'Packet table containing packet number, timestamp, source, destination, protocol, and decoded info.',
    },
    {
      num: 3,
      title: 'STEP 3 — FEATURE EXTRACTION',
      icon: BarChart3,
      action: 'Open Feature Extraction or click Features.',
      whatHappens: 'The system extracts IPsec, network, flow, and statistical behavioral features from the PCAP stream.',
      outputList: [
        'Packet statistics & sizing',
        'ESP / IKE / AH protocols breakdown',
        'Encryption & cipher suite information',
        'SPI and sequence number progression',
        'Flow statistics & throughput characteristics',
        'Timing and burstiness attributes',
        'Feature observability matrix',
      ],
    },
    {
      num: 4,
      title: 'STEP 4 — SECURITY ASSESSMENT',
      icon: ShieldCheck,
      action: 'Open Security Assessment and run the security compliance evaluation.',
      whatHappens: 'The system evaluates extracted features against 8 NIST SP 800-77 & SP 800-57 security categories.',
      coverageList: [
        'Cryptographic Strength',
        'Configuration Compliance',
        'Security Association Parameters',
        'Key Lifetime',
        'Replay Protection',
        'Forward Secrecy / PFS',
        'Cipher Suite Strength',
        'Metadata Exposure',
      ],
      outputList: [
        'NIST rule-by-rule findings',
        'PASS / WARNING / FAIL status indicators',
        'Deterministic risk score (0-100)',
        'Risk level classification (LOW, MEDIUM, HIGH, CRITICAL)',
      ],
    },
    {
      num: 5,
      title: 'STEP 5 — GENERATE SECURITY REPORT',
      icon: FileText,
      action: 'Click "Generate Security Report" in the top bar or assessment panel.',
      whatHappens: 'The system compiles the extracted features, NIST compliance rules, risk score, and AI analysis into an executive security document.',
      outputList: [
        'Executive summary & risk score',
        'Detailed NIST vulnerability findings',
        'Deep AI traffic classification',
        'Prioritized actionable recommendations',
      ],
    },
    {
      num: 6,
      title: 'STEP 6 — ASK QUESTIONS USING RAG',
      icon: MessageSquare,
      action: 'Use the highlighted Interactive RAG Assistant box below the security assessment.',
      whatHappens: 'The latest security assessment is automatically grounded as the knowledge source for real-time Q&A.',
      examples: [
        'Why is my risk score high?',
        'What security weaknesses were detected?',
        'Why did configuration compliance fail?',
        'Was PFS detected in IKE exchanges?',
        'What should I fix first?',
      ],
      output: 'AI-generated answers strictly grounded in your active security assessment data.',
    },
    {
      num: 7,
      title: 'STEP 7 — ATTACKER SIMULATION',
      icon: Flame,
      action: 'Open "Attacker Simulation" from the navigation menu.',
      whatHappens: 'The system reads the latest security findings and identifies vulnerabilities that can be validated in the authorized testbed.',
      outputList: [
        'Detected configuration weakness',
        'Suggested non-destructive security test',
        'Suggested terminal verification command',
        'Expected verification result & rationale',
      ],
    },
    {
      num: 8,
      title: 'STEP 8 — SECURITY TEST RESULT',
      icon: Terminal,
      action: 'Execute the suggested test inside the prototype VPN Test Terminal.',
      whatHappens: 'The terminal simulates the security test against the testbed and displays the raw execution results.',
      outputList: [
        'Simulated test execution status',
        'Simulated weakness / breaking point',
        'Security impact evaluation & severity',
      ],
      note: 'Clearly labeled as prototype simulation results for authorized hardening.',
    },
    {
      num: 9,
      title: 'STEP 9 — AI ATTACK PATH ANALYSIS',
      icon: Brain,
      action: 'Review the AI attack-path tree generated after the simulated validation test.',
      whatHappens: 'AI analyzes the simulated weakness and constructs an interactive attack-path visualization showing what an adversary could attempt.',
      outputList: [
        'Validated weakness entry node',
        'Potential lateral exploit impact',
        'Multi-stage attacker next steps',
        'Recommended hardening controls',
      ],
    },
    {
      num: 10,
      title: 'STEP 10 — HARDEN THE VPN',
      icon: Lock,
      action: 'Apply the recommendations to strengthen strongSwan / IPsec configuration.',
      whatHappens: 'Update encryption ciphers, integrity algorithms, and DH groups in the testbed or production gateway.',
      output: 'A verified, hardened VPN configuration compliant with modern NIST cryptographic guidelines.',
    },
  ]

  return (
    <div className="max-w-4xl mx-auto space-y-6 py-2 text-foreground">
      {/* Title & Subtitle */}
      <div className="border-b pb-4">
        <h1 className="text-2xl font-bold tracking-tight text-foreground sm:text-3xl">
          User Guide
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Follow these structured steps to analyze, evaluate, and harden your IPsec network traffic.
        </p>
      </div>

      {/* Steps List - Each step in a dedicated light-background box */}
      <div className="flex flex-col gap-4">
        {steps.map((s) => {
          const Icon = s.icon
          return (
            <div
              key={s.num}
              className="rounded-xl border border-border/80 bg-card/60 hover:bg-card p-5 md:p-6 shadow-xs hover:shadow-sm hover:border-primary/40 transition-all"
            >
              {/* Step Header */}
              <div className="flex items-center gap-3 border-b pb-3 mb-4">
                <div className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary font-bold text-xs">
                  {s.num}
                </div>
                <h2 className="text-base font-bold tracking-tight text-foreground flex items-center gap-2">
                  <Icon className="size-4 text-primary" />
                  {s.title}
                </h2>
              </div>

              {/* Step Content */}
              <div className="space-y-3.5 text-xs sm:text-sm leading-relaxed">
                <div>
                  <span className="font-semibold text-foreground flex items-center gap-1.5 mb-1">
                    <ArrowRight className="size-3.5 text-primary" />
                    User Action:
                  </span>
                  <p className="text-muted-foreground pl-5">{s.action}</p>
                </div>

                <div>
                  <span className="font-semibold text-foreground flex items-center gap-1.5 mb-1">
                    <CheckCircle2 className="size-3.5 text-emerald-600" />
                    What happens:
                  </span>
                  <p className="text-muted-foreground pl-5">{s.whatHappens}</p>
                  {s.coverageList && (
                    <div className="pl-5 mt-2">
                      <p className="text-xs font-semibold text-foreground/90 mb-1">Covers 8 security categories:</p>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-1 text-xs text-muted-foreground">
                        {s.coverageList.map((c, i) => (
                          <div key={i} className="flex items-center gap-1.5">
                            <span className="text-primary font-bold">•</span>
                            <span>{c}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {s.examples && (
                    <div className="pl-5 mt-2">
                      <p className="text-xs font-semibold text-foreground/90 mb-1">Example questions:</p>
                      <div className="flex flex-wrap gap-1.5">
                        {s.examples.map((ex, i) => (
                          <span
                            key={i}
                            className="rounded-md border bg-muted/40 px-2 py-0.5 text-xs text-muted-foreground"
                          >
                            &quot;{ex}&quot;
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                <div>
                  <span className="font-semibold text-foreground flex items-center gap-1.5 mb-1">
                    <span className="size-1.5 rounded-full bg-primary" />
                    Output:
                  </span>
                  {s.output && <p className="text-muted-foreground pl-5">{s.output}</p>}
                  {s.outputList && (
                    <ul className="list-disc pl-9 space-y-1 text-xs text-muted-foreground">
                      {s.outputList.map((item, i) => (
                        <li key={i}>{item}</li>
                      ))}
                    </ul>
                  )}
                  {s.note && (
                    <p className="text-xs italic text-muted-foreground pl-5 mt-1.5">
                      {s.note}
                    </p>
                  )}
                </div>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

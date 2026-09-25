'use client'

export function UserGuidePage() {
  return (
    <div className="max-w-4xl mx-auto space-y-8 py-2 text-foreground">
      {/* Title & Subtitle */}
      <div className="border-b pb-4">
        <h1 className="text-2xl font-bold tracking-tight text-foreground sm:text-3xl">
          User Guide
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Follow these steps to analyze and assess your IPsec traffic.
        </p>
      </div>

      <div className="space-y-8 divide-y divide-border">
        {/* STEP 1 */}
        <section className="pt-6 first:pt-0 space-y-3">
          <h2 className="text-base font-bold tracking-tight text-foreground">
            STEP 1 — UPLOAD PCAP
          </h2>
          <div className="space-y-2.5 text-sm leading-relaxed pl-1">
            <div>
              <span className="font-semibold text-foreground">User Action:</span>
              <p className="text-muted-foreground mt-0.5">
                Upload a .pcap or .pcapng file containing IPsec traffic.
              </p>
            </div>
            <div>
              <span className="font-semibold text-foreground">What happens:</span>
              <p className="text-muted-foreground mt-0.5">
                The system accepts the capture and creates an analysis session.
              </p>
            </div>
            <div>
              <span className="font-semibold text-foreground">Output:</span>
              <p className="text-muted-foreground mt-0.5">
                Uploaded PCAP and capture information.
              </p>
            </div>
          </div>
        </section>

        {/* STEP 2 */}
        <section className="pt-6 space-y-3">
          <h2 className="text-base font-bold tracking-tight text-foreground">
            STEP 2 — PCAP ANALYSIS
          </h2>
          <div className="space-y-2.5 text-sm leading-relaxed pl-1">
            <div>
              <span className="font-semibold text-foreground">User Action:</span>
              <p className="text-muted-foreground mt-0.5">
                Open PCAP Analysis and inspect the captured packets.
              </p>
            </div>
            <div>
              <span className="font-semibold text-foreground">What happens:</span>
              <p className="text-muted-foreground mt-0.5">
                The system parses the PCAP and identifies observable network and IPsec packets such as IKE, ESP and AH.
              </p>
            </div>
            <div>
              <span className="font-semibold text-foreground">Output:</span>
              <p className="text-muted-foreground mt-0.5">
                Packet table containing source, destination, protocol and packet information.
              </p>
            </div>
          </div>
        </section>

        {/* STEP 3 */}
        <section className="pt-6 space-y-3">
          <h2 className="text-base font-bold tracking-tight text-foreground">
            STEP 3 — FEATURE EXTRACTION
          </h2>
          <div className="space-y-2.5 text-sm leading-relaxed pl-1">
            <div>
              <span className="font-semibold text-foreground">User Action:</span>
              <p className="text-muted-foreground mt-0.5">
                Click &quot;Extract Features&quot;.
              </p>
            </div>
            <div>
              <span className="font-semibold text-foreground">What happens:</span>
              <p className="text-muted-foreground mt-0.5">
                The system extracts IPsec, network, flow and statistical features from the PCAP.
              </p>
            </div>
            <div>
              <span className="font-semibold text-foreground">Output:</span>
              <div className="text-muted-foreground mt-0.5">
                <p>Structured feature data including:</p>
                <ul className="list-disc pl-5 mt-1 space-y-1">
                  <li>Packet statistics</li>
                  <li>ESP/IKE/AH information</li>
                  <li>Encryption-related information</li>
                  <li>SPI and sequence information</li>
                  <li>Flow statistics</li>
                  <li>Timing and traffic characteristics</li>
                  <li>Feature observability</li>
                </ul>
              </div>
            </div>
          </div>
        </section>

        {/* STEP 4 */}
        <section className="pt-6 space-y-3">
          <h2 className="text-base font-bold tracking-tight text-foreground">
            STEP 4 — SECURITY ASSESSMENT
          </h2>
          <div className="space-y-2.5 text-sm leading-relaxed pl-1">
            <div>
              <span className="font-semibold text-foreground">User Action:</span>
              <p className="text-muted-foreground mt-0.5">
                Open Security Assessment and run the assessment.
              </p>
            </div>
            <div>
              <span className="font-semibold text-foreground">What happens:</span>
              <div className="text-muted-foreground mt-0.5">
                <p>The system evaluates the extracted features using NIST-based security rules.</p>
                <p className="mt-1.5 font-medium text-foreground/90">The assessment covers:</p>
                <ul className="list-disc pl-5 mt-1 space-y-1">
                  <li>Cryptographic Strength</li>
                  <li>Configuration Compliance</li>
                  <li>Security Association Parameters</li>
                  <li>Key Lifetime</li>
                  <li>Replay Protection</li>
                  <li>Forward Secrecy / PFS</li>
                  <li>Cipher Suite Strength</li>
                  <li>Metadata Exposure</li>
                </ul>
              </div>
            </div>
            <div>
              <span className="font-semibold text-foreground">Output:</span>
              <ul className="list-disc pl-5 mt-1 space-y-1 text-muted-foreground">
                <li>NIST findings</li>
                <li>PASS / WARNING / FAIL / NOT OBSERVABLE</li>
                <li>Risk factors</li>
                <li>Deterministic risk score</li>
                <li>Risk level</li>
              </ul>
            </div>
          </div>
        </section>

        {/* STEP 5 */}
        <section className="pt-6 space-y-3">
          <h2 className="text-base font-bold tracking-tight text-foreground">
            STEP 5 — GENERATE SECURITY REPORT
          </h2>
          <div className="space-y-2.5 text-sm leading-relaxed pl-1">
            <div>
              <span className="font-semibold text-foreground">User Action:</span>
              <p className="text-muted-foreground mt-0.5">
                Click &quot;Generate Security Report&quot;.
              </p>
            </div>
            <div>
              <span className="font-semibold text-foreground">What happens:</span>
              <p className="text-muted-foreground mt-0.5">
                The system combines the extracted features, NIST assessment, risk score and AI analysis into a final security report.
              </p>
            </div>
            <div>
              <span className="font-semibold text-foreground">Output:</span>
              <div className="text-muted-foreground mt-0.5">
                <p>Complete Security Assessment Report containing:</p>
                <ul className="list-disc pl-5 mt-1 space-y-1">
                  <li>Security findings</li>
                  <li>Risk score</li>
                  <li>Risk level</li>
                  <li>AI analysis</li>
                  <li>Traffic classification</li>
                  <li>Recommendations</li>
                </ul>
              </div>
            </div>
          </div>
        </section>

        {/* STEP 6 */}
        <section className="pt-6 space-y-3">
          <h2 className="text-base font-bold tracking-tight text-foreground">
            STEP 6 — ASK QUESTIONS USING RAG
          </h2>
          <div className="space-y-2.5 text-sm leading-relaxed pl-1">
            <div>
              <span className="font-semibold text-foreground">User Action:</span>
              <p className="text-muted-foreground mt-0.5">
                Open the RAG/report assistant below the generated report.
              </p>
            </div>
            <div>
              <span className="font-semibold text-foreground">What happens:</span>
              <div className="text-muted-foreground mt-0.5">
                <p>
                  The latest generated security report is automatically used as the knowledge source.
                </p>
                <p className="mt-1">
                  The user can ask questions about that specific report.
                </p>
                <p className="mt-2 font-medium text-foreground/90">Examples:</p>
                <ul className="list-disc pl-5 mt-1 space-y-1">
                  <li>Why is my risk score high?</li>
                  <li>What security weaknesses were detected?</li>
                  <li>Why did configuration compliance fail?</li>
                  <li>Was PFS detected?</li>
                  <li>What should I fix first?</li>
                </ul>
              </div>
            </div>
            <div>
              <span className="font-semibold text-foreground">Output:</span>
              <p className="text-muted-foreground mt-0.5">
                AI-generated answers grounded in the current security report.
              </p>
            </div>
          </div>
        </section>

        {/* STEP 7 */}
        <section className="pt-6 space-y-3">
          <h2 className="text-base font-bold tracking-tight text-foreground">
            STEP 7 — ATTACKER SIMULATION
          </h2>
          <div className="space-y-2.5 text-sm leading-relaxed pl-1">
            <div>
              <span className="font-semibold text-foreground">User Action:</span>
              <p className="text-muted-foreground mt-0.5">
                Open &quot;Attacker Simulation&quot;.
              </p>
            </div>
            <div>
              <span className="font-semibold text-foreground">What happens:</span>
              <div className="text-muted-foreground mt-0.5">
                <p>
                  The system reads the latest security assessment and identifies weaknesses that can be validated in the authorized VPN test environment.
                </p>
                <p className="mt-1">
                  Groq AI suggests controlled security validation tests.
                </p>
              </div>
            </div>
            <div>
              <span className="font-semibold text-foreground">Output:</span>
              <ul className="list-disc pl-5 mt-1 space-y-1 text-muted-foreground">
                <li>Detected weakness</li>
                <li>Suggested security test</li>
                <li>Suggested command</li>
                <li>Reason for the test</li>
                <li>Expected result</li>
              </ul>
              <p className="text-muted-foreground mt-2">
                The user can then manually enter the suggested command into the prototype VPN Test Terminal.
              </p>
            </div>
          </div>
        </section>

        {/* STEP 8 */}
        <section className="pt-6 space-y-3">
          <h2 className="text-base font-bold tracking-tight text-foreground">
            STEP 8 — SECURITY TEST RESULT
          </h2>
          <div className="space-y-2.5 text-sm leading-relaxed pl-1">
            <div>
              <span className="font-semibold text-foreground">User Action:</span>
              <p className="text-muted-foreground mt-0.5">
                Execute the suggested test inside the prototype terminal.
              </p>
            </div>
            <div>
              <span className="font-semibold text-foreground">What happens:</span>
              <p className="text-muted-foreground mt-0.5">
                The terminal simulates the security test and displays the result.
              </p>
            </div>
            <div>
              <span className="font-semibold text-foreground">Output:</span>
              <ul className="list-disc pl-5 mt-1 space-y-1 text-muted-foreground">
                <li>Test status</li>
                <li>Simulated weakness/breaking point</li>
                <li>Security impact</li>
                <li>Severity</li>
              </ul>
              <p className="text-xs text-muted-foreground italic mt-2">
                Note: Clearly labeled as simulated/prototype results.
              </p>
            </div>
          </div>
        </section>

        {/* STEP 9 */}
        <section className="pt-6 space-y-3">
          <h2 className="text-base font-bold tracking-tight text-foreground">
            STEP 9 — AI ATTACK PATH ANALYSIS
          </h2>
          <div className="space-y-2.5 text-sm leading-relaxed pl-1">
            <div>
              <span className="font-semibold text-foreground">User Action:</span>
              <p className="text-muted-foreground mt-0.5">
                Review the AI attack-path analysis after the simulated test.
              </p>
            </div>
            <div>
              <span className="font-semibold text-foreground">What happens:</span>
              <p className="text-muted-foreground mt-0.5">
                Groq analyzes the validated/simulated weakness and explains the potential next step an attacker could attempt.
              </p>
            </div>
            <div>
              <span className="font-semibold text-foreground">Output:</span>
              <ul className="list-disc pl-5 mt-1 space-y-1 text-muted-foreground">
                <li>Validated weakness</li>
                <li>Potential impact</li>
                <li>Potential attacker next step</li>
                <li>Recommended hardening</li>
              </ul>
            </div>
          </div>
        </section>

        {/* STEP 10 */}
        <section className="pt-6 space-y-3">
          <h2 className="text-base font-bold tracking-tight text-foreground">
            STEP 10 — HARDEN THE VPN
          </h2>
          <div className="space-y-2.5 text-sm leading-relaxed pl-1">
            <div>
              <span className="font-semibold text-foreground">User Action:</span>
              <p className="text-muted-foreground mt-0.5">
                Review the recommendations and strengthen the VPN configuration.
              </p>
            </div>
            <div>
              <span className="font-semibold text-foreground">Output:</span>
              <p className="text-muted-foreground mt-0.5">
                A list of recommended security improvements.
              </p>
            </div>
          </div>
        </section>
      </div>
    </div>
  )
}

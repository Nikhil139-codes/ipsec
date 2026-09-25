import { apiRequest, delay, useMockApi } from './client'
import {
  type AttackerCommand,
  type AttackerTest,
  type AttackerTestPlanResponse,
  type AttackPathAnalysis,
  type SecurityAnalysisResult,
  type SimulatedTestResult,
} from './types'

const STORAGE_KEY_LATEST_REPORT = 'ipsec_latest_security_assessment'

/**
 * Persists the latest security assessment report to sessionStorage
 * so that /attacker can access it seamlessly across navigation or refreshes.
 */
export function storeLatestReportLocally(report: SecurityAnalysisResult): void {
  if (typeof window === 'undefined') return
  try {
    sessionStorage.setItem(STORAGE_KEY_LATEST_REPORT, JSON.stringify(report))
  } catch {
    // Ignore storage quota or disabled storage
  }
}

/**
 * Retrieves the latest security assessment report from the backend or local storage.
 * Returns null if no report has been generated yet.
 */
export async function getLatestSecurityReport(): Promise<SecurityAnalysisResult | null> {
  // 1. Try fetching from FastAPI backend if connected
  if (!useMockApi) {
    try {
      const remote = await apiRequest<SecurityAnalysisResult>('/api/attacker/latest-report')
      if (remote && (remote.nist_assessment || remote.observed_features)) {
        storeLatestReportLocally(remote)
        return remote
      }
    } catch {
      // Backend may not have an active session yet or is offline, check local storage
    }
  }

  // 2. Check local session storage (populated when user runs PCAP analysis or Security Assessment)
  if (typeof window !== 'undefined') {
    try {
      const stored = sessionStorage.getItem(STORAGE_KEY_LATEST_REPORT)
      if (stored) {
        const parsed = JSON.parse(stored) as SecurityAnalysisResult
        if (parsed && (parsed.nist_assessment || parsed.observed_features)) {
          return parsed
        }
      }
    } catch {
      // Ignore parse failure
    }
  }

  return null
}

/**
 * Sends the latest security assessment report data to Groq to generate controlled validation tests.
 * Never sends raw PCAP data.
 */
export async function generateAttackerTests(
  reportData?: SecurityAnalysisResult | null,
  sessionId?: string
): Promise<AttackerTestPlanResponse> {
  if (!useMockApi) {
    try {
      const res = await apiRequest<AttackerTestPlanResponse>('/api/attacker/generate-tests', {
        method: 'POST',
        body: JSON.stringify({
          session_id: sessionId || reportData?.session_id,
          report_data: reportData || undefined,
        }),
      })
      if (res && res.tests && res.tests.length > 0) {
        return res
      }
    } catch (err: any) {
      // Groq error handling per requirement 11:
      // Show "AI attack-test generation is temporarily unavailable."
      // Never expose API keys or server stack traces
      return {
        tests: buildDeterministicFallbackTests(reportData),
        status: 'fallback',
        message: 'AI attack-test generation is temporarily unavailable.',
      }
    }
  }

  await delay(600)
  return {
    tests: buildDeterministicFallbackTests(reportData),
    status: 'fallback',
    message: null,
  }
}

/**
 * Simulates execution of predefined test commands in the dummy VPN test terminal.
 * Correlates findings with the latest security report.
 * Strictly non-destructive and prototype-safe.
 */
export function executeSimulatedCommand(
  rawCommand: string,
  reportData?: SecurityAnalysisResult | null
): SimulatedTestResult {
  const trimmed = rawCommand.trim()
  const lower = trimmed.toLowerCase()
  const now = new Date().toLocaleTimeString('en-US', { hour12: false })

  const nistChecks = reportData?.nist_assessment?.checks || []

  // Helper to find check by category substring
  const findCheck = (catKeywords: string[]) => {
    return nistChecks.find((c) =>
      catKeywords.some((k) => c.category.toLowerCase().includes(k.toLowerCase()))
    )
  }

  // 1. PFS Configuration Validation
  if (lower === 'pfs-test') {
    const pfsCheck = findCheck(['pfs', 'forward secrecy'])
    const isWeak = pfsCheck ? pfsCheck.status === 'FAIL' || pfsCheck.status === 'WARNING' : true

    const terminal_output = [
      `user@vpn-lab:~$ pfs-test`,
      `[INFO] Starting security validation...`,
      `[INFO] Loading VPN security profile...`,
      `[INFO] Target interface: ipsec0 (CHILD_SA)`,
      `[INFO] Querying Diffie-Hellman transform proposals...`,
    ]

    if (isWeak) {
      terminal_output.push(
        `[WARNING] Ephemeral key exchange absent in CREATE_CHILD_SA proposal`,
        `[WARNING] PFS requirement not enforced`,
        ` `,
        `TEST RESULT: FAILED`
      )
      return {
        command: 'pfs-test',
        test_title: 'PFS Configuration Validation',
        status: 'WEAKNESS CONFIRMED',
        breaking_point: 'PFS configuration is not enforced according to the simulated VPN security profile.',
        security_impact: 'This configuration may provide weaker key-establishment security.',
        severity: 'HIGH',
        terminal_output,
        tested_at: now,
      }
    } else {
      terminal_output.push(
        `[INFO] Ephemeral Diffie-Hellman Group 14 (MODP-2048) active`,
        `[INFO] Perfect Forward Secrecy is strictly enforced`,
        ` `,
        `TEST RESULT: PASSED`
      )
      return {
        command: 'pfs-test',
        test_title: 'PFS Configuration Validation',
        status: 'CONTROLS EFFECTIVE',
        breaking_point: 'None observed. Ephemeral Diffie-Hellman exchange is actively enforced on all CHILD_SAs.',
        security_impact: 'Forward secrecy guarantees are operational against passive retrospective decryption.',
        severity: 'LOW',
        terminal_output,
        tested_at: now,
      }
    }
  }

  // 2. Replay Protection Validation
  if (lower === 'replay-test') {
    const replayCheck = findCheck(['replay'])
    const isWeak = replayCheck ? replayCheck.status === 'FAIL' || replayCheck.status === 'WARNING' : false

    const terminal_output = [
      `user@vpn-lab:~$ replay-test`,
      `[INFO] Starting security validation...`,
      `[INFO] Intercepting inbound ESP sequence numbers...`,
      `[INFO] Current sequence window bounds: [1024..1088]`,
      `[INFO] Transmitting duplicate sequence frame (ESP Seq #1024)...`,
    ]

    if (isWeak) {
      terminal_output.push(
        `[WARNING] Duplicate ESP frame accepted by receiver stack`,
        `[WARNING] Replay protection window validation failed`,
        ` `,
        `TEST RESULT: FAILED`
      )
      return {
        command: 'replay-test',
        test_title: 'Replay Protection Validation',
        status: 'WEAKNESS CONFIRMED',
        breaking_point: 'Anti-replay sliding window did not reject duplicated sequence numbers.',
        security_impact: 'Adversary could replay historical ciphertext packets to cause application desynchronization.',
        severity: 'HIGH',
        terminal_output,
        tested_at: now,
      }
    } else {
      terminal_output.push(
        `[INFO] Duplicate sequence frame rejected (ESP anti-replay drop counter incremented)`,
        `[INFO] Monotonic sequence counter validation verified`,
        ` `,
        `TEST RESULT: PASSED`
      )
      return {
        command: 'replay-test',
        test_title: 'Replay Protection Validation',
        status: 'CONTROLS EFFECTIVE',
        breaking_point: 'None observed. Anti-replay sliding window successfully drops out-of-window and duplicate packets.',
        security_impact: 'Simulated anti-replay filters prevent unauthorized payload re-injection.',
        severity: 'LOW',
        terminal_output,
        tested_at: now,
      }
    }
  }

  // 3. Cipher Configuration Validation
  if (lower === 'cipher-test') {
    const cipherCheck = findCheck(['cipher', 'cryptographic strength'])
    const isWeak = cipherCheck ? cipherCheck.status === 'FAIL' || cipherCheck.status === 'WARNING' : false

    const terminal_output = [
      `user@vpn-lab:~$ cipher-test`,
      `[INFO] Starting security validation...`,
      `[INFO] Auditing negotiated cryptographic transform suite...`,
      `[INFO] Inspecting ESP encryption & authentication transforms...`,
    ]

    if (isWeak) {
      terminal_output.push(
        `[WARNING] Deprecated or non-AEAD transform active in proposal`,
        `[WARNING] Cipher configuration compliance failure`,
        ` `,
        `TEST RESULT: FAILED`
      )
      return {
        command: 'cipher-test',
        test_title: 'Cipher Configuration Validation',
        status: 'WEAKNESS CONFIRMED',
        breaking_point: 'Cipher suite does not comply with modern authenticated encryption requirements.',
        security_impact: 'Potential exposure to padding-oracle or bit-flipping attacks under hostile network interception.',
        severity: 'HIGH',
        terminal_output,
        tested_at: now,
      }
    } else {
      terminal_output.push(
        `[INFO] Observed AES-256-GCM AEAD encryption with 256-bit key length`,
        `[INFO] Cryptographic transform strictly complies with NIST SP 800-77 guidance`,
        ` `,
        `TEST RESULT: PASSED`
      )
      return {
        command: 'cipher-test',
        test_title: 'Cipher Configuration Validation',
        status: 'CONTROLS EFFECTIVE',
        breaking_point: 'None observed. Modern AES-256-GCM authenticated encryption verified.',
        security_impact: 'Symmetric confidentiality and message authenticity meet high-assurance standards.',
        severity: 'LOW',
        terminal_output,
        tested_at: now,
      }
    }
  }

  // 4. Security Association Parameters Validation
  if (lower === 'sa-test') {
    const saCheck = findCheck(['security association', 'sa parameters', 'key lifetime'])
    const isWeak = saCheck ? saCheck.status === 'FAIL' || saCheck.status === 'WARNING' : false

    const terminal_output = [
      `user@vpn-lab:~$ sa-test`,
      `[INFO] Starting security validation...`,
      `[INFO] Inspecting active Security Association database (SAD)...`,
      `[INFO] Checking SPI allocation and rekey thresholds...`,
    ]

    if (isWeak) {
      terminal_output.push(
        `[WARNING] Unconstrained SA lifetime detected; missing rekey renegotiation bounds`,
        `[WARNING] SA parameter validation threshold exceeded`,
        ` `,
        `TEST RESULT: FAILED`
      )
      return {
        command: 'sa-test',
        test_title: 'Security Association Validation',
        status: 'WEAKNESS CONFIRMED',
        breaking_point: 'Security Association lifetime bounds exceed recommended thresholds.',
        security_impact: 'Prolonged key utilization increases susceptibility to cryptanalytic pattern harvesting.',
        severity: 'MEDIUM',
        terminal_output,
        tested_at: now,
      }
    } else {
      terminal_output.push(
        `[INFO] Valid SPI pair negotiated with active sequence tracking`,
        `[INFO] Security Association parameters within policy bounds`,
        ` `,
        `TEST RESULT: PASSED`
      )
      return {
        command: 'sa-test',
        test_title: 'Security Association Validation',
        status: 'CONTROLS EFFECTIVE',
        breaking_point: 'None observed. Security Associations conform to standard lifetime parameters.',
        security_impact: 'Active rekey boundaries ensure key material freshness.',
        severity: 'LOW',
        terminal_output,
        tested_at: now,
      }
    }
  }

  // 5. Metadata Exposure Validation
  if (lower === 'metadata-test') {
    const metaCheck = findCheck(['metadata'])
    const isWeak = metaCheck ? metaCheck.status === 'FAIL' || metaCheck.status === 'WARNING' : true

    const terminal_output = [
      `user@vpn-lab:~$ metadata-test`,
      `[INFO] Starting security validation...`,
      `[INFO] Analyzing outer packet headers and inter-arrival timing...`,
      `[INFO] Evaluating traffic flow confidentiality (RFC 4303 Section 2.7)...`,
    ]

    if (isWeak) {
      terminal_output.push(
        `[WARNING] Outer IPs, SPIs, and distinctive packet size bursts visible in cleartext`,
        `[WARNING] Absence of traffic padding exposes application signatures to passive eavesdropping`,
        ` `,
        `TEST RESULT: FAILED`
      )
      return {
        command: 'metadata-test',
        test_title: 'Metadata Exposure Validation',
        status: 'WEAKNESS CONFIRMED',
        breaking_point: 'Outer network metadata and packet burst distributions remain observable.',
        security_impact: 'Passive observers can conduct statistical traffic fingerprinting and infer communication activity.',
        severity: 'MEDIUM',
        terminal_output,
        tested_at: now,
      }
    } else {
      terminal_output.push(
        `[INFO] Uniform packet lengths and constant-rate cover traffic observed`,
        `[INFO] Traffic flow confidentiality actively obscures burst signatures`,
        ` `,
        `TEST RESULT: PASSED`
      )
      return {
        command: 'metadata-test',
        test_title: 'Metadata Exposure Validation',
        status: 'CONTROLS EFFECTIVE',
        breaking_point: 'None observed. Traffic padding prevents observable flow variance.',
        security_impact: 'Traffic analysis resistance verified against passive metadata inspection.',
        severity: 'LOW',
        terminal_output,
        tested_at: now,
      }
    }
  }

  // 6. Help Command
  if (lower === 'help') {
    return {
      command: 'help',
      test_title: 'Help Menu',
      status: 'VALIDATION COMPLETE',
      breaking_point: 'N/A',
      security_impact: 'N/A',
      severity: 'LOW',
      terminal_output: [
        `user@vpn-lab:~$ help`,
        `Authorized VPN Test Commands:`,
        `  pfs-test       - Validate Perfect Forward Secrecy (PFS) configuration`,
        `  replay-test    - Validate anti-replay window and sequence progression`,
        `  cipher-test    - Validate encryption and authentication algorithm strength`,
        `  sa-test        - Validate Security Association parameters & lifetime`,
        `  metadata-test  - Validate metadata exposure & traffic analysis resistance`,
        `  clear          - Clear terminal display`,
        `  help           - Display this list of authorized simulation commands`,
      ],
      tested_at: now,
    }
  }

  // 7. Clear Command
  if (lower === 'clear') {
    return {
      command: 'clear',
      test_title: 'Clear Terminal',
      status: 'VALIDATION COMPLETE',
      breaking_point: 'N/A',
      security_impact: 'N/A',
      severity: 'LOW',
      terminal_output: [],
      tested_at: now,
    }
  }

  // 8. Unsupported / Unauthorized Command
  return {
    command: rawCommand,
    test_title: 'Unauthorized Command',
    status: 'COMMAND REJECTED',
    breaking_point: 'Execution denied: Command not permitted in authorized test environment.',
    security_impact: 'Only predefined non-destructive security validation tests are authorized.',
    severity: 'LOW',
    terminal_output: [
      `user@vpn-lab:~$ ${rawCommand}`,
      `[ERROR] Command not permitted in authorized test environment.`,
      `Only predefined non-destructive security validation tests are authorized.`,
      `Type 'help' to view available simulation commands:`,
      `  pfs-test, replay-test, cipher-test, sa-test, metadata-test`,
    ],
    tested_at: now,
  }
}

/**
 * Submits the test result and detected weakness to Groq AI
 * to analyze potential attacker next-steps and recommended hardening.
 */
export async function analyzeAttackPath(
  command: string,
  weakness: string,
  simulatedResult: SimulatedTestResult,
  reportSummary?: any
): Promise<AttackPathAnalysis> {
  if (!useMockApi) {
    try {
      const res = await apiRequest<AttackPathAnalysis>('/api/attacker/attack-path', {
        method: 'POST',
        body: JSON.stringify({
          command,
          weakness,
          simulated_result: simulatedResult,
          report_summary: reportSummary,
        }),
      })
      if (res && res.potential_impact && res.attacker_next_step) {
        return res
      }
    } catch {
      // Fallback below
    }
  }

  await delay(600)
  return buildFallbackAttackPath(command, weakness)
}

/**
 * Fallback tests when Groq is temporarily unreachable or mock mode is active.
 */
function buildDeterministicFallbackTests(reportData?: SecurityAnalysisResult | null): AttackerTest[] {
  const nist = reportData?.nist_assessment?.checks || []
  const weaknesses = nist.filter((c) => c.status === 'WARNING' || c.status === 'FAIL')

  const tests: AttackerTest[] = []
  let idx = 1

  // 1. PFS Test
  const pfsCheck = nist.find((c) => c.category.toLowerCase().includes('pfs') || c.category.toLowerCase().includes('forward secrecy'))
  tests.push({
    id: `TEST-${String(idx++).padStart(3, '0')}`,
    title: 'PFS Configuration Validation',
    reason: pfsCheck?.reason || 'PFS-related weakness was identified in the report.',
    command: 'pfs-test',
    expected_result: 'PFS requirement is not enforced',
    potential_impact: 'Weaker key-establishment security',
    next_step: 'Analyze the VPN configuration for additional weaknesses',
  })

  // 2. Replay Test
  const replayCheck = nist.find((c) => c.category.toLowerCase().includes('replay'))
  tests.push({
    id: `TEST-${String(idx++).padStart(3, '0')}`,
    title: 'Replay Protection Validation',
    reason: replayCheck?.reason || 'Replay protection window evaluation based on ESP sequence counters.',
    command: 'replay-test',
    expected_result: 'Simulated duplicate sequence frames tested against sliding window',
    potential_impact: 'Replay attacks could reinject historical encrypted payload',
    next_step: 'Verify anti-replay window size configuration in IPsec daemon',
  })

  // 3. Cipher Configuration
  const cipherCheck = nist.find((c) => c.category.toLowerCase().includes('cipher') || c.category.toLowerCase().includes('cryptographic strength'))
  tests.push({
    id: `TEST-${String(idx++).padStart(3, '0')}`,
    title: 'Cipher Suite Strength Validation',
    reason: cipherCheck?.reason || 'Cryptographic transform parameters evaluated against NIST SP 800-57.',
    command: 'cipher-test',
    expected_result: 'Validate encryption algorithm and key length compliance',
    potential_impact: 'Use of non-AEAD or weak transforms reduces confidentiality assurance',
    next_step: 'Enforce AES-256-GCM AEAD encryption',
  })

  // 4. Metadata Exposure
  const metaCheck = nist.find((c) => c.category.toLowerCase().includes('metadata'))
  if (metaCheck) {
    tests.push({
      id: `TEST-${String(idx++).padStart(3, '0')}`,
      title: 'Traffic Metadata Exposure Validation',
      reason: metaCheck.reason || 'Outer IP and timing signatures observable in network telemetry.',
      command: 'metadata-test',
      expected_result: 'Assess exposure of cleartext outer headers and packet lengths',
      potential_impact: 'Passive traffic analysis and communication profiling',
      next_step: 'Deploy IPsec Traffic Flow Confidentiality or constant padding',
    })
  }

  return tests
}

function buildFallbackAttackPath(command: string, weakness: string): AttackPathAnalysis {
  const cmd = command.toLowerCase()

  if (cmd.includes('pfs')) {
    return {
      validated_weakness: weakness || 'PFS Configuration Weakness',
      potential_impact:
        'Without Perfect Forward Secrecy enforced, compromise of long-term server private keys or credentials could enable retrospective decryption of past recorded tunnel sessions.',
      attacker_next_step:
        'An adversary may prioritize recording and archiving encrypted ESP sessions while launching credential-harvesting or key-exfiltration attacks against endpoints.',
      recommended_hardening:
        'Enforce Diffie-Hellman Group 14 (MODP-2048) or Group 19 (ECDH-256) on all CHILD_SA renegotiations in strongSwan / IPsec policy.',
    }
  }

  if (cmd.includes('replay')) {
    return {
      validated_weakness: weakness || 'Replay Protection Weakness',
      potential_impact:
        'Permitting duplicate or out-of-order sequence numbers enables unauthorized packet re-injection, potentially disrupting application state or causing replay attacks.',
      attacker_next_step:
        'Attacker may intercept valid encrypted packets and inject duplicate frames onto the wire to desynchronize TCP connections or trigger replay vulnerabilities.',
      recommended_hardening:
        'Enable standard 64-packet (or 128-packet) anti-replay sliding window on the ESP receiver stack and enforce strict drop policy.',
    }
  }

  if (cmd.includes('cipher')) {
    return {
      validated_weakness: weakness || 'Cipher Configuration Weakness',
      potential_impact:
        'Non-AEAD ciphers or legacy transforms without message authenticity reduce data integrity and increase vulnerability to bit-flipping attacks.',
      attacker_next_step:
        'Attacker positioned as a man-in-the-middle may alter encrypted ESP ciphertext bits to evaluate integrity verification behavior.',
      recommended_hardening:
        'Migrate all IPsec proposals to AES-256-GCM or ChaCha20-Poly1305 authenticated encryption per NIST SP 800-77 Rev. 1 Section 3.3.',
    }
  }

  return {
    validated_weakness: weakness || 'Observed VPN Weakness',
    potential_impact:
      'Configuration discrepancies reduce the defense-in-depth posture of the IPsec tunnel interface.',
    attacker_next_step:
      'Attacker may perform deeper reconnaissance on IKE proposal negotiations and packet timing characteristics.',
    recommended_hardening:
      'Review strongSwan IPsec configuration profiles against NIST SP 800-77 Rev. 1 benchmarks.',
  }
}

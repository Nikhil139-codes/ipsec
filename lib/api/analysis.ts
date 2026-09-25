import { apiRequest, delay, useMockApi } from './client'
import { type Features, type Prediction, type RagChatResponse, type SecurityAnalysisResult } from './types'

export async function extractFeatures(sessionId?: string): Promise<Features> {
  if (!useMockApi) {
    return apiRequest<Features>('/analysis/features', {
      method: 'POST',
      body: JSON.stringify(sessionId ? { session_id: sessionId } : {}),
    })
  }
  await delay(850)
  const networkFeatures = {
    ipv4_packet_count: 12847,
    ipv6_packet_count: 0,
    unique_source_ips: ['192.168.1.24', '203.0.113.18'],
    unique_destination_ips: ['192.168.1.24', '203.0.113.18'],
    source_ips: ['192.168.1.24', '203.0.113.18'],
    destination_ips: ['192.168.1.24', '203.0.113.18'],
    ttl_observations: [64, 56],
    ttl_hop_limit_observed: [64, 56],
    packet_size_statistics: {
      minimum: 64,
      maximum: 1460,
      mean: 847.0,
      standard_deviation: 412.3,
      min: 64,
      max: 1460,
      std_dev: 412.3,
    },
    packet_sizes: { min: 64, max: 1460, mean: 847.0, std_dev: 412.3 },
    timing_statistics: {
      packet_rate: 47.2,
      minimum_iat: 0.0001,
      maximum_iat: 0.124,
      mean_iat: 0.0212,
      iat_standard_deviation: 0.0155,
      min: 0.0001,
      max: 0.124,
      std_dev: 0.0155,
    },
    inter_arrival_time_seconds: { min: 0.0001, max: 0.124, mean: 0.0212, std_dev: 0.0155 },
    iat_statistics: { min: 0.0001, max: 0.124, mean: 0.0212, std_dev: 0.0155 },
    packet_rate: 47.2,
    packet_rate_per_sec: 47.2,
  }

  return {
    totalPackets: 12847,
    avgPacketSize: 847,
    packetRate: 47.2,
    espRatio: 91.4,
    ikeRatio: 2.8,
    burstiness: 0.73,
    entropy: 7.82,
    capture_name: 'office-vpn-session.pcap',
    capture_size: '2.4 MB',
    session_id: 'mock-session-id',
    capture: {
      filename: 'office-vpn-session.pcap',
      file_size_bytes: 2516582,
      file_size_formatted: '2.4 MB',
      packet_count: 12847,
      capture_duration_seconds: 272.0,
      capture_duration_formatted: '00:04:32',
      first_packet_timestamp: '2026-09-09 11:42:00 UTC',
      last_packet_timestamp: '2026-09-09 11:46:32 UTC',
    },
    network: networkFeatures,
    ip_features: networkFeatures,
    ipsec: {
      ipsec_detected: true,
      protocols_detected: ['IKEv2', 'ESP', 'NAT-T'],
      ike_detected: true,
      ikev2_detected: true,
      esp_detected: true,
      ah_detected: false,
      udp_500_detected: true,
      udp_4500_detected: true,
      nat_t_detected: true,
      esp_packet_count: 11742,
      esp_ratio_percent: 91.4,
      ah_packet_count: 0,
      ike_packet_count: 360,
      ike_versions_observed: ['IKEv2'],
      udp_500_present: true,
      udp_4500_present: true,
      nat_t_indication: true,
      esp_spi_values: ['0x0a3f118c', '0x0b427e91'],
      esp_sequence_numbers: { min: 1, max: 5871, observed_count: 11742 },
      tunnel_transport_mode: 'UNKNOWN',
      tunnel_transport_mode_detail:
        'ESP payload and next-header trailer are encapsulated within encrypted ciphertext; determining tunnel vs transport mode requires Security Association decryption keys or visible inner IP headers.',
    },
    ike: {
      detected: true,
      version: 'IKEv2',
      packet_count: 360,
      initiator: '1122334455667788',
      responder: '99aabbccddeeff11',
      exchange_types: ['IKE_SA_INIT', 'IKE_AUTH', 'CREATE_CHILD_SA'],
      encryption_algorithms: ['AES-256-GCM'],
      integrity_algorithms: ['AUTH_HMAC_SHA2_256_128'],
      prf_algorithms: ['PRF_HMAC_SHA2_256'],
      authentication_methods: ['Pre-Shared Key (PSK)'],
      key_exchange_methods: ['MODP-2048 (Group 14)'],
    },
    esp: {
      detected: true,
      packet_count: 11742,
      spi_values: ['0x0a3f118c', '0x0b427e91'],
      sequence_number_min: 1,
      sequence_number_max: 5871,
      sequence_number_count: 11742,
      udp_encapsulated: true,
      nat_t: true,
      encryption_algorithm: {
        value: 'AES-256-GCM',
        source: 'IKE_SA negotiation transform',
        confidence: 'HIGH',
        evidence: 'Directly observed from IKE proposal transform (AES-256-GCM)',
      },
    },
    ah: {
      detected: false,
      packet_count: 0,
      spi_values: [],
    },
    mode: {
      value: 'UNKNOWN',
      confidence: 'NONE',
      evidence:
        'ESP payload and next-header trailer are encapsulated within encrypted ciphertext; determining tunnel vs transport mode requires Security Association decryption keys or visible inner IP headers.',
    },
    cryptography: {
      ike: {
        encryption: ['AES-256-GCM'],
        integrity: ['AUTH_HMAC_SHA2_256_128'],
        prf: ['PRF_HMAC_SHA2_256'],
        authentication: ['Pre-Shared Key (PSK)'],
        key_exchange: ['MODP-2048 (Group 14)'],
      },
      esp: {
        encryption: ['AES-256-GCM'],
        integrity: ['AUTH_HMAC_SHA2_256_128'],
      },
    },
    security_association: {
      sa_count_observed: 4,
      spi_values: ['0x0a3f118c', '0x0b427e91', '1122334455667788', '99aabbccddeeff11'],
      initiator_spi: '1122334455667788',
      responder_spi: '99aabbccddeeff11',
      traffic_selectors: [],
      rekey_information: 'CREATE_CHILD_SA exchange observed',
      replay_information: 'ESP sequence numbers observed from 1 to 5871',
    },
    protocols: {
      ESP: { packet_count: 11742, percentage: 91.4, byte_count: 10243500 },
      IKEv2: { packet_count: 360, percentage: 2.8, byte_count: 184500 },
      UDP: { packet_count: 745, percentage: 5.8, byte_count: 340000 },
    },
    statistics: {
      total_bytes: 10768000,
      throughput_bps: 316705.88,
      burst_count: 42,
      burstiness: 0.73,
      packet_size_distribution: {
        '<=64': 410,
        '65-128': 335,
        '129-512': 1102,
        '513-1024': 4200,
        '1025-1518': 6800,
        '>1518': 0,
      },
      packet_size_entropy: 7.82,
      shannon_entropy: 7.82,
      flow_summary: {
        flow_count: 2,
        duration_statistics: { min: 270.0, max: 272.0, mean: 271.0, std_dev: 1.414 },
      },
    },
    flows: [
      {
        flow_id: '192.168.1.24:4500 <-> 203.0.113.18:4500 (ESP)',
        source_ip: '192.168.1.24',
        destination_ip: '203.0.113.18',
        src_ip: '192.168.1.24',
        dst_ip: '203.0.113.18',
        source_port: 4500,
        destination_port: 4500,
        src_port: 4500,
        dst_port: 4500,
        protocol: 'ESP',
        duration: 272.0,
        duration_seconds: 272.0,
        packet_count: 11742,
        total_packets: 11742,
        forward_packet_count: 6100,
        forward_packets: 6100,
        backward_packet_count: 5642,
        backward_packets: 5642,
        total_bytes: 10243500,
        forward_bytes: 5400000,
        backward_bytes: 4843500,
        forward_backward_packet_ratio: 1.081,
        forward_backward_byte_ratio: 1.115,
        throughput: 301279.41,
        throughput_bps: 301279.41,
        packet_rate: 43.17,
        inter_arrival_time_seconds: { min: 0.0001, max: 0.082, mean: 0.023, std_dev: 0.014 },
        iat_statistics: { min: 0.0001, max: 0.082, mean: 0.023, std_dev: 0.014 },
        packet_size_statistics: { min: 64, max: 1460, mean: 872.4, std_dev: 398.2 },
        packet_sizes: { min: 64, max: 1460, mean: 872.4, std_dev: 398.2 },
        burst_count: 38,
        burstiness: 0.6087,
        packet_size_entropy: 7.74,
        shannon_entropy: 7.74,
      },
    ],
    feature_availability: {
      capture_metadata: true,
      ip_features: true,
      ike_negotiation: true,
      ike_version: true,
      esp_detection: true,
      ah_detection: false,
      tunnel_transport_mode: false,
      encryption_algorithm: true,
      authentication_algorithm: true,
      key_exchange_method: true,
      security_association: true,
      spi_values: true,
      sequence_numbers: true,
      nat_t_detection: true,
      flow_reconstruction: true,
      traffic_statistics: true,
      payload_entropy: true,
    },
  }
}

export async function runPrediction(sessionId?: string): Promise<Prediction> {
  if (!useMockApi) {
    return apiRequest<Prediction>('/analysis/predict', {
      method: 'POST',
      body: JSON.stringify(sessionId ? { session_id: sessionId } : {}),
    })
  }
  await delay(1100)
  return {
    label: 'VPN Encrypted Traffic',
    confidence: 96.8,
    probabilities: [
      { label: 'VPN Encrypted Traffic', value: 96.8 },
      { label: 'Regular Traffic', value: 3.2 },
    ],
    explanation:
      'High ESP packet ratio, consistent packet sizes, and IKEv2 negotiation signatures strongly indicate an active IPsec tunnel carrying encrypted VPN traffic.',
  }
}

export async function analyzeSecurity(sessionId?: string): Promise<SecurityAnalysisResult> {
  if (!useMockApi) {
    return apiRequest<SecurityAnalysisResult>('/api/security/analyze', {
      method: 'POST',
      body: JSON.stringify(sessionId ? { session_id: sessionId } : {}),
    })
  }

  await delay(1200)
  const mockFeatures = await extractFeatures(sessionId)

  return {
    session_id: sessionId || 'mock-session-id',
    observed_features: mockFeatures,
    nist_assessment: {
      overall_status: 'WARNING',
      checks: [
        {
          category: 'Cryptographic Strength',
          status: 'PASS',
          observed_value: 'AES-256-GCM',
          expected_or_policy:
            'NIST SP 800-77 Rev. 1 / SP 800-57: AES-128/256 (GCM/CBC) or modern AEAD cipher with >= 128-bit key.',
          reason:
            'Observed robust cryptographic transform: AES-256-GCM (256-bit, AEAD=True). Compliant with NIST cryptographic standards.',
          severity: 'LOW',
        },
        {
          category: 'Configuration Compliance',
          status: 'WARNING',
          observed_value: 'IKE Version: IKEv2, ESP: Active, AH: Active, NAT-T: UDP 4500 Encapsulation Active',
          expected_or_policy:
            'NIST SP 800-77 Rev. 1: Standard IKEv2 architecture with ESP encapsulation for confidentiality & integrity.',
          reason:
            'AH protocol detected; per NIST SP 800-77 Rev. 1 Section 3.4, AH does not provide confidentiality and ESP is strongly recommended.',
          severity: 'MEDIUM',
        },
        {
          category: 'Security Association Parameters',
          status: 'PASS',
          observed_value: '2 unique SPI(s): 0x0a3f118c, 0x0b427e91 (Seq range [1..5871], 11742 packets)',
          expected_or_policy:
            'NIST SP 800-77 Rev. 1 Section 3.1: Active Security Associations identified by unique 32-bit SPIs and sequence tracking.',
          reason:
            'Active SA observed with valid SPI values (0x0a3f118c, 0x0b427e91) and active sequence number progression.',
          severity: 'LOW',
        },
        {
          category: 'Key Lifetime',
          status: 'NOT_OBSERVABLE',
          observed_value: null,
          expected_or_policy:
            'NIST SP 800-77 Rev. 1 Section 3.2.4 & SP 800-57: IKE SA lifetime <= 24 hours; IPsec CHILD_SA <= 8 hours or byte-limit rekeying.',
          reason:
            'SA lifetime duration/byte limits were not present in the captured frames. SA lifetimes are frequently enforced locally by host IPsec daemons without explicit on-wire advertisement.',
          severity: 'LOW',
        },
        {
          category: 'Replay Protection',
          status: 'PASS',
          observed_value: 'Monotonic ESP sequence numbers (min: 1, max: 5871, packets: 11742)',
          expected_or_policy:
            'NIST SP 800-77 Rev. 1 Section 3.1.3 & RFC 4303: Monotonically increasing sequence numbers with anti-replay window.',
          reason:
            'Observed 11742 ESP frames with ascending sequence numbers [1..5871] with zero duplicate counters. Note: host receiver anti-replay sliding window buffer size is an internal stack parameter not transmitted on wire.',
          severity: 'LOW',
        },
        {
          category: 'Forward Secrecy (PFS) Configuration',
          status: 'PASS',
          observed_value: 'PFS Enabled (MODP-2048 (Group 14) in CREATE_CHILD_SA)',
          expected_or_policy:
            'NIST SP 800-77 Rev. 1 Section 3.2.3: Perfect Forward Secrecy enabled for CHILD_SAs with DH Group >= 14.',
          reason:
            'CHILD_SA negotiation captured with ephemeral Diffie-Hellman Key Exchange (MODP-2048 (Group 14)), ensuring past session key confidentiality.',
          severity: 'LOW',
        },
        {
          category: 'Cipher Suite Strength',
          status: 'PASS',
          observed_value: 'AES-256-GCM + AUTH_HMAC_SHA2_256_128 + MODP-2048 (Group 14)',
          expected_or_policy:
            'NIST SP 800-77 Rev. 1 Section 3.3.1: Modern AEAD cipher suite (AES-GCM) with authenticated encryption.',
          reason:
            'High-assurance AEAD cipher suite. Provides simultaneous confidentiality and message authenticity without requiring separate MAC.',
          severity: 'LOW',
        },
        {
          category: 'Metadata Exposure',
          status: 'WARNING',
          observed_value:
            'Outer IPs: 2 src IP(s), 2 dst IP(s); SPIs: 0x0a3f118c, 0x0b427e91; Rate: 47.2 pps; Packet sizes: [64..1460] B (std-dev: 412.3)',
          expected_or_policy:
            'NIST SP 800-77 Rev. 1 Section 3.1.1: Standard IPsec encrypts payload; outer IP headers and flow timing remain visible unless traffic flow confidentiality (cover traffic / padding) is deployed.',
          reason:
            'Outer IP headers, ESP SPIs (32-bit flow identifiers), sequence numbers, packet lengths, and timing characteristics remain visible in cleartext on the wire. While packet payloads are encrypted, passive eavesdroppers can perform traffic analysis, correlate communication endpoints, and infer activity bursts or application categories unless traffic padding or cover traffic is deployed.',
          severity: 'MEDIUM',
        },
      ],
    },
    risk_assessment: {
      score: 24,
      level: 'MODERATE',
      method: 'project_policy_v1',
      factors: [
        {
          category: 'Configuration Compliance',
          points: 9,
          reason:
            'AH protocol detected; per NIST SP 800-77 Rev. 1 Section 3.4, AH does not provide confidentiality and ESP is strongly recommended.',
        },
        {
          category: 'Metadata Exposure',
          points: 15,
          reason: 'Outer IP addresses, SPIs, and packet timing remain exposed to network observers.',
        },
      ],
    },
    ai_analysis: {
      available: true,
      traffic_class: 'Video Streaming',
      confidence: 0.91,
      summary:
        'The observed traffic is consistent with encrypted video-streaming behavior based on packet sizes, timing and flow characteristics.',
      security_interpretation:
        'The IPsec deployment demonstrates high confidentiality and integrity assurance via AES-256-GCM. However, the presence of Authentication Header (AH) creates redundant protocol overhead without encrypting transport headers. Significant metadata leakage is observable via outer IP addresses, SPIs, and distinctive packet burst timing, allowing passive traffic analysis.',
      key_observations: [
        'Robust AES-256-GCM cipher suite actively negotiated with Diffie-Hellman Group 14 (MODP-2048).',
        'ESP sequence counters show strict monotonic progression [1..5871], verifying replay protection.',
        'High packet variance (64 to 1460 bytes) and 47.2 pps throughput reflect high-bandwidth media transmission patterns.',
      ],
      recommendations: [
        'Eliminate legacy AH protocol in favor of pure ESP tunnel mode encapsulation.',
        'Enforce Diffie-Hellman Group 19 (ECDH-256) or Curve25519 for modern elliptic-curve efficiency.',
        'Deploy IPsec traffic flow confidentiality or constant-rate padding if traffic pattern privacy is required.',
      ],
    },
  }
}

export async function askReportChat(
  question: string,
  sessionId?: string,
  reportId?: string
): Promise<RagChatResponse> {
  if (!useMockApi) {
    return apiRequest<RagChatResponse>('/api/rag/report-chat', {
      method: 'POST',
      body: JSON.stringify({
        question,
        session_id: sessionId,
        report_id: reportId || sessionId,
      }),
    })
  }

  // Mock API fallback if backend is offline
  await delay(600)
  return {
    report_id: reportId || sessionId || 'mock-report-id',
    session_id: sessionId,
    question,
    answer:
      `Based on the security assessment report, the deterministic risk score is evaluated with standard NIST SP 800-77 rules. Strong symmetric encryption (AES-256) and SHA-256 integrity protection were verified with RFC 7296 IKEv2 compliance.`,
    sources: [
      { section: 'Risk Assessment', relevance: 0.94 },
      { section: 'NIST Security Findings', relevance: 0.89 },
      { section: 'Cryptographic Assessment', relevance: 0.85 },
    ],
  }
}



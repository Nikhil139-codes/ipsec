export type PacketProtocol = 'ESP' | 'IKEv2' | 'UDP' | 'TCP' | string

export type PCAPInfo = {
  id?: string
  session_id?: string
  name: string
  size: string
  packets: number
  duration: string
  capturedAt: string
  features?: Features
  nist_assessment?: NISTAssessment
  risk_assessment?: RiskAssessment
}

export type Packet = {
  no: number
  time: string
  source: string
  destination: string
  protocol: PacketProtocol
  length: number
  info: string
  encrypted: boolean
}

export type EvidenceField<T = string> = {
  value: T
  source?: string
  confidence?: 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE'
  evidence?: string
}

export type CaptureMetadata = {
  filename: string
  file_size_bytes: number
  file_size_formatted?: string
  packet_count: number
  capture_duration_seconds: number
  capture_duration_formatted?: string
  first_packet_timestamp: string | null
  last_packet_timestamp: string | null
}

export type NumberStatistics = {
  min?: number | null
  max?: number | null
  mean?: number | null
  std_dev?: number | null
  minimum?: number | null
  maximum?: number | null
  standard_deviation?: number | null
}

export type TimingStatistics = {
  packet_rate: number
  minimum_iat?: number | null
  maximum_iat?: number | null
  mean_iat?: number | null
  iat_standard_deviation?: number | null
  min?: number | null
  max?: number | null
  std_dev?: number | null
}

export type IPFeatures = {
  ipv4_packet_count: number
  ipv6_packet_count: number
  unique_source_ips: string[]
  unique_destination_ips: string[]
  source_ips?: string[]
  destination_ips?: string[]
  ttl_observations: number[] | null
  ttl_hop_limit_observed?: number[] | null
  packet_size_statistics: NumberStatistics
  packet_sizes?: NumberStatistics
  timing_statistics: TimingStatistics
  inter_arrival_time_seconds?: NumberStatistics
  iat_statistics?: NumberStatistics
  packet_rate?: number
  packet_rate_per_sec?: number
}

export type IPsecIdentification = {
  ipsec_detected: boolean
  protocols_detected: string[]
  ike_detected?: boolean
  ikev2_detected?: boolean
  esp_detected?: boolean
  ah_detected?: boolean
  udp_500_detected?: boolean
  udp_4500_detected?: boolean
  nat_t_detected?: boolean
  esp_packet_count?: number
  esp_ratio_percent?: number
  ah_packet_count?: number
  ike_packet_count?: number
  ike_versions_observed?: string[]
  udp_500_present?: boolean
  udp_4500_present?: boolean
  nat_t_indication?: boolean
  esp_spi_values?: string[]
  esp_sequence_numbers?: { min: number; max: number; observed_count: number } | null
  tunnel_transport_mode?: 'TUNNEL' | 'TRANSPORT' | 'UNKNOWN'
  tunnel_transport_mode_detail?: string
}

export type IKEFeatures = {
  detected: boolean
  version: 'IKEv2' | 'IKEv1' | 'UNKNOWN' | string | null
  packet_count: number
  initiator: string | null
  responder: string | null
  exchange_types: string[]
  encryption_algorithms: string[]
  integrity_algorithms: string[]
  prf_algorithms: string[]
  authentication_methods: string[]
  key_exchange_methods: string[]
}

export type ESPFeatures = {
  detected: boolean
  packet_count: number
  spi_values: string[]
  sequence_number_min: number | null
  sequence_number_max: number | null
  sequence_number_count: number
  udp_encapsulated: boolean
  nat_t: boolean
  encryption_algorithm: EvidenceField<string>
}

export type AHFeatures = {
  detected: boolean
  packet_count: number
  spi_values: string[]
}

export type TunnelModeFeature = {
  value: 'TUNNEL' | 'TRANSPORT' | 'UNKNOWN'
  confidence: 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE'
  evidence: string
}

export type CryptographyFeatures = {
  ike: {
    encryption: string[]
    integrity: string[]
    prf: string[]
    authentication: string[]
    key_exchange: string[]
  }
  esp: {
    encryption: string[]
    integrity: string[]
  }
}

export type SecurityAssociationFeatures = {
  sa_count_observed: number
  spi_values: string[]
  initiator_spi: string | null
  responder_spi: string | null
  traffic_selectors: any[]
  rekey_information: string | null
  replay_information: string | null
}

export type FlowFeature = {
  flow_id: string
  source_ip: string
  destination_ip: string
  src_ip?: string
  dst_ip?: string
  source_port: number
  destination_port: number
  src_port?: number
  dst_port?: number
  protocol: string
  duration: number
  duration_seconds?: number
  packet_count: number
  total_packets?: number
  forward_packet_count: number
  forward_packets?: number
  backward_packet_count: number
  backward_packets?: number
  total_bytes: number
  forward_bytes: number
  backward_bytes: number
  forward_backward_packet_ratio: number | null
  forward_backward_byte_ratio: number | null
  throughput: number | null
  throughput_bps?: number | null
  packet_rate: number | null
  inter_arrival_time_seconds?: NumberStatistics
  iat_statistics?: NumberStatistics
  packet_size_statistics?: NumberStatistics
  packet_sizes?: NumberStatistics
  burst_count?: number
  burstiness?: number
  packet_size_entropy?: number
  shannon_entropy?: number
}

export type FeatureAvailability = {
  capture_metadata?: boolean
  ip_features?: boolean
  ike_negotiation?: boolean
  ike_version?: boolean
  esp_detection?: boolean
  ah_detection?: boolean
  tunnel_transport_mode?: boolean
  encryption_algorithm?: boolean
  authentication_algorithm?: boolean
  key_exchange_method?: boolean
  security_association?: boolean
  spi_values?: boolean
  sequence_numbers?: boolean
  nat_t_detection?: boolean
  flow_reconstruction?: boolean
  traffic_statistics?: boolean
  payload_entropy?: boolean
  [key: string]: boolean | string | undefined
}

export type Features = {
  // Existing compatibility fields for UI
  totalPackets: number
  avgPacketSize: number
  packetRate: number
  espRatio: number
  ikeRatio: number
  burstiness: number
  entropy: number
  cleartextRatio?: number
  // Structured feature blocks from TShark backend
  session_id?: string
  capture_name?: string
  capture_size?: string
  capture?: CaptureMetadata
  network?: IPFeatures
  ip_features?: IPFeatures
  ipsec?: IPsecIdentification
  ike?: IKEFeatures
  esp?: ESPFeatures
  ah?: AHFeatures
  mode?: TunnelModeFeature
  cryptography?: CryptographyFeatures
  security_association?: SecurityAssociationFeatures
  protocols?: Record<string, any>
  statistics?: Record<string, any>
  flows?: FlowFeature[]
  feature_availability?: FeatureAvailability
}

export type Prediction = { label: 'VPN Encrypted Traffic' | 'Regular Traffic'; confidence: number; probabilities: { label: string; value: number }[]; explanation: string }
export type VPNStatus = { connected: boolean; tunnel: string; peer: string; uptime: string; encryption: string }
export const initialInfo: PCAPInfo = { name: 'office-vpn-session.pcap', size: '2.4 MB', packets: 12847, duration: '00:04:32', capturedAt: 'Sep 09, 2026, 11:42 AM' }

export type SecurityCheckStatus = 'PASS' | 'FAIL' | 'WARNING' | 'NOT_OBSERVABLE'
export type SecurityCheckSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

export type SecurityCheckFinding = {
  category: string
  status: SecurityCheckStatus
  observed_value: string | null
  expected_or_policy: string
  reason: string
  severity: SecurityCheckSeverity
}

export type NISTAssessment = {
  overall_status: 'PASS' | 'WARNING' | 'FAIL'
  checks: SecurityCheckFinding[]
}

export type RiskFactor = {
  category: string
  points: number
  reason: string
}

export type RiskLevel = 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL'

export type RiskAssessment = {
  score: number
  level: RiskLevel
  method: string
  factors: RiskFactor[]
}

export type AIAnalysis = {
  available?: boolean
  error?: string
  traffic_class: string
  confidence: number | null
  summary: string
  security_interpretation: string
  key_observations: string[]
  recommendations: string[]
}

export type SecurityAnalysisResult = {
  session_id: string
  report_id?: string
  observed_features: Features
  nist_assessment: NISTAssessment
  risk_assessment: RiskAssessment
  ai_analysis: AIAnalysis
}

export interface RagSourceCitation {
  section: string
  relevance: number
}

export interface RagChatRequest {
  report_id?: string
  session_id?: string
  question: string
}

export interface RagChatResponse {
  report_id: string
  session_id?: string
  question: string
  answer: string
  sources: RagSourceCitation[]
  error?: string
}

export interface ChatMessage {
  id: string
  sender: 'user' | 'assistant'
  text: string
  timestamp: string
  sources?: RagSourceCitation[]
}

export type View = 'dashboard' | 'analysis' | 'features' | 'security' | 'attacker' | 'prediction' | 'testbed' | 'history'

export type AttackerCommand = 'pfs-test' | 'replay-test' | 'cipher-test' | 'sa-test' | 'metadata-test' | string

export interface AttackerTest {
  id: string
  title: string
  reason: string
  command: AttackerCommand
  expected_result: string
  potential_impact: string
  next_step: string
}

export interface AttackerTestPlanResponse {
  tests: AttackerTest[]
  status?: string
  message?: string | null
}

export interface SimulatedTestResult {
  command: AttackerCommand
  test_title: string
  status: 'WEAKNESS CONFIRMED' | 'CONTROLS EFFECTIVE' | 'VALIDATION COMPLETE' | string
  breaking_point: string
  security_impact: string
  severity: SecurityCheckSeverity
  terminal_output: string[]
  tested_at: string
}

export interface AttackPathAnalysis {
  validated_weakness: string
  test_result?: string
  potential_attacker_action?: string
  potential_impact: string
  attacker_next_step: string
  recommended_hardening: string
}

export type TestbedConfig = {
  mode: 'tunnel' | 'transport' | string
  ike_version: 'ikev2' | string
  encryption: 'aes128' | 'aes256' | 'aes-gcm' | string
  integrity: 'sha256' | 'sha384' | 'sha512' | string
  dh_group: 'modp2048' | 'modp3072' | 'modp4096' | string
  pfs: 'true' | 'false' | string
  ip_version: 'ipv4' | 'ipv6' | string
  traffic_type: 'icmp' | 'web' | 'video' | 'voip' | 'email' | string
}

export type TestbedStatus = {
  ok: boolean
  containers: Record<string, string>
  docker_rc: number
  stdout?: string
  stderr?: string
}

export type TestbedRunResponse = {
  ok: boolean
  run_id: string
  config: TestbedConfig
  adapter?: any
  capture?: any
  dataset_dir?: string
  pcap?: string
  download_url?: string
  error?: string
}

export interface VpnRecord {
  id: string
  run_id?: string
  title: string
  created_at: string
  created_at_iso?: string
  status: 'ESTABLISHED' | 'COMPLETED' | 'INACTIVE' | 'FAILED' | string
  established?: boolean
  proposal?: string
  config: TestbedConfig
  pcap: {
    filename: string
    size: string
    size_bytes?: number
    has_pcap?: boolean
    packets?: number
    duration?: string
    download_url: string
  }
  logs_available?: {
    sa?: boolean
    charon_client?: boolean
    charon_server?: boolean
    xfrm?: boolean
  }
  analysis?: {
    score: number
    risk_level: RiskLevel
    traffic_label: string
    confidence: number
    esp_ratio: number
    pass_count: number
    warning_count: number
    fail_count: number
  }
  logs?: {
    sa?: string
    charon_client?: string
    charon_server?: string
    xfrm_state?: string
    xfrm_policy?: string
    terminal_output?: string
  }
  report?: {
    generated_at?: string
    summary?: string
  }
}

export interface SecurityReport {
  id: string
  report_title: string
  generated_at: string
  target_file: string
  file_size?: string
  packet_count?: number
  duration?: string
  risk_score: number
  risk_level: RiskLevel
  traffic_verdict: string
  traffic_confidence: number
  explanation: string
  cryptographic_profile: {
    mode?: string
    ike_version?: string
    encryption?: string
    integrity?: string
    dh_group?: string
    pfs?: string
    esp_ratio?: number
    ike_detected?: boolean
    protocols_detected?: string[]
  }
  nist_compliance: {
    total_checks: number
    pass_count: number
    warning_count: number
    fail_count: number
    checks: Array<{
      id: string
      name: string
      status: SecurityCheckStatus
      severity: SecurityCheckSeverity
      observation: string
      standard: string
    }>
  }
  key_findings: string[]
  recommendations: string[]
  logs_summary?: string
}


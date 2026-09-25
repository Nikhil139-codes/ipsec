import { apiRequest, delay, useMockApi } from './client'
import { type Packet } from './types'

export async function getPackets(sessionId?: string): Promise<Packet[]> {
  if (!useMockApi) {
    const query = sessionId ? `?session_id=${encodeURIComponent(sessionId)}` : ''
    return apiRequest<Packet[]>(`/pcap/packets${query}`)
  }
  await delay(300)
  return [
    { no: 1, time: '0.000000', source: '192.168.1.24', destination: '203.0.113.18', protocol: 'IKEv2', length: 412, info: 'IKE_SA_INIT request', encrypted: false },
    { no: 2, time: '0.024812', source: '203.0.113.18', destination: '192.168.1.24', protocol: 'IKEv2', length: 368, info: 'IKE_SA_INIT response', encrypted: false },
    { no: 3, time: '0.031490', source: '192.168.1.24', destination: '203.0.113.18', protocol: 'ESP', length: 1460, info: 'Encrypted payload data', encrypted: true },
    { no: 4, time: '0.032104', source: '192.168.1.24', destination: '203.0.113.18', protocol: 'ESP', length: 1460, info: 'Encrypted payload data', encrypted: true },
    { no: 5, time: '0.039917', source: '203.0.113.18', destination: '192.168.1.24', protocol: 'ESP', length: 1384, info: 'Encrypted payload data', encrypted: true },
  ]
}

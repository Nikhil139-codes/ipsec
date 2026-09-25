import { apiRequest, delay, useMockApi } from './client'
import { type VPNStatus } from './types'
export async function getVPNStatus(): Promise<VPNStatus> {
  if (!useMockApi) return apiRequest<VPNStatus>('/vpn/status')
  await delay(250)
  return { connected: true, tunnel: 'IPsec / IKEv2', peer: '203.0.113.18', uptime: '04:31:48', encryption: 'AES-256-GCM' }
}

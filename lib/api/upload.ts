import { apiRequest, delay, useMockApi } from './client'
import { type PCAPInfo } from './types'

export async function uploadPCAP(file: File): Promise<PCAPInfo> {
  if (!useMockApi) {
    const form = new FormData()
    form.append('file', file)
    const result = await apiRequest<PCAPInfo & { session_id?: string }>('/pcap/upload', {
      method: 'POST',
      body: form,
    })
    return {
      ...result,
      id: result.id || result.session_id,
      session_id: result.session_id || result.id,
    }
  }
  await delay(650)
  return {
    id: 'mock-session-id',
    session_id: 'mock-session-id',
    name: file.name,
    size: `${(file.size / 1024 / 1024 || 2.4).toFixed(1)} MB`,
    packets: 12847,
    duration: '00:04:32',
    capturedAt: new Date().toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short' }),
  }
}


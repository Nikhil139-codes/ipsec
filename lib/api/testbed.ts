import { API_BASE_URL } from './client'
import { TestbedConfig, TestbedStatus, TestbedRunResponse } from './types'

export async function getTestbedStatus(): Promise<TestbedStatus> {
  try {
    const res = await fetch(`${API_BASE_URL}/api/testbed/status`, { cache: 'no-store' })
    if (!res.ok) throw new Error(`Status check failed: ${res.statusText}`)
    return await res.json()
  } catch (err: any) {
    return {
      ok: false,
      containers: {},
      docker_rc: 1,
      stderr: err.message || 'Docker/Backend unavailable'
    }
  }
}

export async function getTestbedConfig(): Promise<TestbedConfig> {
  const res = await fetch(`${API_BASE_URL}/api/testbed/config`, { cache: 'no-store' })
  if (!res.ok) throw new Error(`Failed to load config: ${res.statusText}`)
  return await res.json()
}

export async function saveTestbedConfig(config: TestbedConfig): Promise<{ ok: boolean; config: TestbedConfig }> {
  const res = await fetch(`${API_BASE_URL}/api/testbed/config`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config)
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || 'Failed to save configuration')
  }
  return await res.json()
}

export async function runTestbedExperiment(config: TestbedConfig): Promise<TestbedRunResponse> {
  const res = await fetch(`${API_BASE_URL}/api/testbed/run`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ config })
  })
  const data = await res.json()
  if (!res.ok) {
    throw new Error(data.error || data.detail || 'Experiment run failed')
  }
  return data
}

export function getPcapDownloadUrl(runId: string): string {
  return `${API_BASE_URL}/api/testbed/download/${runId}`
}

export async function loadPcapToAnalyzer(runId: string): Promise<any> {
  const res = await fetch(`${API_BASE_URL}/api/testbed/load-to-analyzer`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ run_id: runId })
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || 'Failed to load PCAP into analyzer session')
  }
  return await res.json()
}

export async function getTestbedRuns(): Promise<{ ok: boolean; total: number; runs: any[] }> {
  try {
    const res = await fetch(`${API_BASE_URL}/api/testbed/runs`, { cache: 'no-store' })
    if (!res.ok) throw new Error(`Failed to load runs: ${res.statusText}`)
    return await res.json()
  } catch (err: any) {
    console.warn('Backend runs fetch failed, checking fallback:', err.message)
    return { ok: false, total: 0, runs: [] }
  }
}

export async function getTestbedRunDetails(runId: string): Promise<any> {
  const res = await fetch(`${API_BASE_URL}/api/testbed/runs/${runId}`, { cache: 'no-store' })
  if (!res.ok) throw new Error(`Failed to load run details for ${runId}`)
  return await res.json()
}


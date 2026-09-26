export const API_BASE_URL = process.env.NEXT_PUBLIC_ANALYZER_API_URL || 'https://ipsec-backend.onrender.com/'
export const useMockApi = process.env.NEXT_PUBLIC_USE_MOCK_API !== 'false'

export async function apiRequest<T>(path: string, options?: RequestInit): Promise<T> {
  const isFormData = typeof FormData !== 'undefined' && options?.body instanceof FormData
  const headers: Record<string, string> = {
    ...(isFormData ? {} : { 'Content-Type': 'application/json' }),
    ...(options?.headers as Record<string, string> || {}),
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers,
  })
  if (!response.ok) {
    const errorText = await response.text().catch(() => '')
    throw new Error(`Analyzer API request failed (${response.status}): ${errorText || response.statusText}`)
  }
  return response.json() as Promise<T>
}

export const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))


'use client'
import { useRef, useState } from 'react'
import { analyzeSecurity, extractFeatures, getPackets, runPrediction, uploadPCAP } from '@/lib/api'
import { storeLatestReportLocally } from '@/lib/api/attacker'
import { type Features, type Packet, type PCAPInfo, type Prediction, type SecurityAnalysisResult } from '@/lib/api/types'

export function useAnalyzer() {
  const [file, setFile] = useState<File | null>(null)
  const [info, setInfo] = useState<PCAPInfo | null>(null)
  const [packets, setPackets] = useState<Packet[]>([])
  const [features, setFeatures] = useState<Features | null>(null)
  const [prediction, setPrediction] = useState<Prediction | null>(null)
  const [securityAssessment, setSecurityAssessment] = useState<SecurityAnalysisResult | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Keep an active session ID ref for reliable cross-render access
  const activeSessionIdRef = useRef<string | null>(null)

  const run = async <T,>(task: () => Promise<T>, setter?: (value: T) => void) => {
    setBusy(true)
    setError(null)
    try {
      const res = await task()
      if (setter && res !== null && res !== undefined) {
        setter(res)
      }
      return res
    } catch (err: any) {
      console.error('Analyzer error:', err)
      setError(err?.message || 'Operation failed')
      return null
    } finally {
      setBusy(false)
    }
  }

  const getTargetSessionId = (overrideId?: string): string | undefined => {
    return overrideId || activeSessionIdRef.current || info?.session_id || info?.id || undefined
  }

  return {
    file,
    info,
    packets,
    features,
    prediction,
    securityAssessment,
    busy,
    error,
    clearError: () => setError(null),

    upload: async (next?: File) => {
      if (!next || !/\.(pcap|pcapng)$/i.test(next.name)) return
      setFile(next)

      // Clear previous PCAP results immediately so no stale data is displayed
      setPackets([])
      setFeatures(null)
      setPrediction(null)
      setSecurityAssessment(null)
      activeSessionIdRef.current = null

      const res = await run(() => uploadPCAP(next), (uploadedInfo) => {
        setInfo(uploadedInfo)
        const sid = uploadedInfo?.session_id || uploadedInfo?.id || null
        activeSessionIdRef.current = sid
      })

      if (res) {
        const sid = res.session_id || res.id

        // If backend returned features directly on upload, populate immediately
        if (res.features) {
          setFeatures(res.features)
        }

        // If backend returned security assessment directly on upload, populate immediately
        if (res.nist_assessment && res.risk_assessment) {
          setSecurityAssessment({
            session_id: sid || '',
            observed_features: res.features || ({} as any),
            nist_assessment: res.nist_assessment,
            risk_assessment: res.risk_assessment,
            ai_analysis: {
              available: false,
              traffic_class: 'Analyzing...',
              confidence: null,
              summary: 'NIST evaluation completed. Click "Run Security Assessment" to execute AI analysis.',
              security_interpretation: 'Deterministic NIST-based assessment ready.',
              key_observations: [],
              recommendations: [],
            },
          })
        }

        // Pre-fetch the first batch of decoded packets in the background
        if (sid) {
          getPackets(sid).then((pkts) => {
            if (pkts && pkts.length > 0) {
              setPackets(pkts)
            }
          }).catch(() => {})
        }
      }
    },

    inspect: (customSessionId?: string) => {
      const sid = getTargetSessionId(customSessionId)
      return run(() => getPackets(sid), setPackets)
    },

    extract: (customSessionId?: string) => {
      const sid = getTargetSessionId(customSessionId)
      return run(
        () => extractFeatures(sid),
        (res: Features) => {
          setFeatures(res)
          const returnedId = res.session_id || sid
          if (returnedId) {
            activeSessionIdRef.current = returnedId
          }
          if (res?.capture_name || returnedId) {
            setInfo((prev) => ({
              id: returnedId || prev?.id,
              session_id: returnedId || prev?.session_id,
              name: res.capture_name || prev?.name || 'capture.pcap',
              size: res.capture_size || prev?.size || '—',
              packets: res.totalPackets || prev?.packets || 0,
              duration: res.capture?.capture_duration_formatted || prev?.duration || '00:00:00',
              capturedAt: res.capture?.first_packet_timestamp || prev?.capturedAt || 'Loaded',
            }))
          }
        }
      )
    },

    predict: (customSessionId?: string) => {
      const sid = getTargetSessionId(customSessionId)
      return run(() => runPrediction(sid), setPrediction)
    },

    analyzeSecurity: (customSessionId?: string) => {
      const sid = getTargetSessionId(customSessionId)
      return run(
        () => analyzeSecurity(sid),
        (res: SecurityAnalysisResult) => {
          setSecurityAssessment(res)
          if (res) {
            storeLatestReportLocally(res)
          }
          if (res?.session_id) {
            activeSessionIdRef.current = res.session_id
          }
          if (res?.observed_features) {
            setFeatures(res.observed_features)
            const obs = res.observed_features
            if (obs?.capture_name || res.session_id) {
              setInfo((prev) => ({
                id: res.session_id || prev?.id,
                session_id: res.session_id || prev?.session_id,
                name: obs.capture_name || prev?.name || 'capture.pcap',
                size: obs.capture_size || prev?.size || '—',
                packets: obs.totalPackets || prev?.packets || 0,
                duration: obs.capture?.capture_duration_formatted || prev?.duration || '00:00:00',
                capturedAt: obs.capture?.first_packet_timestamp || prev?.capturedAt || 'Loaded',
              }))
            }
          }
        }
      )
    },
  }
}

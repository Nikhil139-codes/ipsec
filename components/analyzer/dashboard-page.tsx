'use client'

import { useEffect, useRef, useState } from 'react'
import { Activity, CloudUpload, Radar, Upload, Server, FileCheck } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { type PCAPInfo, type View } from '@/lib/api/types'

export function DashboardPage({
  info,
  live,
  onUpload,
  onGo,
}: {
  info: PCAPInfo | null
  live: boolean
  onUpload: (file?: File) => void
  onGo: (view: View) => void
}) {
  const fileInputRef = useRef<HTMLInputElement>(null)
  const videoRef = useRef<HTMLVideoElement>(null)
  const [isDragging, setIsDragging] = useState(false)
  const [selectedFileName, setSelectedFileName] = useState<string | null>(null)
  const [videoError, setVideoError] = useState(false)

  useEffect(() => {
    if (videoRef.current) {
      videoRef.current.defaultMuted = true
      videoRef.current.muted = true
      videoRef.current.play().catch(() => {
        // Autoplay policy fallback: muted autoplay might need user interaction on some browsers
      })
    }
  }, [])

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) {
      setSelectedFileName(file.name)
      onUpload(file)
    }
  }

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(true)
  }

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(false)
  }

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(false)
    const file = e.dataTransfer.files?.[0]
    if (file) {
      setSelectedFileName(file.name)
      onUpload(file)
    }
  }

  const openFileDialog = () => {
    if (fileInputRef.current) {
      fileInputRef.current.value = ''
      fileInputRef.current.click()
    }
  }

  return (
    <div className="flex flex-col gap-6">
      {/* Top Row: Live VPN Video and PCAP Upload Side-by-Side */}
      <div className="grid gap-6 lg:grid-cols-2">
        {/* Live VPN Lab Demonstration Video Section */}
        <section className="rounded-xl border bg-card p-5 sm:p-6 shadow-xs flex flex-col justify-between">
          <div className="flex flex-col gap-3">
            <div className="rounded-lg border border-red-500/20 bg-red-500/10 px-4 py-3 text-red-600 dark:text-red-400">
              <p className="text-xs sm:text-sm font-semibold tracking-wide leading-relaxed">
                LIVE VPN LAB DEMONSTRATION — This video demonstrates our Docker-based IPsec VPN environment running in the backend, showing that our VPN setup and traffic analysis workflow are operational.
              </p>
            </div>

            {videoError ? (
              <div className="flex min-h-[220px] items-center justify-center rounded-lg border border-dashed border-muted-foreground/30 bg-muted/20 p-6 text-center text-sm font-medium text-muted-foreground">
                Video demonstration is currently unavailable.
              </div>
            ) : (
              <div className="overflow-hidden rounded-xl border-4 border-black shadow-md bg-black flex items-center justify-center">
                <video
                  ref={videoRef}
                  src="/dashboard-video.mp4"
                  autoPlay
                  muted
                  loop
                  playsInline
                  controls
                  onError={() => setVideoError(true)}
                  className="w-full h-auto max-h-[380px] object-contain rounded-sm"
                >
                  Your browser does not support the video tag.
                </video>
              </div>
            )}
          </div>
        </section>

        {/* Packet Capture Workspace (PCAP Upload) */}
        <div className="rounded-xl border bg-card p-6 flex flex-col justify-between">
          <div>
            <div className="mb-5 flex items-start justify-between">
              <div>
                <p className="mb-2 text-sm font-medium text-primary">Packet capture workspace</p>
                <h2 className="text-2xl sm:text-3xl font-semibold tracking-tight text-balance">
                  Turn encrypted traffic into a clear security report.
                </h2>
                <p className="mt-2 text-sm leading-6 text-muted-foreground">
                  Upload a PCAP file or connect a live stream. The analyzer identifies IPsec patterns,
                  extracts flow features, and classifies the traffic.
                </p>
              </div>
              <Radar className="hidden size-10 text-primary/70 sm:block shrink-0 ml-2" />
            </div>

            {/* Hidden File Input */}
            <input
              ref={fileInputRef}
              type="file"
              accept=".pcap,.pcapng,.cap,application/vnd.tcpdump.pcap,application/x-pcapng,*/*"
              className="hidden"
              onChange={handleFileChange}
            />

            {/* Drag & Drop / Click Zone */}
            <div
              onClick={openFileDialog}
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              className={`group flex cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed px-6 py-8 text-center transition-all ${
                isDragging
                  ? 'border-primary bg-primary/10 scale-[1.01]'
                  : 'border-primary/30 bg-primary/[0.03] hover:border-primary/60 hover:bg-primary/[0.07]'
              }`}
            >
              <div className="mb-3 flex size-12 items-center justify-center rounded-full bg-primary/10 text-primary transition-transform group-hover:scale-110">
                {selectedFileName ? <FileCheck className="size-6 text-emerald-600" /> : <CloudUpload className="size-6" />}
              </div>
              <p className="text-sm font-semibold text-foreground">
                {selectedFileName ? `Selected: ${selectedFileName}` : 'Drop a .pcap, .pcapng or .cap file here'}
              </p>
              <p className="mt-1 text-xs text-muted-foreground">
                or click anywhere in this box to browse files from your computer
              </p>
              <Button
                variant="outline"
                size="sm"
                className="mt-4 gap-2 font-medium shadow-xs"
                type="button"
                onClick={(e) => {
                  e.stopPropagation()
                  openFileDialog()
                }}
              >
                <Upload className="size-4" />
                Choose file
              </Button>
            </div>
          </div>
        </div>
      </div>

      {/* Bottom Row: System Status & Live Testbed Control */}
      <div className="grid gap-6 md:grid-cols-2">
        <div className="rounded-xl border bg-card p-6 flex flex-col justify-between">
          <div>
            <div className="mb-5 flex items-center justify-between">
              <div>
                <p className="text-sm font-semibold">System status</p>
                <p className="mt-1 text-xs text-muted-foreground">Local processing environment</p>
              </div>
              <Activity className="size-5 text-primary" />
            </div>

            <div className="flex flex-col gap-4">
              {[
                ['Analyzer API', 'Operational'],
                ['TShark engine', 'Ready'],
                ['AI classifier', 'Available'],
              ].map(([label, status]) => (
                <div key={label} className="flex items-center justify-between border-b pb-3 text-sm">
                  <span className="text-muted-foreground">{label}</span>
                  <span className="flex items-center gap-2 text-xs font-medium">
                    <span className="size-2 rounded-full bg-emerald-500" />
                    {status}
                  </span>
                </div>
              ))}
            </div>
          </div>

          <Button
            className="mt-6 w-full"
            variant="outline"
            onClick={() => onGo(info ? 'analysis' : 'dashboard')}
          >
            {live ? 'View live stream' : 'Open latest capture'}
          </Button>
        </div>

        <div className="rounded-xl border border-primary/20 bg-primary/5 p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-start justify-between">
              <div>
                <p className="text-base font-semibold text-primary">Live IPsec Testbed Simulation</p>
                <p className="mt-2 text-xs leading-relaxed text-muted-foreground">
                  Configure strongSwan VPN tunnel in Docker, generate traffic, and capture downloadable PCAP.
                </p>
              </div>
              <Server className="size-6 text-primary shrink-0 ml-2" />
            </div>
          </div>
          <Button className="mt-6 w-full" onClick={() => onGo('testbed')}>
            <Server data-icon="inline-start" className="size-4 mr-2" />
            Open Testbed Control Panel
          </Button>
        </div>
      </div>
    </div>
  )
}

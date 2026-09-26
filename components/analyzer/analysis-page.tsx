'use client'

import { ChevronRight, FileCode2, BarChart3 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { type PCAPInfo, type Packet } from '@/lib/api/types'

export function AnalysisPage({
  info,
  packets,
  busy,
  onInspect,
  onFeatures,
}: {
  info: PCAPInfo
  packets: Packet[]
  busy: boolean
  onInspect?: () => void
  onFeatures: () => void
}) {
  return (
    <div className="flex flex-col gap-6">
      <div className="grid gap-4 lg:grid-cols-[1fr_0.8fr]">
        <div className="rounded-xl border bg-card p-5">
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-muted-foreground">
            Loaded capture
          </p>
          <p className="mt-2 flex items-center gap-2 text-lg font-semibold">
            <FileCode2 className="size-5 text-primary" />
            {info.name}
          </p>
          <div className="mt-6 grid grid-cols-2 gap-4 text-sm sm:grid-cols-4">
            {[
              ['File size', info.size],
              ['Packets', info.packets.toLocaleString()],
              ['Duration', info.duration],
              ['Captured', info.capturedAt],
            ].map(([label, value]) => (
              <div key={label}>
                <p className="text-xs text-muted-foreground">{label}</p>
                <p className="mt-1 font-medium">{value}</p>
              </div>
            ))}
          </div>
        </div>

        <div className="rounded-xl border bg-card p-5">
          <p className="text-sm font-semibold">Capture pipeline</p>
          <p className="mt-1 text-xs text-muted-foreground">TShark parser status</p>
          <div className="mt-6 flex items-center gap-2">
            {['Upload', 'Decode', 'Features'].map((label, index) => (
              <div key={label} className="flex flex-1 items-center gap-2">
                <div className="flex size-8 items-center justify-center rounded-full bg-primary text-xs font-semibold text-primary-foreground">
                  {index + 1}
                </div>
                <span className="text-xs font-medium">{label}</span>
              </div>
            ))}
          </div>
          <div className="mt-6 flex items-center">
            <Button
              onClick={onFeatures}
              className="bg-blue-600 hover:bg-blue-700 text-white font-semibold shadow-md shadow-blue-500/25 px-5 py-2.5 rounded-lg border border-blue-600 gap-2 transition-all hover:translate-y-[-1px]"
            >
              <BarChart3 className="size-4 text-white" />
              Features
              <ChevronRight className="size-4 text-white" />
            </Button>
          </div>
        </div>
      </div>

      <div className="rounded-xl border bg-card">
        <div className="border-b p-5">
          <p className="text-sm font-semibold">Packet overview</p>
          <p className="mt-1 text-xs text-muted-foreground">Decoded headers from the capture stream</p>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-muted/40 text-xs text-muted-foreground">
              <tr>
                <th className="p-4">No.</th>
                <th className="p-4">Time</th>
                <th className="p-4">Source</th>
                <th className="p-4">Destination</th>
                <th className="p-4">Protocol</th>
                <th className="p-4">Info</th>
              </tr>
            </thead>
            <tbody>
              {packets.length > 0 ? (
                packets.map((packet) => (
                  <tr key={packet.no} className="border-t hover:bg-muted/20 transition-colors">
                    <td className="p-4 text-muted-foreground">{packet.no}</td>
                    <td className="p-4 font-mono text-xs">{packet.time}</td>
                    <td className="p-4 font-mono text-xs">{packet.source}</td>
                    <td className="p-4 font-mono text-xs">{packet.destination}</td>
                    <td className="p-4">
                      <span className="rounded bg-primary/10 px-2 py-1 text-xs font-semibold text-primary">
                        {packet.protocol}
                      </span>
                    </td>
                    <td className="p-4 text-muted-foreground">{packet.info}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="p-8 text-center text-sm text-muted-foreground">
                    No packets to display. Packets are parsed automatically upon upload.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

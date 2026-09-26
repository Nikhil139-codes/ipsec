'use client'

import { useEffect, useRef, useState } from 'react'
import { Check, CornerDownLeft, Play, RotateCcw, Shield, Terminal as TerminalIcon } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { executeSimulatedCommand } from '@/lib/api/attacker'
import { type SecurityAnalysisResult, type SimulatedTestResult } from '@/lib/api/types'

interface VpnTestTerminalProps {
  reportData: SecurityAnalysisResult | null
  onCommandExecuted: (result: SimulatedTestResult) => void
  commandToRun?: string | null
  onClearCommandToRun?: () => void
}

const INITIAL_GREETING = [
  'Authorized VPN Security Validation Testbed [Lab Prototype v1.2]',
  'Environment: Isolated Linux / strongSwan 5.9.11 Emulation',
  'Security Policy: Non-destructive compliance validation only.',
  "Type 'help' for authorized simulation commands (pfs-test, replay-test, cipher-test, sa-test, metadata-test).",
  '',
]

export function VpnTestTerminal({
  reportData,
  onCommandExecuted,
  commandToRun,
  onClearCommandToRun,
}: VpnTestTerminalProps) {
  const [history, setHistory] = useState<string[]>(INITIAL_GREETING)
  const [inputCommand, setInputCommand] = useState('')
  const [isExecuting, setIsExecuting] = useState(false)
  const [execElapsed, setExecElapsed] = useState(0)
  const terminalEndRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  // Scroll to bottom smoothly on history update
  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [history, isExecuting])

  // Automatically execute command if requested externally (e.g. from test card)
  useEffect(() => {
    if (commandToRun) {
      handleRun(commandToRun)
      onClearCommandToRun?.()
    }
  }, [commandToRun])

  const handleRun = async (cmdToExecute?: string) => {
    const raw = (cmdToExecute ?? inputCommand).trim()
    if (!raw || isExecuting) return

    setInputCommand('')
    setIsExecuting(true)

    // Append command prompt line immediately: $ <command>
    setHistory((prev) => [...prev, `$ ${raw}`])

    const lower = raw.toLowerCase()

    if (lower === 'clear') {
      setHistory([])
      setIsExecuting(false)
      const simResult = executeSimulatedCommand(raw, reportData)
      onCommandExecuted(simResult)
      return
    }

    if (lower === 'help') {
      const simResult = executeSimulatedCommand(raw, reportData)
      const outputLines = simResult.terminal_output.slice(1)
      setHistory((prev) => [...prev, ...outputLines, ''])
      setIsExecuting(false)
      onCommandExecuted(simResult)
      return
    }

    // Predefined simulated execution
    const simResult = executeSimulatedCommand(raw, reportData)

    if (simResult.status === 'COMMAND REJECTED') {
      await new Promise((r) => setTimeout(r, 350))
      setHistory((prev) => [
        ...prev,
        `[ERROR] Command not recognized: '${raw}'`,
        `[INFO] Type 'help' for authorized simulation commands (pfs-test, replay-test, cipher-test, sa-test, metadata-test).`,
        '',
      ])
      setIsExecuting(false)
      onCommandExecuted(simResult)
      return
    }

    // Sequential multi-stage execution lasting ~45 seconds (45000ms)
    setExecElapsed(0)
    const startTime = Date.now()
    const timer = setInterval(() => {
      setExecElapsed(Math.floor((Date.now() - startTime) / 1000))
    }, 1000)

    const progressiveSteps = [
      { delay: 3500, line: `[00:03] [INIT] Allocating sandbox test namespace & attaching veth interface...` },
      { delay: 8000, line: `[00:08] [CONNECT] Hooking into strongSwan charon daemon socket (172.30.0.1:500)...` },
      { delay: 13000, line: `[00:13] [PROBE] Extracting active kernel XFRM state table (SAD/SPD rules)...` },
      { delay: 18000, line: `[00:18] [CRAFT] Generating targeted validation probe sequence for '${raw}'...` },
      { delay: 23000, line: `[00:23] [INJECT] Transmitting frame sequence across ESP tunnel data plane...` },
      { delay: 28000, line: `[00:28] [MONITOR] Intercepting IKEv2 NOTIFY and INFORMATIONAL responses...` },
      { delay: 33000, line: `[00:33] [ANALYSIS] Evaluating cryptographic boundaries against NIST SP 800-77 rules...` },
      { delay: 38000, line: `[00:38] [CORRELATE] Correlating anti-replay counter and packet sequence integrity...` },
      { delay: 42000, line: `[00:42] [COMPILE] Finalizing heuristic exploit analysis and breaking point data...` },
      { delay: 45000, line: `[00:45] [COMPLETE] Validation probe finished. Diagnostic results below:` },
    ]

    for (const step of progressiveSteps) {
      const waitTime = step.delay - (Date.now() - startTime)
      if (waitTime > 0) {
        await new Promise((r) => setTimeout(r, waitTime))
      }
      setHistory((prev) => [...prev, step.line])
    }

    clearInterval(timer)

    // Show final test outcome and results
    await new Promise((r) => setTimeout(r, 400))
    const outputLines = simResult.terminal_output.slice(1)
    const resultLines = outputLines.filter(
      (line) =>
        !line.includes('Starting security validation') &&
        !line.includes('Loading VPN security profile')
    )

    for (let i = 0; i < resultLines.length; i++) {
      await new Promise((r) => setTimeout(r, 120))
      setHistory((prev) => [...prev, resultLines[i]])
    }

    setHistory((prev) => [...prev, '']) // trailing blank line
    setIsExecuting(false)
    setExecElapsed(0)
    onCommandExecuted(simResult)
  }

  const handleClear = () => {
    setHistory([])
  }

  const handleReset = () => {
    setHistory(INITIAL_GREETING)
  }

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-950 font-mono text-zinc-100 shadow-md overflow-hidden flex flex-col">
      {/* Terminal Title Bar */}
      <div className="flex items-center justify-between border-b border-zinc-800 bg-zinc-900/90 px-4 py-2.5 select-none">
        <div className="flex items-center gap-2.5">
          <div className="flex items-center gap-1.5">
            <span className="size-3 rounded-full bg-red-500/80 inline-block" />
            <span className="size-3 rounded-full bg-yellow-500/80 inline-block" />
            <span className="size-3 rounded-full bg-emerald-500/80 inline-block" />
          </div>
          <div className="h-4 w-px bg-zinc-700 mx-1" />
          <div className="flex items-center gap-2 text-xs font-semibold text-zinc-300">
            <TerminalIcon className="size-3.5 text-emerald-400" />
            <span>VPN TEST TERMINAL</span>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 text-[11px] text-zinc-400">
            <span className="size-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="hidden sm:inline">Lab Sandbox Active</span>
          </div>
          <button
            onClick={handleClear}
            className="text-[11px] text-zinc-400 hover:text-zinc-200 transition px-2 py-0.5 rounded border border-zinc-800 hover:bg-zinc-800/60"
            title="Clear terminal window"
          >
            Clear
          </button>
          <button
            onClick={handleReset}
            className="text-[11px] text-zinc-400 hover:text-zinc-200 transition px-2 py-0.5 rounded border border-zinc-800 hover:bg-zinc-800/60"
            title="Reset greeting message"
          >
            Reset
          </button>
        </div>
      </div>

      {/* Terminal History Output */}
      <div className="p-4 text-xs leading-relaxed overflow-y-auto max-h-[340px] min-h-[220px] font-mono select-text space-y-1">
        {history.map((line, idx) => {
          if (line.startsWith('$') || line.startsWith('user@vpn-lab:~$')) {
            return (
              <div key={idx} className="text-emerald-400 font-semibold flex items-center gap-1.5 pt-1">
                <span>{line}</span>
              </div>
            )
          }
          if (line.startsWith('[INFO]')) {
            return (
              <div key={idx} className="text-zinc-300">
                <span className="text-cyan-400 font-bold">[INFO]</span> {line.replace('[INFO]', '').trim()}
              </div>
            )
          }
          if (line.startsWith('[WARNING]')) {
            return (
              <div key={idx} className="text-amber-300 font-medium">
                <span className="text-amber-400 font-bold">[WARNING]</span> {line.replace('[WARNING]', '').trim()}
              </div>
            )
          }
          if (line.startsWith('[ERROR]')) {
            return (
              <div key={idx} className="text-rose-400 font-semibold">
                <span className="text-rose-500 font-bold">[ERROR]</span> {line.replace('[ERROR]', '').trim()}
              </div>
            )
          }
          if (line.includes('TEST RESULT: FAILED')) {
            return (
              <div key={idx} className="text-rose-400 font-bold text-sm tracking-wide pt-1">
                {line}
              </div>
            )
          }
          if (line.includes('TEST RESULT: PASSED')) {
            return (
              <div key={idx} className="text-emerald-400 font-bold text-sm tracking-wide pt-1">
                {line}
              </div>
            )
          }
          return (
            <div key={idx} className="text-zinc-400">
              {line || '\u00A0'}
            </div>
          )
        })}
        {isExecuting && (
          <div className="flex items-center gap-2 text-cyan-400 italic text-xs pt-1">
            <span className="size-2 rounded-full bg-cyan-400 animate-ping inline-block" />
            Executing simulated validation in progress... ({execElapsed}s / ~45s)
          </div>
        )}
        <div ref={terminalEndRef} />
      </div>

      {/* Terminal Input Bar */}
      <form
        onSubmit={(e) => {
          e.preventDefault()
          handleRun()
        }}
        className="flex items-center gap-2 border-t border-zinc-800 bg-zinc-900/60 px-4 py-3"
      >
        <div className="flex items-center gap-1.5 text-xs font-semibold text-emerald-400 shrink-0 select-none">
          <span>user@vpn-lab:~$</span>
        </div>

        <input
          ref={inputRef}
          type="text"
          value={inputCommand}
          onChange={(e) => setInputCommand(e.target.value)}
          disabled={isExecuting}
          placeholder="pfs-test"
          className="flex-1 bg-transparent text-xs text-zinc-100 placeholder:text-zinc-600 focus:outline-none font-mono"
          spellCheck={false}
          autoComplete="off"
        />

        <Button
          type="submit"
          size="sm"
          disabled={isExecuting || !inputCommand.trim()}
          className="h-7 px-3 text-xs bg-emerald-600 hover:bg-emerald-700 text-white font-mono gap-1 shrink-0"
        >
          <Play className="size-3" />
          Execute
        </Button>
      </form>
    </div>
  )
}
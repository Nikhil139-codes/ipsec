'use client'

import { useEffect, useRef, useState } from 'react'
import {
  AlertCircle,
  Bot,
  CornerDownLeft,
  Loader2,
  MessageSquare,
  RotateCcw,
  Send,
  Sparkles,
  User,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { askReportChat } from '@/lib/api/analysis'
import { type ChatMessage, type RagSourceCitation } from '@/lib/api/types'

interface ReportChatProps {
  sessionId?: string
  reportId?: string
  reportName?: string
}

const SUGGESTED_QUESTIONS = [
  'Why is my risk score high?',
  'Explain the NIST findings.',
  'Was PFS detected?',
  'What should I fix first?',
  'Which security checks returned WARNING or FAIL?',
  'What encryption algorithm was observed?',
]

export function ReportChat({ sessionId, reportId, reportName }: ReportChatProps) {
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [inputQuestion, setInputQuestion] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const messagesEndRef = useRef<HTMLDivElement>(null)

  // Scroll to bottom of chat smoothly on new message
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, loading])

  // Clear messages when report or session changes
  useEffect(() => {
    setMessages([])
    setError(null)
  }, [sessionId, reportId])

  const handleSend = async (questionText?: string) => {
    const q = (questionText || inputQuestion).trim()
    if (!q || loading) return

    setError(null)
    setInputQuestion('')

    const userMessage: ChatMessage = {
      id: `user-${Date.now()}`,
      sender: 'user',
      text: q,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    }

    setMessages((prev) => [...prev, userMessage])
    setLoading(true)

    try {
      const res = await askReportChat(q, sessionId, reportId)

      const assistantMessage: ChatMessage = {
        id: `assistant-${Date.now()}`,
        sender: 'assistant',
        text: res.answer,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        sources: res.sources,
      }

      setMessages((prev) => [...prev, assistantMessage])
    } catch (err: any) {
      console.error('[RAG] Query error:', err)
      setError(err?.message || 'Unable to retrieve answer from report right now.')
    } finally {
      setLoading(false)
    }
  }

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }

  const handleClearChat = () => {
    setMessages([])
    setError(null)
  }

  return (
    <div className="rounded-xl border bg-card p-6 shadow-xs mt-6 transition">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b pb-4 mb-5">
        <div>
          <div className="flex items-center gap-2">
            <span className="flex size-7 items-center justify-center rounded-lg bg-primary/10 text-primary">
              <MessageSquare className="size-4" />
            </span>
            <h3 className="text-base font-bold uppercase tracking-wider text-foreground">
              Ask About This Report
            </h3>
            <span className="rounded bg-primary/10 px-2 py-0.5 text-[10px] font-semibold text-primary">
              RAG Assistant
            </span>
          </div>
          <p className="mt-1 text-xs text-muted-foreground">
            Ask grounded questions about your latest security assessment. Answers are derived strictly from the active report.
          </p>
        </div>

        {messages.length > 0 && (
          <Button
            variant="outline"
            size="sm"
            onClick={handleClearChat}
            disabled={loading}
            className="h-8 gap-1.5 text-xs text-muted-foreground hover:text-foreground"
          >
            <RotateCcw className="size-3.5" />
            Clear Chat
          </Button>
        )}
      </div>

      {/* Suggested Questions Chips */}
      {messages.length === 0 && (
        <div className="mb-5">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
            <Sparkles className="size-3.5 text-primary" />
            Suggested Questions:
          </p>
          <div className="flex flex-wrap gap-2">
            {SUGGESTED_QUESTIONS.map((suggestion) => (
              <button
                key={suggestion}
                type="button"
                onClick={() => handleSend(suggestion)}
                disabled={loading}
                className="rounded-lg border bg-muted/40 hover:bg-muted px-3 py-1.5 text-xs text-foreground transition text-left font-medium hover:border-primary/40 disabled:opacity-50"
              >
                {suggestion}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Message Stream */}
      {messages.length > 0 && (
        <div className="space-y-4 mb-6 max-h-[420px] overflow-y-auto pr-1">
          {messages.map((msg) => {
            const isUser = msg.sender === 'user'

            return (
              <div
                key={msg.id}
                className={`flex gap-3 text-xs ${isUser ? 'justify-end' : 'justify-start'}`}
              >
                {!isUser && (
                  <div className="flex size-7 shrink-0 items-center justify-center rounded-full bg-primary/10 text-primary mt-0.5">
                    <Bot className="size-4" />
                  </div>
                )}

                <div className={`max-w-[85%] rounded-xl p-4 shadow-2xs ${isUser
                    ? 'bg-primary text-primary-foreground font-medium rounded-tr-none'
                    : 'bg-muted/40 border text-foreground rounded-tl-none'
                  }`}>
                  {/* Message Sender & Timestamp */}
                  <div className="flex items-center justify-between gap-4 mb-1.5 opacity-80 text-[10px]">
                    <span className="font-semibold uppercase tracking-wider">
                      {isUser ? 'You' : 'Security Report Assistant'}
                    </span>
                    <span>{msg.timestamp}</span>
                  </div>

                  {/* Message Content */}
                  <div className="leading-relaxed whitespace-pre-wrap text-xs">
                    {msg.text}
                  </div>

                  {/* Sources Citation Badge (Section 11) */}
                  {!isUser && msg.sources && msg.sources.length > 0 && (
                    <div className="mt-3.5 pt-2.5 border-t border-border/50">
                      <p className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground mb-1.5">
                        Report Sources Used:
                      </p>
                      <div className="flex flex-wrap gap-1.5">
                        {msg.sources.map((src, i) => (
                          <span
                            key={i}
                            className="inline-flex items-center gap-1 rounded bg-background border px-2 py-0.5 text-[10px] font-medium text-muted-foreground shadow-2xs"
                          >
                            <span className="size-1 rounded-full bg-primary" />
                            {src.section}
                            {src.relevance > 0 && (
                              <span className="text-[9px] opacity-70">
                                ({Math.round(src.relevance * 100)}%)
                              </span>
                            )}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {isUser && (
                  <div className="flex size-7 shrink-0 items-center justify-center rounded-full bg-muted text-muted-foreground mt-0.5">
                    <User className="size-4" />
                  </div>
                )}
              </div>
            )
          })}

          {/* Loading Indicator */}
          {loading && (
            <div className="flex gap-3 text-xs justify-start">
              <div className="flex size-7 shrink-0 items-center justify-center rounded-full bg-primary/10 text-primary mt-0.5">
                <Bot className="size-4" />
              </div>
              <div className="rounded-xl p-4 bg-muted/40 border text-muted-foreground rounded-tl-none flex items-center gap-2.5">
                <Loader2 className="size-4 animate-spin text-primary" />
                <span className="text-xs">Searching report and synthesizing answer...</span>
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>
      )}

      {/* Error State Banner */}
      {error && (
        <div className="mb-4 flex items-center gap-2 rounded-lg border border-destructive/20 bg-destructive/10 p-3 text-xs text-destructive">
          <AlertCircle className="size-4 shrink-0" />
          <p>{error}</p>
        </div>
      )}

      {/* Input Bar */}
      <div className="flex items-center gap-2">
        <div className="relative flex-1">
          <input
            type="text"
            value={inputQuestion}
            onChange={(e) => setInputQuestion(e.target.value)}
            onKeyDown={handleKeyDown}
            disabled={loading}
            placeholder={
              reportName
                ? `Ask anything about ${reportName}...`
                : 'Type your question about this report (e.g. Why is my risk score high?)...'
            }
            className="w-full rounded-lg border bg-background px-3.5 py-2.5 text-xs placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary disabled:opacity-50"
          />
        </div>

        <Button
          onClick={() => handleSend()}
          disabled={loading || !inputQuestion.trim()}
          size="sm"
          className="h-9 px-4 gap-1.5 text-xs font-semibold shadow-xs shrink-0"
        >
          {loading ? (
            <Loader2 className="size-3.5 animate-spin" />
          ) : (
            <Send className="size-3.5" />
          )}
          Ask
        </Button>
      </div>
    </div>
  )
}

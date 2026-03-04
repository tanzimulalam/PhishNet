// popup.tsx — PhishNet v3 Popup (Scan + Chat + Intel)

import { useEffect, useRef, useState } from "react"
import "./popup.css"
import { runDeepScan, type DeepScanResult, type DeepScanStage, type EmailDeepScanContext } from "./lib/deepScan"
import { analyzeUrl, buildScanResult, type ScanResult } from "./lib/phishingDetector"
import { getSettings, type PhishNetSettings } from "./lib/storage"
import { sendChatMessage, type ChatMessage, type ChatContext } from "./lib/chat"
import type { EmailScanResult } from "./contents/gmail"
import { WorldMap, DnaFingerprint, ReportCardSection } from "./components/InsightsTab"
import { lookupHIBP, type HIBPResult } from "./lib/osintServices"

// ─── Small helpers ────────────────────────────────────────────────────────────

const SEVERITY_ICONS: Record<string, string> = {
  "ip-url": "🔢", "suspicious-tld": "🚩", "lookalike-domain": "🎭",
  "excessive-subdomains": "🔗", "long-url": "📏", "http-login": "🔓",
  "at-symbol": "🎣", "redirect-param": "↩️", "login-form": "🔐",
  "external-form": "📤", "hidden-forms": "🙈", "suspicious-keywords": "⚠️", "mismatched-links": "🔀",
  "spoofed-sender": "🎭", "suspicious-sender-tld": "🚩", "free-email-brand": "📧",
  "phishing-keywords": "⚠️", "urgent-subject": "🔔", "suspicious-link": "🔗",
  "many-links": "🔀", "generic-display-name": "👤"
}

const getRiskColor = (l: string) => l === "dangerous" ? "var(--danger)" : l === "suspicious" ? "var(--warn)" : "var(--safe)"
const getRiskLabel = (l: string) => l === "dangerous" ? "Dangerous" : l === "suspicious" ? "Suspicious" : "Safe"

function getRiskDesc(level: string, count: number, isEmail = false) {
  const src = isEmail ? "email" : "page"
  if (level === "dangerous") return `${count} indicator${count !== 1 ? "s" : ""} — do not enter credentials on this ${src}.`
  if (level === "suspicious") return `${count} suspicious indicator${count !== 1 ? "s" : ""}. Proceed with caution.`
  return isEmail ? "Email appears safe. Try Deep Scan for AI analysis." : "No threats detected. Try Deep Scan for a deeper analysis."
}

// ─── Gauge ────────────────────────────────────────────────────────────────────

function RiskGauge({ score, level }: { score: number; level: string }) {
  const r = 34, c = 2 * Math.PI * r, color = getRiskColor(level)
  return (
    <div className="gauge-container">
      <svg className="gauge-svg" viewBox="0 0 88 88">
        <circle className="gauge-track" cx="44" cy="44" r={r} />
        <circle className="gauge-fill" cx="44" cy="44" r={r} stroke={color}
          strokeDasharray={`${(score / 100) * c} ${c - (score / 100) * c}`} strokeDashoffset={0} />
      </svg>
      <div className="gauge-center">
        <span className="score-number" style={{ color }}>{score}</span>
        <span className="score-label">RISK</span>
      </div>
    </div>
  )
}

// ─── VT Card ─────────────────────────────────────────────────────────────────

function VTCard({ vt }: { vt: NonNullable<DeepScanResult["virusTotal"]> }) {
  if (vt.error) return (
    <div className="deep-card vt-card error-card">
      <div className="deep-card-header"><span>🔬 VirusTotal</span></div>
      <p className="vt-error">{vt.error}</p>
    </div>
  )
  return (
    <div className="deep-card vt-card">
      <div className="deep-card-header">
        <span>🔬 VirusTotal</span>
        {vt.lastAnalysisDate && <span className="dc-meta">{vt.lastAnalysisDate}</span>}
        {vt.permalink && <a className="dc-link" href={vt.permalink} target="_blank" rel="noreferrer">Full report ↗</a>}
      </div>
      <div className="vt-stats">
        {[["malicious", vt.malicious, "Malicious"], ["suspicious", vt.suspicious, "Suspicious"],
        ["harmless", vt.harmless, "Harmless"], ["undetected", vt.undetected, "Undetected"]
        ].map(([cls, num, lbl]) => (
          <div key={String(cls)} className={`vt-stat ${cls}`}>
            <span className="vt-stat-num">{num}</span>
            <span className="vt-stat-lbl">{lbl}</span>
          </div>
        ))}
      </div>
      <div className="vt-meta-rows">
        {vt.popularThreatLabel && <div className="vt-meta-row danger-row"><span>⚡ Threat</span><span>{vt.popularThreatLabel}</span></div>}
        {vt.domainReputation !== undefined && <div className="vt-meta-row"><span>🌐 Domain rep</span><span style={{ color: vt.domainReputation < 0 ? "var(--danger)" : "inherit" }}>{vt.domainReputation}</span></div>}
        {vt.registrar && <div className="vt-meta-row"><span>📋 Registrar</span><span>{vt.registrar}</span></div>}
        {vt.creationDate && <div className="vt-meta-row"><span>📅 Registered</span><span>{vt.creationDate}</span></div>}
        {vt.ipAddress && <div className="vt-meta-row"><span>🔌 Server IP</span><span>{vt.ipAddress}{vt.ipCountry ? ` (${vt.ipCountry})` : ""}</span></div>}
        {vt.asOwner && <div className="vt-meta-row"><span>🏢 AS Owner</span><span>{vt.asOwner}</span></div>}
        {(vt.ipMalicious ?? 0) > 0 && <div className="vt-meta-row danger-row"><span>🔴 IP flagged by</span><span>{vt.ipMalicious} engines</span></div>}
      </div>
      {vt.categories.length > 0 && (
        <div className="vt-categories">
          {[...new Set([...vt.categories, ...(vt.domainCategories ?? [])])].slice(0, 5).map(c => <span key={c} className="vt-cat">{c}</span>)}
        </div>
      )}
    </div>
  )
}

// ─── AI Card ─────────────────────────────────────────────────────────────────

function AICard({ ai }: { ai: NonNullable<DeepScanResult["aiVerdict"]> }) {
  const color = ai.verdict === "dangerous" ? "var(--danger)" : ai.verdict === "suspicious" ? "var(--warn)" : "var(--safe)"
  const emoji = ai.verdict === "dangerous" ? "🔴" : ai.verdict === "suspicious" ? "🟡" : "🟢"
  if (ai.error) return (
    <div className="deep-card ai-card error-card">
      <div className="deep-card-header"><span>🤖 {ai.provider}</span></div>
      <p className="vt-error">{ai.error}</p>
    </div>
  )
  return (
    <div className="deep-card ai-card">
      <div className="deep-card-header"><span>🤖 {ai.provider}</span><span className="dc-meta">{ai.model}</span></div>
      <div className="ai-verdict-row">
        <span className="ai-verdict-badge" style={{ color, borderColor: color }}>{emoji} {ai.verdict.charAt(0).toUpperCase() + ai.verdict.slice(1)}</span>
        <span className="ai-confidence">{ai.confidence}% confidence</span>
      </div>
      {ai.primaryReason && <p className="ai-primary">{ai.primaryReason}</p>}
      {ai.explanation && <p className="ai-explanation">{ai.explanation}</p>}
    </div>
  )
}


// ─── URLscan Card ─────────────────────────────────────────────────────────────

function URLscanCard({ urlscan }: { urlscan: NonNullable<DeepScanResult["urlscan"]> }) {
  if (urlscan.error) return (
    <div className="deep-card urlscan-card error-card">
      <div className="deep-card-header"><span>🔍 URLscan.io</span></div>
      <p className="vt-error">{urlscan.error}</p>
    </div>
  )
  const verdictColor = urlscan.verdict === "malicious" ? "var(--danger)" : 
                       urlscan.verdict === "suspicious" ? "var(--warn)" : "var(--safe)"
  return (
    <div className="deep-card urlscan-card">
      <div className="deep-card-header">
        <span>🔍 URLscan.io</span>
        {urlscan.verdict && (
          <span className="dc-meta" style={{ color: verdictColor }}>
            {urlscan.verdict === "malicious" ? "🚨 Malicious" : 
             urlscan.verdict === "suspicious" ? "⚠️ Suspicious" : "✅ Clean"}
          </span>
        )}
        {urlscan.uuid && (
          <a className="dc-link" href={`https://urlscan.io/result/${urlscan.uuid}`} target="_blank" rel="noreferrer">
            View scan ↗
          </a>
        )}
      </div>
      <div className="vt-meta-rows">
        {urlscan.country && <div className="vt-meta-row"><span>🌍 Country</span><span>{urlscan.country}</span></div>}
        {urlscan.ip && <div className="vt-meta-row"><span>🔌 IP</span><span>{urlscan.ip}</span></div>}
        {urlscan.asnname && <div className="vt-meta-row"><span>🏢 ASN</span><span>{urlscan.asnname}</span></div>}
        {urlscan.pageTitle && <div className="vt-meta-row"><span>📄 Title</span><span>{urlscan.pageTitle.substring(0, 50)}</span></div>}
      </div>
    </div>
  )
}

// ─── Google Safe Browsing Card ───────────────────────────────────────────────

function GoogleSBCard({ gsb }: { gsb: NonNullable<DeepScanResult["googleSafeBrowsing"]> }) {
  if (gsb.error) return (
    <div className="deep-card gsb-card error-card">
      <div className="deep-card-header"><span>🛡️ Google Safe Browsing</span></div>
      <p className="vt-error">{gsb.error}</p>
    </div>
  )
  const isSafe = gsb.safe
  return (
    <div className="deep-card gsb-card">
      <div className="deep-card-header">
        <span>🛡️ Google Safe Browsing</span>
        <span className="dc-meta" style={{ color: isSafe ? "var(--safe)" : "var(--danger)" }}>
          {isSafe ? "✅ Safe" : "🚨 Threat Detected"}
        </span>
      </div>
      {!isSafe && gsb.matches.length > 0 && (
        <div className="vt-meta-rows">
          {gsb.matches.map((match, i) => (
            <div key={i} className="vt-meta-row danger-row">
              <span>⚠️ Threat</span>
              <span>{match.threatType} ({match.platformType})</span>
            </div>
          ))}
        </div>
      )}
      {isSafe && <p style={{ margin: 0, padding: "8px 0", color: "var(--text-muted)", fontSize: 13 }}>No threats detected by Google Safe Browsing.</p>}
    </div>
  )
}

// ─── Indicator Card ───────────────────────────────────────────────────────────

function IndicatorCard({ id, label, description, severity, delay }: { id: string; label: string; description: string; severity: string; delay: number }) {
  return (
    <div className={`indicator-card severity-${severity}`} style={{ animationDelay: `${delay}s` }}>
      <div className="indicator-icon">{SEVERITY_ICONS[id] ?? "🔍"}</div>
      <div className="indicator-body">
        <div className="indicator-label">{label}</div>
        <div className="indicator-desc">{description}</div>
      </div>
      <div className="severity-chip">{severity}</div>
    </div>
  )
}

// ─── Chat Panel ───────────────────────────────────────────────────────────────

function ChatPanel({
  chatHistory, setChatHistory, context, settings, hasAiKey
}: {
  chatHistory: ChatMessage[]
  setChatHistory: (h: ChatMessage[]) => void
  context: ChatContext
  settings: PhishNetSettings | null
  hasAiKey: boolean
}) {
  const [input, setInput] = useState("")
  const [sending, setSending] = useState(false)
  const [error, setError] = useState("")
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" })
  }, [chatHistory])

  async function send() {
    const msg = input.trim()
    if (!msg || sending || !settings) return
    setInput(""); setError("")
    const newHistory: ChatMessage[] = [...chatHistory, { role: "user", content: msg }]
    setChatHistory(newHistory)
    setSending(true)
    try {
      const reply = await sendChatMessage(msg, chatHistory, context, settings)
      setChatHistory([...newHistory, { role: "assistant", content: reply }])
    } catch (e) {
      setError(e instanceof Error ? e.message : "Chat failed")
    } finally {
      setSending(false)
    }
  }

  function handleKey(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send() }
  }

  return (
    <div className="chat-panel">
      <div className="chat-header">
        <span className="chat-title">💬 PhishNet AI Assistant</span>
        <button className="chat-clear-btn" onClick={() => { setChatHistory([]); setError("") }} title="Clear chat history">
          🗑 Clear
        </button>
      </div>

      <div className="chat-messages">
        {chatHistory.length === 0 && (
          <div className="chat-empty">
            <div className="chat-empty-icon">🛡️</div>
            <p>Ask me anything about this {context.isEmail ? "email" : "page"} or the threat indicators found.</p>
            <div className="chat-suggestions">
              {["Is this site safe?", "What should I do?", "Explain the risk", "Why is this suspicious?"]
                .map(s => (
                  <button key={s} className="chat-suggestion" onClick={() => { setInput(s) }}>
                    {s}
                  </button>
                ))
              }
            </div>
          </div>
        )}
        {chatHistory.map((msg, i) => (
          <div key={i} className={`chat-msg chat-msg-${msg.role}`}>
            <div className="chat-msg-avatar">{msg.role === "user" ? "👤" : "🛡️"}</div>
            <div className="chat-msg-bubble">{msg.content}</div>
          </div>
        ))}
        {sending && (
          <div className="chat-msg chat-msg-assistant">
            <div className="chat-msg-avatar">🛡️</div>
            <div className="chat-msg-bubble chat-typing">
              <span /><span /><span />
            </div>
          </div>
        )}
        {error && <div className="chat-error">{error}</div>}
        <div ref={bottomRef} />
      </div>

      <div className="chat-input-row">
        <input
          className="chat-input"
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={handleKey}
          placeholder={hasAiKey ? "Ask about this threat…" : "Add an AI key in ⚙️ Settings"}
          disabled={!hasAiKey || sending}
          maxLength={400}
        />
        <button
          className="chat-send-btn"
          onClick={send}
          disabled={!hasAiKey || sending || !input.trim()}>
          {sending ? "…" : "➤"}
        </button>
      </div>
    </div>
  )
}

// ─── Threat Profile Card (WOW factor) ─────────────────────────────────────────

const PAGE_IDS_SET = new Set(["login-form", "external-form", "hidden-forms", "suspicious-keywords", "mismatched-links"])

function ThreatBar({ label, icon, value, color }: { label: string; icon: string; value: number; color: string }) {
  const pct = Math.min(Math.round(value), 100)
  return (
    <div className="threat-bar-row">
      <span className="threat-bar-icon">{icon}</span>
      <span className="threat-bar-label">{label}</span>
      <div className="threat-bar-track">
        <div className="threat-bar-fill" style={{ width: `${pct}%`, background: color }} />
      </div>
      <span className="threat-bar-pct" style={{ color }}>{pct}%</span>
    </div>
  )
}

function getColor(v: number) {
  return v >= 60 ? "var(--danger)" : v >= 25 ? "var(--warn)" : "var(--safe)"
}

function ThreatProfileCard({ deepResult, localInds, activeLevel }:
  { deepResult: DeepScanResult; localInds: any[]; activeLevel: string }) {
  const vt = deepResult.virusTotal
  const ai = deepResult.aiVerdict

  const urlScore = Math.min(localInds.filter(i => !PAGE_IDS_SET.has(i.id)).length * 18, 100)
  const pageScore = Math.min(localInds.filter(i => PAGE_IDS_SET.has(i.id)).length * 25, 100)
  const vtScore = vt && !vt.error ? Math.min(vt.malicious * 12 + (vt.popularThreatLabel ? 20 : 0), 100) : 0
  const domScore = vt && !vt.error ? Math.max(0, Math.min(100, 50 - (vt.domainReputation ?? 0))) : 0
  const netScore = vt && !vt.error ? Math.min((vt.ipMalicious ?? 0) * 15, 100) : 0
  const aiScore = ai && !ai.error ? ai.confidence : 0

  const bars = [
    { label: "URL Analysis", icon: "🔗", value: urlScore, color: getColor(urlScore) },
    { label: "Page Content", icon: "📄", value: pageScore, color: getColor(pageScore) },
    { label: "VirusTotal", icon: "🔬", value: vtScore, color: getColor(vtScore) },
    { label: "Domain Health", icon: "🌐", value: domScore, color: getColor(domScore) },
    { label: "Network Trust", icon: "🔌", value: netScore, color: getColor(netScore) },
    { label: "AI Confidence", icon: "🤖", value: aiScore, color: getColor(ai?.verdict === "safe" ? 0 : aiScore) },
  ]

  const overallColor = activeLevel === "dangerous" ? "var(--danger)" : activeLevel === "suspicious" ? "var(--warn)" : "var(--safe)"

  return (
    <div className="threat-profile-card" style={{ animationDelay: "0.15s" }}>
      <div className="threat-profile-header">
        <span>🎯 Threat Profile</span>
        <span style={{ color: overallColor, fontWeight: 700, fontSize: 10, marginLeft: "auto" }}>
          {activeLevel.toUpperCase()}
        </span>
      </div>
      <div className="threat-profile-body">
        {bars.map(b => <ThreatBar key={b.label} {...b} />)}
      </div>
    </div>
  )
}

// ─── Main Popup ───────────────────────────────────────────────────────────────


function IndexPopup() {
  const [tab, setTab] = useState<"scan" | "chat" | "intel">("scan")
  const [result, setResult] = useState<ScanResult | null>(null)
  const [gmailResult, setGmailResult] = useState<EmailScanResult | null>(null)
  const [deepResult, setDeepResult] = useState<DeepScanResult | null>(null)
  const [chatHistory, setChatHistory] = useState<ChatMessage[]>([])
  const [settings, setSettings] = useState<PhishNetSettings | null>(null)
  const [enriching, setEnriching] = useState(false)
  const [scanning, setScanning] = useState(false)
  const [deepScanning, setDeepScanning] = useState(false)
  const [deepStage, setDeepStage] = useState("")
  const [currentUrl, setCurrentUrl] = useState("")
  const [currentTabId, setCurrentTabId] = useState<number | null>(null)
  const [isGmail, setIsGmail] = useState(false)
  const [hibpResult, setHibpResult] = useState<HIBPResult | null>(null)
  const [checkingHibp, setCheckingHibp] = useState(false)
  const scanTimeRef = useRef("")

  useEffect(() => { getSettings().then(setSettings); initPopup() }, [])
  
  // Listen for tab updates to restore deep scan results when URL changes
  useEffect(() => {
    if (!currentUrl) return
    const restoreDeepScan = async () => {
      try {
        const storageKey = `deepScan_${currentUrl}`
        const stored = await chrome.storage.local.get(storageKey)
        if (stored[storageKey]) {
          const cached = stored[storageKey] as { result: DeepScanResult; timestamp: number; expiresAt: number }
          if (cached.expiresAt > Date.now()) {
            setDeepResult(cached.result)
          } else {
            await chrome.storage.local.remove(storageKey)
            setDeepResult(null)
          }
        } else {
          setDeepResult(null)
        }
      } catch (e) {
        console.error("Failed to restore deep scan result:", e)
      }
    }
    restoreDeepScan()
  }, [currentUrl])

  async function initPopup() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
    if (!tab?.id || !tab?.url) return
    setCurrentTabId(tab.id); setCurrentUrl(tab.url)
    const gmail = tab.url.includes("mail.google.com")
    setIsGmail(gmail)
    // Instant URL scan
    const inst = buildScanResult(tab.url, analyzeUrl(tab.url))
    setResult(inst); scanTimeRef.current = new Date(inst.scannedAt).toLocaleTimeString()
    // Enrich
    setEnriching(true)
    chrome.runtime.sendMessage({ type: "GET_SCAN_RESULT", tabId: tab.id }, (res) => {
      setEnriching(false)
      if (!chrome.runtime.lastError && res?.result) {
        const full = res.result as ScanResult
        if (full.indicators.length >= inst.indicators.length) { setResult(full); scanTimeRef.current = new Date(full.scannedAt).toLocaleTimeString() }
      }
    })
    if (gmail) {
      chrome.runtime.sendMessage({ type: "GET_GMAIL_RESULT", tabId: tab.id }, (res) => {
        if (!chrome.runtime.lastError && res?.result) setGmailResult(res.result as EmailScanResult)
      })
    }
    // Restore persisted deep scan result for this URL
    try {
      const storageKey = `deepScan_${tab.url}`
      const stored = await chrome.storage.local.get(storageKey)
      if (stored[storageKey]) {
        const cached = stored[storageKey] as { result: DeepScanResult; timestamp: number; expiresAt: number }
        // Check if result is still valid (not expired)
        if (cached.expiresAt > Date.now()) {
          setDeepResult(cached.result)
        } else {
          // Clean up expired result
          await chrome.storage.local.remove(storageKey)
        }
      }
    } catch (e) {
      // Ignore storage errors
      console.error("Failed to restore deep scan result:", e)
    }
  }

  async function handleRescan() {
    if (!currentTabId || !currentUrl) return
    setScanning(true); setDeepResult(null)
    // Clear persisted deep scan result when rescanning
    try {
      await chrome.storage.local.remove(`deepScan_${currentUrl}`)
    } catch {}
    const inst = buildScanResult(currentUrl, analyzeUrl(currentUrl))
    setResult(inst); scanTimeRef.current = new Date(inst.scannedAt).toLocaleTimeString(); setScanning(false)
    setEnriching(true)
    chrome.runtime.sendMessage({ type: "RESCAN", tabId: currentTabId }, (res) => {
      setEnriching(false)
      if (!chrome.runtime.lastError && res?.result) {
        const full = res.result as ScanResult
        if (full.indicators.length >= inst.indicators.length) { setResult(full); scanTimeRef.current = new Date(full.scannedAt).toLocaleTimeString() }
      }
    })
    if (isGmail) {
      chrome.runtime.sendMessage({ type: "GET_GMAIL_RESULT", tabId: currentTabId }, (res) => {
        if (!chrome.runtime.lastError && res?.result) setGmailResult(res.result as EmailScanResult)
      })
    }
  }

  async function handleDeepScan() {
    if (!settings) return
    setDeepScanning(true); setDeepResult(null); setDeepStage("Initialising…")
    try {
      let targetUrl = currentUrl
      let emailCtx: EmailDeepScanContext | undefined
      if (isGmail && gmailResult) {
        const sd = gmailResult.senderEmail?.split("@")[1]
        targetUrl = gmailResult.suspiciousLinks[0] ?? (sd ? `https://${sd}` : currentUrl)
        emailCtx = {
          senderEmail: gmailResult.senderEmail, senderDisplay: gmailResult.senderDisplay,
          subject: gmailResult.subject, suspiciousLinks: gmailResult.suspiciousLinks,
          indicators: gmailResult.indicators.map(i => ({ label: i.label, description: i.description }))
        }
      }
      const localLabels = [
        ...(result?.indicators.map(i => i.label) ?? []),
        ...(gmailResult?.indicators.map(i => i.label) ?? [])
      ]
      const dr = await runDeepScan(targetUrl, settings, localLabels, (_s: DeepScanStage, msg: string) => setDeepStage(msg), emailCtx)
      setDeepResult(dr)
      // Persist deep scan result to storage (keyed by URL, expires after 1 hour)
      if (targetUrl) {
        await chrome.storage.local.set({
          [`deepScan_${targetUrl}`]: {
            result: dr,
            timestamp: Date.now(),
            expiresAt: Date.now() + (60 * 60 * 1000) // 1 hour
          }
        })
      }
    } catch { setDeepStage("Deep scan failed — check API keys in Settings.") }
    finally { setDeepScanning(false); setDeepStage("") }
  }

  function openSettings() {
    if (chrome.runtime.openOptionsPage) chrome.runtime.openOptionsPage()
    else chrome.tabs.create({ url: chrome.runtime.getURL("options.html") })
  }

  const hasAiKey = settings ? (settings.aiProvider === "gemini" ? !!settings.geminiApiKey : !!settings.openaiApiKey) : false
  const hasAnyKey = hasAiKey || !!settings?.virusTotalApiKey
  const isUnscannable = !currentUrl || /^(chrome|about|edge):/.test(currentUrl)
  // Merge local scan + deep scan to derive effective risk level/score
  const ORDER: Record<string, number> = { safe: 0, suspicious: 1, dangerous: 2 }
  const baseScore = isGmail && gmailResult ? gmailResult.riskScore : result?.riskScore ?? 0
  const baseLevel = isGmail && gmailResult ? gmailResult.riskLevel : result?.riskLevel ?? "safe"
  const aiLevel = deepResult?.aiVerdict && !deepResult.aiVerdict.error ? deepResult.aiVerdict.verdict : null
  const vtMal = deepResult?.virusTotal?.malicious ?? 0
  // Boost score from deep scan evidence
  const deepBoost = Math.min((vtMal > 0 ? vtMal * 8 : 0) + (aiLevel === "dangerous" ? 30 : aiLevel === "suspicious" ? 12 : 0), 50)
  const activeScore = Math.min(baseScore + deepBoost, 100)
  const effectiveLevel = aiLevel && ORDER[aiLevel] > ORDER[baseLevel] ? aiLevel
    : vtMal > 3 ? "dangerous" : vtMal > 0 && ORDER[baseLevel] < 1 ? "suspicious" : baseLevel
  const activeLevel = effectiveLevel as "safe" | "suspicious" | "dangerous"
  const activeInds = isGmail && gmailResult ? gmailResult.indicators : result?.indicators ?? []

  const displayUrl = currentUrl
    ? currentUrl.replace(/^https?:\/\//, "").substring(0, 52) + (currentUrl.replace(/^https?:\/\//, "").length > 52 ? "…" : "")
    : "—"

  // Context for chat — includes all available scan data
  const chatContext: ChatContext = {
    url: currentUrl,
    riskLevel: activeLevel,
    riskScore: activeScore,
    indicators: (activeInds as any[]).map((i: any) => ({ label: i.label, description: i.description, severity: i.severity })),
    vtResult: deepResult?.virusTotal,
    aiVerdict: deepResult?.aiVerdict,
    isEmail: isGmail && !!gmailResult,
    emailSender: gmailResult?.senderEmail,
    emailSubject: gmailResult?.subject
  }

  return (
    <div className="phishnet-app">
      {/* Header */}
      <header className="header">
        <div className="logo">
          <div className="logo-icon">🛡️</div>
          <span className="logo-text">Phish<span>Net</span></span>
        </div>
        <div className="header-actions">
          <button
            className={`tab-toggle ${tab === "chat" ? "active" : ""}`}
            onClick={() => setTab(t => t === "scan" ? "chat" : "scan")}
            title="Toggle AI chat">
            💬{chatHistory.length > 0 && <span className="chat-dot" />}
          </button>
          <button className="settings-btn" onClick={openSettings} title="Settings">⚙️</button>
        </div>
      </header>

      {/* Tabs indicator */}
      <div className="tabs-bar">
        <button className={`tab-btn ${tab === "scan" ? "active" : ""}`} onClick={() => setTab("scan")}>
          🔍 Scan
        </button>
        <button className={`tab-btn ${tab === "chat" ? "active" : ""}`} onClick={() => setTab("chat")}>
          💬 Chat{chatHistory.length > 0 && <span className="chat-badge">{chatHistory.filter(m => m.role === "assistant").length}</span>}
        </button>
        <button className={`tab-btn ${tab === "intel" ? "active" : ""}`} onClick={() => setTab("intel")}>
          📡 Intel
        </button>
      </div>

      {/* ── SCAN TAB ─────────────────────────────────────────────────────────── */}
      {tab === "scan" && (
        <>
          {/* URL Bar */}
          {currentUrl && (
            <div className="url-bar">
              <span className="url-icon">{isGmail ? "📧" : "🌐"}</span>
              <span className="url-text">{isGmail ? "Gmail — email scan active" : displayUrl}</span>
            </div>
          )}

          {/* Email context */}
          {isGmail && gmailResult && (
            <div className="email-context-bar">
              <div className="email-context-row">
                <span className="ec-label">✉️ From</span>
                <span className="ec-value">{gmailResult.senderEmail || gmailResult.senderDisplay || "Unknown"}</span>
              </div>
              {gmailResult.subject && (
                <div className="email-context-row">
                  <span className="ec-label">📌 Subject</span>
                  <span className="ec-value">{gmailResult.subject.substring(0, 55)}{gmailResult.subject.length > 55 ? "…" : ""}</span>
                </div>
              )}
              {hibpResult && (
                <div className={`hibp-result ${hibpResult.breaches.length > 0 ? "hibp-breached" : "hibp-safe"}`}>
                  {hibpResult.error ? (
                    <div style={{ color: "var(--warn)", fontSize: 12 }}>⚠️ {hibpResult.error}</div>
                  ) : hibpResult.breaches.length > 0 ? (
                    <>
                      <div style={{ fontWeight: 600, marginBottom: 4 }}>
                        🚨 {hibpResult.breaches.length} breach{hibpResult.breaches.length !== 1 ? "es" : ""} found
                      </div>
                      <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                        {hibpResult.breaches.slice(0, 3).map(b => b.Name).join(", ")}
                        {hibpResult.breaches.length > 3 && ` +${hibpResult.breaches.length - 3} more`}
                      </div>
                      <a href={`https://haveibeenpwned.com/account/${encodeURIComponent(hibpResult.email)}`} target="_blank" rel="noreferrer" style={{ fontSize: 11, marginTop: 4, display: "block" }}>
                        View details →
                      </a>
                    </>
                  ) : (
                    <div style={{ color: "var(--safe)", fontSize: 12 }}>✅ No breaches found</div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Risk Score */}
          {!isUnscannable && (result || gmailResult) && (
            <div className="score-section">
              <RiskGauge score={activeScore} level={activeLevel} />
              <div className="score-info">
                <div className={`risk-badge ${activeLevel}`}>
                  <span className="risk-badge-dot" />
                  {getRiskLabel(activeLevel)}
                </div>
                <p className="risk-description">{getRiskDesc(activeLevel, activeInds.length, isGmail && !!gmailResult)}</p>
                {enriching && <div className="enrich-badge"><span className="spin">⟳</span> Scanning page…</div>}
                {!enriching && activeInds.length > 0 && <p className="indicator-count">{activeInds.length} indicator{activeInds.length !== 1 ? "s" : ""}</p>}
              </div>
            </div>
          )}

          {/* Buttons */}
          {!isUnscannable && (
            <div className="btn-row">
              <button className={`scan-btn${scanning ? " scanning" : ""}`} onClick={handleRescan} disabled={scanning || deepScanning}>
                <span className="btn-icon">◈</span>
                <span className="btn-label">{scanning ? "Scanning…" : "Rescan"}</span>
              </button>
              <button
                className={`deep-scan-btn${deepScanning ? " scanning" : ""}${!hasAnyKey ? " no-keys" : ""}`}
                onClick={hasAnyKey ? handleDeepScan : openSettings}
                disabled={deepScanning || scanning}>
                {deepScanning
                  ? <><span className="scan-ring">⬡</span><span className="btn-label">{deepStage.length > 20 ? deepStage.substring(0, 18) + "…" : deepStage || "Scanning…"}</span></>
                  : hasAnyKey
                    ? <><span className="btn-icon">⬡</span><span className="btn-label">Deep Scan{isGmail && gmailResult ? " Email" : ""}</span></>
                    : <><span className="btn-icon">⬡</span><span className="btn-label">Deep Scan</span><span className="no-key-hint">· Add keys</span></>
                }
              </button>
            </div>
          )}

          {/* Deep results */}
          {deepResult && (
            <div className="deep-results">
              {deepResult.aiVerdict && <AICard ai={deepResult.aiVerdict} />}
              {deepResult.googleSafeBrowsing && <GoogleSBCard gsb={deepResult.googleSafeBrowsing} />}
              {deepResult.virusTotal && <VTCard vt={deepResult.virusTotal} />}
              {deepResult.urlscan && <URLscanCard urlscan={deepResult.urlscan} />}
            </div>
          )}

          {/* Indicators */}
          <div className="indicators-section">
            {!result && !gmailResult && !isUnscannable && (
              <div className="loading-dots"><div className="loading-dot" /><div className="loading-dot" /><div className="loading-dot" /></div>
            )}
            {isUnscannable && (
              <div className="empty-state">
                <div className="empty-icon">🔒</div>
                <div className="empty-title">Cannot scan this page</div>
                <div className="empty-sub">Navigate to a website.</div>
              </div>
            )}
            {isGmail && !gmailResult && !isUnscannable && (
              <div className="empty-state">
                <div className="empty-icon">📧</div>
                <div className="empty-title">Open an email to scan it</div>
                <div className="empty-sub">PhishNet auto-scans sender, links, and content.</div>
              </div>
            )}
            {!isUnscannable && activeInds.length === 0 && (result || gmailResult) && !enriching && (
              <div className="empty-state">
                <div className="empty-icon">✅</div>
                <div className="empty-title">No threats detected</div>
                <div className="empty-sub">Try Deep Scan for AI + VirusTotal analysis.</div>
              </div>
            )}
            {activeInds.length > 0 && (
              <>
                <div className="section-title">{isGmail && gmailResult ? "Email Indicators" : "Page Indicators"}
                  <span style={{ color: "var(--text-muted)", fontWeight: 400, marginLeft: 6 }}>{activeInds.length} found</span>
                </div>
                {(activeInds as any[]).map((ind: any, i: number) => (
                  <IndicatorCard key={ind.id} id={ind.id} label={ind.label} description={ind.description} severity={ind.severity} delay={i * 0.05} />
                ))}
              </>
            )}
            {isGmail && gmailResult && result && result.indicators.length > 0 && (
              <>
                <div className="section-title" style={{ marginTop: 8 }}>Page Indicators</div>
                {result.indicators.map((ind, i) => (
                  <IndicatorCard key={ind.id} id={ind.id} label={ind.label} description={ind.description} severity={ind.severity as any} delay={i * 0.05} />
                ))}
              </>
            )}
            {/* Threat Profile — shown after deep scan */}
            {deepResult && !deepResult.aiVerdict?.error && (
              <ThreatProfileCard deepResult={deepResult} localInds={activeInds as any[]} activeLevel={activeLevel} />
            )}
          </div>
        </>
      )}

      {/* ── CHAT TAB ─────────────────────────────────────────────────────────── */}
      {tab === "chat" && (
        <ChatPanel
          chatHistory={chatHistory}
          setChatHistory={setChatHistory}
          context={chatContext}
          settings={settings}
          hasAiKey={hasAiKey}
        />
      )}

      {/* ── INTEL TAB ────────────────────────────────────────────────────────── */}
      {tab === "intel" && (
        <div className="intel-tab">
          <WorldMap
            country={deepResult?.virusTotal?.ipCountry}
            ipAddress={deepResult?.virusTotal?.ipAddress}
            asOwner={deepResult?.virusTotal?.asOwner}
            urlscanIp={deepResult?.urlscan?.ip}
            urlscanCountry={deepResult?.urlscan?.country}
            urlscanAsn={deepResult?.urlscan?.asnname}
          />
          {currentUrl && (
            <DnaFingerprint
              url={currentUrl}
              indicators={activeInds as any[]}
              settings={settings}
            />
          )}
          {/* HIBP Check for User's Own Email */}
          {settings?.userEmail && settings.userEmail.includes("@") && (
            <div className="insight-card">
              <div className="insight-card-header">
                <span>🔐 Have I Been Pwned?</span>
                <button
                  className="hibp-check-btn"
                  onClick={async () => {
                    if (!settings.userEmail || checkingHibp) return
                    setCheckingHibp(true)
                    setHibpResult(null)
                    try {
                      const result = await lookupHIBP(settings.userEmail, settings?.hibpApiKey)
                      setHibpResult(result)
                    } catch (e) {
                      setHibpResult({ email: settings.userEmail, breaches: [], error: e instanceof Error ? e.message : "Check failed" })
                    } finally {
                      setCheckingHibp(false)
                    }
                  }}
                  disabled={checkingHibp}
                  title="Check if your email has been breached">
                  {checkingHibp ? "⏳ Checking…" : "🔍 Check My Email"}
                </button>
              </div>
              {hibpResult && (
                <div className="hibp-result-container" style={{ padding: "10px 12px" }}>
                  {hibpResult.error ? (
                    <div style={{ color: "var(--warn)", fontSize: 12 }}>⚠️ {hibpResult.error}</div>
                  ) : hibpResult.breaches.length > 0 ? (
                    <>
                      <div style={{ fontWeight: 600, marginBottom: 4, color: "var(--danger)" }}>
                        🚨 {hibpResult.breaches.length} breach{hibpResult.breaches.length !== 1 ? "es" : ""} found
                      </div>
                      <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 6 }}>
                        {hibpResult.breaches.slice(0, 3).map(b => b.Name).join(", ")}
                        {hibpResult.breaches.length > 3 && ` +${hibpResult.breaches.length - 3} more`}
                      </div>
                      <a href={`https://haveibeenpwned.com/account/${encodeURIComponent(hibpResult.email)}`} target="_blank" rel="noreferrer" style={{ fontSize: 11, color: "var(--accent)", textDecoration: "none" }}>
                        View details on HIBP →
                      </a>
                    </>
                  ) : (
                    <div style={{ color: "var(--safe)", fontSize: 12, fontWeight: 500 }}>
                      ✅ No breaches found for {hibpResult.email}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
          <ReportCardSection
            url={currentUrl}
            result={result}
            deepResult={deepResult}
            gmailResult={gmailResult}
            isGmail={isGmail}
            activeScore={activeScore}
            activeLevel={activeLevel}
          />
        </div>
      )}

      {/* Footer */}
      <footer className="footer">
        <span className="footer-brand">⚡ PhishNet</span>
        {scanTimeRef.current && <span className="footer-time">Last scan: {scanTimeRef.current}</span>}
      </footer>
    </div>
  )
}

export default IndexPopup

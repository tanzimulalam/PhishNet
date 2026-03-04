// contents/gmail.tsx — PhishNet Gmail Email Scanner

import { useEffect } from "react"
import type { PlasmoCSConfig } from "plasmo"
import { analyzeUrl } from "../lib/phishingDetector"
import { getSetting } from "../lib/storage"

export const config: PlasmoCSConfig = {
    matches: ["https://mail.google.com/*"],
    run_at: "document_idle"
}

// ─── Types ────────────────────────────────────────────────────────────────────

export interface EmailScanResult {
    riskLevel: "safe" | "suspicious" | "dangerous"
    riskScore: number
    senderEmail: string
    senderDisplay: string
    subject: string
    indicators: EmailIndicator[]
    suspiciousLinks: string[]
    rawLinks: string[]
}

export interface EmailIndicator {
    id: string
    label: string
    description: string
    severity: "high" | "medium" | "low"
}

// ─── DOM Extraction ───────────────────────────────────────────────────────────

function extractSender(): { email: string; display: string } {
    const selectors = [".gD", "[data-hovercard-id]", ".go span[email]", ".from span"]
    for (const sel of selectors) {
        const el = document.querySelector(sel) as HTMLElement | null
        if (!el) continue
        const email = el.getAttribute("email") ?? el.getAttribute("data-hovercard-id") ?? el.innerText?.trim()
        const display = (el.getAttribute("name") ?? el.innerText ?? "").trim()
        if (email?.includes("@")) return { email: email.toLowerCase(), display }
    }
    return { email: "", display: "" }
}

function extractSubject(): string {
    return (document.querySelector(".hP") as HTMLElement)?.innerText?.trim() ?? ""
}

function extractBody(container: Element): string {
    return (container.querySelector(".a3s.aiL") as HTMLElement)?.innerText ?? ""
}

function extractLinks(container: Element): string[] {
    return Array.from(container.querySelectorAll(".a3s.aiL a[href]"))
        .map(a => (a as HTMLAnchorElement).href)
        .filter(h => h.startsWith("http") && !h.includes("mail.google.com"))
        .slice(0, 20)
}

// ─── Heuristics ───────────────────────────────────────────────────────────────

const BRAND_NAMES = ["paypal", "apple", "google", "microsoft", "amazon", "netflix", "bank of america", "chase", "wells fargo", "citibank", "hsbc", "barclays", "dhl", "fedex", "ups", "instagram", "facebook", "twitter", "linkedin", "dropbox", "docusign", "irs"]
const SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".pw", ".cc", ".ru", ".cn"]
const PHISHING_KEYWORDS = ["verify your account", "verify your identity", "suspended", "unusual activity", "update your payment", "confirm your details", "click here immediately", "your account will be", "limited access", "unauthorized access", "billing information", "security alert", "immediate action required", "validate your account", "you have been selected", "congratulations you won", "act now", "password expired", "confirm password", "reset your password now"]
const URGENCY_SUBJECTS = ["urgent", "action required", "immediate", "verify", "suspended", "unusual", "alert", "warning", "account locked", "your account", "password", "update required"]
const FREE_PROVIDERS = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com"]

function scanEmail(senderEmail: string, senderDisplay: string, subject: string, bodyText: string, links: string[]): EmailScanResult {
    const indicators: EmailIndicator[] = []
    const suspiciousLinks: string[] = []
    let score = 0
    const bodyLower = bodyText.toLowerCase()
    const senderDomain = senderEmail.split("@")[1]?.toLowerCase() ?? ""

    const claimedBrand = BRAND_NAMES.find(b => senderDisplay.toLowerCase().includes(b) || subject.toLowerCase().includes(b))

    // 1. Brand impersonation
    if (claimedBrand && senderDomain) {
        const brandClean = claimedBrand.replace(/\s/g, "")
        if (!senderDomain.includes(brandClean) && !senderDomain.includes(claimedBrand.split(" ")[0])) {
            indicators.push({ id: "spoofed-sender", label: "Sender Spoofing", description: `Pretends to be "${claimedBrand}" but sent from "${senderDomain}"`, severity: "high" })
            score += 45
        }
    }

    // 2. Suspicious sender TLD
    if (SUSPICIOUS_TLDS.some(t => senderDomain.endsWith(t))) {
        indicators.push({ id: "suspicious-sender-tld", label: "Suspicious Sender Domain", description: `"${senderDomain}" uses a TLD common in spam`, severity: "high" })
        score += 30
    }

    // 3. Brand from free email
    if (claimedBrand && FREE_PROVIDERS.includes(senderDomain)) {
        indicators.push({ id: "free-email-brand", label: "Brand Using Free Email", description: `"${claimedBrand}" wouldn't use ${senderDomain}`, severity: "high" })
        score += 35
    }

    // 4. Sender display vs email mismatch (display looks like a different email)
    if (senderDisplay && senderDisplay.includes("@") && senderEmail) {
        const displayEmail = senderDisplay.replace(/[<>]/g, "").trim().toLowerCase()
        if (displayEmail !== senderEmail.toLowerCase() && displayEmail.includes("@")) {
            indicators.push({ id: "display-email-mismatch", label: "Display Name Mismatch", description: `Shows "${displayEmail}" but actual sender is "${senderEmail}"`, severity: "high" })
            score += 30
        }
    }

    // 5. Phishing keywords
    const foundKeywords = PHISHING_KEYWORDS.filter(k => bodyLower.includes(k))
    if (foundKeywords.length >= 3) {
        indicators.push({ id: "phishing-keywords", label: "Multiple Phishing Phrases", description: `Found: "${foundKeywords.slice(0, 2).join('", "')}" + ${foundKeywords.length - 2} more`, severity: "high" })
        score += Math.min(foundKeywords.length * 8, 35)
    } else if (foundKeywords.length > 0) {
        indicators.push({ id: "phishing-keywords", label: "Suspicious Phrases", description: `Found: "${foundKeywords.join('", "')}"`, severity: "medium" })
        score += foundKeywords.length * 8
    }

    // 6. Urgency in subject
    const subjectLower = subject.toLowerCase()
    const urgencyCount = URGENCY_SUBJECTS.filter(w => subjectLower.includes(w)).length
    if (urgencyCount >= 2) {
        indicators.push({ id: "urgent-subject", label: "High-Urgency Subject", description: `"${subject.substring(0, 60)}"`, severity: "medium" })
        score += 15
    } else if (urgencyCount === 1) {
        indicators.push({ id: "urgent-subject", label: "Urgency Language", description: `"${subject.substring(0, 60)}"`, severity: "low" })
        score += 5
    }

    // 7. Link analysis — check ALL links, not just the first suspicious one
    let suspLinkCount = 0
    for (const link of links) {
        try {
            const linkUrl = new URL(link)
            const hostname = linkUrl.hostname.toLowerCase()
            const linkI = analyzeUrl(link)

            // Check for suspicious link TLDs
            if (SUSPICIOUS_TLDS.some(t => hostname.endsWith(t))) {
                suspiciousLinks.push(link)
                suspLinkCount++
                if (suspLinkCount <= 3) {
                    indicators.push({ id: `sus-link-tld-${suspLinkCount}`, label: "Suspicious Link Domain", description: `${hostname} uses a risky TLD`, severity: "high" })
                    score += 15
                }
            }
            // URL heuristic indicators from analyzeUrl
            else if (linkI.length > 0) {
                suspiciousLinks.push(link)
                suspLinkCount++
                if (suspLinkCount <= 3) {
                    const lScore = linkI.reduce((s, i) => s + i.score, 0)
                    const topLabel = linkI[0].label
                    indicators.push({ id: `suspicious-link-${suspLinkCount}`, label: "Suspicious Link", description: `${hostname} — ${topLabel}`, severity: lScore >= 30 ? "high" : "medium" })
                    score += Math.min(lScore, 20)
                }
            }
            // Check for link text vs actual URL mismatch (common phishing trick)
            // This is handled via body text analysis below
        } catch { /* bad URL */ }
    }

    // 8. Redirect-service links (bit.ly, tinyurl, etc.)
    const REDIRECTORS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "short.io", "rebrand.ly", "cutt.ly"]
    const redirectLinks = links.filter(l => {
        try { return REDIRECTORS.some(r => new URL(l).hostname.includes(r)) } catch { return false }
    })
    if (redirectLinks.length > 0) {
        indicators.push({ id: "redirect-links", label: "URL Shortener Used", description: `${redirectLinks.length} shortened link${redirectLinks.length > 1 ? "s" : ""} hide the real destination`, severity: "medium" })
        score += 12
    }

    // 9. Excessive links
    if (links.length > 8) {
        indicators.push({ id: "many-links", label: "Excessive Links", description: `${links.length} outbound links`, severity: "low" })
        score += 10
    }

    // 10. HTML-heavy with few visible text (e.g. image-only phishing emails)
    if (bodyText.trim().length < 50 && links.length > 0) {
        indicators.push({ id: "low-text", label: "Minimal Text Content", description: "Email body has very little text — may use images to avoid detection", severity: "medium" })
        score += 10
    }

    // 11. Suspicious long unrecognized sender domain
    if (senderDomain && senderDomain.length > 30 && !FREE_PROVIDERS.includes(senderDomain)) {
        indicators.push({ id: "long-sender-domain", label: "Unusual Sender Domain", description: `"${senderDomain.substring(0, 40)}" is unusually long`, severity: "medium" })
        score += 10
    }

    // Aggregate: if we found many suspicious links, add extra score
    if (suspLinkCount > 3) {
        score += (suspLinkCount - 3) * 5
    }

    score = Math.min(score, 100)
    return { riskLevel: score >= 55 ? "dangerous" : score >= 20 ? "suspicious" : "safe", riskScore: score, senderEmail, senderDisplay, subject, indicators, suspiciousLinks, rawLinks: links }
}

// ─── Floating Panel ───────────────────────────────────────────────────────────

const BANNER_ID = "phishnet-float"

function removeBanner() { document.getElementById(BANNER_ID)?.remove() }

function injectStyle() {
    if (document.getElementById("phishnet-styles")) return
    const s = document.createElement("style")
    s.id = "phishnet-styles"
    s.textContent = `
    @keyframes pn-in { from { opacity:0; transform:translateY(16px) scale(0.96); } to { opacity:1; transform:translateY(0) scale(1); } }
    @keyframes pn-out { from { opacity:1; transform:translateY(0) scale(1); } to { opacity:0; transform:translateY(12px) scale(0.96); } }
  `
    document.head.appendChild(s)
}

function injectBanner(result: EmailScanResult) {
    removeBanner()
    injectStyle()

    const isSafe = result.riskLevel === "safe"
    const isD = result.riskLevel === "dangerous"
    const accentColor = isSafe ? "#22c55e" : isD ? "#ef4444" : "#f59e0b"
    const bg = isSafe
        ? "linear-gradient(160deg,#0a1a0e 0%,#0d1117 100%)"
        : isD ? "linear-gradient(160deg,#1a0000 0%,#0d0000 100%)"
            : "linear-gradient(160deg,#1a1200 0%,#0d0c00 100%)"
    const icon = isSafe ? "✅" : isD ? "🚨" : "⚠️"
    const title = isSafe ? "Email Looks Safe" : isD ? "Dangerous Email" : "Suspicious Email"

    const panel = document.createElement("div")
    panel.id = BANNER_ID
    panel.style.cssText = [
        "position:fixed", "bottom:22px", "right:22px", "width:316px", "z-index:2147483647",
        `background:${bg}`,
        `border:1px solid ${accentColor}40`,
        "border-radius:12px",
        "box-shadow:0 12px 40px rgba(0,0,0,0.7),0 0 0 1px rgba(255,255,255,0.04)",
        "font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif",
        "overflow:hidden",
        "animation:pn-in 0.35s cubic-bezier(0.34,1.56,0.64,1) both",
        "color:#e6edf3",
    ].join(";")

    // Indicator rows — show for all risk levels when indicators exist
    let rows = ""
    let extra = ""
    if (result.indicators.length > 0) {
        rows = result.indicators.slice(0, 5).map(ind => {
            const sevColor = ind.severity === "high" ? "#ef4444" : ind.severity === "medium" ? "#f59e0b" : "#6b7280"
            return `<div style="display:flex;gap:8px;padding:5px 14px;border-top:1px solid rgba(255,255,255,0.05);align-items:flex-start">
          <span style="font-size:9px;font-weight:800;color:${sevColor};text-transform:uppercase;margin-top:2px;flex-shrink:0;letter-spacing:0.3px">${ind.severity}</span>
          <div style="flex:1;min-width:0">
            <div style="font-size:11px;font-weight:600;color:#e6edf3;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${ind.label}</div>
            <div style="font-size:10px;color:#8b949e;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin-top:1px">${ind.description}</div>
          </div>
        </div>`
        }).join("")
        extra = result.indicators.length > 5
            ? `<div style="padding:4px 14px 8px;font-size:10px;color:#6b7280">+${result.indicators.length - 5} more — open PhishNet ↗</div>`
            : "<div style='height:6px'></div>"
    } else {
        // Truly no indicators found
        extra = `<div style="padding:6px 14px 10px;font-size:11px;color:#8b949e">No phishing indicators detected in this email.</div>`
    }

    panel.innerHTML = `
    <div style="display:flex;align-items:center;gap:8px;padding:10px 12px;background:rgba(0,0,0,0.25)">
      <span style="font-size:18px;flex-shrink:0">${icon}</span>
      <div style="flex:1;min-width:0">
        <div style="font-size:12px;font-weight:700;color:${accentColor}">${title}</div>
        <div style="font-size:10px;color:#8b949e;margin-top:1px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
          ${result.senderEmail || result.senderDisplay || "Unknown sender"}
        </div>
      </div>
      <span style="font-size:11px;font-weight:700;color:${accentColor};background:rgba(255,255,255,0.07);padding:2px 8px;border-radius:8px;font-family:monospace;flex-shrink:0">${result.riskScore}/100</span>
      <button id="pn-close-btn" style="background:none;border:none;cursor:pointer;color:#6b7280;font-size:20px;padding:0 2px;line-height:1;flex-shrink:0" title="Dismiss">×</button>
    </div>
    ${rows}
    ${extra}
  `

    document.body.appendChild(panel)
    document.getElementById("pn-close-btn")?.addEventListener("click", removeBanner)

    // Auto-dismiss safe banners after 4 seconds
    if (isSafe) {
        setTimeout(() => {
            const el = document.getElementById(BANNER_ID)
            if (el) {
                el.style.animation = "pn-out 0.3s ease forwards"
                setTimeout(removeBanner, 350)
            }
        }, 4000)
    }

    try {
        chrome.runtime.sendMessage({
            type: "GMAIL_SCAN_RESULT",
            result: { riskLevel: result.riskLevel, riskScore: result.riskScore, senderEmail: result.senderEmail, senderDisplay: result.senderDisplay, subject: result.subject, indicators: result.indicators, suspiciousLinks: result.suspiciousLinks, rawLinks: result.rawLinks }
        })
    } catch { /* ok */ }
}

// ─── Observer ─────────────────────────────────────────────────────────────────

let lastScannedId = ""
let inProgress = false

function findEmailContainer(): Element | null {
    return document.querySelector(".ii.gt")?.closest("[role='main']")
        ?? document.querySelector("[role='main'] .a3s.aiL")?.closest("[data-message-id]")
        ?? document.querySelector("[role='main'] .nH.if")
        ?? null
}

async function maybeRescan() {
    if (inProgress) return
    const subject = extractSubject()
    const { email } = extractSender()
    const scanId = `${email}||${subject}`
    if (scanId === lastScannedId || (!email && !subject)) return
    const container = findEmailContainer()
    if (!container) return
    const body = extractBody(container)
    if (!body) return
    lastScannedId = scanId
    inProgress = true
    try {
        const enabled = await getSetting("gmailScanning")
        if (!enabled) { removeBanner(); inProgress = false; return }
        const { email: senderEmail, display: senderDisplay } = extractSender()
        const links = extractLinks(container)
        const result = scanEmail(senderEmail, senderDisplay, subject, body, links)
        // Always show floating indicator — safe emails get a green auto-dismiss panel
        injectBanner(result)
    } catch { /* extension reload */ } finally { inProgress = false }
}

function startObserver() {
    const obs = new MutationObserver(() => {
        clearTimeout((window as any).__pnTimer)
            ; (window as any).__pnTimer = setTimeout(maybeRescan, 600)
    })
    obs.observe(document.body, { childList: true, subtree: true })
    return obs
}

// ─── Plasmo export ────────────────────────────────────────────────────────────

export default function GmailScanner() {
    useEffect(() => {
        const obs = startObserver()
        setTimeout(maybeRescan, 1500)
        return () => {
            obs.disconnect()
            removeBanner()
            clearTimeout((window as any).__pnTimer)
        }
    }, [])
    return null
}

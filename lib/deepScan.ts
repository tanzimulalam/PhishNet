// lib/deepScan.ts — PhishNet Deep Scan Engine (VirusTotal + AI + OSINT)

import type { PhishNetSettings } from "./storage"
import { lookupURLscan, lookupGoogleSafeBrowsing, type URLscanResult, type GoogleSafeBrowsingResult } from "./osintServices"

// ─── Types ────────────────────────────────────────────────────────────────────

export interface VirusTotalResult {
    // URL analysis
    malicious: number
    suspicious: number
    harmless: number
    undetected: number
    timeout: number
    total: number
    community_score: number
    categories: string[]
    permalink: string
    lastAnalysisDate: string | null
    finalUrl?: string
    // Domain enrichment
    domainReputation?: number
    domainCategories?: string[]
    registrar?: string
    creationDate?: string
    lastModifiedDate?: string
    // IP enrichment
    ipAddress?: string
    ipCountry?: string
    ipReputation?: number
    ipMalicious?: number
    asOwner?: string
    // Attack data
    attackTechniques?: string[]
    popularThreatLabel?: string
    error?: string
}

export interface AIVerdict {
    verdict: "safe" | "suspicious" | "dangerous"
    confidence: number
    explanation: string
    primaryReason: string
    provider: string
    model: string
    error?: string
}

export interface DeepScanResult {
    url: string
    virusTotal: VirusTotalResult | null
    urlscan: URLscanResult | null
    googleSafeBrowsing: GoogleSafeBrowsingResult | null
    aiVerdict: AIVerdict | null
    scannedAt: number
}

// Context for email-based deep scans
export interface EmailDeepScanContext {
    senderEmail: string
    senderDisplay: string
    subject: string
    suspiciousLinks: string[]
    indicators: Array<{ label: string; description: string }>
}

export type DeepScanStage =
    | "idle" | "vt_url" | "vt_domain" | "vt_ip" | "urlscan" | "google_sb" | "ai_analysis" | "done" | "error"

export type ProgressCallback = (stage: DeepScanStage, message: string) => void

// ─── VirusTotal helpers ───────────────────────────────────────────────────────

function vtErrorResult(encoded: string, msg: string): VirusTotalResult {
    return {
        malicious: 0, suspicious: 0, harmless: 0, undetected: 0,
        timeout: 0, total: 0, community_score: 0, categories: [],
        permalink: `https://www.virustotal.com/gui/url/${encoded}`,
        lastAnalysisDate: null, error: msg
    }
}

// ── URL Lookup ─────────────────────────────────────────────────────────────────
async function vtUrlLookup(url: string, apiKey: string, onP: ProgressCallback): Promise<VirusTotalResult> {
    onP("vt_url", "Checking URL in VirusTotal database…")
    const encoded = btoa(url).replace(/=/g, "")

    try {
        let getRes = await fetch(`https://www.virustotal.com/api/v3/urls/${encoded}`, {
            headers: { "x-apikey": apiKey }
        })

        if (getRes.status === 404) {
            // Submit new URL
            const fd = new FormData(); fd.append("url", url)
            const submitRes = await fetch("https://www.virustotal.com/api/v3/urls", {
                method: "POST", headers: { "x-apikey": apiKey }, body: fd
            })
            if (!submitRes.ok) {
                const err = await submitRes.json().catch(() => ({}))
                return vtErrorResult(encoded, err?.error?.message ?? `VT submission failed (${submitRes.status})`)
            }
            return vtErrorResult(encoded, "URL submitted to VirusTotal for first-time analysis. Try again in ~30 seconds.")
        }

        if (getRes.status === 429)
            return vtErrorResult(encoded, "VirusTotal rate limit reached (4 req/min on free tier). Please wait.")

        if (!getRes.ok)
            return vtErrorResult(encoded, `VirusTotal error: ${getRes.status}`)

        const data = await getRes.json()
        const attrs = data?.data?.attributes ?? {}
        const stats = attrs.last_analysis_stats ?? {}
        const cats = attrs.categories ?? {}
        const epochDate = attrs.last_analysis_date

        return {
            malicious: stats.malicious ?? 0,
            suspicious: stats.suspicious ?? 0,
            harmless: stats.harmless ?? 0,
            undetected: stats.undetected ?? 0,
            timeout: stats.timeout ?? 0,
            total: Object.values(stats).reduce((a: number, b) => a + (b as number), 0) as number,
            community_score: attrs.reputation ?? 0,
            categories: Object.values(cats) as string[],
            permalink: `https://www.virustotal.com/gui/url/${encoded}`,
            lastAnalysisDate: epochDate ? new Date(epochDate * 1000).toLocaleDateString() : null,
            finalUrl: attrs.last_final_url,
            popularThreatLabel: attrs.popular_threat_classification?.suggested_threat_label ?? undefined,
            attackTechniques: (attrs.popular_threat_classification?.popular_threat_name ?? [])
                .map((t: any) => t.value).slice(0, 3)
        }
    } catch (e) {
        return vtErrorResult(encoded, e instanceof Error ? e.message : "Network error")
    }
}

// ── Domain Lookup ──────────────────────────────────────────────────────────────
async function vtDomainLookup(domain: string, apiKey: string, onP: ProgressCallback): Promise<Partial<VirusTotalResult>> {
    onP("vt_domain", `Checking domain reputation: ${domain}…`)
    try {
        const res = await fetch(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`, {
            headers: { "x-apikey": apiKey }
        })
        if (!res.ok) return {}
        const data = await res.json()
        const attrs = data?.data?.attributes ?? {}
        const cats = attrs.categories ?? {}
        const creationEpoch = attrs.creation_date
        const modEpoch = attrs.last_modification_date

        return {
            domainReputation: attrs.reputation ?? 0,
            domainCategories: Object.values(cats) as string[],
            registrar: attrs.registrar ?? undefined,
            creationDate: creationEpoch ? new Date(creationEpoch * 1000).toLocaleDateString() : undefined,
            lastModifiedDate: modEpoch ? new Date(modEpoch * 1000).toLocaleDateString() : undefined,
        }
    } catch {
        return {}
    }
}

// ── IP Lookup ──────────────────────────────────────────────────────────────────
async function vtIpLookup(ip: string, apiKey: string, onP: ProgressCallback): Promise<Partial<VirusTotalResult>> {
    onP("vt_ip", `Checking IP reputation: ${ip}…`)
    try {
        const res = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ip)}`, {
            headers: { "x-apikey": apiKey }
        })
        if (!res.ok) return {}
        const data = await res.json()
        const attrs = data?.data?.attributes ?? {}
        const stats = attrs.last_analysis_stats ?? {}

        return {
            ipAddress: ip,
            ipCountry: attrs.country ?? undefined,
            ipReputation: attrs.reputation ?? 0,
            ipMalicious: stats.malicious ?? 0,
            asOwner: attrs.as_owner ?? undefined,
        }
    } catch {
        return {}
    }
}

// ── Resolve domain → IP via DNS-over-HTTPS ────────────────────────────────────
async function resolveToIp(domain: string): Promise<string | null> {
    try {
        const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`)
        if (!res.ok) return null
        const data = await res.json()
        return data?.Answer?.[0]?.data ?? null
    } catch {
        return null
    }
}

// ─── Combined VT scan ─────────────────────────────────────────────────────────

async function lookupVirusTotal(url: string, apiKey: string, onP: ProgressCallback): Promise<VirusTotalResult> {
    // Step 1: URL lookup
    const urlResult = await vtUrlLookup(url, apiKey, onP)
    if (urlResult.error && !urlResult.error.includes("first-time")) return urlResult

    // Extract domain from URL
    let domain = ""
    try { domain = new URL(url).hostname } catch { return urlResult }

    // Step 2: Domain lookup
    const domainData = await vtDomainLookup(domain, apiKey, onP)
    Object.assign(urlResult, domainData)

    // Step 3: IP lookup via DNS → VT
    const ip = await resolveToIp(domain)
    if (ip) {
        const ipData = await vtIpLookup(ip, apiKey, onP)
        Object.assign(urlResult, ipData)
    }

    return urlResult
}

// ─── Prompt Builder ───────────────────────────────────────────────────────────

function buildPrompt(
    url: string,
    vtResult: VirusTotalResult | null,
    urlscanResult: URLscanResult | null,
    googleSBResult: GoogleSafeBrowsingResult | null,
    localIndicators: string[],
    emailContext?: EmailDeepScanContext
): string {
    const vtSummary = vtResult && !vtResult.error
        ? [
            `VirusTotal results: ${vtResult.malicious} malicious, ${vtResult.suspicious} suspicious, ${vtResult.harmless} harmless, ${vtResult.undetected} undetected out of ${vtResult.total} engines.`,
            vtResult.popularThreatLabel ? `Threat label: ${vtResult.popularThreatLabel}.` : "",
            vtResult.domainReputation !== undefined ? `Domain reputation score: ${vtResult.domainReputation} (negative = bad, positive = good, 0 = neutral).` : "",
            vtResult.ipMalicious !== undefined ? `IP flagged malicious by ${vtResult.ipMalicious} engines.` : "",
            vtResult.registrar ? `Registrar: ${vtResult.registrar}.` : "",
            vtResult.creationDate ? `Domain registered: ${vtResult.creationDate}.` : "",
            vtResult.categories.length ? `URL categories: ${vtResult.categories.join(", ")}.` : "",
        ].filter(Boolean).join(" ")
        : vtResult?.error
            ? `VirusTotal: ${vtResult.error}`
            : "VirusTotal: not checked."

    const heuristics = localIndicators.length
        ? `Local heuristic flags: ${localIndicators.join("; ")}.`
        : "No local heuristic flags."

    const urlscanSummary = urlscanResult && !urlscanResult.error
        ? [
            urlscanResult.verdict ? `URLscan verdict: ${urlscanResult.verdict}.` : "",
            urlscanResult.country ? `Hosted in: ${urlscanResult.country}.` : "",
            urlscanResult.asnname ? `ASN: ${urlscanResult.asnname}.` : "",
        ].filter(Boolean).join(" ")
        : urlscanResult?.error
            ? `URLscan: ${urlscanResult.error}`
            : "URLscan: not checked."

    const googleSBSummary = googleSBResult && !googleSBResult.error
        ? googleSBResult.safe
            ? "Google Safe Browsing: No threats detected (safe)."
            : `Google Safe Browsing: ⚠️ THREAT DETECTED — ${googleSBResult.matches.map(m => m.threatType).join(", ")}.`
        : googleSBResult?.error
            ? `Google Safe Browsing: ${googleSBResult.error}`
            : "Google Safe Browsing: not checked."

    const emailSection = emailContext
        ? `\nEMAIL CONTEXT:\n- Sender: ${emailContext.senderEmail} (display: "${emailContext.senderDisplay}")\n- Subject: "${emailContext.subject}"\n- Email indicators: ${emailContext.indicators.map(i => i.label).join("; ")}\n- Suspicious links in email: ${emailContext.suspiciousLinks.length > 0 ? emailContext.suspiciousLinks.slice(0, 3).join(", ") : "none"}`
        : ""

    return `You are a cybersecurity expert inside the PhishNet browser extension.

Analyze the following for phishing/malware risk and respond ONLY with valid JSON:
{
  "verdict": "safe" | "suspicious" | "dangerous",
  "confidence": <integer 0-100>,
  "explanation": "<max 3 plain-English sentences for a non-technical user>",
  "primaryReason": "<one short sentence — the single most important finding>"
}

URL: ${url}
${vtSummary}
${urlscanSummary}
${googleSBSummary}
${heuristics}${emailSection}

CRITICAL RULES — follow these precisely:
1. VirusTotal data is the most authoritative signal. If VT shows 0 malicious AND 0 suspicious engines AND domain reputation >= 0, the verdict MUST be "safe" unless there is extremely strong contradictory evidence.
2. Login forms, password fields, and form submissions to external domains are COMPLETELY NORMAL on legitimate banking, email, e-commerce, streaming, and social media sites (e.g. paypal.com, netflix.com, amazon.com, facebook.com). Do NOT treat these as suspicious on established domains.
3. A high "harmless" count from VirusTotal (e.g. 60+ engines) is strong evidence the site is legitimate.
4. Only use "dangerous" when there is CLEAR, CONCRETE evidence of phishing or malware — such as VT engines flagging it, a known threat label, very negative domain reputation, or highly deceptive URL patterns (typosquatting, homoglyph attacks).
5. "suspicious" should only be used when there are genuine yellow flags, NOT simply because a site has a login form or collects passwords.
6. Consider the overall picture: a well-known domain with positive VT results and normal website features (forms, logins) is safe.
7. confidence reflects how certain you are in your verdict.
8. Do not include markdown, return only the JSON object`
}

// ─── Strip markdown code fences ───────────────────────────────────────────────

function stripFences(text: string): string {
    return text.replace(/^```(?:json)?\s*/i, "").replace(/\s*```\s*$/i, "").trim()
}

// ─── AI Providers ─────────────────────────────────────────────────────────────

async function runGeminiAnalysis(prompt: string, apiKey: string, model: string, onP: ProgressCallback): Promise<AIVerdict> {
    onP("ai_analysis", `Analyzing with Gemini (${model})…`)
    try {
        const res = await fetch(
            `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`,
            {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    contents: [{ parts: [{ text: prompt }] }],
                    generationConfig: { temperature: 0.2, maxOutputTokens: 512, responseMimeType: "application/json" }
                })
            }
        )
        if (!res.ok) {
            const err = await res.json().catch(() => ({}))
            throw new Error(err?.error?.message ?? `Gemini API error ${res.status}`)
        }
        const data = await res.json()
        const raw = data?.candidates?.[0]?.content?.parts?.[0]?.text ?? ""
        const parsed = JSON.parse(stripFences(raw))
        return { ...parsed, provider: "Gemini", model }
    } catch (e) {
        return {
            verdict: "suspicious", confidence: 0, explanation: "", primaryReason: "",
            provider: "Gemini", model, error: e instanceof Error ? e.message : "Gemini request failed"
        }
    }
}

async function runOpenAIAnalysis(prompt: string, apiKey: string, model: string, onP: ProgressCallback): Promise<AIVerdict> {
    onP("ai_analysis", `Analyzing with OpenAI (${model})…`)
    try {
        const res = await fetch("https://api.openai.com/v1/chat/completions", {
            method: "POST",
            headers: { "Content-Type": "application/json", "Authorization": `Bearer ${apiKey}` },
            body: JSON.stringify({
                model,
                messages: [{ role: "user", content: prompt }],
                temperature: 0.2, max_tokens: 512,
                response_format: { type: "json_object" }
            })
        })
        if (!res.ok) {
            const err = await res.json().catch(() => ({}))
            throw new Error(err?.error?.message ?? `OpenAI API error ${res.status}`)
        }
        const data = await res.json()
        const raw = data?.choices?.[0]?.message?.content ?? ""
        const parsed = JSON.parse(stripFences(raw))
        return { ...parsed, provider: "OpenAI", model }
    } catch (e) {
        return {
            verdict: "suspicious", confidence: 0, explanation: "", primaryReason: "",
            provider: "OpenAI", model, error: e instanceof Error ? e.message : "OpenAI request failed"
        }
    }
}

// ─── Public API ───────────────────────────────────────────────────────────────

export async function runDeepScan(
    url: string,
    settings: PhishNetSettings,
    localIndicatorLabels: string[],
    onProgress: ProgressCallback,
    emailContext?: EmailDeepScanContext
): Promise<DeepScanResult> {
    let vtResult: VirusTotalResult | null = null
    let urlscanResult: URLscanResult | null = null
    let googleSBResult: GoogleSafeBrowsingResult | null = null
    let aiVerdict: AIVerdict | null = null

    // VirusTotal — URL + Domain + IP
    if (settings.virusTotalApiKey) {
        vtResult = await lookupVirusTotal(url, settings.virusTotalApiKey, onProgress)
    }

    // URLscan.io Lookup
    if (settings.enableURLscan) {
        onProgress("urlscan", "Scanning URL with URLscan.io…")
        urlscanResult = await lookupURLscan(url, settings.urlscanApiKey)
    }

    // Google Safe Browsing
    if (settings.enableGoogleSafeBrowsing && settings.googleSafeBrowsingApiKey) {
        onProgress("google_sb", "Checking Google Safe Browsing…")
        googleSBResult = await lookupGoogleSafeBrowsing(url, settings.googleSafeBrowsingApiKey)
    }

    // AI Analysis
    const aiKey = settings.aiProvider === "gemini" ? settings.geminiApiKey : settings.openaiApiKey
    const aiModel = settings.aiProvider === "gemini" ? settings.geminiModel : settings.openaiModel

    if (aiKey) {
        const prompt = buildPrompt(url, vtResult, urlscanResult, googleSBResult, localIndicatorLabels, emailContext)
        aiVerdict = settings.aiProvider === "gemini"
            ? await runGeminiAnalysis(prompt, aiKey, aiModel, onProgress)
            : await runOpenAIAnalysis(prompt, aiKey, aiModel, onProgress)

        // VT sanity override: if VT is clean but AI hallucinated danger, downgrade
        if (aiVerdict && !aiVerdict.error && vtResult && !vtResult.error) {
            const vtClean = vtResult.malicious === 0 && vtResult.suspicious === 0
                && (vtResult.domainReputation === undefined || vtResult.domainReputation >= 0)
                && (vtResult.ipMalicious ?? 0) === 0
            if (vtClean && aiVerdict.verdict === "dangerous") {
                aiVerdict.verdict = "suspicious"
                aiVerdict.explanation = `[Adjusted] VirusTotal shows 0 malicious engines and clean domain reputation, suggesting this is likely legitimate. ${aiVerdict.explanation}`
            }
            // Also cap confidence if VT is overwhelmingly clean but AI says suspicious
            if (vtClean && vtResult.harmless >= 50 && aiVerdict.verdict === "suspicious") {
                aiVerdict.verdict = "safe"
                aiVerdict.confidence = Math.min(aiVerdict.confidence, 60)
                aiVerdict.explanation = `[Adjusted] ${vtResult.harmless} of ${vtResult.total} VirusTotal engines mark this as harmless with no malicious flags. ${aiVerdict.explanation}`
            }
        }
    }

    onProgress("done", "Deep scan complete")
    return { 
        url, 
        virusTotal: vtResult, 
        urlscan: urlscanResult,
        googleSafeBrowsing: googleSBResult,
        aiVerdict, 
        scannedAt: Date.now() 
    }
}

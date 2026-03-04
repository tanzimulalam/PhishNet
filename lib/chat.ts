// lib/chat.ts — PhishNet AI Chat helper

import type { PhishNetSettings } from "./storage"
import type { VirusTotalResult, AIVerdict } from "./deepScan"

export interface ChatMessage {
    role: "user" | "assistant"
    content: string
}

export interface ChatContext {
    url: string
    riskLevel: string
    riskScore: number
    indicators: Array<{ label: string; description: string; severity: string }>
    vtResult?: VirusTotalResult | null
    aiVerdict?: AIVerdict | null
    isEmail?: boolean
    emailSender?: string
    emailSubject?: string
}

function buildSystemPrompt(ctx: ChatContext): string {
    const indicators = ctx.indicators.length
        ? ctx.indicators.map(i => `  • [${i.severity.toUpperCase()}] ${i.label}: ${i.description}`).join("\n")
        : "  None"

    const vtSection = ctx.vtResult && !ctx.vtResult.error
        ? [
            `  Malicious engines: ${ctx.vtResult.malicious}/${ctx.vtResult.total}`,
            `  Domain reputation: ${ctx.vtResult.domainReputation ?? "N/A"}`,
            ctx.vtResult.popularThreatLabel ? `  Threat label: ${ctx.vtResult.popularThreatLabel}` : "",
            ctx.vtResult.registrar ? `  Registrar: ${ctx.vtResult.registrar}` : "",
            ctx.vtResult.creationDate ? `  Domain registered: ${ctx.vtResult.creationDate}` : "",
            ctx.vtResult.ipAddress ? `  Server IP: ${ctx.vtResult.ipAddress} (${ctx.vtResult.ipCountry ?? "?"}) — ${ctx.vtResult.ipMalicious ?? 0} malicious flags` : "",
            ctx.vtResult.asOwner ? `  AS Owner: ${ctx.vtResult.asOwner}` : "",
        ].filter(Boolean).join("\n")
        : ctx.vtResult?.error
            ? `  Error: ${ctx.vtResult.error}`
            : "  Not checked yet"

    const aiSection = ctx.aiVerdict && !ctx.aiVerdict.error
        ? `  Verdict: ${ctx.aiVerdict.verdict} (${ctx.aiVerdict.confidence}% confidence)\n  Reason: ${ctx.aiVerdict.primaryReason}`
        : "  Not available"

    const emailSection = ctx.isEmail && ctx.emailSender
        ? `\nEmail Context:\n  From: ${ctx.emailSender}${ctx.emailSubject ? `\n  Subject: "${ctx.emailSubject}"` : ""}`
        : ""

    return `You are PhishNet, an expert cybersecurity AI assistant embedded in a browser extension that protects users from phishing and malware.

Current analysis context:
  URL/Target: ${ctx.url}
  Risk Level: ${ctx.riskLevel.toUpperCase()} (${ctx.riskScore}/100)${emailSection}

Indicators Found:
${indicators}

VirusTotal Report:
${vtSection}

AI Analysis:
${aiSection}

Instructions:
- Answer questions about the current threat in plain English
- Be helpful, concise, and honest about uncertainty
- Explain technical terms simply when needed
- If the site/email appears safe, say so clearly
- Never suggest the user enter credentials on suspicious sites
- Keep responses under 150 words unless the user explicitly asks for more details`
}

function stripFences(text: string): string {
    return text.replace(/^```(?:json)?\s*/i, "").replace(/\s*```\s*$/i, "").trim()
}

export async function sendChatMessage(
    userMessage: string,
    history: ChatMessage[],
    context: ChatContext,
    settings: PhishNetSettings
): Promise<string> {
    const systemPrompt = buildSystemPrompt(context)

    if (settings.aiProvider === "gemini" && settings.geminiApiKey) {
        // Build Gemini contents array: system + history + new message
        const contents = [
            { role: "user", parts: [{ text: systemPrompt }] },
            { role: "model", parts: [{ text: "Understood. I'm ready to help analyse this threat. What would you like to know?" }] },
            ...history.map(m => ({
                role: m.role === "user" ? "user" : "model",
                parts: [{ text: m.content }]
            })),
            { role: "user", parts: [{ text: userMessage }] }
        ]

        const res = await fetch(
            `https://generativelanguage.googleapis.com/v1beta/models/${settings.geminiModel}:generateContent?key=${settings.geminiApiKey}`,
            {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ contents, generationConfig: { temperature: 0.4, maxOutputTokens: 400 } })
            }
        )
        if (!res.ok) {
            const err = await res.json().catch(() => ({}))
            throw new Error(err?.error?.message ?? `Gemini error ${res.status}`)
        }
        const data = await res.json()
        return (data?.candidates?.[0]?.content?.parts?.[0]?.text ?? "").trim()
    }

    if (settings.aiProvider === "openai" && settings.openaiApiKey) {
        const messages = [
            { role: "system", content: systemPrompt },
            ...history.map(m => ({ role: m.role, content: m.content })),
            { role: "user", content: userMessage }
        ]
        const res = await fetch("https://api.openai.com/v1/chat/completions", {
            method: "POST",
            headers: { "Content-Type": "application/json", Authorization: `Bearer ${settings.openaiApiKey}` },
            body: JSON.stringify({ model: settings.openaiModel, messages, temperature: 0.4, max_tokens: 400 })
        })
        if (!res.ok) {
            const err = await res.json().catch(() => ({}))
            throw new Error(err?.error?.message ?? `OpenAI error ${res.status}`)
        }
        const data = await res.json()
        return (data?.choices?.[0]?.message?.content ?? "").trim()
    }

    throw new Error("No AI API key configured. Add one in ⚙️ Settings.")
}

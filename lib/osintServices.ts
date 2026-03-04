// lib/osintServices.ts — OSINT Integration Services (WHOIS, URLscan, Google Safe Browsing, HIBP)

import type { PhishNetSettings } from "./storage"

// ─── Types ────────────────────────────────────────────────────────────────────

export interface WHOISResult {
    domain: string
    registrar?: string
    creationDate?: string
    expirationDate?: string
    updatedDate?: string
    nameservers?: string[]
    registrant?: string
    country?: string
    ageDays?: number
    error?: string
}

export interface URLscanResult {
    uuid?: string
    url: string
    verdict?: "malicious" | "suspicious" | "clean" | "unrated"
    screenshot?: string
    country?: string
    ip?: string
    asn?: string
    asnname?: string
    pageTitle?: string
    task?: {
        url: string
        visibility: string
        method: string
        time: string
    }
    error?: string
}

export interface GoogleSafeBrowsingResult {
    matches: Array<{
        threatType: string
        platformType: string
        threatEntryType: string
    }>
    safe: boolean
    error?: string
}

export interface HIBPResult {
    email: string
    breaches: Array<{
        Name: string
        Title: string
        Domain: string
        BreachDate: string
        AddedDate: string
        ModifiedDate: string
        PwnCount: number
        Description: string
        DataClasses: string[]
        IsVerified: boolean
        IsFabricated: boolean
        IsSensitive: boolean
        IsRetired: boolean
        IsSpamList: boolean
    }>
    pastes?: Array<{
        Source: string
        Id: string
        Title: string
        Date: string
        EmailCount: number
    }>
    error?: string
}

// ─── Helper: Extract domain from URL ──────────────────────────────────────────

function extractDomain(url: string): string | null {
    try {
        return new URL(url).hostname.replace(/^www\./, "")
    } catch {
        return null
    }
}

// ─── Helper: Calculate domain age ─────────────────────────────────────────────

function calculateAge(creationDate: string | undefined): number | undefined {
    if (!creationDate) return undefined
    try {
        const created = new Date(creationDate)
        const now = new Date()
        const diffTime = now.getTime() - created.getTime()
        return Math.floor(diffTime / (1000 * 60 * 60 * 24))
    } catch {
        return undefined
    }
}

// ─── WHOIS Lookup ─────────────────────────────────────────────────────────────

export async function lookupWHOIS(domain: string, apiKey?: string): Promise<WHOISResult> {
    const cleanDomain = domain.replace(/^www\./, "").toLowerCase()
    
    try {
        // Try whoisxmlapi.com if API key provided
        if (apiKey) {
            const res = await fetch(`https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${apiKey}&domainName=${encodeURIComponent(cleanDomain)}&outputFormat=JSON`)
            if (res.ok) {
                const data = await res.json()
                const whois = data.WhoisRecord || {}
                return {
                    domain: cleanDomain,
                    registrar: whois.registrarName || whois.registrar?.name,
                    creationDate: whois.createdDate || whois.registryData?.createdDate,
                    expirationDate: whois.expiresDate || whois.registryData?.expiresDate,
                    updatedDate: whois.updatedDate || whois.registryData?.updatedDate,
                    nameservers: whois.nameServers?.hostNames || whois.nameServers?.map((ns: any) => ns.hostName),
                    registrant: whois.registrant?.organization || whois.registrant?.name,
                    country: whois.registrant?.country || whois.registryData?.registrant?.country,
                    ageDays: calculateAge(whois.createdDate || whois.registryData?.createdDate)
                }
            }
        }
        
        // Fallback: Use IPWHOIS free API (no key required, limited)
        try {
            const res = await fetch(`https://ipwhois.app/json/${encodeURIComponent(cleanDomain)}`)
            if (res.ok) {
                const data = await res.json()
                // This API returns IP data, not full WHOIS, but we can extract some info
                return {
                    domain: cleanDomain,
                    country: data.country,
                    error: "Limited WHOIS data. Add API key for full details."
                }
            }
        } catch {
            // Ignore fallback errors
        }
        
        return { 
            domain: cleanDomain, 
            error: apiKey ? "WHOIS lookup failed. Check API key." : "WHOIS API key recommended for full details." 
        }
    } catch (e) {
        return {
            domain: cleanDomain,
            error: e instanceof Error ? e.message : "WHOIS lookup failed"
        }
    }
}

// ─── URLscan.io Lookup ───────────────────────────────────────────────────────

export async function lookupURLscan(url: string, apiKey?: string): Promise<URLscanResult> {
    try {
        // First, try to get existing scan result
        const domain = extractDomain(url)
        if (!domain) return { url, error: "Invalid URL" }
        
        // Search for existing scans
        const searchRes = await fetch(`https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(domain)}&size=1`, {
            headers: apiKey ? { "API-Key": apiKey } : {}
        })
        
        if (searchRes.ok) {
            const searchData = await searchRes.json()
            if (searchData.results && searchData.results.length > 0) {
                const result = searchData.results[0]
                return {
                    uuid: result._id,
                    url: result.page?.url || url,
                    verdict: result.verdicts?.overall?.malicious ? "malicious" :
                            result.verdicts?.overall?.suspicious ? "suspicious" :
                            result.verdicts?.overall?.score === 0 ? "clean" : "unrated",
                    screenshot: result.screenshot,
                    country: result.page?.country,
                    ip: result.page?.ip,
                    asn: result.page?.asn,
                    asnname: result.page?.asnname,
                    pageTitle: result.page?.title
                }
            }
        }
        
        // If no existing scan and we have API key, submit new scan
        if (apiKey) {
            const submitRes = await fetch("https://urlscan.io/api/v1/scan/", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "API-Key": apiKey
                },
                body: JSON.stringify({
                    url: url,
                    visibility: "public"
                })
            })
            
            if (submitRes.ok) {
                const submitData = await submitRes.json()
                return {
                    uuid: submitData.uuid,
                    url: url,
                    task: submitData,
                    error: "Scan submitted. Results available in ~30 seconds. Check URLscan.io for results."
                }
            }
        }
        
        return {
            url,
            error: apiKey ? "Failed to submit scan" : "No existing scan found. Add API key to submit new scans."
        }
    } catch (e) {
        return {
            url,
            error: e instanceof Error ? e.message : "URLscan lookup failed"
        }
    }
}

// ─── Google Safe Browsing Lookup ─────────────────────────────────────────────

export async function lookupGoogleSafeBrowsing(url: string, apiKey: string): Promise<GoogleSafeBrowsingResult> {
    if (!apiKey) {
        return { matches: [], safe: true, error: "API key required" }
    }
    
    try {
        // Google Safe Browsing v4 API
        const res = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                client: {
                    clientId: "phishnet",
                    clientVersion: "1.0.0"
                },
                threatInfo: {
                    threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    platformTypes: ["ANY_PLATFORM"],
                    threatEntryTypes: ["URL"],
                    threatEntries: [{ url }]
                }
            })
        })
        
        if (!res.ok) {
            return {
                matches: [],
                safe: true,
                error: `Safe Browsing API error: ${res.status}`
            }
        }
        
        const data = await res.json()
        const matches = data.matches || []
        
        return {
            matches,
            safe: matches.length === 0
        }
    } catch (e) {
        return {
            matches: [],
            safe: true,
            error: e instanceof Error ? e.message : "Safe Browsing lookup failed"
        }
    }
}

// ─── Have I Been Pwned Lookup ────────────────────────────────────────────────

export async function lookupHIBP(email: string, apiKey?: string): Promise<HIBPResult> {
    if (!email || !email.includes("@")) {
        return { email, breaches: [], error: "Invalid email address" }
    }
    
    try {
        // HIBP v3 API - requires User-Agent header
        const headers: HeadersInit = {
            "User-Agent": "PhishNet-Extension/1.0"
        }
        if (apiKey) {
            headers["hibp-api-key"] = apiKey
        }
        
        const res = await fetch(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`, {
            headers
        })
        
        if (res.status === 404) {
            // No breaches found
            return { email, breaches: [], pastes: [] }
        }
        
        if (res.status === 429) {
            return { email, breaches: [], error: "Rate limit exceeded. Please wait a moment." }
        }
        
        if (!res.ok) {
            return { email, breaches: [], error: `HIBP API error: ${res.status}` }
        }
        
        const breaches = await res.json()
        
        // Also check pastes
        let pastes: any[] = []
        try {
            const pasteRes = await fetch(`https://haveibeenpwned.com/api/v3/pasteaccount/${encodeURIComponent(email)}`, {
                headers
            })
            if (pasteRes.ok) {
                pastes = await pasteRes.json()
            }
        } catch {
            // Ignore paste errors
        }
        
        return {
            email,
            breaches: Array.isArray(breaches) ? breaches : [],
            pastes: Array.isArray(pastes) ? pastes : []
        }
    } catch (e) {
        return {
            email,
            breaches: [],
            error: e instanceof Error ? e.message : "HIBP lookup failed"
        }
    }
}

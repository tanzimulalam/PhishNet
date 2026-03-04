// components/InsightsTab.tsx — World Map (OSM tiles + ipinfo.io), DNA Fingerprint + AI Explain, Report Card

import { useEffect, useState } from "react"
import type { ScanResult } from "../lib/phishingDetector"
import type { DeepScanResult } from "../lib/deepScan"
import type { EmailScanResult } from "../contents/gmail"
import type { PhishNetSettings } from "../lib/storage"

// ─── Country fallback → lat/lon ───────────────────────────────────────────────

const COUNTRY_LOC: Record<string, [number, number]> = {
    US: [37.1, -95.7], CA: [56.1, -106.3], MX: [23.6, -102.5], BR: [-14.2, -51.9],
    AR: [-38.4, -63.6], CL: [-35.7, -71.5], CO: [4.1, -72.9], PE: [-9.2, -75.0],
    GB: [55.3, -3.4], DE: [51.1, 10.4], FR: [46.2, 2.2], IT: [41.9, 12.6],
    ES: [40.5, -3.7], NL: [52.1, 5.3], SE: [60.1, 18.6], NO: [60.5, 8.5],
    FI: [61.9, 25.7], PL: [51.9, 19.1], UA: [48.4, 31.2], RU: [61.5, 105.3],
    TR: [38.9, 35.2], CH: [46.8, 8.2], PT: [39.4, -8.2], BE: [50.5, 4.5],
    CN: [35.8, 104.2], JP: [36.2, 138.2], KR: [35.9, 127.8], IN: [20.6, 78.9],
    AU: [-25.3, 133.8], NZ: [-40.9, 174.9], SG: [1.3, 103.8], TH: [15.9, 100.9],
    VN: [14.1, 108.3], ID: [-0.8, 113.9], PH: [12.9, 121.8], TW: [23.7, 121.0],
    HK: [22.4, 114.1], MY: [4.2, 108.0], PK: [30.4, 69.3], BD: [23.7, 90.3],
    SA: [24.0, 45.0], AE: [24.0, 53.8], IL: [31.0, 35.0], IR: [32.4, 53.7],
    ZA: [-30.6, 22.9], NG: [9.1, 8.7], EG: [26.8, 30.8], MA: [31.8, -7.1],
    RO: [45.9, 24.9], CZ: [49.8, 15.5], AT: [47.5, 14.5], HU: [47.2, 19.5],
    GR: [39.1, 21.8], SK: [48.7, 19.7], BG: [42.7, 25.5], HR: [45.1, 15.2],
    DK: [56.3, 9.5], IS: [64.9, -19.0], IE: [53.4, -8.0], LU: [49.8, 6.1],
    LT: [55.2, 24.0], LV: [56.9, 24.6], EE: [58.6, 25.0], RS: [44.0, 21.0],
    KZ: [48.0, 68.0], UZ: [41.4, 64.6], GE: [42.3, 43.4], AM: [40.1, 45.0],
    CY: [35.1, 33.4], MT: [35.9, 14.4], MD: [47.0, 28.4], BY: [53.7, 27.9],
    MN: [46.9, 103.8], KP: [40.3, 127.5], TZ: [-6.4, 35.0], ET: [9.1, 40.5],
    GH: [7.9, -1.0], SN: [14.5, -14.5], CI: [7.5, -5.5], CM: [3.8, 11.5],
    AO: [-11.2, 17.9], ZM: [-13.1, 27.8], MW: [-13.3, 34.3], UG: [1.4, 32.3],
    MZ: [-18.7, 35.5], SD: [12.9, 30.2], CG: [-0.2, 15.8], BF: [12.4, -1.6],
    ML: [17.6, -3.9], TG: [8.6, 0.8], BJ: [9.3, 2.3], NE: [17.6, 8.1],
    VE: [6.4, -66.6], EC: [-1.8, -78.2], BO: [-16.3, -63.6], PY: [-23.4, -58.4],
    UY: [-32.5, -55.8], GY: [4.9, -59.0], SR: [3.9, -56.0], GF: [4.0, -52.9],
    PA: [8.6, -80.8], CR: [9.7, -83.8], NI: [12.9, -85.2], HN: [15.2, -86.2],
    SV: [13.8, -88.9], GT: [15.8, -90.2], BZ: [17.2, -88.5], CU: [21.5, -79.5],
    DO: [18.7, -70.2], HT: [18.9, -72.7], JM: [18.1, -77.3], TT: [10.7, -61.2],
    PR: [18.2, -66.6], BB: [13.2, -59.6], DZ: [28.0, 1.7], LY: [26.3, 17.2],
    TN: [33.9, 9.5], GN: [10.9, -10.9], LR: [6.4, -9.4], SL: [8.5, -11.8],
    GM: [13.4, -15.3], BW: [-22.3, 24.7], NA: [-22.9, 18.5], SZ: [-26.5, 31.5],
    LS: [-29.6, 28.2], DJ: [11.8, 42.6], SO: [5.2, 46.2], PG: [-6.3, 143.9],
    FJ: [-16.6, 179.4], WS: [-13.8, -172.1], TO: [-21.2, -175.2], VU: [-15.4, 166.9],
    LK: [7.9, 80.8], NP: [28.4, 84.1], AF: [33.9, 67.7], IQ: [33.2, 43.7],
    SY: [34.8, 38.9], JO: [30.6, 36.2], LB: [33.9, 35.9], OM: [21.0, 55.0],
    YE: [15.6, 48.5], KW: [29.3, 47.5], BH: [26.0, 50.6], QA: [25.4, 51.2],
    MV: [3.2, 73.2], MU: [-20.3, 57.6], SC: [-4.7, 55.5], KE: [-0.0, 37.9],
    RW: [-1.9, 29.9], BI: [-3.4, 29.9], CF: [6.6, 20.9], TD: [15.5, 19.0],
    GQ: [1.5, 10.5], GA: [-0.8, 11.6], ST: [0.2, 6.6], CV: [16.5, -23.0],
    MM: [17.1, 96.9], KH: [12.6, 104.7], LA: [19.9, 102.5], BT: [27.5, 90.4],
    TL: [-8.9, 125.7], BN: [4.5, 114.7], MO: [22.2, 113.5], KG: [41.2, 74.8],
    TM: [38.1, 59.6], TJ: [38.9, 71.3], AZ: [40.1, 47.6], AL: [41.2, 20.2],
    MK: [41.6, 21.7], ME: [42.7, 19.4], BA: [43.9, 17.7], SI: [46.2, 14.9],
    LI: [47.1, 9.5], MC: [43.7, 7.4], SM: [43.9, 12.5], VA: [41.9, 12.5],
    AD: [42.5, 1.5], GI: [36.1, -5.3], FO: [61.9, -6.9], AX: [60.1, 19.9],
    GG: [49.5, -2.5], JE: [49.2, -2.1], IM: [54.2, -4.5],
}

// ─── OSM Tile helpers ─────────────────────────────────────────────────────────

function latLonToTile(lat: number, lon: number, z: number): [number, number] {
    const n = Math.pow(2, z)
    const tx = Math.floor((lon + 180) / 360 * n)
    const latR = lat * Math.PI / 180
    const ty = Math.floor((1 - Math.asinh(Math.tan(latR)) / Math.PI) / 2 * n)
    return [tx, ty]
}

function latLonToFrac(lat: number, lon: number, z: number): [number, number] {
    const n = Math.pow(2, z)
    const fx = ((lon + 180) / 360 * n) % 1
    const latR = lat * Math.PI / 180
    const fy = ((1 - Math.asinh(Math.tan(latR)) / Math.PI) / 2 * n) % 1
    return [fx, fy]
}

function osmUrl(z: number, x: number, y: number) {
    const sub = ["a", "b", "c"][((x + y) % 3 + 3) % 3]
    return `https://${sub}.tile.openstreetmap.org/${z}/${x}/${y}.png`
}

// ─── World Map with OSM Tiles + ipinfo geolocation ────────────────────────────

export function WorldMap({ country, ipAddress, asOwner, urlscanIp, urlscanCountry, urlscanAsn }:
    { country?: string; ipAddress?: string; asOwner?: string; urlscanIp?: string; urlscanCountry?: string; urlscanAsn?: string }) {

    const [geoLoc, setGeoLoc] = useState<[number, number] | null>(null)
    const [geoCity, setGeoCity] = useState<string | undefined>(undefined)
    const [loading, setLoading] = useState(false)

    // Fetch precise coordinates from IP via ipinfo.io (free, no key)
    // Prioritize URLscan IP if available, fallback to VirusTotal IP
    useEffect(() => {
        const ipToUse = urlscanIp || ipAddress
        if (!ipToUse || ipToUse === "0.0.0.0") {
            setGeoLoc(null); return
        }
        setLoading(true)
        fetch(`https://ipinfo.io/${ipToUse}/json`)
            .then(r => r.json())
            .then(data => {
                if (data.loc) {
                    const [lat, lon] = data.loc.split(",").map(Number)
                    setGeoLoc([lat, lon])
                    setGeoCity(data.city || data.region || urlscanCountry || undefined)
                }
            })
            .catch(() => { })
            .finally(() => setLoading(false))
    }, [ipAddress, urlscanIp, urlscanCountry])

    // Fall back to country centroid when no IP geolocation available
    // Use URLscan country if available, otherwise VirusTotal country
    const countryToUse = urlscanCountry || country
    const loc = geoLoc ?? (countryToUse ? COUNTRY_LOC[countryToUse.toUpperCase()] : null)

    const ZOOM = 4
    const COLS = 3, ROWS = 2
    const TILE_PX = 106  // 3 × 106 ≈ 318px

    let tiles: { x: number; y: number; col: number; row: number }[] = []
    let dotLeft = "50%", dotTop = "50%"

    if (loc) {
        const [tx, ty] = latLonToTile(loc[0], loc[1], ZOOM)
        const [fx, fy] = latLonToFrac(loc[0], loc[1], ZOOM)
        const startX = tx - Math.floor(COLS / 2)
        const startY = ty - Math.floor(ROWS / 2)
        for (let r = 0; r < ROWS; r++)
            for (let c = 0; c < COLS; c++)
                tiles.push({ x: startX + c, y: startY + r, col: c, row: r })
        dotLeft = `${(((Math.floor(COLS / 2) + fx) / COLS) * 100).toFixed(1)}%`
        dotTop = `${(((Math.floor(ROWS / 2) + fy) / ROWS) * 100).toFixed(1)}%`
    }

    const mapsUrl = loc
        ? `https://www.openstreetmap.org/?mlat=${loc[0]}&mlon=${loc[1]}#map=8/${loc[0]}/${loc[1]}`
        : null

    const displayCountry = geoCity ? `${geoCity}${countryToUse ? `, ${countryToUse}` : ""}` : countryToUse

    return (
        <div className="insight-card">
            <div className="insight-card-header">
                <span>🗺️ Server Location</span>
                {displayCountry && (
                    <span className="insight-badge" style={{ color: "var(--accent)", borderColor: "rgba(88,166,255,0.3)" }}>
                        {displayCountry}
                    </span>
                )}
                {!countryToUse && !ipAddress && !urlscanIp && <span className="insight-badge dim">Run Deep Scan</span>}
                {loading && <span className="insight-badge dim">Locating…</span>}
                {mapsUrl && (
                    <a href={mapsUrl} target="_blank" rel="noreferrer"
                        style={{ marginLeft: 6, fontSize: 10, color: "var(--accent)", textDecoration: "none" }}>
                        Open ↗
                    </a>
                )}
            </div>

            <div className="world-map-wrap">
                {loc ? (
                    <div style={{
                        display: "grid",
                        gridTemplateColumns: `repeat(${COLS}, ${TILE_PX}px)`,
                        gridTemplateRows: `repeat(${ROWS}, ${TILE_PX}px)`,
                        position: "relative",
                        borderRadius: 6,
                        overflow: "hidden",
                        width: COLS * TILE_PX,
                        maxWidth: "100%",
                    }}>
                        {tiles.map(t => (
                            <img key={`${t.x}-${t.y}`} src={osmUrl(ZOOM, t.x, t.y)}
                                width={TILE_PX} height={TILE_PX} alt=""
                                style={{ 
                                    display: "block", 
                                    filter: "brightness(0.4) saturate(0.3) hue-rotate(200deg) contrast(1.2)",
                                    border: "1px solid rgba(88,166,255,0.1)",
                                    boxShadow: "inset 0 0 2px rgba(0,0,0,0.5)"
                                }}
                            />
                        ))}
                        <div style={{
                            position: "absolute", left: dotLeft, top: dotTop,
                            transform: "translate(-50%,-50%)", pointerEvents: "none"
                        }}>
                            <div className="map-dot-ring" />
                            <div className="map-dot-ring map-dot-ring-2" />
                            <div className="map-dot-core" />
                        </div>
                    </div>
                ) : (
                    <div className="world-map-empty">
                        {ipAddress && loading ? "Fetching server coordinates…" : "Run Deep Scan to locate the server IP"}
                    </div>
                )}

                {(ipAddress || urlscanIp || asOwner || urlscanAsn) && (
                    <div className="world-map-meta">
                        {(urlscanIp || ipAddress) && <span>🔌 {urlscanIp || ipAddress}</span>}
                        {countryToUse && !geoCity && <span>📍 {countryToUse}</span>}
                        {geoCity && <span>📍 {geoCity}{countryToUse ? `, ${countryToUse}` : ""}</span>}
                        {(urlscanAsn || asOwner) && <span>🏢 {(urlscanAsn || asOwner)?.substring(0, 28)}</span>}
                    </div>
                )}
            </div>
        </div>
    )
}

// ─── DNA Fingerprint + AI Explain ─────────────────────────────────────────────

function seededRng(seed: number) {
    let s = seed >>> 0
    return () => { s = (Math.imul(s, 1664525) + 1013904223) >>> 0; return s / 0x100000000 }
}

async function callAiExplain(
    url: string, indicators: any[], riskLevel: string, settings: PhishNetSettings
): Promise<string> {
    const indList = indicators.slice(0, 6).map((i: any) => `- ${i.label}: ${i.description}`).join("\n") || "none"
    const prompt = `You are a cybersecurity expert. A URL has been scanned and shows the following threat DNA fingerprint pattern:

URL: ${url.replace(/^https?:\/\//, "").substring(0, 80)}
Risk Level: ${riskLevel.toUpperCase()}
Indicators found (${indicators.length}):
${indList}

In 3-4 sentences, explain:
1. What this specific pattern of indicators reveals about this URL
2. What type of attack or threat this most resembles (e.g. phishing, malware, credential harvesting)
3. What the user should do

Be direct, specific about this URL, and use plain language. Do NOT use markdown formatting.`

    if (settings.aiProvider === "gemini" && settings.geminiApiKey) {
        const res = await fetch(
            `https://generativelanguage.googleapis.com/v1beta/models/${settings.geminiModel || "gemini-2.0-flash"}:generateContent?key=${settings.geminiApiKey}`,
            {
                method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }], generationConfig: { temperature: 0.3, maxOutputTokens: 250 } })
            }
        )
        const data = await res.json()
        return data?.candidates?.[0]?.content?.parts?.[0]?.text?.trim() ?? "No explanation available."
    }

    if (settings.aiProvider === "openai" && settings.openaiApiKey) {
        const res = await fetch("https://api.openai.com/v1/chat/completions", {
            method: "POST",
            headers: { "Content-Type": "application/json", Authorization: `Bearer ${settings.openaiApiKey}` },
            body: JSON.stringify({
                model: settings.openaiModel || "gpt-4o-mini",
                messages: [{ role: "user", content: prompt }], max_tokens: 250, temperature: 0.3
            })
        })
        const data = await res.json()
        return data?.choices?.[0]?.message?.content?.trim() ?? "No explanation available."
    }

    throw new Error("Add an AI key in Settings to use this feature.")
}

export function DnaFingerprint({ url, indicators, settings }:
    { url: string; indicators: any[]; settings: PhishNetSettings | null }) {

    const [explain, setExplain] = useState("")
    const [explaining, setExplaining] = useState(false)
    const [explainErr, setExplainErr] = useState("")

    const BAR_COUNT = 52
    const rng = seededRng(url.split("").reduce((h, c) => (h * 31 + c.charCodeAt(0)) | 0, 0x1337))
    const hasDanger = indicators.some(i => i.severity === "high")
    const hasWarn = indicators.some(i => i.severity === "medium")
    const threatRate = Math.min(indicators.length / 6, 0.85)
    const baseColor = hasDanger ? "#ef4444" : hasWarn ? "#f59e0b" : "#22c55e"
    const level = hasDanger ? "HIGH RISK" : hasWarn ? "MODERATE" : "CLEAN"
    const riskLabel = hasDanger ? "dangerous" : hasWarn ? "suspicious" : "safe"

    const bars = Array.from({ length: BAR_COUNT }, () => {
        const h = rng(), isThreat = rng() < threatRate
        return { height: Math.max(0.12, h), color: isThreat ? baseColor : "#161f2c", isThreat }
    })

    const domain = url.replace(/^https?:\/\//, "").split("/")[0].substring(0, 36)
    const hasAiKey = settings ? (settings.aiProvider === "gemini" ? !!settings.geminiApiKey : !!settings.openaiApiKey) : false

    async function handleExplain() {
        if (!settings) return
        setExplaining(true); setExplainErr(""); setExplain("")
        try {
            const result = await callAiExplain(url, indicators, riskLabel, settings)
            setExplain(result)
        } catch (e) {
            setExplainErr(e instanceof Error ? e.message : "AI explain failed")
        } finally { setExplaining(false) }
    }

    return (
        <div className="insight-card">
            <div className="insight-card-header">
                <span>🧬 Threat DNA</span>
                <span className="insight-badge" style={{ color: baseColor, borderColor: `${baseColor}44` }}>{level}</span>
            </div>
            <div className="dna-wrap">
                <div className="dna-domain">/{domain}</div>
                <svg viewBox={`0 0 ${BAR_COUNT * 5} 50`} style={{ width: "100%", height: 50 }}>
                    {bars.map((b, i) => {
                        const barH = b.height * 46
                        return (
                            <rect key={i} x={i * 5 + 0.5} y={(50 - barH) / 2} width="3.5" height={barH}
                                fill={b.color} rx="1" opacity={b.isThreat ? 0.9 : 0.35} />
                        )
                    })}
                </svg>
                <div className="dna-legend">
                    <span style={{ color: baseColor }}>■</span>&nbsp;Threat signals&nbsp;&nbsp;
                    <span style={{ color: "#1e3040", border: "1px solid #1e3040", padding: "0 3px" }}>■</span>&nbsp;Baseline
                </div>

                {hasAiKey && (
                    <button className="dna-explain-btn" onClick={handleExplain} disabled={explaining}>
                        {explaining ? <><span className="spin">⟳</span>&nbsp;Analysing…</> : <>🤖 Explain by AI</>}
                    </button>
                )}
                {!hasAiKey && (
                    <div className="dna-no-key">Add an AI key in ⚙️ Settings to explain this pattern</div>
                )}

                {explain && (
                    <div className="dna-explanation">
                        <div className="dna-exp-header">🤖 AI Analysis</div>
                        <p className="dna-exp-text">{explain}</p>
                    </div>
                )}
                {explainErr && <div className="dna-exp-err">{explainErr}</div>}
            </div>
        </div>
    )
}

// ─── Report card HTML generator ───────────────────────────────────────────────

function sevColor(level: string) {
    return level === "dangerous" ? "#ef4444" : level === "suspicious" ? "#f59e0b" : "#22c55e"
}

export function generateReportHTML(
    url: string,
    result: ScanResult | null,
    deepResult: DeepScanResult | null,
    gmailResult: EmailScanResult | null,
    isGmail: boolean,
    mergedScore?: number,
    mergedLevel?: string,
): string {
    // Always use merged (deep-scan-aware) values when provided
    const level = mergedLevel ?? (isGmail && gmailResult ? gmailResult.riskLevel : result?.riskLevel ?? "safe")
    const score = mergedScore ?? (isGmail && gmailResult ? gmailResult.riskScore : result?.riskScore ?? 0)
    const inds = isGmail && gmailResult ? gmailResult.indicators : result?.indicators ?? []
    const vt = deepResult?.virusTotal
    const ai = deepResult?.aiVerdict
    const color = sevColor(level)
    const now = new Date().toLocaleString()

    const loc = vt?.ipCountry ? COUNTRY_LOC[vt.ipCountry.toUpperCase()] : null
    const mapEmbed = loc
        ? `https://www.openstreetmap.org/export/embed.html?bbox=${loc[1] - 8},${loc[0] - 5},${loc[1] + 8},${loc[0] + 5}&layer=mapnik&marker=${loc[0]},${loc[1]}`
        : null

    const indRows = inds.map(i => `
    <tr>
      <td style="padding:5px 8px;font-size:12px;font-weight:600;color:#c9d1d9">${i.label}</td>
      <td style="padding:5px 8px;font-size:11px;color:#8b949e">${i.description}</td>
      <td style="padding:5px 8px;font-size:11px;text-align:center;font-weight:700;
        color:${i.severity === "high" ? "#ef4444" : i.severity === "medium" ? "#f59e0b" : "#6b7280"}">
        ${i.severity.toUpperCase()}</td></tr>`).join("")

    const vtSection = vt && !vt.error ? `
    <div class="section">
      <div class="section-title">VirusTotal Analysis</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px">
        ${[["Malicious", vt.malicious, "#ef4444"], ["Suspicious", vt.suspicious, "#f59e0b"],
        ["Harmless", vt.harmless, "#22c55e"], ["Undetected", vt.undetected, "#6b7280"]]
            .map(([l, n, c]) => `<div style="flex:1;min-width:70px;background:#21262d;border-radius:8px;padding:10px;text-align:center">
            <div style="font-size:22px;font-weight:800;color:${c};font-family:monospace">${n}</div>
            <div style="font-size:10px;color:#8b949e;margin-top:3px">${l}</div></div>`).join("")}
      </div>
      <table style="width:100%;border-collapse:collapse">
        ${[["Domain Reputation", vt.domainReputation ?? "N/A"],
        ["Registrar", vt.registrar ?? "N/A"],
        ["Registered", vt.creationDate ?? "N/A"],
        ["Server IP", vt.ipAddress ? `${vt.ipAddress}${vt.ipCountry ? " (" + vt.ipCountry + ")" : ""}` : "N/A"],
        ["AS Owner", vt.asOwner ?? "N/A"],
        ["IP Flagged By", vt.ipMalicious ? `${vt.ipMalicious} engines` : "None"],
        ["Threat Label", vt.popularThreatLabel ?? "None"]].map(([l, v]) =>
            `<tr style="border-top:1px solid #21262d">
            <td style="padding:5px 8px;font-size:11px;color:#8b949e;width:140px">${l}</td>
            <td style="padding:5px 8px;font-size:11px;color:#c9d1d9">${v}</td></tr>`).join("")}
      </table>
    </div>` : ""

    const mapSection = mapEmbed ? `
    <div class="section">
      <div class="section-title">Server Location — ${vt?.ipCountry ?? ""}${vt?.ipAddress ? ` (${vt.ipAddress})` : ""}</div>
      <iframe src="${mapEmbed}" width="100%" height="220"
        style="border:1px solid #30363d;border-radius:8px;display:block" loading="lazy"></iframe>
      <div style="margin-top:6px;font-size:11px;color:#8b949e">
        ${vt?.asOwner ? `🏢 ${vt.asOwner}` : ""}
      </div>
    </div>` : ""

    const aiSection = ai && !ai.error ? `
    <div class="section">
      <div class="section-title">AI Analysis — ${ai.provider} (${ai.model})</div>
      <div style="display:inline-block;padding:5px 14px;border-radius:20px;
        border:1px solid ${sevColor(ai.verdict)};color:${sevColor(ai.verdict)};
        font-size:13px;font-weight:700;margin-bottom:12px">
        ${ai.verdict.toUpperCase()} — ${ai.confidence}% confidence
      </div>
      ${ai.primaryReason ? `<p style="font-size:13px;font-weight:600;color:#c9d1d9;margin:0 0 8px">${ai.primaryReason}</p>` : ""}
      ${ai.explanation ? `<p style="font-size:12px;color:#8b949e;line-height:1.7;margin:0">${ai.explanation}</p>` : ""}
    </div>` : ""

    const emailSection = isGmail && gmailResult ? `
    <div class="section">
      <div class="section-title">Email Analysis</div>
      <table style="width:100%;border-collapse:collapse">
        ${[["From", gmailResult.senderEmail || "Unknown"],
        ["Sender Name", gmailResult.senderDisplay || "Unknown"],
        ["Subject", (gmailResult.subject || "Unknown").substring(0, 100)],
        ["Suspicious Links", String(gmailResult.suspiciousLinks.length)]].map(([l, v]) =>
            `<tr style="border-top:1px solid #21262d">
            <td style="padding:5px 8px;font-size:11px;color:#8b949e;width:140px">${l}</td>
            <td style="padding:5px 8px;font-size:11px;color:#c9d1d9;word-break:break-all">${v}</td></tr>`).join("")}
      </table>
    </div>` : ""

    return `<!DOCTYPE html><html lang="en">
<head>
  <meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>PhishNet Security Report</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet"/>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Inter',system-ui,sans-serif;background:#0d1117;color:#c9d1d9;min-height:100vh;padding:28px 20px}
    .card{max-width:720px;margin:0 auto;background:#161b22;border:1px solid #30363d;border-radius:16px;overflow:hidden}
    .card-header{padding:24px 28px;background:linear-gradient(135deg,#0d1117 0%,#161b22 100%);border-bottom:1px solid #30363d}
    .brand{display:flex;align-items:center;gap:10px;margin-bottom:16px}
    .brand-name{font-size:17px;font-weight:800;color:#e6edf3}
    .brand-name span{color:${color}}
    .url-badge{display:inline-block;padding:4px 12px;background:rgba(255,255,255,0.04);border:1px solid #30363d;
      border-radius:6px;font-family:'JetBrains Mono',monospace;font-size:11px;color:#8b949e;word-break:break-all;margin-bottom:18px}
    .risk-row{display:flex;align-items:flex-start;gap:20px}
    .risk-score{font-size:58px;font-weight:800;color:${color};font-family:'JetBrains Mono',monospace;line-height:1}
    .risk-level{font-size:22px;font-weight:700;color:${color};text-transform:uppercase;letter-spacing:1px}
    .risk-sub{font-size:12px;color:#8b949e;margin-top:5px}
    .section{padding:20px 28px;border-top:1px solid #30363d}
    .section-title{font-size:10px;font-weight:700;color:#6b7280;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:12px}
    table{width:100%;border-collapse:collapse}
    tr:nth-child(even){background:rgba(255,255,255,0.015)}
    th{font-size:10px;font-weight:700;color:#6b7280;text-align:left;padding:6px 8px;letter-spacing:0.5px;
       background:rgba(255,255,255,0.03);border-bottom:1px solid #30363d}
    .footer{padding:14px 28px;border-top:1px solid #30363d;display:flex;align-items:center;justify-content:space-between;
      background:rgba(0,0,0,0.2)}
    .footer-brand{font-size:11px;color:#484f58;font-family:'JetBrains Mono',monospace}
    .print-btn{position:fixed;bottom:24px;right:24px;background:${color};color:#000;border:none;
      border-radius:10px;padding:12px 22px;font-family:'Inter',sans-serif;font-size:13px;font-weight:700;
      cursor:pointer;box-shadow:0 4px 20px rgba(0,0,0,0.5);letter-spacing:0.3px}
    @media print{.print-btn{display:none}}
  </style>
</head>
<body>
  <div class="card">
    <div class="card-header">
      <div class="brand">
        <span style="font-size:24px">🛡️</span>
        <span class="brand-name">Phish<span>Net</span> Security Report</span>
      </div>
      <div class="url-badge">🌐 ${url}</div>
      <div class="risk-row">
        <div class="risk-score">${score}</div>
        <div>
          <div class="risk-level">${level}</div>
          <div class="risk-sub">${inds.length} indicator${inds.length !== 1 ? "s" : ""} · ${now}</div>
          ${deepResult ? `<div style="font-size:10px;color:#6b7280;margin-top:3px">✓ Deep Scan included</div>` : ""}
        </div>
      </div>
    </div>
    ${inds.length > 0 ? `
    <div class="section">
      <div class="section-title">Threat Indicators (${inds.length})</div>
      <table>
        <thead><tr><th>Indicator</th><th>Description</th><th style="text-align:center">Severity</th></tr></thead>
        <tbody>${indRows}</tbody>
      </table>
    </div>` : ""}
    ${emailSection}
    ${vtSection}
    ${mapSection}
    ${aiSection}
    <div class="footer">
      <span class="footer-brand">⚡ PhishNet</span>
      <span style="font-size:10px;color:#484f58">${now}</span>
    </div>
  </div>
  <button class="print-btn" onclick="window.print()">🖨️ Save PDF</button>
</body></html>`
}

// ─── Report Button ────────────────────────────────────────────────────────────

export function ReportCardSection({ url, result, deepResult, gmailResult, isGmail, activeScore, activeLevel }:
    {
        url: string; result: ScanResult | null; deepResult: DeepScanResult | null;
        gmailResult: EmailScanResult | null; isGmail: boolean;
        activeScore?: number; activeLevel?: string
    }) {

    function openReport() {
        const html = generateReportHTML(url, result, deepResult, gmailResult, isGmail, activeScore, activeLevel)
        const blob = new Blob([html], { type: "text/html" })
        chrome.tabs.create({ url: URL.createObjectURL(blob) })
    }

    return (
        <div className="insight-card">
            <div className="insight-card-header">
                <span>📋 Security Report</span>
                {deepResult && <span className="insight-badge safe">Deep data included</span>}
            </div>
            <div className="report-section-body">
                <p className="report-desc">
                    Generate a shareable HTML report with all indicators{deepResult ? ", VirusTotal stats, server map, and AI verdict" : ""}. Opens in a new tab — ready to save as PDF.
                </p>
                <button className="report-btn" onClick={openReport} disabled={!result && !gmailResult}>
                    <span>📊</span>
                    <span>Generate Report Card</span>
                    <span className="report-btn-arrow">↗</span>
                </button>
                {!result && !gmailResult && (
                    <p className="report-hint">Scan a page first to generate a report.</p>
                )}
            </div>
        </div>
    )
}

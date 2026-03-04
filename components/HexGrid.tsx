// components/HexGrid.tsx — Hexagonal Threat Map

import { useState } from "react"
import type { ScanResult } from "../lib/phishingDetector"
import type { DeepScanResult } from "../lib/deepScan"
import type { EmailScanResult } from "../contents/gmail"

// ─── Types ────────────────────────────────────────────────────────────────────

export interface HexCell {
    id: string
    label: string
    icon: string
    severity: "safe" | "suspicious" | "dangerous" | "unknown"
    details: string[]
    count?: number
}

const URL_IDS = new Set(["ip-url", "suspicious-tld", "lookalike-domain", "excessive-subdomains", "long-url", "at-symbol", "redirect-param", "http-login"])
const PAGE_IDS = new Set(["login-form", "external-form", "hidden-forms", "suspicious-keywords", "mismatched-links"])
const EMAIL_IDS = new Set(["spoofed-sender", "free-email-brand", "suspicious-sender-tld", "phishing-keywords", "urgent-subject", "suspicious-link", "many-links", "generic-display-name"])

function sev(inds: any[]): HexCell["severity"] {
    if (!inds.length) return "safe"
    if (inds.some(i => i.severity === "high")) return "dangerous"
    if (inds.some(i => i.severity === "medium")) return "suspicious"
    return "safe"
}

export function buildHexCells(
    result: ScanResult | null,
    gmailResult: EmailScanResult | null,
    deepResult: DeepScanResult | null,
    isGmail: boolean
): HexCell[] {
    const all = result?.indicators ?? []
    const vt = deepResult?.virusTotal
    const ai = deepResult?.aiVerdict
    const inds = isGmail ? (gmailResult?.indicators ?? []) : []

    const urlInds = all.filter(i => URL_IDS.has(i.id))
    const pageInds = all.filter(i => PAGE_IDS.has(i.id))
    const mailInds = inds.filter(i => EMAIL_IDS.has(i.id))

    return [
        {
            id: "url", label: "URL", icon: "🔗",
            severity: urlInds.length ? sev(urlInds) : (result ? "safe" : "unknown"),
            details: urlInds.length ? urlInds.map(i => i.label) : [result ? "✓ No URL threats" : "Scanning…"],
            count: urlInds.length
        },
        {
            id: "page", label: "Page", icon: "📄",
            severity: pageInds.length ? sev(pageInds) : (result ? "safe" : "unknown"),
            details: pageInds.length ? pageInds.map(i => i.label) : [result ? "✓ Page content clean" : "Scanning…"],
            count: pageInds.length
        },
        {
            id: "email", label: "Email", icon: "📧",
            severity: !isGmail ? "unknown" : mailInds.length ? sev(mailInds) : (gmailResult ? "safe" : "unknown"),
            details: !isGmail ? ["Gmail only"] : mailInds.length ? mailInds.map(i => i.label) : [gmailResult ? "✓ Email clean" : "Open an email"],
            count: mailInds.length
        },
        {
            id: "domain", label: "Domain", icon: "🌐",
            severity: !vt || vt.error ? "unknown"
                : (vt.domainReputation ?? 0) < -5 ? "suspicious" : "safe",
            details: vt && !vt.error
                ? [`Rep: ${vt.domainReputation ?? "N/A"}`, vt.registrar?.substring(0, 22) ?? "", vt.creationDate ? `Reg: ${vt.creationDate}` : ""].filter(Boolean)
                : ["Run Deep Scan →"]
        },
        {
            id: "vt", label: "VirusTotal", icon: "🔬",
            severity: !vt || vt.error ? "unknown"
                : vt.malicious > 0 ? "dangerous" : vt.suspicious > 0 ? "suspicious" : "safe",
            details: vt && !vt.error
                ? [`${vt.malicious}/${vt.total} malicious`, vt.suspicious ? `${vt.suspicious} suspicious` : "", vt.popularThreatLabel ?? ""].filter(Boolean)
                : ["Run Deep Scan →"],
            count: vt && !vt.error ? vt.malicious : undefined
        },
        {
            id: "ai", label: "AI", icon: "🤖",
            severity: !ai || ai.error ? "unknown" : ai.verdict,
            details: ai && !ai.error
                ? [`${ai.verdict} (${ai.confidence}%)`, (ai.primaryReason ?? "").substring(0, 45)].filter(Boolean)
                : ["Run Deep Scan →"]
        }
    ]
}

// ─── Colours ──────────────────────────────────────────────────────────────────

const SEV_STROKE: Record<string, string> = {
    dangerous: "#ef4444", suspicious: "#f59e0b", safe: "#22c55e", unknown: "#1e2d45"
}
const SEV_FILL: Record<string, string> = {
    dangerous: "rgba(239,68,68,0.13)", suspicious: "rgba(245,158,11,0.11)",
    safe: "rgba(34,197,94,0.09)", unknown: "rgba(15,20,30,0.7)"
}
const SEV_GLOW: Record<string, string> = {
    dangerous: "drop-shadow(0 0 7px rgba(239,68,68,0.7))",
    suspicious: "drop-shadow(0 0 7px rgba(245,158,11,0.7))",
    safe: "drop-shadow(0 0 7px rgba(34,197,94,0.5))",
    unknown: "none"
}

// ─── Single Hex ───────────────────────────────────────────────────────────────

function HexSVG({ cell, active, onClick }:
    { cell: HexCell; active: boolean; onClick: () => void }) {
    const W = 88, H = 100
    const stroke = SEV_STROKE[cell.severity]
    const fill = SEV_FILL[cell.severity]
    // pointy-top polygon
    const pts = `${W / 2},1 ${W - 1},${H / 4} ${W - 1},${H * 3 / 4} ${W / 2},${H - 1} 1,${H * 3 / 4} 1,${H / 4}`
    return (
        <g onClick={onClick} style={{ cursor: "pointer" }}>
            <polygon points={pts} fill={fill} stroke={stroke}
                strokeWidth={active ? 2 : 1}
                style={{ transition: "all 0.2s", filter: active ? SEV_GLOW[cell.severity] : "none" }}
            />
            <text x={W / 2} y={H * 0.32} textAnchor="middle" dominantBaseline="middle" fontSize="18">{cell.icon}</text>
            <text x={W / 2} y={H * 0.56} textAnchor="middle" dominantBaseline="middle" fontSize="8.5"
                fill="#8b949e" fontFamily="system-ui,sans-serif">{cell.label}</text>
            <text x={W / 2} y={H * 0.76} textAnchor="middle" dominantBaseline="middle" fontSize="7.5"
                fill={stroke} fontFamily="monospace" fontWeight="bold">
                {cell.severity === "unknown" ? "N/A" : cell.severity.toUpperCase()}
            </text>
            {(cell.count ?? 0) > 0 && (
                <circle cx={W - 12} cy={12} r="10" fill={stroke} opacity="0.9" />
            )}
            {(cell.count ?? 0) > 0 && (
                <text x={W - 12} y={12} textAnchor="middle" dominantBaseline="middle"
                    fontSize="8" fill="#fff" fontWeight="bold" fontFamily="monospace">
                    {cell.count}
                </text>
            )}
        </g>
    )
}

// ─── Grid ─────────────────────────────────────────────────────────────────────

export function HexGrid({ cells }: { cells: HexCell[] }) {
    const [activeId, setActiveId] = useState<string | null>(null)

    const W = 88, H = 100, GAP = 4
    const ROW_H = H * 0.77  // vertical overlap for honeycomb
    const OFFSET = W / 2 + GAP / 2

    // 2 rows of 3: row1=[0,1,2], row2=[3,4,5] offset by OFFSET
    const positions: [number, number][] = [
        [0, 0], [W + GAP, 0], [(W + GAP) * 2, 0],
        [OFFSET, ROW_H], [OFFSET + W + GAP, ROW_H], [OFFSET + (W + GAP) * 2, ROW_H],
    ]

    const svgW = (W + GAP) * 3 - GAP
    const svgH = H + ROW_H

    const active = activeId ? cells.find(c => c.id === activeId) : null

    return (
        <div className="hex-grid-container">
            <svg width="100%" viewBox={`-2 -2 ${svgW + 4} ${svgH + 4}`}>
                {cells.map((cell, i) => (
                    <g key={cell.id} transform={`translate(${positions[i][0]},${positions[i][1]})`}>
                        <HexSVG
                            cell={cell}
                            active={activeId === cell.id}
                            onClick={() => setActiveId(activeId === cell.id ? null : cell.id)}
                        />
                    </g>
                ))}
            </svg>

            {active && (
                <div className="hex-detail" style={{ borderColor: SEV_STROKE[active.severity] }}>
                    <div className="hex-detail-header">
                        <span>{active.icon} {active.label}</span>
                        <span style={{ color: SEV_STROKE[active.severity], fontWeight: 700, fontSize: 10 }}>
                            {active.severity.toUpperCase()}
                        </span>
                        <button onClick={() => setActiveId(null)}>×</button>
                    </div>
                    {active.details.map((d, i) => (
                        <div key={i} className="hex-detail-row">▸ {d}</div>
                    ))}
                </div>
            )}
        </div>
    )
}

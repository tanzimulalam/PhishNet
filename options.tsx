// options.tsx — PhishNet Settings Page

import { useEffect, useState } from "react"
import "./options.css"
import {
    DEFAULT_SETTINGS,
    GEMINI_MODELS,
    OPENAI_MODELS,
    getSettings,
    saveSettings,
    type AIProvider,
    type GeminiModel,
    type OpenAIModel,
    type PhishNetSettings
} from "./lib/storage"

// ─── API Key Field ────────────────────────────────────────────────────────────

type KeyStatus = "idle" | "testing" | "valid" | "invalid"

function ApiKeyField({
    label,
    hint,
    hintUrl,
    value,
    onChange,
    testFn
}: {
    label: string
    hint: string
    hintUrl: string
    value: string
    onChange: (v: string) => void
    testFn: (key: string) => Promise<boolean>
}) {
    const [show, setShow] = useState(false)
    const [status, setStatus] = useState<KeyStatus>("idle")

    async function handleTest() {
        if (!value.trim()) return
        setStatus("testing")
        const ok = await testFn(value.trim())
        setStatus(ok ? "valid" : "invalid")
        setTimeout(() => setStatus("idle"), 4000)
    }

    return (
        <div className="field-group">
            <label className="field-label">
                {label}
                <span className="optional">Optional</span>
                {status !== "idle" && (
                    <span className={`key-status ${status}`}>
                        {status === "testing" && "⏳ Testing…"}
                        {status === "valid" && "✓ Valid"}
                        {status === "invalid" && "✕ Invalid"}
                    </span>
                )}
            </label>
            <div className="input-wrapper">
                <input
                    className={`field-input${value ? " has-value" : ""}`}
                    type={show ? "text" : "password"}
                    value={value}
                    onChange={e => onChange(e.target.value)}
                    placeholder="Paste your API key here…"
                    spellCheck={false}
                    autoComplete="off"
                />
                <div className="input-actions">
                    <button className="btn-icon" onClick={() => setShow(s => !s)} title={show ? "Hide" : "Show"}>
                        {show ? "🙈" : "👁️"}
                    </button>
                    <button
                        className={`btn-test${status === "testing" ? " testing" : ""}`}
                        onClick={handleTest}
                        disabled={!value.trim() || status === "testing"}>
                        {status === "testing" ? "Testing…" : "Test"}
                    </button>
                </div>
            </div>
            <p className="field-hint">
                {hint}{" "}
                <a href={hintUrl} target="_blank" rel="noreferrer">Get API key →</a>
            </p>
        </div>
    )
}

// ─── Toggle Row ───────────────────────────────────────────────────────────────

function ToggleRow({
    label, desc, checked, onChange
}: { label: string; desc: string; checked: boolean; onChange: (v: boolean) => void }) {
    return (
        <div className="toggle-row">
            <div className="toggle-info">
                <span className="toggle-label">{label}</span>
                <span className="toggle-desc">{desc}</span>
            </div>
            <label className="toggle">
                <input type="checkbox" checked={checked} onChange={e => onChange(e.target.checked)} />
                <span className="toggle-slider" />
            </label>
        </div>
    )
}

// ─── API Test Functions ────────────────────────────────────────────────────────

async function testGeminiKey(key: string): Promise<boolean> {
    try {
        const res = await fetch(
            `https://generativelanguage.googleapis.com/v1beta/models?key=${key}`
        )
        return res.ok
    } catch { return false }
}

async function testOpenAIKey(key: string): Promise<boolean> {
    try {
        const res = await fetch("https://api.openai.com/v1/models", {
            headers: { Authorization: `Bearer ${key}` }
        })
        return res.ok
    } catch { return false }
}

async function testVirusTotalKey(key: string): Promise<boolean> {
    try {
        const res = await fetch("https://www.virustotal.com/api/v3/urls/aHR0cHM6Ly9nb29nbGUuY29t", {
            headers: { "x-apikey": key }
        })
        return res.status !== 401 && res.status !== 403
    } catch { return false }
}

async function testGoogleSafeBrowsingKey(key: string): Promise<boolean> {
    try {
        const res = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${key}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                client: { clientId: "test", clientVersion: "1.0" },
                threatInfo: {
                    threatTypes: ["MALWARE"],
                    platformTypes: ["ANY_PLATFORM"],
                    threatEntryTypes: ["URL"],
                    threatEntries: [{ url: "http://testsafebrowsing.appspot.com/s/malware.html" }]
                }
            })
        })
        return res.status !== 400 && res.status !== 401 && res.status !== 403
    } catch { return false }
}

async function testURLscanKey(key: string): Promise<boolean> {
    if (!key || key.trim().length === 0) return false
    
    // URLscan.io API key format check (UUID format)
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
    if (!uuidRegex.test(key.trim())) return false
    
    // Try to validate by attempting a simple search (more reliable than quotas endpoint)
    try {
        // Try a simple search query - this endpoint works with API keys
        const res = await fetch("https://urlscan.io/api/v1/search/?q=domain:example.com&size=1", {
            headers: { "API-Key": key.trim() }
        })
        // 200 = valid key, 401/403 = invalid key, other errors might be CORS/network
        if (res.status === 200 || res.status === 404) return true // 404 means no results but key is valid
        if (res.status === 401 || res.status === 403) return false // Invalid key
        // For other status codes, assume valid if format is correct (might be CORS issues)
        return true
    } catch {
        // If fetch fails (CORS, network), just validate format
        // The key will be tested when actually used
        return uuidRegex.test(key.trim())
    }
}

async function testHIBPKey(key: string): Promise<boolean> {
    // HIBP API key format check and basic validation
    if (key.length === 0) return true // Optional key
    if (key.length < 32) return false // Invalid format
    // Try a test request (using a known non-existent email to avoid rate limits)
    try {
        const res = await fetch("https://haveibeenpwned.com/api/v3/breachedaccount/test-validation-only@example.com", {
            headers: {
                "hibp-api-key": key,
                "User-Agent": "PhishNet-Extension/1.0"
            }
        })
        // 404 means API key is valid (email doesn't exist, which is expected)
        // 401/403 means invalid key
        return res.status === 404 || res.status !== 401 && res.status !== 403
    } catch {
        return key.length >= 32 // Fallback to format check
    }
}

// ─── Main Settings Page ────────────────────────────────────────────────────────

function OptionsPage() {
    const [settings, setSettings] = useState<PhishNetSettings>(DEFAULT_SETTINGS)
    const [loaded, setLoaded] = useState(false)
    const [saveMsg, setSaveMsg] = useState(false)

    useEffect(() => {
        getSettings().then(s => { setSettings(s); setLoaded(true) })
    }, [])

    function update<K extends keyof PhishNetSettings>(key: K, value: PhishNetSettings[K]) {
        setSettings(prev => ({ ...prev, [key]: value }))
    }

    async function handleSave() {
        await saveSettings(settings)
        setSaveMsg(true)
        setTimeout(() => setSaveMsg(false), 2500)
    }

    if (!loaded) return <div style={{ padding: 32, color: "#8b949e" }}>Loading settings…</div>

    const activeModels = settings.aiProvider === "gemini" ? GEMINI_MODELS : OPENAI_MODELS
    const activeModelKey = settings.aiProvider === "gemini" ? "geminiModel" : "openaiModel"
    const activeModelValue = settings.aiProvider === "gemini"
        ? settings.geminiModel
        : settings.openaiModel

    return (
        <div className="settings-page">
            <header className="settings-header">
                <div className="settings-logo">
                    <div className="settings-logo-icon">🛡️</div>
                    <span className="settings-logo-text">Phish<span>Net</span> Settings</span>
                </div>
                <span className="settings-subtitle">v0.0.1</span>
            </header>

            <div className="settings-content">

                {/* ─── API Keys ─── */}
                <div className="card">
                    <div className="card-header">
                        <span className="card-icon">🔑</span>
                        <span className="card-title">API Keys</span>
                        <span className="card-subtitle">Stored locally in Chrome — never sent to PhishNet servers</span>
                    </div>
                    <div className="card-body">
                        <div className="alert info">
                            ℹ️ All API keys are stored in your browser's secure sync storage and sent only directly to the respective API provider.
                        </div>
                        <ApiKeyField
                            label="Google Gemini API Key"
                            hint="Required for Gemini AI deep scan."
                            hintUrl="https://aistudio.google.com/apikey"
                            value={settings.geminiApiKey}
                            onChange={v => update("geminiApiKey", v)}
                            testFn={testGeminiKey}
                        />
                        <ApiKeyField
                            label="OpenAI API Key"
                            hint="Required for GPT-based deep scan."
                            hintUrl="https://platform.openai.com/api-keys"
                            value={settings.openaiApiKey}
                            onChange={v => update("openaiApiKey", v)}
                            testFn={testOpenAIKey}
                        />
                        <ApiKeyField
                            label="VirusTotal API Key"
                            hint="Free tier: 4 requests/min, 500/day."
                            hintUrl="https://www.virustotal.com/gui/my-apikey"
                            value={settings.virusTotalApiKey}
                            onChange={v => update("virusTotalApiKey", v)}
                            testFn={testVirusTotalKey}
                        />
                        <ApiKeyField
                            label="Google Safe Browsing API Key"
                            hint="Free tier: 10,000 requests/day. Required for Safe Browsing checks."
                            hintUrl="https://console.cloud.google.com/apis/credentials"
                            value={settings.googleSafeBrowsingApiKey}
                            onChange={v => update("googleSafeBrowsingApiKey", v)}
                            testFn={testGoogleSafeBrowsingKey}
                        />
                        <ApiKeyField
                            label="URLscan.io API Key"
                            hint="Optional. Free tier: 100 scans/day. Enables URL submission and private scans."
                            hintUrl="https://urlscan.io/user/signup"
                            value={settings.urlscanApiKey}
                            onChange={v => update("urlscanApiKey", v)}
                            testFn={testURLscanKey}
                        />
                        <ApiKeyField
                            label="Have I Been Pwned API Key"
                            hint="Optional. Free tier available. Increases rate limits for breach checking."
                            hintUrl="https://haveibeenpwned.com/API/Key"
                            value={settings.hibpApiKey}
                            onChange={v => update("hibpApiKey", v)}
                            testFn={testHIBPKey}
                        />
                        <div className="field-group">
                            <label className="field-label">
                                Your Email Address
                                <span className="optional">For HIBP Checks</span>
                            </label>
                            <div className="input-wrapper">
                                <input
                                    className={`field-input${settings.userEmail ? " has-value" : ""}`}
                                    type="email"
                                    value={settings.userEmail}
                                    onChange={e => update("userEmail", e.target.value)}
                                    placeholder="your.email@example.com"
                                    spellCheck={false}
                                    autoComplete="email"
                                />
                            </div>
                            <p className="field-hint">
                                Enter your email to check if it's been breached. Used in the Intel tab.
                            </p>
                        </div>
                    </div>
                </div>

                {/* ─── OSINT Features ─── */}
                <div className="card">
                    <div className="card-header">
                        <span className="card-icon">🔍</span>
                        <span className="card-title">OSINT Features</span>
                        <span className="card-subtitle">Enable/disable OSINT intelligence sources</span>
                    </div>
                    <div className="card-body">
                        <ToggleRow
                            label="Google Safe Browsing"
                            desc="Check URLs against Google's Safe Browsing database (requires API key)"
                            checked={settings.enableGoogleSafeBrowsing}
                            onChange={v => update("enableGoogleSafeBrowsing", v)}
                        />
                        <ToggleRow
                            label="URLscan.io Analysis"
                            desc="Submit URLs for visual analysis and screenshots (works without key, better with key)"
                            checked={settings.enableURLscan}
                            onChange={v => update("enableURLscan", v)}
                        />
                    </div>
                </div>

                {/* ─── AI Provider & Model ─── */}
                <div className="card">
                    <div className="card-header">
                        <span className="card-icon">🤖</span>
                        <span className="card-title">AI Provider & Model</span>
                    </div>
                    <div className="card-body">
                        <div className="field-group">
                            <label className="field-label">AI Provider</label>
                            <div className="provider-row">
                                <div
                                    className={`provider-card ${settings.aiProvider === "gemini" ? "selected" : ""}`}
                                    onClick={() => update("aiProvider", "gemini" as AIProvider)}>
                                    <span className="provider-name">✨ Google Gemini</span>
                                    <span className="provider-desc">Fast, free tier available</span>
                                </div>
                                <div
                                    className={`provider-card ${settings.aiProvider === "openai" ? "selected" : ""}`}
                                    onClick={() => update("aiProvider", "openai" as AIProvider)}>
                                    <span className="provider-name">⚡ OpenAI GPT</span>
                                    <span className="provider-desc">GPT-4o, pay-per-use</span>
                                </div>
                            </div>
                        </div>

                        <div className="field-group">
                            <label className="field-label">
                                {settings.aiProvider === "gemini" ? "Gemini" : "OpenAI"} Model
                            </label>
                            <select
                                className="select-field"
                                value={activeModelValue}
                                onChange={e => update(activeModelKey as keyof PhishNetSettings, e.target.value as GeminiModel & OpenAIModel)}>
                                {activeModels.map(m => (
                                    <option key={m.value} value={m.value}>{m.label}</option>
                                ))}
                            </select>
                        </div>
                    </div>
                </div>

                {/* ─── Feature Toggles ─── */}
                <div className="card">
                    <div className="card-header">
                        <span className="card-icon">🎛️</span>
                        <span className="card-title">Features</span>
                    </div>
                    <div className="card-body">
                        <ToggleRow
                            label="Auto Deep Scan on page load"
                            desc="Automatically runs AI + VirusTotal when you visit a page (uses API credits)"
                            checked={settings.autoDeepScan}
                            onChange={v => update("autoDeepScan", v)}
                        />
                        <ToggleRow
                            label="Gmail Email Scanning"
                            desc="Automatically scans emails in Gmail and shows a warning banner for suspicious content"
                            checked={settings.gmailScanning}
                            onChange={v => update("gmailScanning", v)}
                        />
                        <ToggleRow
                            label="Extension Badge"
                            desc="Show risk level badge (✓ / ! / ✕) on the extension icon"
                            checked={settings.showBadge}
                            onChange={v => update("showBadge", v)}
                        />
                        <ToggleRow
                            label="Danger Notifications"
                            desc="Show a Chrome notification when you land on a dangerous page"
                            checked={settings.dangerNotifications}
                            onChange={v => update("dangerNotifications", v)}
                        />
                    </div>
                </div>

                {/* ─── Save ─── */}
                <div className="save-row">
                    <button className="btn-save" onClick={handleSave}>
                        Save Settings
                    </button>
                    <span className={`save-status ${saveMsg ? "visible" : ""}`}>
                        ✓ Settings saved
                    </span>
                </div>

            </div>
        </div>
    )
}

export default OptionsPage

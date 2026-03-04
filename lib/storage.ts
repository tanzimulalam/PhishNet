// lib/storage.ts — Typed chrome.storage.sync helpers for PhishNet settings

export type GeminiModel =
    | "gemini-2.5-pro-preview-05-06"
    | "gemini-2.0-flash"
    | "gemini-1.5-flash"
    | "gemini-1.5-pro"

export type OpenAIModel =
    | "gpt-4o"
    | "gpt-4o-mini"
    | "gpt-4-turbo"

export type AIProvider = "gemini" | "openai"

export interface PhishNetSettings {
    // API Keys
    geminiApiKey: string
    openaiApiKey: string
    virusTotalApiKey: string
    googleSafeBrowsingApiKey: string
    urlscanApiKey: string
    hibpApiKey: string
    userEmail: string  // User's own email for HIBP checks

    // AI Config
    aiProvider: AIProvider
    geminiModel: GeminiModel
    openaiModel: OpenAIModel

    // Feature toggles
    autoDeepScan: boolean
    gmailScanning: boolean
    showBadge: boolean
    dangerNotifications: boolean
    enableGoogleSafeBrowsing: boolean
    enableURLscan: boolean
}

export const DEFAULT_SETTINGS: PhishNetSettings = {
    geminiApiKey: "",
    openaiApiKey: "",
    virusTotalApiKey: "",
    googleSafeBrowsingApiKey: "",
    urlscanApiKey: "",
    hibpApiKey: "",
    userEmail: "",
    aiProvider: "gemini",
    geminiModel: "gemini-2.0-flash",
    openaiModel: "gpt-4o",
    autoDeepScan: false,
    gmailScanning: true,
    showBadge: true,
    dangerNotifications: true,
    enableGoogleSafeBrowsing: true,
    enableURLscan: true
}

export const GEMINI_MODELS: { value: GeminiModel; label: string }[] = [
    { value: "gemini-2.5-pro-preview-05-06", label: "Gemini 2.5 Pro" },
    { value: "gemini-2.0-flash", label: "Gemini 2.0 Flash (Recommended)" },
    { value: "gemini-1.5-pro", label: "Gemini 1.5 Pro" },
    { value: "gemini-1.5-flash", label: "Gemini 1.5 Flash" }
]

export const OPENAI_MODELS: { value: OpenAIModel; label: string }[] = [
    { value: "gpt-4o", label: "GPT-4o (Recommended)" },
    { value: "gpt-4o-mini", label: "GPT-4o Mini (Faster, cheaper)" },
    { value: "gpt-4-turbo", label: "GPT-4 Turbo" }
]

export async function getSettings(): Promise<PhishNetSettings> {
    const stored = await chrome.storage.sync.get(Object.keys(DEFAULT_SETTINGS))
    return { ...DEFAULT_SETTINGS, ...stored } as PhishNetSettings
}

export async function saveSettings(partial: Partial<PhishNetSettings>): Promise<void> {
    await chrome.storage.sync.set(partial)
}

export async function getSetting<K extends keyof PhishNetSettings>(
    key: K
): Promise<PhishNetSettings[K]> {
    const settings = await getSettings()
    return settings[key]
}

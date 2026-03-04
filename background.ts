// background.ts — PhishNet v2 Service Worker

import {
    analyzeUrl,
    buildScanResult,
    type PhishingIndicator,
    type ScanResult
} from "./lib/phishingDetector"
import { getSettings } from "./lib/storage"
import type { EmailScanResult } from "./contents/gmail"

export { }

const tabResults = new Map<number, ScanResult>()
const gmailResults = new Map<number, EmailScanResult>()

// ─── Badge ────────────────────────────────────────────────────────────────────

async function setBadge(tabId: number, level: "safe" | "suspicious" | "dangerous") {
    const settings = await getSettings()
    if (!settings.showBadge) { chrome.action.setBadgeText({ text: "", tabId }); return }
    const cfg = { safe: { text: "✓", color: "#22c55e" }, suspicious: { text: "!", color: "#f59e0b" }, dangerous: { text: "✕", color: "#ef4444" } }
    const { text, color } = cfg[level]
    chrome.action.setBadgeText({ text, tabId })
    chrome.action.setBadgeBackgroundColor({ color, tabId })
}

// ─── Notifications ────────────────────────────────────────────────────────────

async function showDangerNotification(tabId: number, result: ScanResult) {
    const s = await getSettings()
    if (!s.dangerNotifications) return
    const top = result.indicators[0]
    chrome.notifications.create(`phishnet-tab-${tabId}`, {
        type: "basic", iconUrl: chrome.runtime.getURL("assets/icon.png"),
        title: "⚠️ PhishNet: Dangerous Page",
        message: top ? `${top.label} — Risk: ${result.riskScore}/100` : `Risk: ${result.riskScore}/100`,
        priority: 2
    })
}

async function showGmailNotification(result: EmailScanResult) {
    const s = await getSettings()
    if (!s.dangerNotifications) return
    const topLabel = result.indicators[0]?.label ?? "Suspicious content detected"
    chrome.notifications.create("phishnet-gmail", {
        type: "basic", iconUrl: chrome.runtime.getURL("assets/icon.png"),
        title: `📧 PhishNet: ${result.riskLevel === "dangerous" ? "Dangerous" : "Suspicious"} Email`,
        message: `"${result.subject?.substring(0, 50) ?? "(no subject)"}" — ${topLabel}`,
        priority: result.riskLevel === "dangerous" ? 2 : 1
    })
}

// ─── Core Scan ────────────────────────────────────────────────────────────────

async function scanTab(tabId: number, url: string) {
    if (!url || url.startsWith("chrome") || url.startsWith("about") || url.startsWith("edge")) {
        chrome.action.setBadgeText({ text: "", tabId })
        return
    }
    const urlIndicators = analyzeUrl(url)
    let pageIndicators: PhishingIndicator[] = []
    try {
        const res = await chrome.tabs.sendMessage(tabId, { type: "GET_PAGE_SIGNALS" })
        if (res?.indicators) pageIndicators = res.indicators
    } catch { /* content script not ready */ }

    const result = buildScanResult(url, [...urlIndicators, ...pageIndicators])
    tabResults.set(tabId, result)
    await setBadge(tabId, result.riskLevel)
    try { await chrome.storage.session.set({ [`scan_${tabId}`]: result }) } catch { }
    if (result.riskLevel === "dangerous") showDangerNotification(tabId, result).catch(() => { })
}

// ─── Context Menu ─────────────────────────────────────────────────────────────

if (chrome.contextMenus) {
    chrome.runtime.onInstalled.addListener(() => {
        chrome.contextMenus.create({
            id: "phishnet-check-link", title: "🛡️ Check link with PhishNet", contexts: ["link"]
        })
    })
    chrome.contextMenus.onClicked.addListener(async (info) => {
        if (info.menuItemId !== "phishnet-check-link" || !info.linkUrl) return
        const url = info.linkUrl
        const indicators = analyzeUrl(url)
        const result = buildScanResult(url, indicators)
        const emoji = result.riskLevel === "dangerous" ? "🔴" : result.riskLevel === "suspicious" ? "🟡" : "🟢"
        const reason = result.indicators[0]?.label ?? "No threats detected"
        chrome.notifications.create("phishnet-link-check", {
            type: "basic", iconUrl: chrome.runtime.getURL("assets/icon.png"),
            title: `${emoji} PhishNet Link Check`,
            message: `${result.riskLevel.toUpperCase()} (${result.riskScore}/100) — ${reason}`,
            contextMessage: url.substring(0, 80)
        })
    })
}

// ─── Tab Events ───────────────────────────────────────────────────────────────

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === "complete" && tab.url) {
        // Clear stale gmail result when navigating away from email
        if (!tab.url.includes("mail.google.com")) gmailResults.delete(tabId)
        scanTab(tabId, tab.url).catch(() => { })
    }
})

chrome.tabs.onRemoved.addListener((tabId) => {
    tabResults.delete(tabId)
    gmailResults.delete(tabId)
    chrome.storage.session.remove(`scan_${tabId}`).catch(() => { })
})

// ─── Message Handler ──────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

    if (message.type === "GET_SCAN_RESULT") {
        const tabId = message.tabId as number
        const cached = tabResults.get(tabId)
        if (cached) { sendResponse({ result: cached }); return }
        chrome.tabs.get(tabId, (tab) => {
            if (chrome.runtime.lastError || !tab.url) { sendResponse({ result: null }); return }
            scanTab(tabId, tab.url).then(() => sendResponse({ result: tabResults.get(tabId) ?? null })).catch(() => sendResponse({ result: null }))
        })
        return true
    }

    if (message.type === "RESCAN") {
        const tabId = message.tabId as number
        chrome.tabs.get(tabId, (tab) => {
            if (chrome.runtime.lastError || !tab.url) { sendResponse({ result: null }); return }
            scanTab(tabId, tab.url).then(() => sendResponse({ result: tabResults.get(tabId) ?? null })).catch(() => sendResponse({ result: null }))
        })
        return true
    }

    // Gmail scanner sends full result
    if (message.type === "GMAIL_SCAN_RESULT") {
        const tabId = sender.tab?.id
        if (tabId) {
            gmailResults.set(tabId, message.result as EmailScanResult)
            if (message.result.riskLevel !== "safe") {
                showGmailNotification(message.result as EmailScanResult).catch(() => { })
            }
        }
        sendResponse({ ok: true })
        return
    }

    // Popup requests Gmail result
    if (message.type === "GET_GMAIL_RESULT") {
        const tabId = message.tabId as number
        sendResponse({ result: gmailResults.get(tabId) ?? null })
        return
    }
})

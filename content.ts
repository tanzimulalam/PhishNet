// content.ts — PhishNet Content Script
// Injected into every web page to scan DOM for phishing signals

import {
    analyzePageSignals,
    getPhishingKeywords,
    type PhishingIndicator
} from "./lib/phishingDetector"

function scanPage(): PhishingIndicator[] {
    const pageUrl = window.location.href
    const bodyText = document.body?.innerText?.toLowerCase() ?? ""
    const keywords = getPhishingKeywords()

    // 1. Password fields
    const passwordFields = document.querySelectorAll('input[type="password"]')
    const hasPasswordField = passwordFields.length > 0

    // 2. Login forms (forms containing password fields)
    const allForms = Array.from(document.querySelectorAll("form"))
    const loginForms = allForms.filter(form => form.querySelector('input[type="password"]'))
    const hasLoginForm = loginForms.length > 0

    // 3. External form action (form that posts to a different origin)
    let externalFormAction = false
    for (const form of allForms) {
        const action = form.getAttribute("action")
        if (action) {
            try {
                const actionUrl = new URL(action, window.location.href)
                if (actionUrl.hostname !== window.location.hostname) {
                    externalFormAction = true
                    break
                }
            } catch {
                /* ignore malformed action URLs */
            }
        }
    }

    // 4. Hidden forms
    const hiddenForms = allForms.filter(form => {
        const style = window.getComputedStyle(form)
        return style.display === "none" || style.visibility === "hidden" || style.opacity === "0"
    }).length

    // 5. Suspicious keywords in page text
    const suspiciousKeywordsFound = keywords.filter(kw => bodyText.includes(kw.toLowerCase()))

    // 6. Mismatched links (anchor text looks like a URL but href is different)
    const allLinks = Array.from(document.querySelectorAll("a[href]"))
    let mismatchedLinks = 0
    for (const link of allLinks) {
        const href = (link as HTMLAnchorElement).href
        const text = (link as HTMLAnchorElement).innerText?.trim()
        if (text && /^https?:\/\//i.test(text)) {
            try {
                const textHost = new URL(text).hostname
                const hrefHost = new URL(href).hostname
                if (textHost !== hrefHost) mismatchedLinks++
            } catch {
                /* ignore */
            }
        }
    }

    return analyzePageSignals(
        {
            hasPasswordField,
            hasLoginForm,
            suspiciousKeywordsFound,
            mismatchedLinks,
            hiddenForms,
            externalFormAction
        },
        pageUrl
    )
}

// ─── Send signals to background on page load ─────────────────────────────────

function reportToBackground() {
    try {
        const indicators = scanPage()
        if (indicators.length > 0) {
            chrome.runtime.sendMessage({
                type: "PAGE_SIGNALS_READY",
                indicators
            })
        }
    } catch {
        /* extension may be reloading */
    }
}

// Run after DOM is ready
if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", reportToBackground)
} else {
    reportToBackground()
}

// ─── Respond to background / popup requests ───────────────────────────────────

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message.type === "GET_PAGE_SIGNALS") {
        try {
            const indicators = scanPage()
            sendResponse({ indicators })
        } catch (err) {
            sendResponse({ indicators: [] })
        }
        return true
    }
})

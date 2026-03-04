# 🛡️ PhishNet — AI-Powered Phishing Detection Chrome Extension

PhishNet is a Chrome browser extension that combines **local heuristic analysis**, **VirusTotal threat intelligence**, and **Google Gemini AI** to detect phishing websites and scam emails in real time. It scans every page you visit and every email you open in Gmail — providing instant, actionable risk assessments right in your browser.

---

## 📦 Installation & Setup

### Prerequisites

- **Node.js** v18 or later — [Download](https://nodejs.org/)
- **npm** (comes with Node.js)
- **Google Chrome** browser

### 1. Install Dependencies

Open a terminal in the project root and run:

```bash
npm install
```

This installs all required packages including Plasmo, React, TypeScript, and Chrome type definitions.

### 2. Build the Extension

For a **production build**:

```bash
npm run build
```

This creates the compiled extension in the `build/chrome-mv3-prod` folder.

For **development mode** (auto-reloads on code changes):

```bash
npm run dev
```

This creates a development build in `build/chrome-mv3-dev` and watches for file changes.

### 3. Load into Chrome

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable **Developer mode** (toggle in the top-right corner)
3. Click **"Load unpacked"**
4. Select the build folder:
   - Production: `build/chrome-mv3-prod`
   - Development: `build/chrome-mv3-dev`
5. The PhishNet icon (🛡️) will appear in your Chrome toolbar
6. **Pin it** by clicking the puzzle-piece icon in the toolbar → Pin

### 4. Configure API Keys

Click the PhishNet icon → ⚙️ Settings gear icon → Fill in:

| Setting | Required? | Purpose |
|---------|-----------|---------|
| **VirusTotal API Key** | Recommended | Threat intelligence from 90+ antivirus engines |
| **Gemini API Key** | Recommended | AI-powered analysis and chat |
| **AI Provider** | Optional | Choose between Gemini (default) or OpenAI |
| **Gmail Scanning** | Optional | Toggle email scanning on/off |

- Get a free VirusTotal API key at [virustotal.com](https://www.virustotal.com/gui/join-us)
- Get a free Gemini API key at [aistudio.google.com](https://aistudio.google.com/apikey)

---

## 🚀 Features

### 🔍 Instant URL Scanning
Every webpage you visit is automatically analyzed using **15+ local heuristics** — no API calls needed for the initial scan. Checks include:
- Suspicious TLDs (`.tk`, `.ml`, `.xyz`, etc.)
- IP-based URLs and excessive subdomains
- URL length anomalies and encoded characters
- Login forms with external form actions
- Missing HTTPS, data URIs, and homoglyph attacks

### 🧪 Deep Scan (VirusTotal + AI)
Click **"Deep Scan"** for a comprehensive multi-stage analysis:
1. **VirusTotal URL Lookup** — checks against 90+ antivirus engines
2. **VirusTotal Domain Lookup** — domain reputation, registrar, creation date
3. **DNS Resolution + IP Lookup** — resolves the domain, checks if the server IP is flagged
4. **AI Analysis** — sends all evidence to Gemini for an expert-level verdict

### 📊 Risk Score with Smart Merging
The risk gauge at the top dynamically updates after deep scan:
- Combines local heuristics, VirusTotal flags, and AI verdict
- Uses the **most severe finding** as the final risk level
- Includes a post-AI safety net: if VirusTotal says a site is clean (0 malicious engines, 50+ harmless) but AI hallucinated a danger, the verdict is automatically corrected

### 📧 Gmail Email Scanning
When you open an email in Gmail, PhishNet automatically:
- Extracts sender, subject, body text, and all embedded links
- Runs **11 heuristic checks**: sender spoofing, display-name mismatch, phishing keywords, urgency language, suspicious link TLDs, URL shorteners, and more
- Shows a **floating indicator panel** in the bottom-right:
  - ✅ Green = Safe (auto-dismisses after 4 seconds)
  - ⚠️ Yellow = Suspicious (persists with indicator details)
  - 🚨 Red = Dangerous (persists with full threat breakdown)

### 💬 AI Chat
Built-in chat tab powered by Gemini or OpenAI:
- Ask questions about the current page's security
- Get explanations of specific threats in plain English
- Context-aware: the AI knows the current URL and scan results

### 🗺️ Intel Tab
A dedicated intelligence dashboard with:
- **Server Location Map** — Real OpenStreetMap tiles showing where the server is hosted, with precise geolocation via ipinfo.io and a pulsing red crosshair marker
- **Threat DNA Fingerprint** — A unique barcode-style visualization of the threat pattern, with an **"Explain by AI"** button that calls Gemini to explain what the pattern means
- **Threat Profile Card** — Six animated progress bars showing threat levels across URL, Page Content, VirusTotal, Domain Health, Network Trust, and AI Confidence
- **Security Report Generator** — Creates a rich, printable HTML report with all findings, embedded map, VirusTotal data table, and AI analysis

### ⚙️ Settings & Customization
Full settings page with:
- API key management (VirusTotal, Gemini, OpenAI)
- AI model selection (Gemini 2.0 Flash, GPT-4o-mini, etc.)
- Gmail scanning toggle
- Notification preferences

---

## 🛠️ Technology Stack

### Core Framework

| Technology | Version | Purpose |
|------------|---------|---------|
| **[Plasmo](https://www.plasmo.com/)** | 0.90.5 | Chrome extension framework — handles manifest generation, content scripts, background workers, and hot-reload during development. Eliminates the boilerplate of raw Chrome extension development. |
| **[React](https://react.dev/)** | 18.2.0 | Component-based UI for the popup, settings page, and all interactive elements. Enables reactive state management for real-time scan result updates. |
| **[TypeScript](https://www.typescriptlang.org/)** | 5.3.3 | Static typing across the entire codebase — catches bugs at compile time, provides better IDE support, and makes the code self-documenting. |

### External APIs

| Service | How It's Used |
|---------|---------------|
| **[VirusTotal API](https://www.virustotal.com/)** | URL reputation check (90+ engines), domain WHOIS data (registrar, creation date, reputation score), IP geolocation and malicious flagging. Provides the hard data that grounds the AI analysis. |
| **[Google Gemini API](https://ai.google.dev/)** | AI-powered threat analysis, chat, and DNA fingerprint explanation. Acts as the "expert brain" that synthesizes all evidence into a human-readable verdict. |
| **[OpenAI API](https://openai.com/)** | Alternative AI provider (GPT-4o-mini) — users can choose their preferred AI backend. |
| **[ipinfo.io](https://ipinfo.io/)** | Precise IP geolocation (latitude/longitude + city) for the server location map. Free tier, no API key required. |
| **[Google DNS-over-HTTPS](https://dns.google/)** | Resolves domain names to IP addresses for the IP lookup stage of deep scan — avoids CORS issues with traditional DNS. |
| **[OpenStreetMap](https://www.openstreetmap.org/)** | Map tile images for the server location visualization. Free, open-source map data. |

### Chrome APIs Used

| API | Purpose |
|-----|---------|
| `chrome.tabs` | Get active tab URL and inject content scripts |
| `chrome.storage` | Persist settings (API keys, preferences) and chat history |
| `chrome.scripting` | Execute page analysis scripts in the active tab |
| `chrome.contextMenus` | Right-click menu integration |
| `chrome.notifications` | System notifications for threat alerts |

---

## 🤖 How Gemini AI Makes PhishNet Better

### 1. Expert-Level Threat Analysis

Local heuristics can detect surface-level red flags (suspicious TLD, long URL), but they lack **contextual understanding**. Gemini receives ALL evidence — VirusTotal results, local indicators, domain metadata, email context — and acts as a cybersecurity expert that weighs everything together.

For example, a login form on `paypal.com` is normal. A login form on `paypa1-secure.xyz` is phishing. **Only an AI can make this contextual distinction** — pure heuristics would flag both equally.

### 2. Intelligent Chat Assistant

The chat tab turns PhishNet from a passive scanner into an **interactive security advisor**. Users can ask:
- *"Is this email safe to click?"*
- *"What does 'domain reputation -78' mean?"*
- *"Should I enter my credit card on this site?"*

Gemini responds with context-aware, plain-English explanations — making cybersecurity accessible to non-technical users.

### 3. Threat DNA Explanation

The DNA fingerprint is a visual pattern, but it means nothing without interpretation. The **"Explain by AI"** button calls Gemini to analyze the specific indicators and explain:
- What type of attack this resembles
- Why the fingerprint pattern looks the way it does
- What the user should do

### 4. Accuracy Safeguards

The AI prompt is carefully calibrated with **8 explicit rules** that prevent false positives:
- "If VirusTotal shows 0 malicious engines, the verdict MUST be safe"
- "Login forms on established domains are completely normal"
- A **post-AI override** system catches any remaining hallucinations by cross-checking the AI verdict against hard VirusTotal data

### 5. Report Generation Intelligence

The generated HTML security report includes the AI's full analysis — verdict, confidence percentage, primary reason, and detailed explanation — alongside all other data, creating a **comprehensive, shareable document** that IT teams can use for incident response.

---

## 📁 Project Structure

```
phish-net/
├── popup.tsx                  # Main extension popup (Scan, Chat, Intel tabs)
├── popup.css                  # All popup styles (1300+ lines)
├── options.tsx                # Settings page
├── options.css                # Settings page styles
├── background.ts              # Service worker (context menus, notifications, messaging)
├── content.ts                 # Content script injected into all pages
├── contents/
│   └── gmail.tsx              # Gmail content script (email scanning + floating panel)
├── components/
│   └── InsightsTab.tsx        # Intel tab components (WorldMap, DnaFingerprint, ReportCard)
├── lib/
│   ├── phishingDetector.ts    # Local URL heuristic analysis (15+ checks)
│   ├── deepScan.ts            # Deep scan orchestrator (VT + AI + prompt builder)
│   ├── chat.ts                # AI chat integration (Gemini + OpenAI)
│   └── storage.ts             # Chrome storage wrapper for settings
├── assets/
│   └── icon.png               # Extension icon
├── package.json               # Dependencies, scripts, and manifest config
└── tsconfig.json              # TypeScript configuration
```

---

## 📝 Additional Notes

### Privacy & Security
- **All API keys are stored locally** in Chrome's `chrome.storage.sync` — never sent to any third-party server except the respective API endpoints
- **No user data is collected** — scan results are stored in session storage and cleared when Chrome closes
- **All network requests** go directly to official API endpoints (VirusTotal, Google AI, ipinfo.io) — no middleman servers

### Performance
- **Initial scan is instant** (< 50ms) — runs entirely locally using URL pattern matching
- **Deep scan** takes 3-8 seconds depending on API response times
- **Gmail scanning** runs on a MutationObserver, triggering only when you open a new email
- The extension popup is lightweight at ~33KB CSS + ~31KB TSX

### Browser Compatibility
- Built for **Chrome (Manifest V3)** — the latest extension platform
- Compatible with all Chromium-based browsers (Edge, Brave, Arc, Opera)
- Requires Chrome 88+ for Manifest V3 support

### Rate Limits
- **VirusTotal free tier**: 4 requests/minute, 500 requests/day
- **Gemini free tier**: 15 requests/minute, 1500 requests/day
- **ipinfo.io free tier**: 50,000 requests/month
- PhishNet gracefully handles rate limits and API errors with fallback behavior

---

## 📜 License

This project is created by [fahim5898@gmail.com](mailto:fahim5898@gmail.com).

---

*Built with ❤️ using React, TypeScript, Plasmo, and Google Gemini AI.*

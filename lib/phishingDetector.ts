// lib/phishingDetector.ts — Core PhishNet detection engine

export interface PhishingIndicator {
  id: string
  label: string
  description: string
  severity: "low" | "medium" | "high"
  score: number
}

export interface ScanResult {
  url: string
  riskScore: number // 0–100
  riskLevel: "safe" | "suspicious" | "dangerous"
  indicators: PhishingIndicator[]
  scannedAt: number
}

// ─── URL-based Heuristics ────────────────────────────────────────────────────

const SUSPICIOUS_TLDS = [
  ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click",
  ".link", ".info", ".online", ".site", ".tech", ".pw", ".cc"
]

const LOOKALIKE_BRANDS = [
  "paypa1", "paypai", "g00gle", "googIe", "micosoft", "microsofft",
  "arnazon", "amazzon", "faceb00k", "facebok", "netfl1x", "netfIix",
  "appleid", "apple-id", "icloud-", "chase-", "wellsfargo-", "bankofamerica-",
  "signin-", "login-", "secure-", "verify-", "account-", "update-"
]

const PHISHING_KEYWORDS = [
  "verify your account", "confirm your identity", "your account has been suspended",
  "unusual activity", "click here to restore", "update your payment",
  "your account will be closed", "immediate action required",
  "enter your credentials", "validate your email", "unlock your account",
  "limited time offer", "you have been selected", "congratulations you won",
  "your apple id", "your paypal account", "your bank account",
  "social security", "credit card number", "password expired"
]

export function analyzeUrl(urlString: string): PhishingIndicator[] {
  const indicators: PhishingIndicator[] = []

  let url: URL
  try {
    url = new URL(urlString)
  } catch {
    return indicators
  }

  const hostname = url.hostname.toLowerCase()
  const fullUrl = urlString.toLowerCase()

  // 1. IP address in hostname
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    indicators.push({
      id: "ip-url",
      label: "IP Address URL",
      description: "The URL uses a raw IP address instead of a domain name — a common phishing tactic.",
      severity: "high",
      score: 30
    })
  }

  // 2. Suspicious TLD
  const suspiciousTld = SUSPICIOUS_TLDS.find(tld => hostname.endsWith(tld))
  if (suspiciousTld) {
    indicators.push({
      id: "suspicious-tld",
      label: `Suspicious TLD (${suspiciousTld})`,
      description: "This domain uses a TLD commonly associated with free phishing domains.",
      severity: "medium",
      score: 20
    })
  }

  // 3. Lookalike brand in hostname
  const lookalike = LOOKALIKE_BRANDS.find(brand => hostname.includes(brand))
  if (lookalike) {
    indicators.push({
      id: "lookalike-domain",
      label: "Lookalike Domain",
      description: `The domain appears to impersonate a well-known brand (contains "${lookalike}").`,
      severity: "high",
      score: 35
    })
  }

  // 4. Excessive subdomains (more than 3 levels)
  const subdomainCount = hostname.split(".").length - 2
  if (subdomainCount > 2) {
    indicators.push({
      id: "excessive-subdomains",
      label: "Excessive Subdomains",
      description: `The URL has ${subdomainCount} subdomains — phishers often use this to hide the real domain.`,
      severity: "medium",
      score: 15
    })
  }

  // 5. Very long URL
  if (urlString.length > 100) {
    indicators.push({
      id: "long-url",
      label: "Unusually Long URL",
      description: `The URL is ${urlString.length} characters long — long URLs are often used to obscure the real destination.`,
      severity: "low",
      score: 10
    })
  }

  // 6. HTTP (not HTTPS) on a login-looking page
  if (url.protocol === "http:" && (fullUrl.includes("login") || fullUrl.includes("signin") || fullUrl.includes("account"))) {
    indicators.push({
      id: "http-login",
      label: "Unencrypted Login Page (HTTP)",
      description: "This page uses HTTP (not HTTPS) but appears to be a login page — your credentials would be sent in plaintext.",
      severity: "high",
      score: 30
    })
  }

  // 7. @ symbol in URL (common obfuscation trick)
  if (url.href.includes("@")) {
    indicators.push({
      id: "at-symbol",
      label: "@ Symbol in URL",
      description: "The URL contains an @ symbol, which can be used to disguise the real destination.",
      severity: "high",
      score: 25
    })
  }

  // 8. Redirect parameter
  if (fullUrl.includes("redirect=") || fullUrl.includes("url=") || fullUrl.includes("next=http")) {
    indicators.push({
      id: "redirect-param",
      label: "Redirect Parameter",
      description: "This URL contains a redirect parameter, which may be used to send you to a malicious site after a fake login.",
      severity: "medium",
      score: 15
    })
  }

  return indicators
}

// ─── Page Content Heuristics ─────────────────────────────────────────────────

export interface PageSignals {
  hasPasswordField: boolean
  hasLoginForm: boolean
  suspiciousKeywordsFound: string[]
  mismatchedLinks: number
  hiddenForms: number
  externalFormAction: boolean
}

export function analyzePageSignals(signals: PageSignals, pageUrl: string): PhishingIndicator[] {
  const indicators: PhishingIndicator[] = []

  let pageHost = ""
  try {
    pageHost = new URL(pageUrl).hostname
  } catch {
    /* ignore */
  }

  // Login form detected
  if (signals.hasLoginForm && signals.hasPasswordField) {
    indicators.push({
      id: "login-form",
      label: "Login Form Detected",
      description: "This page contains a form requesting credentials (username/password).",
      severity: "low",
      score: 8
    })
  }

  // External form action (submits to a different domain)
  if (signals.externalFormAction) {
    indicators.push({
      id: "external-form",
      label: "Form Submits to External Domain",
      description: "A form on this page sends data to a different domain — a key sign of credential harvesting.",
      severity: "high",
      score: 35
    })
  }

  // Hidden forms
  if (signals.hiddenForms > 0) {
    indicators.push({
      id: "hidden-forms",
      label: "Hidden Forms Detected",
      description: `${signals.hiddenForms} hidden form(s) found on the page — may be used to silently capture data.`,
      severity: "medium",
      score: 20
    })
  }

  // Suspicious keywords
  if (signals.suspiciousKeywordsFound.length > 0) {
    indicators.push({
      id: "suspicious-keywords",
      label: "Suspicious Phishing Language",
      description: `Found ${signals.suspiciousKeywordsFound.length} phishing keyword(s): "${signals.suspiciousKeywordsFound.slice(0, 2).join('", "')}${signals.suspiciousKeywordsFound.length > 2 ? "..." : ""}"`,
      severity: signals.suspiciousKeywordsFound.length > 2 ? "high" : "medium",
      score: Math.min(signals.suspiciousKeywordsFound.length * 8, 30)
    })
  }

  // Mismatched links
  if (signals.mismatchedLinks > 0) {
    indicators.push({
      id: "mismatched-links",
      label: "Misleading Links",
      description: `${signals.mismatchedLinks} link(s) display one URL but actually point to a different destination.`,
      severity: "high",
      score: signals.mismatchedLinks * 10
    })
  }

  return indicators
}

export function getPhishingKeywords(): string[] {
  return PHISHING_KEYWORDS
}

// ─── Score Calculator ────────────────────────────────────────────────────────

export function calculateRiskScore(indicators: PhishingIndicator[]): number {
  const raw = indicators.reduce((sum, ind) => sum + ind.score, 0)
  return Math.min(raw, 100)
}

export function getRiskLevel(score: number): "safe" | "suspicious" | "dangerous" {
  if (score >= 60) return "dangerous"
  if (score >= 25) return "suspicious"
  return "safe"
}

export function buildScanResult(url: string, indicators: PhishingIndicator[]): ScanResult {
  const riskScore = calculateRiskScore(indicators)
  return {
    url,
    riskScore,
    riskLevel: getRiskLevel(riskScore),
    indicators,
    scannedAt: Date.now()
  }
}

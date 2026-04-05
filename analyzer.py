"""
Phishing Detection Engine
Analyzes URLs and email headers for malicious indicators.
"""

import re
import urllib.parse
import socket
import ssl
import datetime
from dataclasses import dataclass, field
from typing import Optional
import ipaddress

# ── Popular brands commonly spoofed ──────────────────────────────────────────
SPOOFED_BRANDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix", "facebook",
    "instagram", "twitter", "linkedin", "chase", "wellsfargo", "bankofamerica",
    "citibank", "irs", "fedex", "ups", "usps", "dhl", "dropbox", "docusign",
    "zoom", "outlook", "office365", "icloud", "steam", "coinbase", "binance",
    "robinhood", "venmo", "cashapp", "zelle",
]

# ── Suspicious TLDs often abused in phishing ─────────────────────────────────
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",  # Free Freenom domains
    ".xyz", ".top", ".club", ".online", ".site", ".website",
    ".info", ".biz", ".work", ".live", ".click", ".link",
    ".ru", ".cn", ".pw", ".cc",
}

# ── Legitimate domains for typosquatting comparison ──────────────────────────
LEGITIMATE_DOMAINS = {
    "paypal.com", "apple.com", "microsoft.com", "google.com", "amazon.com",
    "netflix.com", "facebook.com", "instagram.com", "twitter.com", "linkedin.com",
    "chase.com", "wellsfargo.com", "bankofamerica.com", "irs.gov", "fedex.com",
    "ups.com", "usps.com", "dropbox.com", "zoom.us", "outlook.com",
}

# ── Phishing keywords ─────────────────────────────────────────────────────────
PHISHING_KEYWORDS = [
    "verify", "account", "update", "confirm", "secure", "login", "signin",
    "password", "credential", "suspend", "urgent", "alert", "billing",
    "payment", "invoice", "refund", "reward", "winner", "click", "free",
    "limited", "expire", "cancel", "unauthorized", "unusual", "activity",
]


@dataclass
class Indicator:
    name: str
    severity: str          # "critical", "high", "medium", "low", "safe"
    description: str
    points: int            # positive = bad, negative = good


@dataclass
class AnalysisResult:
    target: str
    analysis_type: str     # "url" or "email"
    risk_score: int        # 0–100
    risk_level: str        # "Safe", "Low", "Medium", "High", "Critical"
    indicators: list = field(default_factory=list)
    summary: str = ""
    recommendations: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


# ─────────────────────────────────────────────────────────────────────────────
#  URL ANALYZER
# ─────────────────────────────────────────────────────────────────────────────


def _detect_scheme(url: str) -> str:
    """
    Try connecting on port 443 (HTTPS) first, then port 80 (HTTP).
    Returns the URL with the correct scheme prepended.
    """
    hostname = url.split("/")[0].split("?")[0].split(":")[0]
    # Try HTTPS first
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname):
                return "https://" + url
    except Exception:
        pass
    # Fall back to HTTP
    try:
        with socket.create_connection((hostname, 80), timeout=4):
            return "http://" + url
    except Exception:
        pass
    # Can't reach it — default to https for analysis purposes
    return "https://" + url


def analyze_url(url: str) -> AnalysisResult:
    """Full phishing analysis of a URL."""
    indicators = []
    metadata = {}

    # Normalize — auto-detect scheme if missing
    if not url.startswith(("http://", "https://")):
        url = _detect_scheme(url)

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return AnalysisResult(
            target=url, analysis_type="url", risk_score=50,
            risk_level="Unknown", summary="Could not parse URL.",
        )

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    full_url = url.lower()
    scheme = parsed.scheme
    query = parsed.query or ""
    domain_parts = hostname.split(".")
    tld = "." + domain_parts[-1] if domain_parts else ""
    registered_domain = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else hostname

    metadata["hostname"] = hostname
    metadata["scheme"] = scheme
    metadata["registered_domain"] = registered_domain
    metadata["tld"] = tld
    metadata["path"] = path

    # ── 1. HTTPS check ───────────────────────────────────────────────────────
    if scheme == "http":
        indicators.append(Indicator("No HTTPS", "high",
            "Site uses unencrypted HTTP — legitimate services always use HTTPS.", 20))
    else:
        indicators.append(Indicator("HTTPS Present", "safe",
            "Site uses encrypted HTTPS connection.", -5))

    # ── 2. IP address as hostname ─────────────────────────────────────────────
    try:
        ipaddress.ip_address(hostname)
        indicators.append(Indicator("IP Address as Host", "critical",
            f"URL uses a raw IP address ({hostname}) instead of a domain name — "
            "a strong phishing indicator.", 35))
    except ValueError:
        pass

    # ── 3. Suspicious TLD ─────────────────────────────────────────────────────
    if tld in SUSPICIOUS_TLDS:
        indicators.append(Indicator("Suspicious TLD", "high",
            f"Top-level domain '{tld}' is commonly used in phishing campaigns.", 20))

    # ── 4. Excessive subdomains ───────────────────────────────────────────────
    subdomain_count = len(domain_parts) - 2
    if subdomain_count >= 3:
        indicators.append(Indicator("Excessive Subdomains", "high",
            f"URL has {subdomain_count} subdomains — often used to hide the real domain "
            f"(e.g. paypal.com.verify.{registered_domain}).", 20))
    elif subdomain_count == 2:
        indicators.append(Indicator("Multiple Subdomains", "medium",
            f"URL has {subdomain_count} subdomains — slightly unusual.", 10))

    # ── 5. Brand spoofing ─────────────────────────────────────────────────────
    spoofed = []
    for brand in SPOOFED_BRANDS:
        if brand in hostname and registered_domain not in LEGITIMATE_DOMAINS:
            spoofed.append(brand)
    if spoofed:
        indicators.append(Indicator("Brand Spoofing", "critical",
            f"URL contains brand name(s) '{', '.join(spoofed)}' but does NOT belong to "
            f"their official domain. Classic phishing technique.", 40))

    # ── 6. Typosquatting ─────────────────────────────────────────────────────
    for legit in LEGITIMATE_DOMAINS:
        legit_base = legit.split(".")[0]
        if legit_base in registered_domain and registered_domain != legit:
            distance = _levenshtein(registered_domain, legit)
            if 1 <= distance <= 3:
                indicators.append(Indicator("Typosquatting", "critical",
                    f"'{registered_domain}' looks very similar to '{legit}' "
                    f"(edit distance: {distance}). Likely a spoofed domain.", 35))
                break

    # ── 7. URL length ─────────────────────────────────────────────────────────
    url_len = len(url)
    metadata["url_length"] = url_len
    if url_len > 200:
        indicators.append(Indicator("Very Long URL", "high",
            f"URL is {url_len} characters — attackers use long URLs to hide malicious destinations.", 15))
    elif url_len > 100:
        indicators.append(Indicator("Long URL", "medium",
            f"URL is {url_len} characters — somewhat suspicious.", 8))

    # ── 8. Phishing keywords in URL ───────────────────────────────────────────
    found_keywords = [kw for kw in PHISHING_KEYWORDS if kw in full_url]
    if len(found_keywords) >= 3:
        indicators.append(Indicator("Multiple Phishing Keywords", "high",
            f"URL contains {len(found_keywords)} phishing-related keywords: "
            f"{', '.join(found_keywords[:5])}.", 20))
    elif len(found_keywords) >= 1:
        indicators.append(Indicator("Phishing Keywords", "medium",
            f"URL contains suspicious keywords: {', '.join(found_keywords)}.", 8))

    # ── 9. Suspicious characters ──────────────────────────────────────────────
    if "@" in url:
        indicators.append(Indicator("@ Symbol in URL", "critical",
            "The '@' symbol in a URL is used to trick browsers — everything before "
            "it is ignored, redirecting to a different host.", 35))

    if url.count("-") > 4:
        indicators.append(Indicator("Excessive Hyphens", "medium",
            f"Domain contains {url.count('-')} hyphens — often used in fake domains "
            "like 'secure-paypal-login-verify.com'.", 10))

    # ── 10. URL shortener ─────────────────────────────────────────────────────
    shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
                  "short.io", "rebrand.ly", "is.gd", "buff.ly"]
    if any(s in hostname for s in shorteners):
        indicators.append(Indicator("URL Shortener", "medium",
            "URL shorteners hide the real destination — common in phishing links.", 15))

    # ── 11. Hex / encoded characters ─────────────────────────────────────────
    if "%" in url and url.count("%") > 5:
        indicators.append(Indicator("URL Encoding Abuse", "high",
            "Excessive URL encoding can be used to obscure malicious content "
            "and evade filters.", 15))

    # ── 12. Numeric domain ───────────────────────────────────────────────────
    if re.match(r"^\d+\.\d+\.\d+", registered_domain):
        indicators.append(Indicator("Numeric Domain", "high",
            "Domain consists mainly of numbers — unusual for legitimate websites.", 15))

    # ── 13. Double slash redirect ────────────────────────────────────────────
    if "//" in path:
        indicators.append(Indicator("Double Slash Redirect", "medium",
            "Double slashes in the path can indicate redirect manipulation.", 10))

    # ── 14. Query string with credentials ────────────────────────────────────
    sensitive = ["password", "passwd", "token", "api_key", "secret", "auth", "session"]
    found_sensitive = [s for s in sensitive if s in query.lower()]
    if found_sensitive:
        indicators.append(Indicator("Sensitive Data in Query", "high",
            f"URL query string contains: {', '.join(found_sensitive)} — "
            "credentials should never appear in URLs.", 20))

    # ── 15. SSL cert check (basic) ───────────────────────────────────────────
    if scheme == "https":
        cert_result = _check_ssl(hostname)
        if cert_result:
            indicators.append(cert_result)

    # ── Compute score ─────────────────────────────────────────────────────────
    raw_score = sum(i.points for i in indicators)
    risk_score = max(0, min(100, raw_score))
    risk_level, recommendations = _score_to_level(risk_score, "url")

    summary = _build_url_summary(hostname, risk_level, indicators)

    return AnalysisResult(
        target=url,
        analysis_type="url",
        risk_score=risk_score,
        risk_level=risk_level,
        indicators=indicators,
        summary=summary,
        recommendations=recommendations,
        metadata=metadata,
    )


# ─────────────────────────────────────────────────────────────────────────────
#  EMAIL HEADER ANALYZER
# ─────────────────────────────────────────────────────────────────────────────

def analyze_email(headers: str) -> AnalysisResult:
    """Analyze raw email headers for phishing/spoofing indicators."""
    indicators = []
    metadata = {}
    headers_lower = headers.lower()

    # Parse key headers
    from_addr = _extract_header(headers, "From")
    reply_to = _extract_header(headers, "Reply-To")
    return_path = _extract_header(headers, "Return-Path")
    received_spf = _extract_header(headers, "Received-SPF")
    dkim_sig = _extract_header(headers, "DKIM-Signature")
    dmarc = _extract_header(headers, "Authentication-Results")
    subject = _extract_header(headers, "Subject")
    x_mailer = _extract_header(headers, "X-Mailer")
    message_id = _extract_header(headers, "Message-ID")

    metadata["from"] = from_addr
    metadata["reply_to"] = reply_to
    metadata["subject"] = subject
    metadata["return_path"] = return_path

    # ── 1. SPF check ─────────────────────────────────────────────────────────
    if received_spf:
        if "fail" in received_spf.lower():
            indicators.append(Indicator("SPF Fail", "critical",
                "SPF check FAILED — the sending server is NOT authorized to send "
                "email for this domain. Strong spoofing indicator.", 40))
        elif "softfail" in received_spf.lower():
            indicators.append(Indicator("SPF Softfail", "high",
                "SPF softfail — the server is not fully authorized. Suspicious.", 20))
        elif "pass" in received_spf.lower():
            indicators.append(Indicator("SPF Pass", "safe",
                "SPF check passed — sending server is authorized.", -10))
        elif "none" in received_spf.lower():
            indicators.append(Indicator("No SPF Record", "medium",
                "Domain has no SPF record — cannot verify sender authenticity.", 10))
    else:
        indicators.append(Indicator("SPF Header Missing", "medium",
            "No SPF result found in headers — cannot verify sender.", 10))

    # ── 2. DKIM check ────────────────────────────────────────────────────────
    if dkim_sig:
        indicators.append(Indicator("DKIM Signature Present", "safe",
            "Email has a DKIM signature — helps verify it wasn't tampered with.", -8))
    else:
        indicators.append(Indicator("No DKIM Signature", "medium",
            "Email lacks a DKIM signature — cannot verify message integrity.", 12))

    # ── 3. DMARC check ───────────────────────────────────────────────────────
    if dmarc:
        if "dmarc=pass" in dmarc.lower():
            indicators.append(Indicator("DMARC Pass", "safe",
                "DMARC authentication passed.", -8))
        elif "dmarc=fail" in dmarc.lower():
            indicators.append(Indicator("DMARC Fail", "critical",
                "DMARC authentication FAILED — email likely spoofed.", 35))

    # ── 4. From / Reply-To mismatch ──────────────────────────────────────────
    if from_addr and reply_to:
        from_domain = _extract_domain(from_addr)
        reply_domain = _extract_domain(reply_to)
        if from_domain and reply_domain and from_domain != reply_domain:
            indicators.append(Indicator("From/Reply-To Mismatch", "critical",
                f"From domain ({from_domain}) differs from Reply-To domain ({reply_domain}). "
                "Replies will go to a different address than the sender — classic phishing.", 35))

    # ── 5. From / Return-Path mismatch ───────────────────────────────────────
    if from_addr and return_path:
        from_domain = _extract_domain(from_addr)
        rp_domain = _extract_domain(return_path)
        if from_domain and rp_domain and from_domain != rp_domain:
            indicators.append(Indicator("From/Return-Path Mismatch", "high",
                f"From domain ({from_domain}) differs from Return-Path ({rp_domain}). "
                "Indicates possible spoofing.", 20))

    # ── 6. Brand spoofing in From ────────────────────────────────────────────
    if from_addr:
        from_lower = from_addr.lower()
        from_domain = _extract_domain(from_addr) or ""
        for brand in SPOOFED_BRANDS:
            if brand in from_lower and brand + ".com" not in from_domain and brand + ".org" not in from_domain:
                indicators.append(Indicator("Brand Name in From Address", "high",
                    f"From address mentions '{brand}' but doesn't come from their "
                    f"official domain. Possible spoofing.", 25))
                break

    # ── 7. Phishing keywords in subject ──────────────────────────────────────
    if subject:
        subj_lower = subject.lower()
        urgent_words = ["urgent", "immediate", "action required", "account suspended",
                       "verify now", "unusual activity", "you won", "limited time",
                       "click here", "password expired", "security alert", "final notice"]
        found = [w for w in urgent_words if w in subj_lower]
        if len(found) >= 2:
            indicators.append(Indicator("Urgency/Manipulation in Subject", "high",
                f"Subject uses pressure tactics: '{', '.join(found)}'. "
                "Common in phishing emails.", 20))
        elif found:
            indicators.append(Indicator("Suspicious Subject Keywords", "medium",
                f"Subject contains: '{found[0]}'.", 10))

    # ── 8. Free email provider as sender ─────────────────────────────────────
    free_providers = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
                      "aol.com", "protonmail.com", "yandex.com", "mail.com"]
    if from_addr:
        from_domain = _extract_domain(from_addr) or ""
        if any(fp in from_domain for fp in free_providers):
            indicators.append(Indicator("Free Email Provider", "medium",
                f"Sent from a free email address ({from_domain}). "
                "Legitimate businesses use their own domains.", 10))

    # ── 9. Suspicious Message-ID ─────────────────────────────────────────────
    if message_id:
        if not re.search(r"@[\w.-]+\.\w+", message_id):
            indicators.append(Indicator("Malformed Message-ID", "medium",
                "Message-ID doesn't follow standard format — can indicate spam tools.", 10))

    # ── 10. Received hops analysis ───────────────────────────────────────────
    received_count = headers_lower.count("\nreceived:")
    metadata["received_hops"] = received_count
    if received_count > 8:
        indicators.append(Indicator("Excessive Routing Hops", "medium",
            f"Email passed through {received_count} servers — unusual, may indicate "
            "routing obfuscation.", 10))

    # ── 11. X-Mailer check ───────────────────────────────────────────────────
    if x_mailer:
        spam_mailers = ["phpmailer", "sendgrid", "mailchimp", "massmail", "bulk"]
        if any(sm in x_mailer.lower() for sm in spam_mailers):
            indicators.append(Indicator("Bulk Mail Tool Detected", "medium",
                f"X-Mailer reveals bulk sending tool: {x_mailer}.", 8))

    # ── Compute score ─────────────────────────────────────────────────────────
    raw_score = sum(i.points for i in indicators)
    risk_score = max(0, min(100, raw_score))
    risk_level, recommendations = _score_to_level(risk_score, "email")
    summary = _build_email_summary(from_addr, subject, risk_level, indicators)

    return AnalysisResult(
        target=from_addr or "Unknown Sender",
        analysis_type="email",
        risk_score=risk_score,
        risk_level=risk_level,
        indicators=indicators,
        summary=summary,
        recommendations=recommendations,
        metadata=metadata,
    )


# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _check_ssl(hostname: str) -> Optional[Indicator]:
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((hostname, 443), timeout=4),
                             server_hostname=hostname) as s:
            cert = s.getpeercert()
            exp_str = cert.get("notAfter", "")
            if exp_str:
                exp_date = datetime.datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
                days_left = (exp_date - datetime.datetime.utcnow()).days
                if days_left < 0:
                    return Indicator("SSL Certificate Expired", "critical",
                        f"SSL certificate expired {abs(days_left)} days ago.", 30)
                elif days_left < 30:
                    return Indicator("SSL Certificate Expiring Soon", "medium",
                        f"SSL certificate expires in {days_left} days.", 10)
    except Exception:
        pass
    return None


def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1,
                            prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


def _extract_header(headers: str, name: str) -> str:
    pattern = rf"^{re.escape(name)}:\s*(.+?)(?=\n\S|\Z)"
    match = re.search(pattern, headers, re.MULTILINE | re.IGNORECASE | re.DOTALL)
    return match.group(1).strip().replace("\n", " ").replace("\r", "") if match else ""


def _extract_domain(email_or_header: str) -> str:
    match = re.search(r"@([\w.-]+)", email_or_header)
    return match.group(1).lower() if match else ""


def _score_to_level(score: int, analysis_type: str):
    if score <= 10:
        level = "Safe"
        recs = ["This appears legitimate. Still exercise caution with any links or attachments."]
    elif score <= 30:
        level = "Low Risk"
        recs = [
            "Low risk but proceed with caution.",
            "Verify the sender or website through official channels before taking action.",
        ]
    elif score <= 55:
        level = "Medium Risk"
        recs = [
            "Multiple suspicious indicators detected.",
            "Do NOT enter credentials or personal information.",
            "Contact the organization directly via their official website or phone number.",
        ]
    elif score <= 75:
        level = "High Risk"
        recs = [
            "Strong phishing indicators present — treat this as malicious.",
            "Do NOT click any links or download attachments.",
            "Report to your IT/security team immediately.",
            "If you already clicked, change your passwords immediately.",
        ]
    else:
        level = "Critical"
        recs = [
            "LIKELY PHISHING — do not interact with this content.",
            "Do NOT enter any information.",
            "Report to: phishing@apwg.org (URLs) or spam@uce.gov (emails).",
            "If credentials were entered, change passwords immediately and enable MFA.",
            "Consider reporting to the impersonated brand's security team.",
        ]
    return level, recs


def _build_url_summary(hostname: str, risk_level: str, indicators: list) -> str:
    critical = [i for i in indicators if i.severity == "critical"]
    high = [i for i in indicators if i.severity == "high"]
    if critical:
        return (f"'{hostname}' shows {len(critical)} critical phishing indicator(s): "
                f"{critical[0].name}. Treat as malicious.")
    elif high:
        return (f"'{hostname}' shows {len(high)} high-severity indicator(s). "
                "Exercise extreme caution.")
    elif risk_level in ("Medium Risk",):
        return f"'{hostname}' has some suspicious characteristics. Verify before proceeding."
    else:
        return f"'{hostname}' appears relatively safe but always stay vigilant."


def _build_email_summary(from_addr: str, subject: str, risk_level: str, indicators: list) -> str:
    critical = [i for i in indicators if i.severity == "critical"]
    if critical:
        return (f"Email from '{from_addr}' failed critical authentication checks: "
                f"{critical[0].name}. Likely phishing.")
    elif risk_level in ("High Risk", "Critical"):
        return f"Email from '{from_addr}' shows strong phishing characteristics."
    else:
        return f"Email from '{from_addr}' — {risk_level.lower()} detected."

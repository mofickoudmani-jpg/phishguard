# 🛡️ PhishGuard — Phishing Detection & Analysis Engine

> A cybersecurity portfolio project by **Mofic Koudmani**  
> B.A.S. Cybersecurity & Ethical Hacking | Broward College | 2026

---

## Overview

PhishGuard is a Python-based phishing detection tool that analyzes **URLs** and **email headers** for malicious indicators using heuristic analysis and threat intelligence techniques.

Built to demonstrate practical cybersecurity skills including:
- Threat detection & indicator analysis
- Secure web application development
- Network & email security protocols (SPF, DKIM, DMARC)
- Python security tooling

---

## Features

### URL Analyzer
- ✅ HTTPS / HTTP detection
- ✅ IP address used as hostname (major phishing indicator)
- ✅ Suspicious TLD detection (`.tk`, `.xyz`, `.ru`, etc.)
- ✅ Brand spoofing detection (PayPal, Apple, Microsoft, etc.)
- ✅ Typosquatting via Levenshtein distance comparison
- ✅ Excessive subdomain analysis
- ✅ Phishing keyword scanning
- ✅ URL shortener detection
- ✅ URL encoding abuse detection
- ✅ Sensitive data in query strings
- ✅ SSL certificate validation
- ✅ Risk scoring (0–100) with severity levels

### Email Header Analyzer
- ✅ SPF record validation (Pass / Fail / Softfail / None)
- ✅ DKIM signature verification
- ✅ DMARC authentication results
- ✅ From / Reply-To mismatch detection
- ✅ From / Return-Path mismatch
- ✅ Brand spoofing in sender address
- ✅ Urgency/manipulation keywords in subject
- ✅ Free email provider as business sender
- ✅ Malformed Message-ID detection
- ✅ Bulk mail tool fingerprinting

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3, Flask |
| Analysis Engine | Custom heuristic engine (analyzer.py) |
| Frontend | HTML5, CSS3, Vanilla JS |
| Security Protocols | SPF, DKIM, DMARC, SSL/TLS |

---

## Installation & Running

### Requirements
- Python 3.8+
- pip

### Setup
```bash
# Clone or download the project
cd phishing-detector

# Install dependencies
pip install -r requirements.txt

# Run the app
python app.py
```

Then open your browser to: **http://localhost:5000**

---

## Usage

### Analyzing a URL
1. Click the **URL Analyzer** tab
2. Paste any URL into the input field
3. Click **⚡ Analyze URL**
4. Review the risk score, threat indicators, and recommendations

### Analyzing Email Headers
1. Click the **Email Header Analyzer** tab
2. Paste raw email headers (how to get them below)
3. Click **⚡ Analyze Headers**

#### How to get raw email headers:
- **Gmail**: Open email → ⋮ (3 dots) → "Show original"
- **Outlook**: File → Properties → Internet headers
- **Apple Mail**: View → Message → All Headers

---

## Risk Levels

| Score | Level | Description |
|-------|-------|-------------|
| 0–10 | ✅ Safe | Likely legitimate |
| 11–30 | 🟡 Low Risk | Proceed with caution |
| 31–55 | 🟠 Medium Risk | Suspicious — verify before interacting |
| 56–75 | 🔴 High Risk | Strong phishing indicators — do not interact |
| 76–100 | ☠️ Critical | Almost certainly phishing |

---

## Project Structure

```
phishing-detector/
├── app.py              # Flask web server & API routes
├── analyzer.py         # Core detection engine
├── requirements.txt    # Python dependencies
├── templates/
│   └── index.html      # Frontend UI
└── README.md
```

---

## About the Developer

**Mofic Koudmani**  
📧 mofic123@hotmail.com | 📞 (954) 249-5068  

- B.A.S. Cybersecurity & Ethical Hacking — Broward College (Expected Aug 2026)
- Microsoft AZ-900 Certified | CompTIA Security+ (In Progress)
- Tools: Kali Linux, Wireshark, Metasploit, Nessus, Microsoft Azure
- Bilingual: English & Arabic

---

## Disclaimer

This tool is built for educational and defensive cybersecurity purposes only.  
Always report suspected phishing to: phishing@apwg.org

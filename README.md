# 🔍 OSINT Platform — Refactored

Open Source Intelligence Gathering Tool built with Streamlit.

---

## 📁 Project Structure

```
osint-platform/
│
├── app.py                        # Main entry point
├── requirements.txt              # All Python dependencies
├── .env                          # Your API keys (never commit this)
├── .env.example                  # Template for API keys
│
├── assets/
│   └── style.css                 # Global design system (amber/warm palette)
│
├── utils/
│   ├── __init__.py
│   └── helpers.py                # Shared utilities: CSS loader, retry, input detection, threat scoring
│
├── modules/
│   ├── __init__.py
│   ├── reputation.py             # VirusTotal + Shodan + AbuseIPDB
│   ├── ssl_cert.py               # TLS/SSL Certificate Inspector
│   ├── dns_intel.py              # DNS + ViewDNS Intelligence
│   ├── subdomains.py             # Subdomain Discovery via crt.sh
│   ├── typosquatting.py          # Typosquatting via DNSTwist
│   ├── sherlock_hunt.py          # Username Hunt via Sherlock
│   ├── hash_tool.py              # Hash Generator + Integrity Checker
│   ├── security_hub.py           # India Security Support Hub
│   ├── metadata_inspector.py     # File Metadata Extractor
│   └── truecaller_lookup.py      # Phone Number Lookup
│
└── sherlock_src/                 # Sherlock bundled source
```

---

## 🚀 Setup

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Copy and fill in your API keys
cp .env.example .env
# Edit .env with your keys

# 3. Run
streamlit run app.py
```

---

## 🔑 API Keys Required

| Service | Where to get | Used for |
|---------|-------------|----------|
| VirusTotal | https://virustotal.com | IP/Domain reputation |
| Shodan | https://shodan.io | IP intelligence |
| AbuseIPDB | https://abuseipdb.com | IP abuse reports |
| ViewDNS | https://viewdns.info | DNS records |
| Truecaller* | See modules/truecaller_lookup.py | Phone lookup |
| Numverify* | https://numverify.com | Phone carrier info |

*Optional — phone lookup will show setup instructions if not configured.

---

## 🧰 Tools & Features

| Filter | Description |
|--------|-------------|
| IP/Domain Reputation | VirusTotal + Shodan + AbuseIPDB + Threat Score |
| TLS/SSL Certificate | Cert expiry, issuer, SANs |
| DNS Intelligence | IP history, NS lookup, port scan, site status |
| Subdomain Discovery | Passive OSINT via crt.sh |
| Typosquatting Analysis | Registered lookalike domains via DNSTwist |
| Username Hunt | Sherlock — 400+ platforms |
| Breach Check | Redirects to Have I Been Pwned |
| Generate Hash | MD5/SHA-1/SHA-256/SHA-512/SHA3/BLAKE2 + Integrity Checker |
| Metadata Inspector | Images, PDFs, DOCX, Audio/Video metadata extraction |
| Security Support Hub | India emergency contacts + safety resources |
| Phone Lookup | Truecaller / Numverify integration |

---

## 📞 Truecaller Setup

Truecaller has no public API. Use the unofficial `truecallerpy`:

```bash
pip install truecallerpy
python -c "
from truecallerpy import TruecallerPy
t = TruecallerPy('+91YOUR_NUMBER')
t.generate_otp()
# Enter OTP when prompted → copy the printed token → add to .env
"
```

Then add to `.env`:
```
TRUECALLER_AUTH_TOKEN=your_token_here
```

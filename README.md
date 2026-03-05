# PhishGuard 🛡️

**AI-Powered Phishing & URL Threat Intelligence Platform**

PhishGuard is a full-stack security tool that combines machine learning, real-time network analysis, and NLP content inspection to detect phishing URLs, malicious email campaigns, and suspicious domains — all from a clean, minimalist web dashboard.

---

## ✨ Features

| Feature | Description |
|---|---|
| **ML URL Scoring** | RandomForest trained on real phishing feeds to score any URL 0–100 |
| **NLP Email Analysis** | TF-IDF + Naive Bayes model reads email text to detect social engineering |
| **Live SSL/TLS Analysis** | Connects to the domain and inspects the X.509 certificate issuer, age, and validity |
| **URL Redirect Tracing** | Follows the full redirect chain hop-by-hop — unmasking URL shorteners and open redirects |
| **WHOIS Deep-Dive** | Registrar, country, creation/expiry date, and domain-age risk rating |
| **Threat Intelligence** | Google Safe Browsing, VirusTotal, and urlscan.io integration (API keys required) |
| **Advanced PDF Reports** | Dark-themed reports with embedded risk gauge, radar chart, bar chart, and full telemetry tables |
| **Bulk URL Scanner** | Paste or upload `.txt`/`.csv` files of URLs for concurrent batch scanning and CSV export |
| **.eml File Upload** | Upload raw email files — SPF, DKIM, DMARC header validation included |

---

## 🚀 Quick Start

### 1. Clone the repo
```bash
git clone https://github.com/YOUR_USERNAME/PhishGuard.git
cd PhishGuard
```

### 2. Create a virtual environment & install dependencies
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate

pip install -r requirements.txt
```

### 3. Train the ML models
```bash
# URL-structure RandomForest model
python models/train_real_world.py

# NLP email content model  
python models/train_nlp.py
```

### 4. Configure API Keys (optional but recommended)
Create a `.env` file in the project root (this is gitignored):
```env
GOOGLE_SAFE_BROWSING_KEY=your_key_here
VIRUSTOTAL_KEY=your_key_here
URLSCAN_KEY=your_key_here
```

### 5. Run the app
```bash
python app.py
```

Open **[http://127.0.0.1:5000](http://127.0.0.1:5000)** in your browser.

---

## 📁 Project Structure

```
PhishGuard/
├── app.py                    # Flask backend — routes & orchestration
├── requirements.txt
├── analyzer/
│   ├── url_features.py       # URL structure feature extraction
│   ├── dns_features.py       # DNS + WHOIS lookups
│   ├── content_features.py   # Email text keyword scoring
│   ├── ssl_features.py       # Live SSL/TLS certificate analysis
│   ├── redirect_tracer.py    # Hop-by-hop redirect chain tracing
│   ├── threat_intel.py       # Google Safe Browsing / VT / urlscan APIs
│   ├── eml_parser.py         # .eml file + SPF/DKIM/DMARC parsing
│   └── bulk_scanner.py       # Concurrent bulk URL scanner
├── models/
│   ├── risk_scorer.py        # Core ML + NLP scoring engine
│   ├── train_real_world.py   # RF model training script
│   ├── train_nlp.py          # NLP model training script
│   ├── pdf_generator.py      # ReportLab PDF builder
│   └── chart_generator.py    # Matplotlib chart generator
├── static/
│   ├── style.css             # Minimalist dark theme
│   └── script.js             # Dashboard logic
└── templates/
    └── index.html            # Single-page application shell
```

---

## 🧪 Test URLs

| URL | Expected Score |
|---|---|
| `https://github.com/torvalds/linux` | 0–10 (Safe) |
| `https://google.com` | 0–10 (Safe) |
| `http://support-ticket-system.net/login` | ~80–100 (Phishing) |
| `http://192.168.1.15/banking/signin.php` | 90+ (Phishing) |
| `http://paypal.com-secure-login.update-account-info-now.com/verify` | 100 (Phishing) |

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

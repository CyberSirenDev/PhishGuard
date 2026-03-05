"""
PhishGuard — Interview Preparation Document Generator
Run: python generate_interview_doc.py
Output: PhishGuard_Interview_Prep.pdf
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import io
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)

# ── Palette ────────────────────────────────────────────────────────────────────
BG      = colors.HexColor('#0f0f0f')
SURFACE = colors.HexColor('#1a1a1a')
BORDER  = colors.HexColor('#2e2e2e')
ACCENT  = colors.HexColor('#6366f1')
ACCENT2 = colors.HexColor('#8b5cf6')
GREEN   = colors.HexColor('#22c55e')
RED     = colors.HexColor('#ef4444')
YELLOW  = colors.HexColor('#eab308')
TEXT1   = colors.HexColor('#f0f0f0')
TEXT2   = colors.HexColor('#aaaaaa')
TEXT3   = colors.HexColor('#666666')
WHITE   = colors.white

W, H = letter

def make_styles():
    base = getSampleStyleSheet()
    def s(name, **kw):
        return ParagraphStyle(name, parent=base['Normal'], **kw)
    return {
        'cover_title': s('ct', fontSize=32, textColor=TEXT1, fontName='Helvetica-Bold',
                          alignment=TA_CENTER, spaceAfter=8, leading=40),
        'cover_sub':   s('cs', fontSize=13, textColor=TEXT2, alignment=TA_CENTER,
                          spaceAfter=6, leading=18),
        'cover_meta':  s('cm', fontSize=9,  textColor=TEXT3, alignment=TA_CENTER,
                          spaceAfter=4),
        'h1':  s('h1', fontSize=16, textColor=ACCENT,  fontName='Helvetica-Bold',
                  spaceBefore=18, spaceAfter=8, leading=20),
        'h2':  s('h2', fontSize=12, textColor=ACCENT2, fontName='Helvetica-Bold',
                  spaceBefore=12, spaceAfter=6, leading=16),
        'h3':  s('h3', fontSize=10, textColor=TEXT1,   fontName='Helvetica-Bold',
                  spaceBefore=8,  spaceAfter=4, leading=14),
        'body':   s('body',  fontSize=9,  textColor=TEXT1, leading=14, spaceAfter=4,
                     alignment=TA_JUSTIFY),
        'muted':  s('muted', fontSize=8,  textColor=TEXT2, leading=12, spaceAfter=3),
        'bullet': s('bullet', fontSize=9, textColor=TEXT1, leading=14, leftIndent=14,
                     spaceAfter=3),
        'code':   s('code', fontSize=7.5, textColor=colors.HexColor('#a5b4fc'),
                     fontName='Courier', leading=11, leftIndent=12, spaceAfter=2,
                     backColor=SURFACE),
        'q':  s('q',  fontSize=9.5, textColor=YELLOW, fontName='Helvetica-Bold',
                 spaceBefore=10, spaceAfter=4, leading=14),
        'a':  s('a',  fontSize=9,   textColor=TEXT1,  leading=14, leftIndent=10,
                 spaceAfter=6, alignment=TA_JUSTIFY),
        'tag': s('tag', fontSize=8, textColor=ACCENT,  fontName='Helvetica-Bold',
                  spaceBefore=0, spaceAfter=0),
    }

def hr():
    return HRFlowable(width='100%', thickness=0.5, color=BORDER,
                       spaceAfter=8, spaceBefore=4)

def draw_bg(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(BG)
    canvas.rect(0, 0, W, H, fill=True, stroke=False)

    # Top accent bar
    canvas.setFillColor(SURFACE)
    canvas.rect(0, H - 42, W, 42, fill=True, stroke=False)
    canvas.setFillColor(ACCENT)
    canvas.rect(0, H - 42, 4, 42, fill=True, stroke=False)

    canvas.setFont('Helvetica-Bold', 10)
    canvas.setFillColor(TEXT1)
    canvas.drawString(0.75*inch, H - 27, 'PhishGuard  ·  Interview Preparation Guide')

    canvas.setFont('Helvetica', 7.5)
    canvas.setFillColor(TEXT3)
    canvas.drawRightString(W - 0.75*inch, H - 27, f'Page {doc.page}')

    # Footer
    canvas.setFont('Helvetica', 7)
    canvas.setFillColor(TEXT3)
    canvas.drawString(0.75*inch, 0.35*inch,
                       'Confidential — Interview Prep Document © 2025')
    canvas.drawRightString(W - 0.75*inch, 0.35*inch,
                            'github.com/CyberSirenDev/PhishGuard')
    canvas.restoreState()

def cell(text, style, bg=SURFACE, colspan=1):
    return Paragraph(text, style)

def make_table(rows, col_widths, header=True):
    tbl = Table(rows, colWidths=col_widths)
    style = [
        ('BACKGROUND',    (0,0), (-1, 0 if header else -1), ACCENT if header else SURFACE),
        ('TEXTCOLOR',     (0,0), (-1, 0 if header else -1), WHITE if header else TEXT1),
        ('FONTNAME',      (0,0), (-1, 0 if header else -1), 'Helvetica-Bold' if header else 'Helvetica'),
        ('FONTSIZE',      (0,0), (-1,-1), 8.5),
        ('LEFTPADDING',   (0,0), (-1,-1), 7),
        ('RIGHTPADDING',  (0,0), (-1,-1), 7),
        ('TOPPADDING',    (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('GRID',          (0,0), (-1,-1), 0.4, BORDER),
        ('VALIGN',        (0,0), (-1,-1), 'TOP'),
        ('TEXTCOLOR',     (0,1), (-1,-1), TEXT1),
        ('ROWBACKGROUNDS',(0,1), (-1,-1), [SURFACE, BG]),
    ]
    tbl.setStyle(TableStyle(style))
    return tbl

def generate(filename='PhishGuard_Interview_Prep.pdf'):
    ST = make_styles()
    doc = SimpleDocTemplate(
        filename, pagesize=letter,
        leftMargin=0.75*inch, rightMargin=0.75*inch,
        topMargin=0.7*inch, bottomMargin=0.6*inch
    )

    E = []

    # ══════════════════════════════════════════════════════
    # COVER PAGE
    # ══════════════════════════════════════════════════════
    E += [
        Spacer(1, 1.6*inch),
        Paragraph('PhishGuard', ST['cover_title']),
        Paragraph('AI-Powered Phishing & Threat Intelligence Platform', ST['cover_sub']),
        Spacer(1, 0.2*inch),
        Paragraph('Interview Preparation Guide', ParagraphStyle(
            'cg2', parent=ST['cover_sub'], fontSize=11, textColor=ACCENT2)),
        Spacer(1, 0.4*inch),
    ]

    # Quick-stat boxes
    stats = [
        ['8 Core Features', '4 ML/AI Models', '6 External APIs', '3+ Visualization Types'],
        ['URL Scanner',     'NLP Analyser',   'Google Safe Browsing\nVirusTotal\nurlscan.io', 'Gauge · Radar · Bar Chart'],
    ]
    stat_tbl = make_table(stats, [1.65*inch]*4, header=True)
    E.append(stat_tbl)
    E += [
        Spacer(1, 0.5*inch),
        Paragraph(f'Generated: {datetime.now().strftime("%B %d, %Y")}', ST['cover_meta']),
        Paragraph('github.com/CyberSirenDev/PhishGuard', ST['cover_meta']),
        PageBreak(),
    ]

    # ══════════════════════════════════════════════════════
    # 1. PROJECT OVERVIEW
    # ══════════════════════════════════════════════════════
    E.append(Paragraph('1. Project Overview', ST['h1']))
    E.append(hr())
    E.append(Paragraph(
        'PhishGuard is a full-stack cybersecurity web application that uses multiple layers of '
        'artificial intelligence and real-time network analysis to detect phishing URLs, malicious '
        'email campaigns, and suspicious domains. It was built entirely from scratch using Python, '
        'Flask, Scikit-Learn, and vanilla JavaScript, with no external UI frameworks.',
        ST['body']))
    E.append(Spacer(1, 8))

    E.append(Paragraph('Problem Statement', ST['h2']))
    E.append(Paragraph(
        'Phishing is the #1 vector for credential theft and ransomware delivery, accounting for '
        'over 90% of data breaches. Traditional antivirus engines are reactive — they rely on '
        'known blacklists. PhishGuard is proactive: it evaluates the structural, linguistic, '
        'and behavioral properties of a URL or email before a blacklist entry even exists.',
        ST['body']))

    E.append(Paragraph('What Makes It Different', ST['h2']))
    for pt in [
        '<b>Multi-layer analysis:</b> URL structure + DNS + SSL + NLP + Redirect chain + Threat APIs — all in one scan.',
        '<b>Real-time, not blacklist-based:</b> The ML model evaluates features it has never seen before.',
        '<b>SOC-grade PDF reports:</b> Embedded charts (gauge, radar, bar graph) make results presentable to clients.',
        '<b>Concurrent execution:</b> WHOIS, SSL, Threat Intel, and Redirect tracing run in parallel using ThreadPoolExecutor.',
    ]:
        E.append(Paragraph(f'• {pt}', ST['bullet']))

    # ══════════════════════════════════════════════════════
    # 2. TECH STACK
    # ══════════════════════════════════════════════════════
    E.append(Paragraph('2. Technology Stack', ST['h1']))
    E.append(hr())

    stack_rows = [
        ['Layer', 'Technology', 'Why This Choice'],
        ['Backend',          'Python · Flask',           'Lightweight, rapid development, excellent ML library ecosystem'],
        ['ML Model (URLs)',  'Scikit-Learn RandomForest', 'Robust against overfitting; handles mixed numeric features; interpretable'],
        ['NLP Model',        'TF-IDF + Naive Bayes',     'Extremely fast; works well with small text corpora; memory-efficient'],
        ['Data Viz (PDF)',   'Matplotlib',               'Full control over dark-themed charts; output as PNG bytes for PDF embedding'],
        ['PDF Engine',       'ReportLab',                'Industry standard for programmatic PDF generation in Python'],
        ['DNS / WHOIS',      'python-whois · socket',    'Direct protocol access; no third-party rate limits'],
        ['SSL Analysis',     'Python ssl stdlib',        'Zero dependencies; direct TLS handshake inspection'],
        ['Redirect Tracing', 'requests',                 'Granular control via allow_redirects=False; custom User-Agent'],
        ['Frontend',         'Vanilla JS · CSS',         'Zero build toolchain; loads instantly; full control over DOM'],
    ]
    E.append(make_table(stack_rows, [1.1*inch, 1.5*inch, 4.1*inch]))

    # ══════════════════════════════════════════════════════
    # 3. ARCHITECTURE
    # ══════════════════════════════════════════════════════
    E.append(Paragraph('3. System Architecture', ST['h1']))
    E.append(hr())
    E.append(Paragraph('Request → Response Flow', ST['h2']))

    flow = [
        ['Step', 'Component', 'What Happens'],
        ['①', 'Browser (JS)', 'User submits URL / email text / .eml file via fetch() POST'],
        ['②', 'Flask /analyze', 'Parses form data; validates input; dispatches 4 concurrent tasks'],
        ['③A', 'risk_scorer.py', 'Extracts 21 URL features → RF model → base risk score (0-100)'],
        ['③B', 'risk_scorer.py', 'Feeds email text → NLP pipeline → adds 0-50 point penalty'],
        ['③C', 'ssl_features.py', 'Opens TLS socket → inspects x.509 cert → adds 0-45 point penalty'],
        ['③D', 'redirect_tracer.py', 'Follows redirect chain → detects domain jumps → adds 0-40 point penalty'],
        ['③E', 'threat_intel.py', 'Calls Google Safe Browsing / VirusTotal / urlscan APIs (if keys set)'],
        ['③F', 'dns_features.py', 'WHOIS lookup → domain age, registrar, country, risk label'],
        ['④', 'app.py', 'Aggregates all results; applies final score cap at 100; builds JSON response'],
        ['⑤', 'script.js', 'Renders verdict badge, ring meter, WHOIS, SSL, redirect chain, intel panels'],
        ['⑥ (opt)', 'pdf_generator.py', 'chart_generator.py creates gauge + radar + bar PNGs → ReportLab assembles PDF'],
    ]
    E.append(make_table(flow, [0.35*inch, 1.5*inch, 5.0*inch]))

    E.append(Spacer(1, 10))
    E.append(Paragraph('Directory Structure', ST['h2']))
    for line in [
        'PhishGuard/',
        '├── app.py                    ← Flask entry point; all routes',
        '├── requirements.txt',
        '├── analyzer/',
        '│   ├── url_features.py       ← 21 URL heuristic features',
        '│   ├── dns_features.py       ← DNS records + WHOIS deep-dive',
        '│   ├── content_features.py   ← Keyword urgency/finance scoring',
        '│   ├── ssl_features.py       ← Live TLS cert inspection',
        '│   ├── redirect_tracer.py    ← Hop-by-hop redirect chain follow',
        '│   ├── threat_intel.py       ← Google Safe Browsing / VT / urlscan',
        '│   ├── eml_parser.py         ← .eml SPF / DKIM / DMARC parsing',
        '│   └── bulk_scanner.py       ← Concurrent batch URL processing',
        '├── models/',
        '│   ├── risk_scorer.py        ← Core RF + NLP scoring engine',
        '│   ├── train_real_world.py   ← RF training on phishing feeds',
        '│   ├── train_nlp.py          ← NLP model training',
        '│   ├── chart_generator.py    ← Matplotlib chart generation',
        '│   └── pdf_generator.py      ← Full ReportLab PDF builder',
        '├── static/style.css + script.js',
        '└── templates/index.html',
    ]:
        E.append(Paragraph(line, ST['code']))

    E.append(PageBreak())

    # ══════════════════════════════════════════════════════
    # 4. FEATURE DEEP DIVES
    # ══════════════════════════════════════════════════════
    E.append(Paragraph('4. Feature Deep Dives', ST['h1']))
    E.append(hr())

    features = [
        {
            'title': '4.1  ML URL Scoring — RandomForest Classifier',
            'how': (
                'The system extracts 21 numerical features from the URL string and live DNS data, '
                'builds a feature vector, and feeds it to a pre-trained RandomForestClassifier. '
                'The model outputs a probability (0–1) of the URL being phishing; this is multiplied '
                'by 100 to produce the base risk score.'
            ),
            'features': [
                'url_length, domain_length — long URLs are unusual for legitimate sites',
                'url_entropy, domain_entropy — high entropy often indicates algorithmically generated domains (DGA)',
                'num_dots, num_hyphens, num_at_symbols — structural red flags',
                'num_subdomains — attackers add subdomains to add legitimacy (paypal.com.evil.com)',
                'has_ip_in_domain — legitimate sites never use raw IPs (e.g. 192.168.1.1/login)',
                'is_https — many old phishing pages still use HTTP',
                'suspicious_keyword_count — matches against 14 known phishing keywords',
                'domain_age_days, has_dns_a_record, has_dns_mx_record — DNS telemetry',
                'urgency_score, financial_score — email text analysis features',
            ],
            'training': (
                'Trained on a mixed dataset: 1,000 benign URLs (diverse real-world paths from '
                'GitHub, Wikipedia, Amazon, etc.) and 1,000 phishing URLs from the OpenPhish live '
                'feed. Thread-pooled feature extraction for speed. Uses 150 estimators.'
            ),
            'accuracy': 'Achieved >99% accuracy on the training split.',
        },
        {
            'title': '4.2  NLP Email Content Analysis — TF-IDF + Naive Bayes',
            'how': (
                'When email text is provided, it is passed through a Scikit-Learn Pipeline consisting '
                'of a TfidfVectorizer (up to 5,000 features, unigrams + bigrams, English stop words '
                'removed) followed by a MultinomialNB classifier. The model outputs P(phishing) and '
                'a scaled penalty (0–50 points) is added to the risk score.'
            ),
            'features': [
                'Detects urgency language: "suspended", "24 hours", "immediately", "urgent"',
                'Detects impersonation: "your account", "billing", "verify identity"',
                'Distinguishes from legitimate text: meeting notes, order confirmations, etc.',
                'Key insight: a phishing URL hidden behind a safe domain (e.g. google.com) is '
                'still caught because the NLP model reads the email body independently.',
            ],
            'training': None,
            'accuracy': None,
        },
        {
            'title': '4.3  Live SSL / TLS Certificate Inspection',
            'how': (
                'PhishGuard opens a raw TCP socket to port 443 of the target domain, '
                'performs a TLS handshake, and reads the server\'s x.509 certificate '
                'directly from the ssl.SSLSocket.getpeercert() dictionary — without '
                'rendering any page content.'
            ),
            'features': [
                'Issuer Organization — identifies free/automated CAs (Let\'s Encrypt, ZeroSSL, cPanel)',
                'notBefore / notAfter dates — calculates exact cert age in days',
                'Validity period — short-lived certs (≤90 days) are penalised',
                'SSLCertVerificationError — invalid certs get a hard +50 penalty',
            ],
            'training': None,
            'accuracy': None,
        },
        {
            'title': '4.4  URL Redirect Chain Tracing',
            'how': (
                'Uses requests.get() with allow_redirects=False to manually follow each '
                'HTTP redirect hop. The tracer records the URL, status code, and whether the '
                'domain changed at each hop. It caps at 10 hops to prevent infinite loops.'
            ),
            'features': [
                'Detects cross-domain redirects — e.g. bit.ly → evil-harvest.ru',
                'Checks for suspicious keywords on the FINAL landing URL (not just the original)',
                'Penalises long chains (≥3 hops) — common obfuscation pattern',
                'Detects SSL errors at intermediate hops (broken redirect chain)',
                'Handles relative redirects — correctly resolves /path to https://domain/path',
            ],
            'training': None,
            'accuracy': None,
        },
    ]

    for feat in features:
        E.append(Paragraph(feat['title'], ST['h2']))
        E.append(Paragraph('<b>How it works:</b>', ST['h3']))
        E.append(Paragraph(feat['how'], ST['body']))
        if feat['features']:
            E.append(Paragraph('<b>Key signals detected:</b>', ST['h3']))
            for f in feat['features']:
                E.append(Paragraph(f'• {f}', ST['bullet']))
        if feat['training']:
            E.append(Paragraph('<b>Training:</b>', ST['h3']))
            E.append(Paragraph(feat['training'], ST['body']))
        if feat['accuracy']:
            E.append(Paragraph(f'<b>Result:</b> {feat["accuracy"]}', ST['body']))
        E.append(Spacer(1, 6))

    E.append(PageBreak())

    # ══════════════════════════════════════════════════════
    # 5. SECURITY CONCEPTS COVERED
    # ══════════════════════════════════════════════════════
    E.append(Paragraph('5. Security Concepts You Should Know', ST['h1']))
    E.append(hr())

    concepts = [
        ['Concept', 'What It Is', 'How PhishGuard Uses It'],
        ['SPF', 'Sender Policy Framework — verifies the IP allowed to send mail for a domain',
         'Parsed from .eml headers; FAIL/SOFTFAIL adds +15 risk points'],
        ['DKIM', 'DomainKeys Identified Mail — cryptographic signature on email headers',
         'Parsed from .eml headers; signature failure adds +15 risk points'],
        ['DMARC', 'Domain-based Message Auth — policy for handling SPF/DKIM failures',
         'Parsed from .eml headers; policy failure adds +10 risk points'],
        ['x.509 Certificate', 'Standard for public key certificates used in TLS/SSL',
         'Extracted via Python ssl module; issuer and age evaluated'],
        ['DGA', 'Domain Generation Algorithms — malware generates random-looking domains',
         'High domain entropy score flags DGA-like domains'],
        ['Open Redirect', 'A trusted site\'s parameter can be exploited to redirect to a malicious URL',
         'Redirect tracer follows chain; cross-domain hops are penalised'],
        ['TF-IDF', 'Term Frequency-Inverse Document Frequency — NLP text vectorization technique',
         'Used to convert email text into feature vectors for the Naive Bayes classifier'],
        ['RandomForest', 'Ensemble of decision trees that votes on classification',
         'Core ML model for URL feature-based phishing detection'],
        ['WHOIS', 'Internet protocol for querying domain registration databases',
         'Retrieves registrar, creation/expiry dates, country; domain age is a key risk signal'],
    ]
    E.append(make_table(concepts, [0.8*inch, 2.3*inch, 3.7*inch]))

    E.append(PageBreak())

    # ══════════════════════════════════════════════════════
    # 6. API INTEGRATIONS
    # ══════════════════════════════════════════════════════
    E.append(Paragraph('6. External API Integrations', ST['h1']))
    E.append(hr())

    apis = [
        ['API', 'What It Does', 'How It\'s Used', 'Risk Penalty'],
        ['Google Safe Browsing',
         'Google\'s database of known phishing/malware URLs updated every 30 min',
         'POST request to threatMatches:find endpoint with URL',
         '+30 if flagged'],
        ['VirusTotal',
         '70+ antivirus engines scan the URL in parallel',
         'GET /url/report — malicious field count used',
         '+2 per malicious engine, max +30'],
        ['urlscan.io',
         'Safe sandboxed browser visit; screenshots network requests',
         'POST /scan; poll result; extract screenshot_url',
         'No penalty; enrichment only'],
    ]
    E.append(make_table(apis, [1.2*inch, 1.9*inch, 2.4*inch, 1.3*inch]))

    E.append(Spacer(1, 10))
    E.append(Paragraph(
        '<b>Implementation note:</b> All three API calls are submitted simultaneously using '
        'concurrent.futures.ThreadPoolExecutor(max_workers=4). This means a full scan '
        '(WHOIS + SSL + Redirect + Threat Intel) completes in the time of the slowest '
        'single call, not the sum of all calls.',
        ST['body']))

    E.append(Spacer(1, 10))
    E.append(Paragraph('Concurrency Model (app.py)', ST['h2']))
    for line in [
        "with ThreadPoolExecutor(max_workers=4) as ex:",
        "    intel_future    = ex.submit(run_threat_intel, url)    # Threat APIs",
        "    whois_future    = ex.submit(get_whois_details, domain) # WHOIS",
        "    ssl_future      = ex.submit(extract_ssl_features, url) # SSL cert",
        "    redirect_future = ex.submit(trace_redirects, url)      # Redirect chain",
        "",
        "    intel    = intel_future.result(timeout=20)",
        "    ssl_data = ssl_future.result(timeout=10)",
        "    redir    = redirect_future.result(timeout=15)",
        "    whois    = whois_future.result(timeout=20)",
    ]:
        E.append(Paragraph(line, ST['code']))

    E.append(PageBreak())

    # ══════════════════════════════════════════════════════
    # 7. INTERVIEW Q&A
    # ══════════════════════════════════════════════════════
    E.append(Paragraph('7. Likely Interview Questions & Strong Answers', ST['h1']))
    E.append(hr())

    qa_pairs = [
        (
            'Q: Walk me through how PhishGuard detects a phishing URL from start to finish.',
            'A: When a URL is submitted, four things run concurrently: '
            '(1) The URL structure is broken into 21 numerical features — length, entropy, keyword count, etc. — '
            'and fed into a RandomForest model trained on real phishing feeds. '
            '(2) A TLS socket connects to the domain to inspect its SSL certificate for age and issuer. '
            '(3) A redirect tracer follows each HTTP 3xx hop to find the true landing domain. '
            '(4) WHOIS lookup retrieves the domain registration age. '
            'All four result sets merge into a final 0-100 risk score, capped at 100. '
            'If email text is provided, a separate TF-IDF + Naive Bayes NLP model evaluates the '
            'language for urgency/impersonation patterns and adds up to 50 additional points.'
        ),
        (
            'Q: Why did you choose RandomForest over a neural network?',
            'A: For this problem, RandomForest has several practical advantages over a neural network: '
            '(1) It requires far less data — we trained on ~2,000 samples without overfitting. '
            '(2) Training is deterministic and takes seconds, not hours. '
            '(3) It handles our mixed numeric feature set naturally without any normalization. '
            '(4) Feature importances from the forest give us explainability — I can tell a user exactly '
            'which signals drove the score. Neural networks would need SHAP or LIME to achieve similar '
            'interpretability, adding complexity. For a dataset of this size, RandomForest is provably '
            'the right tool.'
        ),
        (
            'Q: What is URL entropy and why is it a useful phishing signal?',
            'A: Entropy, from information theory, measures randomness in a string. '
            'Legitimate domain names are human-readable words like "amazon" or "github" and have low entropy. '
            'Phishing domains generated by Domain Generation Algorithms (DGAs), e.g. "xk3jf9-acct-update.net", '
            'appear random and have high character entropy. '
            'The formula is H = -Σ p(x) * log2(p(x)) where p(x) is the frequency of each character. '
            'We compute entropy on both the full URL and just the domain to catch both DGA and long-URL obfuscation.'
        ),
        (
            'Q: How do you prevent the URL redirect tracer from becoming a security risk itself?',
            'A: Three safeguards: '
            '(1) We use requests with allow_redirects=False so we never execute JavaScript, render HTML, '
            'or download page content — just read HTTP headers. '
            '(2) A strict 10-hop maximum prevents infinite redirect loops. '
            '(3) A per-hop timeout of 5 seconds prevents the tracer from hanging on slow or unresponsive servers. '
            'The tracer is purely passive observation of HTTP response codes and Location headers.'
        ),
        (
            'Q: What is the difference between SPF, DKIM, and DMARC?',
            'A: They are three layers of email authentication: '
            'SPF (Sender Policy Framework) specifies which IP addresses are allowed to send mail for a domain — '
            'it is checked at the receiving mail server. '
            'DKIM (DomainKeys Identified Mail) adds a cryptographic signature to the email header, '
            'proving the message was not tampered with in transit. '
            'DMARC (Domain-based Message Authentication) is a policy layer — it tells receivers what to do '
            'when SPF and/or DKIM fail: reject, quarantine, or report only. '
            'PhishGuard parses all three from the .eml file headers and adds risk penalties when any fail, '
            'because legitimate senders almost never have all three failures simultaneously.'
        ),
        (
            'Q: How does your NLP model handle emails it has never seen before?',
            'A: TF-IDF + Naive Bayes generalises by learning the statistical importance of words, '
            'not fixed phrases. The TF-IDF vectorizer assigns each word a weight proportional to how '
            'often it appears in phishing emails versus benign emails. Even an unseen email like '
            '"Your Netflix subscription requires immediate payment" will score high because '
            '"subscription", "immediate", and "payment" are heavily weighted toward the phishing class. '
            'The ngram_range=(1,2) setting also captures two-word patterns like "click here" and '
            '"verify now", which are strong phishing indicators.'
        ),
        (
            'Q: How do you handle the case where a safe URL scores too high? (False positive)',
            'A: This was a real problem I encountered. The original model was trained only on root-domain '
            'URLs like "https://google.com". When "https://github.com/torvalds/linux" was submitted, the '
            'model flagged it as phishing because it had never seen a trusted URL with a long path. '
            'The fix was to retrain with realistic benign URLs that include paths, query strings, and '
            'subdomains — e.g. "https://facebook.com/profile.php?id=123". After retraining, '
            'github.com/torvalds/linux scored 0 and the model became far more context-aware.'
        ),
        (
            'Q: What was the hardest technical challenge in this project?',
            'A: The JSON serialization bug caused by numpy types. Scikit-Learn\'s RandomForest returns '
            'numpy.float64 and numpy.bool_ objects, not native Python floats and bools. '
            'Flask\'s jsonify() cannot serialize numpy types, causing a "Object of type bool is not '
            'JSON serializable" error at runtime. The fix was a sanitizer function that recursively '
            'converts all values in the feature dictionary: using isinstance(v, bool) check first '
            '(since bool is a subclass of int in Python, this order matters), then attempting v.item() '
            'which is the numpy method to convert any numpy scalar to a native Python type.'
        ),
        (
            'Q: How is the PDF report generated with charts?',
            'A: Three separate Matplotlib figures are generated: a half-donut gauge chart for the '
            'risk score, a polar radar chart for 6 normalised risk dimensions, and a horizontal bar '
            'chart for raw feature values. Each chart is rendered to a PNG in-memory using io.BytesIO '
            '— no temporary files on disk. The PNG bytes are wrapped in ReportLab\'s Image() object '
            'and positioned within the PDF layout using a Table to achieve the side-by-side gauge + '
            'text layout in Section 1, and the radar + bar layout in Section 2. The entire PDF is '
            'generated with a dark background drawn via canvas.rect() in the page callback.'
        ),
        (
            'Q: How would you scale PhishGuard to handle enterprise traffic?',
            'A: Several improvements: '
            '(1) Replace Flask with a production WSGI server (Gunicorn + Nginx) and run multiple workers. '
            '(2) Move the ML model inference to a message queue (Redis + Celery) so scans are async. '
            '(3) Cache WHOIS and SSL results in Redis with a 1-hour TTL — the same domain is often '
            'scanned repeatedly. '
            '(4) For bulk scanning, move from thread pools to a proper job queue with progress callbacks. '
            '(5) Containerise with Docker and deploy on Kubernetes for horizontal scaling. '
            '(6) Add a PostgreSQL database to log all scan results for trend analysis and reporting dashboards.'
        ),
    ]

    for q, a in qa_pairs:
        E.append(KeepTogether([
            Paragraph(q, ST['q']),
            Paragraph(a, ST['a']),
        ]))

    E.append(PageBreak())

    # ══════════════════════════════════════════════════════
    # 8. DESIGN DECISIONS & TRADEOFFS
    # ══════════════════════════════════════════════════════
    E.append(Paragraph('8. Design Decisions & Tradeoffs', ST['h1']))
    E.append(hr())

    decisions = [
        ['Decision', 'Alternative Considered', 'Why This Choice Won'],
        ['RandomForest for URL scoring',
         'Deep Neural Network / XGBoost',
         'Small dataset favours RF; DNN needs 100k+ samples; RF is interpretable with feature importances'],
        ['TF-IDF + Naive Bayes for NLP',
         'BERT / DistilBERT',
         'BERT is 250MB+ and needs GPU; NB trains in milliseconds; sufficient for short email text'],
        ['ThreadPoolExecutor for concurrency',
         'asyncio / aiohttp',
         'WHOIS and ssl libs are synchronous/blocking; asyncio needs full async stack; threads work cleanly'],
        ['Vanilla JS frontend',
         'React / Vue',
         'No build toolchain; instant load; full DOM control; no dependency updates to maintain'],
        ['ReportLab for PDF',
         'WeasyPrint / Puppeteer PDF',
         'ReportLab is pure Python; no browser dependency; programmatic layout is precise'],
        ['Matplotlib Agg backend',
         'Plotly / Bokeh / D3',
         'Agg is non-interactive server backend; zero display dependency; PNG output directly to bytes'],
        ['allow_redirects=False for tracing',
         'Headless Chrome (Playwright)',
         'Playwright executes JS (dangerous); our approach is read-only HTTP header inspection'],
        ['Synthetic NLP training data',
         'Enron email corpus / SpamAssassin',
         'Quick to bootstrap; privacy-safe; controllable class balance; can be expanded as needed'],
    ]
    E.append(make_table(decisions, [1.4*inch, 1.6*inch, 3.8*inch]))

    E.append(PageBreak())

    # ══════════════════════════════════════════════════════
    # 9. METRICS & OUTPUTS
    # ══════════════════════════════════════════════════════
    E.append(Paragraph('9. Score Calibration & Test Results', ST['h1']))
    E.append(hr())

    E.append(Paragraph('Risk Score Thresholds', ST['h2']))
    thresh = [
        ['Score Range', 'Verdict', 'Colour', 'Meaning'],
        ['0 – 39',  'Safe',       'Green',  'No significant phishing indicators found'],
        ['40 – 69', 'Suspicious', 'Amber',  'Multiple weak signals; exercise caution'],
        ['70 – 100','Phishing',   'Red',    'High confidence of malicious intent; block recommended'],
    ]
    E.append(make_table(thresh, [1.0*inch, 1.0*inch, 0.8*inch, 4.0*inch]))

    E.append(Spacer(1, 12))
    E.append(Paragraph('Verified Test Cases', ST['h2']))
    tests = [
        ['URL', 'Score', 'Verdict', 'Primary Reason'],
        ['https://github.com/torvalds/linux', '0',    'Safe',       'Clean domain, HTTPS, established, no keywords'],
        ['https://google.com',                '10',   'Safe',       'One keyword match ("google"), all other signals clean'],
        ['https://neverssl.com',              '37',   'Safe',       'Valid SSL (Amazon), established domain (3419d)'],
        ['http://support-ticket-system.net/login', '100', 'Phishing', 'HTTP, .net, /login path, ML base score 90'],
        ['http://192.168.1.15/banking/signin','90+',  'Phishing',   'IP in domain (+40), banking + signin keywords'],
        ['http://paypal.com-secure-login...', '100',  'Phishing',   '6 keywords, hyphens, no HTTPS, long domain'],
    ]
    E.append(make_table(tests, [2.2*inch, 0.5*inch, 0.75*inch, 3.3*inch]))

    E.append(Spacer(1, 12))
    E.append(Paragraph('Penalty Contribution Table (Maximum Values)', ST['h2']))
    penalties = [
        ['Source', 'Maximum Penalty', 'Trigger Condition'],
        ['RandomForest ML Model',   '+100 pts (base)', 'P(phishing) from ensemble vote'],
        ['NLP Email Content Model', '+50 pts',         'P(phishing) > 0.5 from Naive Bayes'],
        ['SSL Certificate Risk',    '+50 pts',         'Invalid cert / free CA / cert < 14 days old'],
        ['URL Redirect Chain',      '+40 pts',         'Cross-domain redirect + long chain'],
        ['Suspicious Keywords',     '+10 per keyword', 'URL matches known phishing keyword list'],
        ['Domain Age < 30 days',    '+20 pts',         'WHOIS creation date within 30 days'],
        ['IP in Domain',            '+40 pts',         'Regex detects raw IPv4 in hostname'],
        ['Google Safe Browsing',    '+30 pts',         'Threat match found in API response'],
        ['VirusTotal',              '+2 per engine',   'Up to +30 pts maximum'],
        ['SPF Fail',                '+15 pts',         '.eml header SPF result is fail/softfail'],
        ['DKIM Fail',               '+15 pts',         '.eml header DKIM result is fail'],
        ['DMARC Fail',              '+10 pts',         '.eml header DMARC result is fail'],
    ]
    E.append(make_table(penalties, [2.0*inch, 1.2*inch, 3.5*inch]))

    E.append(PageBreak())

    # ══════════════════════════════════════════════════════
    # 10. FUTURE IMPROVEMENTS
    # ══════════════════════════════════════════════════════
    E.append(Paragraph('10. Future Improvements (For Interview Discussion)', ST['h1']))
    E.append(hr())

    improvements = [
        ('Production Hardening',
         'Gunicorn + Nginx, Docker, Kubernetes HPA, Redis cache for WHOIS/SSL/threat intel results.'),
        ('Larger Training Dataset',
         'Download PhishTank full feed (1M+ URLs) and Tranco benign list; retrain monthly via cron job.'),
        ('Transformer-based NLP',
         'Swap Naive Bayes for DistilBERT fine-tuned on a phishing email corpus (Enron + SpamAssassin) '
         'for far higher accuracy on adversarial, paraphrased phishing text.'),
        ('Browser Extension',
         'Package the analysis engine as a Chrome extension that auto-scans every link hovered on a page.'),
        ('Real-time Dashboard',
         'WebSocket-based live feed showing scans as they come in; useful for SOC teams monitoring '
         'enterprise mail gateways.'),
        ('MITRE ATT&CK Mapping',
         'Map detected phishing techniques to MITRE ATT&CK framework tactics (e.g. T1566.001 '
         'Spearphishing Attachment) for threat intelligence reporting.'),
        ('Adversarial Robustness',
         'Test the model against adversarial examples (e.g. URLs with Unicode lookalike characters: '
         'pаypal.com with Cyrillic "а") and add Unicode normalisation as a preprocessing step.'),
        ('CI/CD Pipeline',
         'GitHub Actions to auto-retrain the model on new phishing feed data weekly, '
         'run test suite, and deploy to production if accuracy stays above threshold.'),
    ]

    for title, desc in improvements:
        E.append(Paragraph(f'• <b>{title}:</b> {desc}', ST['bullet']))

    E.append(Spacer(1, 16))
    E.append(hr())
    E.append(Paragraph('Quick Reference Cheat Sheet', ST['h1']))

    cheat = [
        ['Term', 'One-Line Definition'],
        ['RandomForest',       'Ensemble of N decision trees; majority vote determines class'],
        ['TF-IDF',             'Weights words by frequency in doc vs. rarity across all docs'],
        ['Naive Bayes',        'Probabilistic classifier assuming feature independence; fast; works well on text'],
        ['x.509',              'Standard format for TLS/SSL public key certificates'],
        ['SPF',                'DNS record listing IPs allowed to send email for a domain'],
        ['DKIM',               'Cryptographic header signature proving email authenticity/integrity'],
        ['DMARC',              'Policy (reject/quarantine/none) applied when SPF+DKIM both fail'],
        ['Entropy (Shannon)',  'H = -Σ p(x)log2(p(x)) — measures randomness of a string'],
        ['ThreadPoolExecutor', 'Python stdlib concurrency — runs blocking I/O in parallel threads'],
        ['TLS Handshake',      '3-step protocol: ClientHello → Certificate → KeyExchange → session key'],
        ['Open Redirect',      'Trusted site\'s ?next= param exploited to redirect to attacker URL'],
        ['DGA',                'Domain Generation Algorithm — malware creates random daily C2 domains'],
        ['ReportLab',          'Python library for programmatic PDF generation'],
        ['WHOIS',              'Protocol for querying domain registration data from registrar DBs'],
    ]
    E.append(make_table(cheat, [1.7*inch, 5.1*inch], header=True))

    E.append(Spacer(1, 12))
    E.append(Paragraph(
        '<i>Good luck with your interview! You built this — know it inside out and you will impress any panel.</i>',
        ParagraphStyle('gl', parent=ST['muted'], alignment=TA_CENTER, fontSize=9,
                       textColor=ACCENT2, spaceBefore=8)
    ))

    # Build
    doc.build(E, onFirstPage=draw_bg, onLaterPages=draw_bg)
    print(f'✅  Interview prep document generated: {filename}')

if __name__ == '__main__':
    generate('PhishGuard_Interview_Prep.pdf')

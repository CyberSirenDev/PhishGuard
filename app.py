from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    from analyzer.eml_parser import parse_eml
    
    # Check if request has files (multipart/form-data)
    eml_data = None
    email_text = ""
    url = ""
    generate_pdf = False
    
    if 'file' in request.files:
        file = request.files['file']
        if file.filename != '':
            eml_data = parse_eml(file.stream)
            email_text = eml_data.get('body', '')
            
    # Also support JSON or form data for normal text inputs
    if request.is_json:
        data = request.json
        url = data.get('url', url)
        if not email_text:
            email_text = data.get('email_text', '')
        generate_pdf = data.get('generate_pdf', False)
    else:
        # Form data fallback
        url = request.form.get('url', url)
        if not email_text:
            email_text = request.form.get('email_text', '')
        generate_pdf = request.form.get('generate_pdf') == 'true'

    if not url and not email_text:
        return jsonify({'error': 'Please provide a URL, Email text, or upload an EML file to analyze.'}), 400

    # Implement actual analysis logic
    from models.risk_scorer import calculate_risk_score
    from analyzer.threat_intel import run_threat_intel
    from analyzer.dns_features import get_whois_details
    from analyzer.ssl_features import extract_ssl_features
    from analyzer.redirect_tracer import trace_redirects
    import tldextract, concurrent.futures
    try:
        result = calculate_risk_score(url, email_text, eml_data)
        result['status'] = 'success'

        # Run threat intel + WHOIS deep-dive + SSL + Redirect tracing concurrently
        if url:
            ext = tldextract.extract(url)
            registered_domain = f"{ext.domain}.{ext.suffix}" if ext.domain else ""

            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
                intel_future    = ex.submit(run_threat_intel, url)
                whois_future    = ex.submit(get_whois_details, registered_domain) if registered_domain else None
                ssl_future      = ex.submit(extract_ssl_features, url)
                redirect_future = ex.submit(trace_redirects, url)

                intel = intel_future.result(timeout=20)
                result['threat_intel'] = intel

                ssl_data = ssl_future.result(timeout=10)
                result['ssl_data'] = ssl_data

                redirect_data = redirect_future.result(timeout=15)
                result['redirect_data'] = redirect_data

                if whois_future:
                    result['whois_data'] = whois_future.result(timeout=20)

            # Bump risk score if Google or VT flag the URL
            gsb = intel.get("google_safe_browsing", {})
            vt  = intel.get("virustotal", {})
            if gsb.get("available") and not gsb.get("safe", True):
                result['risk_score'] = min(100, result['risk_score'] + 30)
                result['details'].append(
                    f"Google Safe Browsing flagged this URL: {', '.join(gsb.get('threats', []))}")
            if vt.get("available") and not vt.get("safe", True):
                mal = vt.get("malicious", 0)
                result['risk_score'] = min(100, result['risk_score'] + min(30, mal * 2))
                result['details'].append(
                    f"VirusTotal: {mal} AV engines flagged this URL as malicious.")
            
            # Bump risk score if SSL cert is highly suspicious
            if ssl_data and ssl_data.get('available'):
                ssl_penalty = ssl_data.get('risk_score_penalty', 0)
                if ssl_penalty > 0:
                    result['risk_score'] = min(100, result['risk_score'] + ssl_penalty)
                    for flag in ssl_data.get('risk_flags', []):
                        result['details'].append(flag)
            elif ssl_data and not ssl_data.get('available'):
                err = ssl_data.get('error', 'Unknown error')
                result['risk_score'] = min(100, result['risk_score'] + 15)
                result['details'].append(f"Failed to verify SSL certificate: {err}")

            # Apply redirect chain penalties
            if redirect_data and redirect_data.get('available'):
                redir_penalty = redirect_data.get('risk_score_penalty', 0)
                if redir_penalty > 0:
                    result['risk_score'] = min(100, result['risk_score'] + redir_penalty)
                    for flag in redirect_data.get('risk_flags', []):
                        result['details'].append(flag)
                # If the redirect landed on a different URL, note the final destination
                if redirect_data.get('domain_changed') and redirect_data.get('final_url') != url:
                    result['details'].append(
                        f"Final landing domain: {redirect_data['final_url']}")

            # Update final verdict flag after all adjustments
            result['is_phishing'] = int(result['risk_score'] >= 60)

        # Save a report if requested
        generate_pdf_flag = generate_pdf
        if generate_pdf_flag:
            import os, uuid, tempfile
            from models.pdf_generator import ThreatReportGenerator
            report_id   = str(uuid.uuid4())
            # Use /tmp on cloud (read-only app dir), local reports/ otherwise
            reports_dir = tempfile.gettempdir()
            local_dir   = os.path.join(os.path.dirname(__file__), 'reports')
            if os.path.exists(local_dir) or not os.access(os.path.dirname(__file__), os.W_OK):
                try:
                    os.makedirs(local_dir, exist_ok=True)
                    reports_dir = local_dir
                except OSError:
                    pass  # Fall back to /tmp
            report_path = os.path.join(reports_dir, f"phishguard_report_{report_id}.pdf")
            generator = ThreatReportGenerator(report_path)
            pdf_data  = result.copy()
            pdf_data['url'] = url if url else "Email Content Analysis Only"
            generator.generate_report(pdf_data)
            result['report_url'] = f"/download/{report_id}"

        return jsonify(result)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e), 'status': 'error'}), 500

from flask import send_file

@app.route('/download/<report_id>')
def download_report(report_id):
    import os, tempfile
    # Check both local reports/ and /tmp
    local_path = os.path.join(os.path.dirname(__file__), f"reports/phishguard_report_{report_id}.pdf")
    tmp_path   = os.path.join(tempfile.gettempdir(), f"phishguard_report_{report_id}.pdf")
    path = local_path if os.path.exists(local_path) else tmp_path
    if os.path.exists(path):
        return send_file(path, as_attachment=True,
                         download_name=f'phishguard_{report_id[:8]}.pdf')
    return "Report not found.", 404

@app.route('/bulk-analyze', methods=['POST'])
def bulk_analyze():
    """
    Accepts a list of URLs (from a textarea or uploaded .txt/.csv file)
    and returns batch results sorted by risk score.
    """
    from analyzer.bulk_scanner import bulk_scan

    urls = []

    # File upload takes priority
    if 'file' in request.files:
        f = request.files['file']
        if f.filename:
            content = f.read().decode('utf-8', errors='ignore')
            for line in content.splitlines():
                # Strip CSV quoting/commas — take first column
                line = line.strip().strip('"').split(',')[0].strip()
                if line and not line.lower().startswith('url'):
                    urls.append(line)

    # Also accept pasted URLs from JSON or form
    if not urls:
        if request.is_json:
            urls = request.json.get('urls', [])
        else:
            raw = request.form.get('urls', '')
            urls = [u.strip() for u in raw.splitlines() if u.strip()]

    if not urls:
        return jsonify({'error': 'No URLs provided.', 'status': 'error'}), 400

    if len(urls) > 500:
        return jsonify({'error': 'Maximum 500 URLs per batch.', 'status': 'error'}), 400

    results = bulk_scan(urls)

    # Summary stats
    phishing_count   = sum(1 for r in results if r['verdict'] == 'Phishing')
    suspicious_count = sum(1 for r in results if r['verdict'] == 'Suspicious')
    safe_count       = sum(1 for r in results if r['verdict'] == 'Legitimate')

    return jsonify({
        'status': 'success',
        'total': len(results),
        'phishing': phishing_count,
        'suspicious': suspicious_count,
        'safe': safe_count,
        'results': results
    })

@app.route('/bulk-export', methods=['POST'])
def bulk_export():
    """Returns bulk scan results as a downloadable CSV file."""
    from analyzer.bulk_scanner import bulk_scan, results_to_csv
    import io

    urls = []
    if request.is_json:
        urls = request.json.get('urls', [])
    else:
        raw = request.form.get('urls', '')
        urls = [u.strip() for u in raw.splitlines() if u.strip()]

    if not urls:
        return "No URLs provided.", 400

    results  = bulk_scan(urls)
    csv_data = results_to_csv(results)

    return send_file(
        io.BytesIO(csv_data.encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name='phishguard_bulk_report.csv'
    )

if __name__ == '__main__':
    app.run(debug=True)

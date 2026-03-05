import concurrent.futures
import csv
import io
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.url_features import extract_url_features
from analyzer.content_features import extract_content_features
from models.risk_scorer import FEATURE_NAMES, load_model

def _score_single_url(url):
    """
    Fast, offline-only scoring for a single URL (no DNS/WHOIS/API calls).
    Designed for bulk throughput.
    """
    url = url.strip()
    if not url:
        return None
    if not url.startswith('http'):
        url = 'http://' + url

    try:
        url_feats    = extract_url_features(url)
        content_feats = extract_content_features("")
        combined = {**url_feats, **content_feats}
        combined.setdefault('domain_age_days', -1)
        combined.setdefault('has_dns_a_record', 0)
        combined.setdefault('has_dns_mx_record', 0)

        vector = [combined.get(f, 0) for f in FEATURE_NAMES]

        model = load_model()
        ml_prob = 0.0
        if model:
            ml_prob = model.predict_proba([vector])[0][1]

        risk_score = ml_prob * 100

        # Quick heuristics (no network calls)
        if combined.get('suspicious_keyword_count', 0) > 0:
            risk_score += combined['suspicious_keyword_count'] * 10
        if combined.get('has_ip_in_domain', 0):
            risk_score += 40
        if not combined.get('is_https', 0):
            risk_score += 5

        risk_score = min(100, max(0, round(risk_score, 1)))

        if risk_score >= 70:
            verdict = 'Phishing'
        elif risk_score >= 40:
            verdict = 'Suspicious'
        else:
            verdict = 'Legitimate'

        return {
            'url': url,
            'risk_score': float(risk_score),
            'verdict': verdict,
            'is_https': int(bool(combined.get('is_https', 0))),
            'suspicious_keywords': int(combined.get('suspicious_keyword_count', 0)),
            'url_length': int(combined.get('url_length', 0)),
            'domain_entropy': round(float(combined.get('domain_entropy', 0)), 2),
        }
    except Exception as e:
        return {
            'url': url,
            'risk_score': -1,
            'verdict': 'Error',
            'error': str(e)
        }

def bulk_scan(urls, max_workers=20):
    """
    Scans a list of URLs concurrently and returns a sorted list of results.
    """
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_score_single_url, u): u for u in urls}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                results.append(result)

    # Sort by risk_score descending (highest risk first)
    results.sort(key=lambda r: r['risk_score'], reverse=True)
    return results

def results_to_csv(results):
    """Converts bulk scan results to a CSV string."""
    output = io.StringIO()
    fieldnames = ['url', 'risk_score', 'verdict', 'is_https',
                  'suspicious_keywords', 'url_length', 'domain_entropy']
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
    writer.writeheader()
    writer.writerows(results)
    return output.getvalue()

if __name__ == '__main__':
    test_urls = [
        "https://google.com",
        "http://secure-paypal-login.com",
        "https://github.com",
        "http://192.168.1.1/login",
        "https://amazon.com"
    ]
    res = bulk_scan(test_urls)
    for r in res:
        print(r)

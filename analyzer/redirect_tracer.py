import requests
from urllib.parse import urlparse
from analyzer.url_features import extract_url_features

MAX_HOPS = 10
TIMEOUT  = 5  # seconds per hop

SAFE_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (PhishGuard URL Inspector/2.0)'
}

def trace_redirects(url):
    """
    Manually follows the redirect chain of a URL hop-by-hop without
    rendering any page content. Returns metadata about each hop and
    the final destination URL.
    """
    if not url.startswith('http'):
        url = 'http://' + url

    chain = []
    current_url = url
    initial_domain = urlparse(url).netloc

    try:
        for hop in range(MAX_HOPS):
            try:
                resp = requests.get(
                    current_url,
                    allow_redirects=False,
                    headers=SAFE_HEADERS,
                    timeout=TIMEOUT
                )
            except requests.exceptions.SSLError:
                chain.append({
                    'hop': hop + 1,
                    'url': current_url,
                    'status': 'SSL_ERROR',
                    'domain_changed': False,
                    'note': 'SSL handshake failed at this hop'
                })
                break
            except requests.exceptions.ConnectionError:
                chain.append({
                    'hop': hop + 1,
                    'url': current_url,
                    'status': 'CONNECTION_ERROR',
                    'domain_changed': False,
                    'note': 'Could not connect at this hop'
                })
                break
            except requests.exceptions.Timeout:
                chain.append({
                    'hop': hop + 1,
                    'url': current_url,
                    'status': 'TIMEOUT',
                    'domain_changed': False,
                    'note': 'Connection timed out at this hop'
                })
                break

            status = resp.status_code
            hop_domain = urlparse(current_url).netloc
            domain_changed = hop_domain != urlparse(url).netloc

            hop_entry = {
                'hop': hop + 1,
                'url': current_url,
                'status': status,
                'domain_changed': domain_changed,
                'note': ''
            }

            # Check if this is a redirect
            if status in (301, 302, 303, 307, 308) and 'location' in resp.headers:
                next_url = resp.headers['location']
                # Handle relative redirects
                if next_url.startswith('/'):
                    parsed = urlparse(current_url)
                    next_url = f"{parsed.scheme}://{parsed.netloc}{next_url}"
                hop_entry['redirect_to'] = next_url
                chain.append(hop_entry)
                current_url = next_url
            else:
                # Final destination reached
                hop_entry['note'] = 'Final destination'
                chain.append(hop_entry)
                break
        else:
            # Hit the redirect limit
            chain.append({
                'hop': MAX_HOPS + 1,
                'url': current_url,
                'status': 'LOOP_LIMIT',
                'domain_changed': True,
                'note': f'Redirect loop detected after {MAX_HOPS} hops'
            })

    except Exception as e:
        return {
            'available': False,
            'error': str(e),
            'chain': chain,
            'final_url': url,
            'was_redirected': False,
            'hop_count': 0,
            'domain_changed': False,
            'risk_score_penalty': 0,
            'risk_flags': []
        }

    final_url  = current_url
    hop_count  = len(chain)
    final_domain  = urlparse(final_url).netloc
    domain_changed = final_domain != initial_domain

    # --- Risk Analysis ---
    risk_flags = []
    risk_score_penalty = 0

    if domain_changed and hop_count > 1:
        risk_score_penalty += 15
        risk_flags.append(
            f"URL redirects across domains: original domain '{initial_domain}' → final domain '{final_domain}'"
        )

    if hop_count >= 3:
        risk_score_penalty += 10
        risk_flags.append(
            f"Long redirect chain detected ({hop_count} hops). Commonly used to obscure final phishing destination."
        )

    if any(h.get('status') in ('SSL_ERROR', 'CONNECTION_ERROR') for h in chain):
        risk_score_penalty += 10
        risk_flags.append("An intermediate hop in the redirect chain has a broken or missing SSL certificate.")

    # If there was a cross-domain redirect, also score the final URL
    final_url_risk = {}
    if domain_changed and final_url != url:
        try:
            feats = extract_url_features(final_url)
            kw = feats.get('suspicious_keyword_count', 0)
            if kw > 0:
                risk_score_penalty += kw * 10
                risk_flags.append(
                    f"Final redirect destination contains {kw} suspicious keyword(s)."
                )
            final_url_risk = {'url': final_url, 'suspicious_keywords': kw}
        except Exception:
            pass

    return {
        'available': True,
        'chain': chain,
        'final_url': final_url,
        'was_redirected': hop_count > 1 or domain_changed,
        'hop_count': hop_count,
        'domain_changed': domain_changed,
        'risk_score_penalty': min(risk_score_penalty, 40),
        'risk_flags': risk_flags,
        'final_url_analysis': final_url_risk
    }


if __name__ == '__main__':
    import json
    # Test with a known redirect chain
    print("--- Testing bit.ly shortener ---")
    print(json.dumps(trace_redirects("https://bit.ly/3xKeMjf"), indent=2))
    print("\n--- Testing direct safe URL ---")
    print(json.dumps(trace_redirects("https://google.com"), indent=2))

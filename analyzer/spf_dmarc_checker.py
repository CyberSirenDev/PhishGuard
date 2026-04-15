import re
import dns.resolver
import tldextract


# ─── SPF ──────────────────────────────────────────────────────────────────────

def check_spf_policy(domain: str) -> dict:
    """
    Queries the domain's DNS TXT records for an SPF policy.
    Parses the 'all' qualifier to assess how strictly the domain
    controls who can send email on its behalf.

    Risk levels:
      - No record    → high  (+20)
      - +all         → high  (+25) — anyone can spoof this domain
      - ?all         → medium (+10) — neutral, no enforcement
      - ~all         → medium (+5)  — soft fail, usually lands in spam
      - -all         → low   (+0)  — strict, best practice
    """
    result = {
        'domain': domain,
        'record': None,
        'exists': False,
        'mechanism': None,
        'risk': 'high',
        'risk_label': '🔴 No SPF Record — Anyone Can Spoof This Domain',
        'risk_score_penalty': 20,
        'available': False,
    }

    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        result['available'] = True

        for rdata in answers:
            # TXT records may be chunked strings — join them
            txt = ''.join(
                s.decode('utf-8', errors='ignore') if isinstance(s, bytes) else s
                for s in rdata.strings
            )
            if not txt.lower().startswith('v=spf1'):
                continue

            result['exists'] = True
            result['record'] = txt

            # Parse the 'all' qualifier (the catch-all mechanism)
            all_match = re.search(r'([+\-~?])all', txt, re.IGNORECASE)
            if all_match:
                qualifier = all_match.group(1)
                result['mechanism'] = f'{qualifier}all'

                if qualifier == '-':
                    result['risk'] = 'low'
                    result['risk_label'] = '🟢 SPF Strict (-all) — Unauthorized senders are rejected'
                    result['risk_score_penalty'] = 0
                elif qualifier == '~':
                    result['risk'] = 'medium'
                    result['risk_label'] = '🟡 SPF Soft Fail (~all) — Unauthorized senders are soft-rejected'
                    result['risk_score_penalty'] = 5
                elif qualifier == '?':
                    result['risk'] = 'medium'
                    result['risk_label'] = '🟡 SPF Neutral (?all) — No enforcement, spoofing possible'
                    result['risk_score_penalty'] = 10
                elif qualifier == '+':
                    result['risk'] = 'high'
                    result['risk_label'] = '🔴 SPF Pass-All (+all) — Anyone can send as this domain!'
                    result['risk_score_penalty'] = 25
            else:
                # SPF record exists but has no 'all' mechanism
                result['risk'] = 'medium'
                result['risk_label'] = '🟡 SPF record found but no catch-all mechanism defined'
                result['risk_score_penalty'] = 8
            break  # Found the SPF record — stop iterating

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        # Domain exists but has no TXT or no SPF TXT
        result['available'] = True
    except dns.resolver.Timeout:
        result['available'] = False
        result['error'] = 'DNS lookup timed out'
    except Exception as e:
        result['available'] = False
        result['error'] = str(e)

    return result


# ─── DMARC ────────────────────────────────────────────────────────────────────

def check_dmarc_policy(domain: str) -> dict:
    """
    Queries _dmarc.<domain> DNS TXT records for a DMARC policy.
    Parses the 'p=' tag (policy) to determine enforcement level.

    Risk levels:
      - No record      → high   (+20) — no email authentication policy
      - p=none         → medium (+15) — monitoring only, no enforcement
      - p=quarantine   → medium (+5)  — suspicious mail goes to spam
      - p=reject       → low    (+0)  — strict, best practice
    """
    dmarc_domain = f'_dmarc.{domain}'
    result = {
        'domain': domain,
        'dmarc_domain': dmarc_domain,
        'record': None,
        'exists': False,
        'policy': None,
        'subdomain_policy': None,
        'pct': None,
        'rua': None,
        'risk': 'high',
        'risk_label': '🔴 No DMARC Record — Domain Has No Email Authentication Policy',
        'risk_score_penalty': 20,
        'available': False,
    }

    try:
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        result['available'] = True

        for rdata in answers:
            txt = ''.join(
                s.decode('utf-8', errors='ignore') if isinstance(s, bytes) else s
                for s in rdata.strings
            )
            if 'v=DMARC1' not in txt:
                continue

            result['exists'] = True
            result['record'] = txt

            # Policy (p=)
            p_match = re.search(r'\bp=(\w+)', txt, re.IGNORECASE)
            if p_match:
                policy = p_match.group(1).lower()
                result['policy'] = policy

                if policy == 'reject':
                    result['risk'] = 'low'
                    result['risk_label'] = '🟢 DMARC: reject — Non-compliant mail is rejected outright'
                    result['risk_score_penalty'] = 0
                elif policy == 'quarantine':
                    result['risk'] = 'medium'
                    result['risk_label'] = '🟡 DMARC: quarantine — Suspicious mail goes to spam folder'
                    result['risk_score_penalty'] = 5
                elif policy == 'none':
                    result['risk'] = 'medium'
                    result['risk_label'] = '🟡 DMARC: none — Monitoring only, no active enforcement'
                    result['risk_score_penalty'] = 15

            # Subdomain policy (sp=)
            sp_match = re.search(r'\bsp=(\w+)', txt, re.IGNORECASE)
            if sp_match:
                result['subdomain_policy'] = sp_match.group(1).lower()

            # Percentage filter (pct=)
            pct_match = re.search(r'\bpct=(\d+)', txt, re.IGNORECASE)
            if pct_match:
                result['pct'] = int(pct_match.group(1))

            # Reporting URI (rua=)
            rua_match = re.search(r'\brua=mailto:([^\s;,]+)', txt, re.IGNORECASE)
            if rua_match:
                result['rua'] = rua_match.group(1)

            break  # Found DMARC record — stop iterating

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        result['available'] = True
    except dns.resolver.Timeout:
        result['available'] = False
        result['error'] = 'DNS lookup timed out'
    except Exception as e:
        result['available'] = False
        result['error'] = str(e)

    return result


# ─── COMBINED ─────────────────────────────────────────────────────────────────

def run_spf_dmarc_check(url_or_domain: str) -> dict:
    """
    Extracts the registered domain from a URL (or takes a bare domain),
    then runs both SPF and DMARC checks concurrently.
    Returns a combined result with a total risk penalty capped at 40 pts.
    """
    import concurrent.futures

    ext = tldextract.extract(url_or_domain)
    domain = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else url_or_domain

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        spf_future   = ex.submit(check_spf_policy, domain)
        dmarc_future = ex.submit(check_dmarc_policy, domain)
        spf   = spf_future.result(timeout=10)
        dmarc = dmarc_future.result(timeout=10)

    total_penalty = spf.get('risk_score_penalty', 0) + dmarc.get('risk_score_penalty', 0)

    return {
        'domain': domain,
        'spf': spf,
        'dmarc': dmarc,
        'total_penalty': min(total_penalty, 40),
        'available': spf['available'] or dmarc['available'],
    }


if __name__ == '__main__':
    import json, sys
    target = sys.argv[1] if len(sys.argv) > 1 else 'google.com'
    print(json.dumps(run_spf_dmarc_check(target), indent=2))

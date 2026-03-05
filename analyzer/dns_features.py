import whois
import dns.resolver
from datetime import datetime
import tldextract

def get_domain_age(domain):
    """
    Returns the domain age in days. If unable to retrieve, returns -1.
    """
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        
        if not creation_date:
            return -1
            
        if type(creation_date) is list:
            creation_date = creation_date[0]
        
        # Strip timezone info if present to allow arithmetic
        if hasattr(creation_date, 'tzinfo') and creation_date.tzinfo:
            creation_date = creation_date.replace(tzinfo=None)
            
        now = datetime.now()
        age = (now - creation_date).days
        return max(0, age)
    except Exception:
        return -1

def get_whois_details(domain):
    """
    Returns a rich WHOIS data dictionary for the given registered domain.
    Includes registrar, registrant country, creation/expiry dates, and a risk level.
    """
    result = {
        'domain': domain,
        'registrar': 'Unknown',
        'registrant_country': 'Unknown',
        'creation_date': 'Unknown',
        'expiry_date': 'Unknown',
        'age_days': -1,
        'age_risk': 'unknown',       # 'low' | 'medium' | 'high'
        'age_risk_label': 'Unknown', # Human-readable label
        'available': False
    }

    try:
        w = whois.whois(domain)
        result['available'] = True

        # Registrar
        if w.registrar:
            result['registrar'] = w.registrar if isinstance(w.registrar, str) else w.registrar[0]

        # Country
        if hasattr(w, 'country') and w.country:
            result['registrant_country'] = w.country if isinstance(w.country, str) else w.country[0]

        # Creation date
        creation_date = w.creation_date
        if creation_date:
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if hasattr(creation_date, 'tzinfo') and creation_date.tzinfo:
                creation_date = creation_date.replace(tzinfo=None)
            result['creation_date'] = creation_date.strftime('%Y-%m-%d')
            age_days = (datetime.now() - creation_date).days
            result['age_days'] = max(0, age_days)

        # Expiry date
        expiry_date = w.expiration_date
        if expiry_date:
            if isinstance(expiry_date, list):
                expiry_date = expiry_date[0]
            if hasattr(expiry_date, 'tzinfo') and expiry_date.tzinfo:
                expiry_date = expiry_date.replace(tzinfo=None)
            result['expiry_date'] = expiry_date.strftime('%Y-%m-%d')

        # Determine age risk level
        age = result['age_days']
        if age == -1 or age < 30:
            result['age_risk'] = 'high'
            result['age_risk_label'] = '🔴 Very New / Unknown — High Risk'
        elif age < 180:
            result['age_risk'] = 'medium'
            result['age_risk_label'] = '🟡 Less Than 6 Months — Moderate Risk'
        elif age < 365:
            result['age_risk'] = 'medium'
            result['age_risk_label'] = '🟡 Less Than 1 Year — Moderate Risk'
        else:
            result['age_risk'] = 'low'
            result['age_risk_label'] = '🟢 Established Domain — Low Risk'

    except Exception as e:
        result['available'] = False
        result['error'] = str(e)

    return result

def check_dns_records(domain):
    """
    Checks if A and MX records exist for a given domain.
    """
    has_a = 0
    has_mx = 0
    try:
        a_records = dns.resolver.resolve(domain, 'A')
        if len(a_records) > 0:
            has_a = 1
    except Exception:
        pass
        
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        if len(mx_records) > 0:
            has_mx = 1
    except Exception:
        pass
        
    return has_a, has_mx

def extract_dns_features(url):
    ext = tldextract.extract(url)
    # the registered domain is what we can WHOIS
    domain = f"{ext.domain}.{ext.suffix}"
    
    if not ext.domain or not ext.suffix:
        return {
            'domain_age_days': -1,
            'has_dns_a_record': 0,
            'has_dns_mx_record': 0
        }
    
    age = get_domain_age(domain)
    has_a, has_mx = check_dns_records(domain)
    
    return {
        'domain_age_days': age,
        'has_dns_a_record': has_a,
        'has_dns_mx_record': has_mx
    }

if __name__ == '__main__':
    import sys
    test_domain = sys.argv[1] if len(sys.argv) > 1 else "google.com"
    print(get_whois_details(test_domain))

import socket
import ssl
from datetime import datetime
from urllib.parse import urlparse

# Common known free or automated Certificate Authorities
FREE_CAS = ['Let\'s Encrypt', 'ZeroSSL', 'cPanel', 'Cloudflare', 'GTS CA 1P5', 'GoDaddy', 'Sectigo']

def extract_ssl_features(url):
    """
    Connects to the server, pulls the x.509 certificate, 
    and checks issuer, validity period, and age.
    """
    if not url.startswith('http'):
         url = 'https://' + url

    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    
    if not hostname:
        return {'available': False, 'error': 'Invalid hostname'}

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # We just want to inspect the cert, even if invalid

    try:
        # Connect and grab cert
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                
                # We need the readable dict form to parse dates and issuer
                # getpeercert() with default args throws errors on invalid certs
                # so we grab binary and parse it with ssl.DER_cert_to_PEM and standard lib or
                # just use the default form if verify_mode=CERT_NONE isn't blocking us.
        
        # Actually, getpeercert() without binary_form=True needs CERT_REQUIRED.
        # Let's do it the safe way with a new context requiring certs.
        strict_context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with strict_context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        # Parse Issuer
        issuer = dict(x[0] for x in cert['issuer'])
        issuer_name = issuer.get('organizationName', issuer.get('commonName', 'Unknown Issuer'))
        
        # Parse Dates
        not_before = datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
        not_after = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
        
        # Calculate periods
        from datetime import timezone
        now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
        cert_age_days = (now_utc - not_before).days
        validity_period_days = (not_after - not_before).days
        
        is_free_ca = any(ca.lower() in issuer_name.lower() for ca in FREE_CAS)
        
        features = {
            'available': True,
            'issuer': issuer_name,
            'age_days': cert_age_days,
            'validity_days': validity_period_days,
            'is_free_ca': is_free_ca,
            'expires_on': not_after.strftime('%Y-%m-%d')
        }
        
        # Risk heuristics
        risk_flags = []
        risk_score = 0
        
        if is_free_ca:
            risk_score += 15
            risk_flags.append(f"Certificate issued by a free/automated CA: {issuer_name}")
            
        if cert_age_days < 14:
            risk_score += 25
            risk_flags.append(f"Certificate is extremely new ({cert_age_days} days old)")
            
        if validity_period_days <= 90:
            risk_score += 10
            risk_flags.append(f"Short-lived certificate ({validity_period_days} days valid)")
            
        features['risk_score_penalty'] = min(risk_score, 45) # Cap penalties
        features['risk_flags'] = risk_flags
        
        return features

    except ssl.SSLCertVerificationError as e:
        return {'available': True, 'risk_score_penalty': 50, 'risk_flags': [f'SSL Verification Failed: {e.verify_message}'], 'issuer': 'Unknown'}
    except Exception as e:
        return {'available': False, 'error': str(e)}

if __name__ == '__main__':
    print(extract_ssl_features("https://google.com"))
    print(extract_ssl_features("https://cloudflare.com"))

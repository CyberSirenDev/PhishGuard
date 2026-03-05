import email
from email import policy
import re

def parse_eml(file_stream):
    """
    Parses an .eml file stream to extract content and authentication headers (SPF, DKIM, DMARC).
    """
    msg = email.message_from_file(file_stream, policy=policy.default)
    
    # Extract body text
    body = ""
    if msg.is_multipart():
        for part in msg.iter_parts():
            if part.get_content_type() == 'text/plain':
                body += part.get_content()
            elif part.get_content_type() == 'text/html':
                # Alternatively extract HTML content
                body += part.get_content()
    else:
        body = msg.get_content()

    # Extract Authentication-Results
    auth_results = msg.get_all('Authentication-Results', [])
    
    spf_status = 'none'
    dkim_status = 'none'
    dmarc_status = 'none'

    for auth in auth_results:
        auth_lower = auth.lower()
        
        # Simple regex extraction for status
        spf_match = re.search(r'spf=(\w+)', auth_lower)
        if spf_match:
            spf_status = spf_match.group(1)
            
        dkim_match = re.search(r'dkim=(\w+)', auth_lower)
        if dkim_match:
            dkim_status = dkim_match.group(1)
            
        dmarc_match = re.search(r'dmarc=(\w+)', auth_lower)
        if dmarc_match:
            dmarc_status = dmarc_match.group(1)

    return {
        'body': body,
        'spf_status': spf_status,
        'dkim_status': dkim_status,
        'dmarc_status': dmarc_status,
        'subject': msg.get('Subject', ''),
        'from': msg.get('From', ''),
        'to': msg.get('To', '')
    }

if __name__ == '__main__':
    # Add a mock test if running directly
    pass

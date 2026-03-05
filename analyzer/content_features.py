import re

URGENCY_KEYWORDS = ['urgent', 'immediately', 'suspended', 'locked', 'restricted', 'verify', 'required', 'attention', 'alert', 'important', 'action']
FINANCIAL_KEYWORDS = ['invoice', 'payment', 'billing', 'statement', 'receipt', 'overdue']

def extract_content_features(email_text):
    """
    Extracts numerical features from email text.
    """
    if not email_text:
        return {
            'urgency_score': 0,
            'financial_score': 0,
            'num_links': 0,
            'has_html': 0
        }
    
    text_lower = email_text.lower()
    
    # Keyword scores
    urgency_count = sum(1 for word in URGENCY_KEYWORDS if word in text_lower)
    financial_count = sum(1 for word in FINANCIAL_KEYWORDS if word in text_lower)
    
    # Extract links (basic regex)
    links = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', email_text)
    num_links = len(links)
    
    # Checking if it has HTML tags
    has_html = 1 if bool(re.search(r'<[^>]+>', email_text)) else 0
    
    return {
        'urgency_score': urgency_count,
        'financial_score': financial_count,
        'num_links': num_links,
        'has_html': has_html
    }

if __name__ == '__main__':
    text = "Dear user, your account has been suspended. Please click here to verify immediately: http://bad.com"
    print(extract_content_features(text))

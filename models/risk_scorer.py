import os
import pickle
from analyzer.url_features import extract_url_features
from analyzer.dns_features import extract_dns_features
from analyzer.content_features import extract_content_features

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'model.pkl')
NLP_MODEL_PATH = os.path.join(os.path.dirname(__file__), 'nlp_model.pkl')

FEATURE_NAMES = [
    'url_length', 'domain_length', 'url_entropy', 'domain_entropy',
    'num_dots', 'num_hyphens', 'num_at_symbols', 'num_queries',
    'num_ampersands', 'num_equals', 'num_subdomains', 'has_ip_in_domain',
    'is_https', 'suspicious_keyword_count', 'domain_age_days',
    'has_dns_a_record', 'has_dns_mx_record', 'urgency_score',
    'financial_score', 'num_links', 'has_html'
]

def load_model():
    if os.path.exists(MODEL_PATH):
        with open(MODEL_PATH, 'rb') as f:
            return pickle.load(f)
    # Auto-train on first run (e.g. fresh cloud deployment)
    print("[PhishGuard] model.pkl not found — training RF model now...")
    try:
        from models.train_real_world import train_on_real_data
        train_on_real_data()
        if os.path.exists(MODEL_PATH):
            with open(MODEL_PATH, 'rb') as f:
                return pickle.load(f)
    except Exception as e:
        print(f"[PhishGuard] Auto-train failed: {e}")
    return None

def load_nlp_model():
    if os.path.exists(NLP_MODEL_PATH):
        with open(NLP_MODEL_PATH, 'rb') as f:
            return pickle.load(f)
    # Auto-train on first run
    print("[PhishGuard] nlp_model.pkl not found — training NLP model now...")
    try:
        from models.train_nlp import train_nlp_model
        train_nlp_model()
        if os.path.exists(NLP_MODEL_PATH):
            with open(NLP_MODEL_PATH, 'rb') as f:
                return pickle.load(f)
    except Exception as e:
        print(f"[PhishGuard] NLP auto-train failed: {e}")
    return None

def calculate_risk_score(url, email_text="", eml_data=None):
    """
    Analyzes the URL and email text, extracts features, 
    runs the ML model, and returns a 0-100 risk score with details.
    """
    url_feats = extract_url_features(url) if url else {}
    dns_feats = extract_dns_features(url) if url else {}
    content_feats = extract_content_features(email_text)
    
    # Combine features
    combined_features = {**url_feats, **dns_feats, **content_feats}
    
    # Fill missing features with 0
    for f in FEATURE_NAMES:
        if f not in combined_features:
            combined_features[f] = 0
            
    # Prepare feature vector for model
    feature_vector = [combined_features[f] for f in FEATURE_NAMES]
    
    # Run model
    model = load_model()
    ml_probability = 0
    if model:
        # predict_proba returns [[P(class_0), P(class_1)]]
        probs = model.predict_proba([feature_vector])[0]
        ml_probability = probs[1] # Probability of being phishing
        
    # Calculate base score from ML (0-100)
    risk_score = ml_probability * 100
    
    # NLP Content Analysis
    details = []
    if email_text.strip():
        nlp_model = load_nlp_model()
        if nlp_model:
            nlp_prob = nlp_model.predict_proba([email_text])[0][1]
            if nlp_prob > 0.5:
                penalty = int((nlp_prob - 0.5) * 100) # Give 0 to +50 points
                risk_score += penalty
                details.append(f"NLP Model flagged email content as highly suspicious (Confidence: {nlp_prob*100:.1f}%).")
            else:
                details.append("NLP Model analyzed email content and found no major threats.")
    
    # Heuristic adjustments
    if combined_features.get('domain_age_days') != -1 and combined_features.get('domain_age_days', 999) < 30:
        risk_score += 20
        details.append("Domain is very new (less than 30 days old).")
        
    if combined_features.get('suspicious_keyword_count', 0) > 0:
        risk_score += (combined_features['suspicious_keyword_count'] * 10)
        details.append(f"Found {combined_features['suspicious_keyword_count']} suspicious keyword(s) in URL.")
        
    if combined_features.get('urgency_score', 0) > 0:
        risk_score += (combined_features['urgency_score'] * 5)
        details.append("Email contains urgency/action keywords.")
        
    if combined_features.get('has_ip_in_domain', 0) == 1:
        risk_score += 40
        details.append("URL domain is an IP address, strongly indicating phishing.")
        
    if not url and email_text:
        details.append("No URL provided, analyzing text only.")
        
    if url and ml_probability > 0.6:
        details.append("Machine learning model predicted high likelihood of phishing.")

    # EML-specific heuristic adjustments
    if eml_data:
        spf = eml_data.get('spf_status', 'none')
        dkim = eml_data.get('dkim_status', 'none')
        dmarc = eml_data.get('dmarc_status', 'none')
        
        # Add to telemetry table
        combined_features['spf_status'] = spf
        combined_features['dkim_status'] = dkim
        combined_features['dmarc_status'] = dmarc
        
        fail_statuses = ['fail', 'softfail', 'neutral', 'permerror', 'temperror']
        
        if spf in fail_statuses:
            risk_score += 15
            details.append(f"SPF Validation Failed: {spf}. Sender may be spoofed.")
        
        if dkim in fail_statuses:
            risk_score += 15
            details.append(f"DKIM Validation Failed: {dkim}. Message may be spoofed/tampered.")
            
        if dmarc in fail_statuses:
            risk_score += 10
            details.append(f"DMARC Validation Failed: {dmarc}.")

    # Cap at 100
    risk_score = min(100, max(0, risk_score))

    is_phishing = bool(risk_score >= 60)

    # Sanitize feature dict — convert any Python bool/numpy types to plain
    # Python int/float so Flask's jsonify can serialize them without errors.
    def _safe(v):
        if isinstance(v, bool):
            return int(v)
        try:
            # Handles numpy int64, float32, etc.
            return v.item()
        except AttributeError:
            return v

    safe_features = {k: _safe(v) for k, v in combined_features.items()}

    return {
        'risk_score': round(float(risk_score), 1),
        'is_phishing': int(is_phishing),
        'details': details,
        'features': safe_features
    }

if __name__ == '__main__':
    print(calculate_risk_score("http://secure-login-paypal.com", "Urgent! Please verify your account."))

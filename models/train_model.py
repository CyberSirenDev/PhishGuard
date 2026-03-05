import pickle
import os
import random
from sklearn.ensemble import RandomForestClassifier
import sys

# Define expected feature names based on the feature extractors
FEATURE_NAMES = [
    'url_length', 'domain_length', 'url_entropy', 'domain_entropy',
    'num_dots', 'num_hyphens', 'num_at_symbols', 'num_queries',
    'num_ampersands', 'num_equals', 'num_subdomains', 'has_ip_in_domain',
    'is_https', 'suspicious_keyword_count', 'domain_age_days',
    'has_dns_a_record', 'has_dns_mx_record', 'urgency_score',
    'financial_score', 'num_links', 'has_html'
]

def generate_synthetic_data(num_samples=1000):
    """
    Generates synthetic feature data for phishing and legitimate samples 
    to train the initial basic classifier.
    """
    X = []
    y = []

    for _ in range(num_samples // 2):
        # Legitimate samples
        legit = {
            'url_length': random.randint(15, 60),
            'domain_length': random.randint(5, 20),
            'url_entropy': random.uniform(3.0, 4.2),
            'domain_entropy': random.uniform(2.0, 3.5),
            'num_dots': random.randint(1, 3),
            'num_hyphens': random.randint(0, 1),
            'num_at_symbols': 0,
            'num_queries': random.randint(0, 1),
            'num_ampersands': 0,
            'num_equals': 0,
            'num_subdomains': random.randint(0, 1),
            'has_ip_in_domain': 0,
            'is_https': 1,
            'suspicious_keyword_count': 0,
            'domain_age_days': random.randint(365, 3650),
            'has_dns_a_record': 1,
            'has_dns_mx_record': random.choice([0, 1]),
            'urgency_score': 0,
            'financial_score': random.randint(0, 1),
            'num_links': random.randint(0, 5),
            'has_html': random.choice([0, 1])
        }
        X.append([legit[f] for f in FEATURE_NAMES])
        y.append(0) # 0 = Legitimate

    for _ in range(num_samples // 2):
        # Phishing samples
        phish = {
            'url_length': random.randint(50, 200),
            'domain_length': random.randint(15, 50),
            'url_entropy': random.uniform(4.0, 6.0),
            'domain_entropy': random.uniform(3.5, 5.0),
            'num_dots': random.randint(2, 6),
            'num_hyphens': random.randint(1, 4),
            'num_at_symbols': random.choice([0, 1]),
            'num_queries': random.randint(0, 3),
            'num_ampersands': random.randint(0, 3),
            'num_equals': random.randint(0, 3),
            'num_subdomains': random.randint(1, 4),
            'has_ip_in_domain': random.choice([0, 1]),
            'is_https': random.choice([0, 1]),
            'suspicious_keyword_count': random.randint(1, 4),
            'domain_age_days': random.randint(0, 100),
            'has_dns_a_record': random.choice([0, 1]),
            'has_dns_mx_record': 0,
            'urgency_score': random.randint(1, 3),
            'financial_score': random.randint(1, 3),
            'num_links': random.randint(2, 10),
            'has_html': 1
        }
        X.append([phish[f] for f in FEATURE_NAMES])
        y.append(1) # 1 = Phishing

    return X, y

def train_and_save_model():
    X, y = generate_synthetic_data(2000)
    
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X, y)
    
    model_path = os.path.join(os.path.dirname(__file__), 'model.pkl')
    with open(model_path, 'wb') as f:
        pickle.dump(clf, f)
        
    print(f"Model saved to {model_path}")

if __name__ == '__main__':
    train_and_save_model()

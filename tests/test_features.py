import unittest
from analyzer.url_features import extract_url_features
from analyzer.content_features import extract_content_features

class TestFeatureExtraction(unittest.TestCase):

    def test_url_features_legit(self):
        url = "https://www.google.com"
        features = extract_url_features(url)
        self.assertEqual(features['is_https'], 1)
        self.assertEqual(features['suspicious_keyword_count'], 0)
        self.assertEqual(features['has_ip_in_domain'], 0)

    def test_url_features_phishing(self):
        url = "http://192.168.1.1/secure-update-paypal.php"
        features = extract_url_features(url)
        self.assertEqual(features['is_https'], 0)
        self.assertGreater(features['suspicious_keyword_count'], 0)
        self.assertEqual(features['has_ip_in_domain'], 1)

    def test_content_features_urgency(self):
        text = "URGENT: Your account will be suspended immediately if you don't verify."
        features = extract_content_features(text)
        self.assertGreaterEqual(features['urgency_score'], 1)

    def test_content_features_clean(self):
        text = "Hey Bob, let's catch up for lunch tomorrow!"
        features = extract_content_features(text)
        self.assertEqual(features['urgency_score'], 0)
        self.assertEqual(features['financial_score'], 0)

if __name__ == '__main__':
    unittest.main()

import os
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline

def train_nlp_model():
    print("1. Collecting Email NLP Dataset...")
    
    # Simple, realistic sample dataset
    # In a production environment, this would be thousands of rows from a CSV
    phishing_emails = [
        "URGENT: Your account will be suspended in 24 hours. Please click the link to verify your identity.",
        "Dear Customer, we detected unusual login activity on your banking account. Secure it now.",
        "You have a pending package delivery. Please pay the $2.99 shipping fee at this link to receive your parcel.",
        "Congratulations! You have been selected to receive a $1000 Amazon Gift Card. Claim yours immediately.",
        "IT Helpdesk: Please migrate your email to the new Office 365 server before midnight or lose access.",
        "Your PayPal account is restricted. Update your billing information to restore full access.",
        "Apple ID locked due to security reasons. Verify your account details at the Apple Support gateway.",
        "Invoice #49281 attached. Please review the attached document and remit payment by Friday.",
        "Final Notice: Unpaid toll road bill. Pay now to avoid a $50 penalty and court summons.",
        "Warning: Your mailbox is 99% full. Click here to increase your quota for free."
    ] * 50  # Multiply to give the model some weight

    benign_emails = [
        "Hey team, don't forget we have the standup meeting at 10 AM tomorrow in Room B.",
        "Hi John, attached is the Q3 financial report you asked for. Let me know if you need any changes.",
        "Are we still on for lunch today? I was thinking we could grab Mexican food down the street.",
        "Thanks for signing up for our newsletter! We'll send you weekly updates on our software features.",
        "Your order #9928 has shipped. You can track your package using the tracking number below.",
        "Reminder: Doctor's appointment for Jane Doe on Tuesday at 3:00 PM.",
        "What time are you getting off work today? Can you pick up some milk on the way home?",
        "Please see the revised presentation slides. I've updated the metrics on slide 4.",
        "I'll be out of office until next Monday. Please contact Sarah for any urgent matters.",
        "Sounds good to me. I'll go ahead and approve the PR so we can merge it into main."
    ] * 50

    # Labels: 1 = Phishing/Spam, 0 = Legitimate/Ham
    X = phishing_emails + benign_emails
    y = [1] * len(phishing_emails) + [0] * len(benign_emails)
    
    # Shuffle
    import random
    combined = list(zip(X, y))
    random.shuffle(combined)
    X, y = zip(*combined)

    print(f"Collected {len(X)} training samples.")
    print("2. Training NLP Pipeline (TF-IDF + Naive Bayes)...")
    
    # Create a pipeline that vectorizes text and then classifies it
    model = make_pipeline(
        TfidfVectorizer(stop_words='english', max_features=5000, ngram_range=(1, 2)),
        MultinomialNB(alpha=0.1)
    )
    
    model.fit(X, y)
    
    # Test accuracy on a few holdouts implicitly (since it's a simple dataset)
    test_phish = "Urgent: Verify your bank account immediately or face suspension"
    test_benign = "Can we reschedule our meeting to 2 PM?"
    
    phish_score = model.predict_proba([test_phish])[0][1]
    benign_score = model.predict_proba([test_benign])[0][1]
    
    print(f"Test Phishing Score: {phish_score:.2f} (Should be high)")
    print(f"Test Benign Score:   {benign_score:.2f} (Should be low)")
    
    print("3. Saving Model...")
    nlp_model_path = os.path.join(os.path.dirname(__file__), 'nlp_model.pkl')
    with open(nlp_model_path, 'wb') as f:
        pickle.dump(model, f)
        
    print(f"Success! NLP Model saved to {nlp_model_path}")

if __name__ == '__main__':
    train_nlp_model()

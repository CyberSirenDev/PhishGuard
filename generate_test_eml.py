import os

sample_eml = """From: Security Team <security@paypal.com>
To: target@example.com
Subject: URGENT: Your account will be suspended
Date: Mon, 20 Mar 2023 10:00:00 +0000
Message-ID: <1234567890@fake-mailer.com>
Authentication-Results: mx.google.com;
       dkim=fail (bad signature) header.i=@fake-mailer.com;
       spf=fail (google.com: domain of admin@fake-mailer.com does not designate 192.168.1.100 as permitted sender) smtp.mailfrom=admin@fake-mailer.com;
       dmarc=fail (p=REJECT sp=REJECT dis=REJECT) header.from=paypal.com
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Dear User,

We noticed unauthorized login attempts on your account. 
To prevent immediate suspension, you must verify your identity immediately.

Click here to verify: http://secure-update-paypal-login.com/auth

Thank you,
Verification Team
"""

with open("spoofed_phishing.eml", "w") as f:
    f.write(sample_eml)

print("Created spoofed_phishing.eml for testing.")

import requests
import base64
import os

# ─── CONFIG ──────────────────────────────────────────────────────────────────
# Set these in environment variables or paste your API keys directly below.
# Get keys at:
#   Google Safe Browsing : https://console.cloud.google.com  (enable "Safe Browsing API")
#   VirusTotal           : https://www.virustotal.com/gui/my-apikey
#   urlscan.io           : https://urlscan.io/user/profile/ (API key)
GOOGLE_SAFE_BROWSING_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_KEY", "")
VIRUSTOTAL_KEY           = os.environ.get("VIRUSTOTAL_KEY", "")
URLSCAN_KEY              = os.environ.get("URLSCAN_KEY", "")


# ─── GOOGLE SAFE BROWSING ─────────────────────────────────────────────────────
def check_google_safe_browsing(url: str) -> dict:
    """
    Checks if a URL is blacklisted by Google Safe Browsing's Threat Lookup API.
    Returns a dict with `safe` (bool), `threats` (list), and `source`.
    """
    if not GOOGLE_SAFE_BROWSING_KEY:
        return {"source": "Google Safe Browsing", "available": False,
                "message": "API key not configured."}

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_KEY}"
    payload = {
        "client": {"clientId": "PhishGuard", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        resp = requests.post(endpoint, json=payload, timeout=8)
        data = resp.json()
        matches = data.get("matches", [])
        if matches:
            threats = [m.get("threatType", "UNKNOWN") for m in matches]
            return {"source": "Google Safe Browsing", "available": True,
                    "safe": False, "threats": threats,
                    "verdict": f"⚠️ Flagged: {', '.join(threats)}"}
        return {"source": "Google Safe Browsing", "available": True,
                "safe": True, "threats": [], "verdict": "✅ Not blacklisted"}
    except Exception as e:
        return {"source": "Google Safe Browsing", "available": False,
                "message": f"Request failed: {str(e)}"}


# ─── VIRUSTOTAL ───────────────────────────────────────────────────────────────
def check_virustotal(url: str) -> dict:
    """
    Submits a URL to VirusTotal and retrieves the analysis from 70+ AV engines.
    Uses the VirusTotal v3 API.
    """
    if not VIRUSTOTAL_KEY:
        return {"source": "VirusTotal", "available": False,
                "message": "API key not configured."}

    headers = {"x-apikey": VIRUSTOTAL_KEY, "Content-Type": "application/x-www-form-urlencoded"}

    try:
        # Step 1: Submit the URL for scanning
        submit_resp = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data=f"url={url}",
            timeout=10
        )
        submit_data = submit_resp.json()
        analysis_id = submit_data.get("data", {}).get("id")

        if not analysis_id:
            return {"source": "VirusTotal", "available": False,
                    "message": "Failed to submit URL."}

        # Step 2: Retrieve the URL report (use URL-encoded ID)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        report_resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=10
        )
        report_data = report_resp.json()
        stats = report_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless   = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total      = malicious + suspicious + harmless + undetected

        verdict = "✅ Clean" if malicious == 0 and suspicious == 0 else f"⚠️ {malicious} engines flagged as malicious, {suspicious} suspicious"

        return {
            "source": "VirusTotal",
            "available": True,
            "safe": (malicious == 0 and suspicious == 0),
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "total_engines": total,
            "verdict": verdict
        }
    except Exception as e:
        return {"source": "VirusTotal", "available": False,
                "message": f"Request failed: {str(e)}"}


# ─── URLSCAN.IO ───────────────────────────────────────────────────────────────
def check_urlscan(url: str) -> dict:
    """
    Submits a URL to urlscan.io and retrieves the scan verdict + screenshot.
    Returns result dict with screenshot_url and verdict info.
    """
    if not URLSCAN_KEY:
        return {"source": "urlscan.io", "available": False,
                "message": "API key not configured."}

    headers = {
        "API-Key": URLSCAN_KEY,
        "Content-Type": "application/json"
    }
    try:
        # Submit scan
        submit_resp = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers=headers,
            json={"url": url, "visibility": "public"},
            timeout=10
        )
        submit_data = submit_resp.json()
        scan_uuid = submit_data.get("uuid")

        if not scan_uuid:
            msg = submit_data.get("message", "Unknown error")
            return {"source": "urlscan.io", "available": False,
                    "message": f"Scan submission failed: {msg}"}

        result_url = f"https://urlscan.io/result/{scan_uuid}/"
        screenshot_url = f"https://urlscan.io/screenshots/{scan_uuid}.png"

        return {
            "source": "urlscan.io",
            "available": True,
            "scan_uuid": scan_uuid,
            "result_url": result_url,
            "screenshot_url": screenshot_url,
            "verdict": "✅ Scan submitted — results available in ~30s",
            "note": "Screenshot may take 30-60 seconds to generate."
        }
    except Exception as e:
        return {"source": "urlscan.io", "available": False,
                "message": f"Request failed: {str(e)}"}


# ─── COMBINED LOOKUP ──────────────────────────────────────────────────────────
def run_threat_intel(url: str) -> dict:
    """
    Runs all three API checks concurrently and returns aggregated results.
    """
    import concurrent.futures

    results = {}
    checks = {
        "google_safe_browsing": (check_google_safe_browsing, url),
        "virustotal":            (check_virustotal, url),
        "urlscan":               (check_urlscan, url),
    }

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            key: executor.submit(fn, arg)
            for key, (fn, arg) in checks.items()
        }
        for key, future in futures.items():
            try:
                results[key] = future.result(timeout=15)
            except Exception as e:
                results[key] = {"source": key, "available": False,
                                "message": str(e)}

    return results


if __name__ == "__main__":
    # Quick smoke test (will return "not configured" without real keys)
    res = run_threat_intel("https://google.com")
    for k, v in res.items():
        print(f"{k}: {v}")

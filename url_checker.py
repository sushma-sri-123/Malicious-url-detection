# url_checker.py
import re
import tldextract
import validators

# 🔹 Common suspicious TLDs often used for phishing or spam
SUSPICIOUS_TLDS = {
    "tk", "xyz", "top", "gq", "ml", "cf", "cn", "ru", "work", "zip"
}

# 🔹 Suspicious keywords frequently found in fake or phishing domains
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "update", "account", "support",
    "banking", "webmail", "payment", "confirm", "service", "signin"
]

# 🔹 Look-alike character replacements (used in typosquatting)
LOOKALIKE_MAP = {
    "0": "o",  # zero for 'o'
    "1": "l",  # one for 'l'
    "rn": "m"  # 'rn' used to look like 'm'
}


def check_url_heuristics(url: str):
    """
    Basic heuristic checks for fake or suspicious URLs.
    Returns:
        (is_suspicious: bool, reasons: list[str])
    """
    reasons = []
    url = url.strip()

    # 0️⃣ Validate URL format
    if not validators.url(url):
        reasons.append("Invalid or malformed URL format.")
        return True, reasons  # directly suspicious

    ext = tldextract.extract(url)
    domain = (ext.domain or "").lower()
    subdomain = (ext.subdomain or "").lower()
    suffix = (ext.suffix or "").lower()
    combined = f"{subdomain}.{domain}"

    # 1️⃣ Suspicious TLDs
    if suffix in SUSPICIOUS_TLDS:
        reasons.append(f"Suspicious top-level domain (TLD): .{suffix}")

    # 2️⃣ Suspicious keywords in domain or subdomain
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in combined:
            reasons.append(f"Contains phishing-related keyword: '{kw}'")

    # 3️⃣ Look-alike pattern detection
    for fake_char, real_char in LOOKALIKE_MAP.items():
        # Example: "0" used in google → g00gle
        if fake_char in domain and real_char in domain:
            reasons.append(f"Look-alike domain pattern ('{fake_char}' and '{real_char}' both appear).")
        elif fake_char in domain:
            reasons.append(f"Possible look-alike substitution ('{fake_char}' used instead of '{real_char}').")

    # 4️⃣ Overly long URLs (common in phishing campaigns)
    if len(url) > 100:
        reasons.append("URL is unusually long — possible obfuscation attempt.")

    # 5️⃣ Encoded characters or “@” (used for phishing redirects)
    if "%" in url or "@" in url:
        reasons.append("URL contains encoded or special redirect characters (% or @).")

    # 6️⃣ Repeated dots, hyphens, or nested subdomains (e.g., login.secure.bank.update.tk)
    if combined.count(".") > 2 or "-" in domain and len(domain) > 15:
        reasons.append("Unusually complex domain structure — possible fake site.")

    # ✅ Final result
    is_suspicious = len(reasons) > 0
    return is_suspicious, reasons

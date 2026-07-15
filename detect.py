"""Rule-based red-flag detector for the phishing message classifier.

Used both as the primary signal fed to the LLM and as the offline fallback
when the AI call is unavailable.
"""
import re

FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "rediffmail.com", "live.com", "aol.com", "icloud.com", "yopmail.com",
}

OFFICIAL_CLAIM_WORDS = [
    "scholarship board", "college administration", "university", "government",
    "ministry", "official", "placement cell", "admissions office",
    "financial aid office", "student affairs",
]

RULES = [
    {
        "category": "Urgency",
        "weight": 20,
        "patterns": [
            r"\bimmediately\b", r"\burgent(ly)?\b", r"\bact now\b",
            r"\bexpire[sd]?\b", r"\bwithin\s+\d+\s*(hours?|hrs?|minutes?)\b",
            r"\blast chance\b", r"\btoday only\b", r"\bhurry\b",
            r"\blimited time\b", r"\bdo not delay\b",
        ],
        "reason": "Creates artificial time pressure to rush you into acting without thinking.",
    },
    {
        "category": "Payment demand",
        "weight": 25,
        "patterns": [
            r"\bpay\b", r"\bfee\b", r"₹", r"\bRs\.?\s?\d", r"\$\s?\d",
            r"\bdeposit\b", r"\btransfer\b", r"\bconfirm your eligibility\b",
            r"\bprocessing charge\b", r"\bregistration amount\b",
        ],
        "reason": "Asks for money upfront — legitimate scholarships/placements never require an advance payment to 'confirm' eligibility.",
    },
    {
        "category": "Suspicious link",
        "weight": 20,
        "patterns": [
            r"https?://\S+", r"\bclick\s+(this|the)?\s*link\b", r"\bbit\.ly\b",
            r"\btinyurl\b", r"\bclick here\b",
        ],
        "reason": "Contains a link urging an immediate click — a common vector for credential harvesting.",
    },
    {
        "category": "Fake authority",
        "weight": 15,
        "patterns": [
            r"\bon behalf of\b", r"\bofficial notice\b", r"\bofficial communication\b",
            r"\bauthorized by\b", r"\bgovernment approved\b",
        ],
        "reason": "Claims institutional/government authority without any way to verify it.",
    },
    {
        "category": "Unrealistic reward",
        "weight": 20,
        "patterns": [
            r"\bcongratulations\b", r"\byou have been selected\b", r"\bguaranteed\b",
            r"\b100%\s*free\b", r"\bwinner\b", r"\bcash prize\b", r"\blucky\b",
        ],
        "reason": "Promises an unusually generous or guaranteed reward — a classic bait tactic.",
    },
    {
        "category": "Sensitive info request",
        "weight": 25,
        "patterns": [
            r"\bOTP\b", r"\bpassword\b", r"\bbank details?\b", r"\bverify your account\b",
            r"\bcard number\b", r"\bCVV\b", r"\bpin\s*number\b", r"\baadhaar\b",
        ],
        "reason": "Requests confidential personal/financial information that a legitimate sender would never ask for over message.",
    },
]

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})")


def _check_sender_email(text):
    flags = []
    match = EMAIL_RE.search(text)
    if not match:
        return flags
    email = match.group(0)
    domain = match.group(1).lower()
    lower_text = text.lower()

    claims_official = any(word in lower_text for word in OFFICIAL_CLAIM_WORDS)

    if domain in FREE_EMAIL_PROVIDERS and claims_official:
        flags.append({
            "category": "Sender email/domain",
            "matched": email,
            "reason": f"Uses a free public email provider ({domain}) while claiming to represent an official institution — real institutions send from their own domain.",
            "weight": 20,
        })
    elif domain in FREE_EMAIL_PROVIDERS:
        flags.append({
            "category": "Sender email/domain",
            "matched": email,
            "reason": f"Sent from a free public email provider ({domain}) rather than an institutional domain.",
            "weight": 10,
        })
    return flags


def analyze(text):
    flags = []
    for rule in RULES:
        for pattern in rule["patterns"]:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                flags.append({
                    "category": rule["category"],
                    "matched": match.group(0),
                    "reason": rule["reason"],
                    "weight": rule["weight"],
                })
                break  # only count each category once

    flags.extend(_check_sender_email(text))

    score = min(100, sum(f["weight"] for f in flags))

    if score >= 65:
        label = "High Risk"
    elif score >= 30:
        label = "Suspicious"
    else:
        label = "Safe"

    next_actions = {
        "High Risk": "Do not click any links, reply, or pay anything. Report this message to your college administration or cybercrime.gov.in.",
        "Suspicious": "Do not act on this message yet. Verify directly with the official institution using a known contact (their official website/phone), not the details given in the message.",
        "Safe": "No red flags detected, but always double-check unfamiliar senders before sharing personal information.",
    }

    red_flags = [{"category": f["category"], "matched": f["matched"], "reason": f["reason"]} for f in flags]

    return {
        "score": score,
        "label": label,
        "red_flags": red_flags,
        "explanation": build_explanation(label, red_flags),
        "next_action": next_actions[label],
    }


def build_explanation(label, red_flags):
    if not red_flags:
        return "No known phishing patterns were detected in this message. It reads as a routine, low-risk communication."
    categories = ", ".join(sorted(set(f["category"] for f in red_flags)))
    tone = {
        "High Risk": "These are strong signals of a scam attempt.",
        "Suspicious": "These signals suggest caution before acting on this message.",
        "Safe": "Review carefully before proceeding.",
    }.get(label, "Review carefully before proceeding.")
    return f"This message shows {len(red_flags)} phishing indicator(s) across: {categories}. {tone}"

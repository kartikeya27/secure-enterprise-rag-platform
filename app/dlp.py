"""Illustrative DLP only: SSN/email/Luhn-validated payment card candidates."""
import re

SSN = re.compile(r'(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)')
EMAIL = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
CARD_CANDIDATE = re.compile(r'(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)')
INJECTION = re.compile(r'(?i)(ignore (all |any )?(previous|prior) instructions|reveal (the )?(system|developer) prompt|bypass (your )?safety rules|exfiltrate secrets)')


def luhn_valid(value: str) -> bool:
    digits = [int(c) for c in value if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, number in enumerate(reversed(digits)):
        if i % 2:
            number *= 2
            if number > 9:
                number -= 9
        total += number
    return total % 10 == 0


def detect_pii(text: str) -> set[str]:
    found = set()
    if SSN.search(text):
        found.add('ssn')
    if EMAIL.search(text):
        found.add('email')
    if any(luhn_valid(m.group()) for m in CARD_CANDIDATE.finditer(text)):
        found.add('payment_card')
    return found


def redact(text: str) -> str:
    text = SSN.sub('[REDACTED_SSN]', text)
    text = EMAIL.sub('[REDACTED_EMAIL]', text)
    text = CARD_CANDIDATE.sub(lambda m: '[REDACTED_PAYMENT_CARD]' if luhn_valid(m.group()) else m.group(), text)
    return text


def has_prompt_injection_indicators(text: str) -> bool:
    return bool(INJECTION.search(text))

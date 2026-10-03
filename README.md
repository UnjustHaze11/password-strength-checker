# Password Strength Checker

A NIST SP 800-63B compliant internal audit tool for evaluating password strength and recommending remediation strategies. Designed for organizations without hard-enforced password policies to quickly identify credential weaknesses and attack vectors.

## Overview

This tool evaluates a list of passwords against industry best practices and returns:
- **Strength Rating** (Weak, Fair, Good, Strong, Very Strong)
- **Numerical Score** (0–10)
- **Actionable Feedback** for remediation

## Features

### Alignment with NIST SP 800-63B
- **Favors length over arbitrary complexity rules** – NIST recommends 8+ characters minimum, with 12+ as a strong baseline
- **Blacklist and breach detection** – Checks passwords against common breach lists and dictionary words
- **Pattern avoidance** – Flags keyboard sequences, repeated characters, and common years
- **Character variety** – Rewards diversity without requiring it as a hard gate
- **User-friendly feedback** – Returns specific, actionable suggestions rather than vague rejection

### Key Checks
1. **Length Scoring**
   - < 8 characters: Fail
   - 8–11 characters: Weak/Fair (points deducted)
   - 12–15 characters: Good
   - 16+ characters: Excellent

2. **Character Variety**
   - Lowercase letters
   - Uppercase letters
   - Numbers
   - Symbols

3. **Pattern Detection**
   - Repeated characters (aaa, 111)
   - Keyboard sequences (qwerty, asdfgh, 123)
   - Common years (1990, 2023)

4. **Blacklist / Darklist Checks**
   - Direct password matches against known breached passwords
   - Detection of embedded common words (admin, password, etc.)

## Requirements

- Python 3.6+
- No external dependencies (uses only standard library)

## Installation

```bash
git clone https://github.com/UnjustHaze11/password-strength-checker.git
cd password-strength-checker
```

## Usage

### Basic Usage: Audit a Password List

```bash
python3 password_checker.py
```

This reads passwords from `sample_passwords.txt` and evaluates them against the darklist in `wordlist.txt`.

### Expected Output

```
======================================================================
Password Strength Audit Report
======================================================================

[1] Password: password
    Rating: Weak (Score: 0/10)
    Feedback:
      • Password is too short. Add at least 8 characters.
      • This password is in a known breach or common password list.

[2] Password: MySecurePass2023!
    Rating: Very Strong (Score: 10/10)
    Feedback:
      • Password meets basic requirements.

...

======================================================================
Summary
======================================================================
Total passwords checked:    100
Very Strong:                15
Strong:                     28
Good:                       31
Fair:                       18
Weak:                        8

⚠️  Passwords needing improvement: 26 (26.0%)
======================================================================
```

## File Structure

- **`password_checker.py`** – Main script with `PasswordChecker` class
- **`wordlist.txt`** – Darklist of common passwords and dictionary words
- **`sample_passwords.txt`** – 100 sample passwords for testing (~25% weak/fair, ~75% good/strong/very strong)
- **`README.md`** – Complete documentation with NIST alignment and usage examples
- **`requirements.txt`** – Dependencies (currently empty; no external packages required)

## Customization

### Load Your Own Password File

```python
from password_checker import PasswordChecker

checker = PasswordChecker(darklist_path="wordlist.txt")
checker.check_passwords_from_file("your_passwords.txt")
```

### Programmatic Usage

```python
from password_checker import PasswordChecker

checker = PasswordChecker(darklist_path="wordlist.txt")

result = checker.evaluate_password("MyP@ssw0rd2024!")
print(result)
# Output:
# {
#   'password': 'MyP@ssw0rd2024!',
#   'rating': 'Very Strong',
#   'score': 10,
#   'feedback': ['Password meets basic requirements.']
# }
```

### Extend the Darklist

Add more common passwords or dictionary words to `wordlist.txt` (one per line):

```text
password
qwerty
...
mycompanyname
secretproject
```

## Scoring Model

| Component | Points |
|-----------|--------|
| Length 8–11 chars | 1 |
| Length 12–15 chars | 2 |
| Length 16+ chars | 3 |
| Lowercase | 1 |
| Uppercase | 1 |
| Digits | 1 |
| Symbols | 1 |
| **Base Max** | **10** |

**Penalties:**
- Common pattern detected: −1 per pattern
- Blacklisted/breached: −2

**Ratings:**
- 0–2: **Weak**
- 3–4: **Fair**
- 5–6: **Good**
- 7–8: **Strong**
- 9–10: **Very Strong**

## Feedback Examples

| Issue | Feedback |
|-------|----------|
| Too short | "Add at least 8 characters." |
| Missing variety | "Add uppercase letters." |
| Common word | "Contains common word 'admin'. Use unique, non-dictionary words." |
| Sequences | "Avoid keyboard sequences like 'qwerty'." |
| Repeated chars | "Avoid repeated characters (e.g., aaa, 111)." |
| Breached | "This password is in a known breach or common password list." |
| Year | "Avoid using years (e.g., 1990, 2023)." |

## NIST Alignment Notes

This tool aligns with NIST SP 800-63B Section 5.1.1 (Memorized Secret Verifiers):

✅ **Enforced:**
- Minimum 8-character length
- Blacklist checking (breach list)
- Feedback for user-selectable passwords
- No arbitrary composition rules as hard gates

✅ **Recommended:**
- 12+ characters for higher security
- Length over complexity
- Clear, actionable user guidance

⚠️ **Not Enforced (by design):**
- Hard requirement for all character classes (confuses users)
- Expiration or rotation policies (use MFA instead)
- Hint systems (disclosed in breach)

## Use Cases

1. **Internal Audit** – Scan user passwords against NIST standards before policy deployment
2. **Password Reset Campaigns** – Identify weak credentials requiring immediate update
3. **Onboarding Verification** – Check initial passwords from batch user imports
4. **Policy Validation** – Verify policy-enforced passwords meet expected standards
5. **Incident Response** – Rapid credential strength assessment in security incidents

## Limitations

- Does not interact with Active Directory or other identity systems
- Does not enforce password changes
- Not a replacement for MFA or hard password policies (e.g., via AD)
- Requires manual file input/output (no API yet)

## Future Enhancements

- [ ] Interactive CLI for single-password checks
- [ ] API endpoint for integration with identity systems
- [ ] Import/export to CSV
- [ ] Configurable darklist weights
- [ ] Integration with Troy Hunt's "Pwned Passwords" API
- [ ] Support for additional languages in wordlist

## License

Internal use only. Not for redistribution without authorization.

## References

- **NIST SP 800-63B**: [https://pages.nist.gov/800-63-3/sp800-63b.html](https://pages.nist.gov/800-63-3/sp800-63b.html)
- **OWASP Password Guidelines**: [https://owasp.org/www-community/vulnerabilities/Weak_Password_Requirements](https://owasp.org/www-community/vulnerabilities/Weak_Password_Requirements)

---

**Status:** Ready for internal audit pilot  
**Last Updated:** 2024

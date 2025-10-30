# password_checker.py

import re

# small list of common weak passwords
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345",
    "qwerty", "abc123", "111111", "123123", "password1", "password123", "987654321"
}

KEYBOARD_SEQS = [
    "qwerty", "asdf", "zxcv", "1234", "4321", "abcd", "dcba"
]

def score_length(pw: str) -> int:
    n = len(pw)
    if n < 8:
        return 0
    if 8 <= n <= 10:
        return 1
    if 11 <= n <= 14:
        return 2
    if 15 <= n <= 20:
        return 3
    return 4

def has_lower(pw: str) -> bool:
    return bool(re.search(r"[a-z]", pw))

def has_upper(pw: str) -> bool:
    return bool(re.search(r"[A-Z]", pw))

def has_digit(pw: str) -> bool:
    return bool(re.search(r"\d", pw))

def has_special(pw: str) -> bool:
    return bool(re.search(r"[^\w\s]", pw))

def repeated_chars_penalty(pw: str) -> int:
    # penalize long runs of same char, e.g. "aaaaaa"
    max_run = 1
    run = 1
    for i in range(1, len(pw)):
        if pw[i] == pw[i-1]:
            run += 1
            max_run = max(max_run, run)
        else:
            run = 1
    if max_run >= 6:
        return -2
    if max_run >= 4:
        return -1
    return 0

def keyboard_sequence_penalty(pw: str) -> int:
    lower = pw.lower()
    for seq in KEYBOARD_SEQS:
        if seq in lower:
            return -1
    # detect numeric simple sequences like 12345 or 54321
    if re.search(r"(012345|123456|234567|345678|456789|987654|876543)", lower):
        return -1
    return 0

def common_password_penalty(pw: str) -> int:
    if pw.lower() in COMMON_PASSWORDS:
        return -3
    return 0

def evaluate_password(pw: str) -> dict:
    if pw is None:
        pw = ""
    score = 0
    feedback = []

    # length
    len_score = score_length(pw)
    score += len_score

    # character classes
    lower = has_lower(pw)
    upper = has_upper(pw)
    digit = has_digit(pw)
    special = has_special(pw)

    score += 1 if lower else 0
    score += 1 if upper else 0
    score += 1 if digit else 0
    score += 1 if special else 0

    # variety bonus
    classes = sum([lower, upper, digit, special])
    if classes >= 4:
        score += 2
    elif classes == 3:
        score += 1

    # penalties
    p_common = common_password_penalty(pw)
    p_repeat = repeated_chars_penalty(pw)
    p_seq = keyboard_sequence_penalty(pw)
    score += p_common + p_repeat + p_seq

    # normalize minimum
    if score < 0:
        score = 0

    # max possible roughly 4(length)+4(classes)+2(bonus)=10
    # Map to label
    if score <= 2:
        label = "Very Weak"
    elif score <= 4:
        label = "Weak"
    elif score <= 6:
        label = "Moderate"
    elif score <= 8:
        label = "Strong"
    else:
        label = "Very Strong"

    # Feedback messages
    if len(pw) < 8:
        feedback.append("Password is too short, use at least 12 characters for better security.")
    elif len(pw) < 12:
        feedback.append("Consider increasing password length to 12 or more characters.")

    if not lower:
        feedback.append("Add lowercase letters.")
    if not upper:
        feedback.append("Add uppercase letters.")
    if not digit:
        feedback.append("Add digits.")
    if not special:
        feedback.append("Add special characters, like !@#$%.")

    if p_common < 0:
        feedback.append("This password is commonly used, do not use common passwords.")
    if p_repeat < 0:
        feedback.append("Avoid long repeated characters, like 'aaaaaa'.")
    if p_seq < 0:
        feedback.append("Avoid simple sequences or keyboard patterns like '12345' or 'qwerty'.")

    if not feedback:
        feedback.append("Good password composition, consider using a password manager for long unique passwords.")

    return {
        "score": score,
        "label": label,
        "feedback": feedback,
        "details": {
            "length": len(pw),
            "has_lower": lower,
            "has_upper": upper,
            "has_digit": digit,
            "has_special": special,
            "penalties": {"common": p_common, "repeat": p_repeat, "sequence": p_seq}
        }
    }

def main():
    print("Password Complexity Checker")
    pw = input("Enter the password to evaluate: ")
    result = evaluate_password(pw)

    print(f"\nStrength: {result['label']} (score {result['score']})\n")
    print("Feedback:")
    for f in result["feedback"]:
        print("-", f)

if __name__ == "__main__":
    main()

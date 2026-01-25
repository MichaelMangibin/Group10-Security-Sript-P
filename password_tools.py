import re
import secrets
import string
import hashlib
from datetime import datetime
from constants import SPECIALS


def generate_password() -> str:
    """
    Generates a secure random password:
    - length 8 to 16 (inclusive)
    - at least 1 uppercase, 1 lowercase, 1 digit, 1 special (from SPECIALS)
    - uses secrets for randomness
    """
    length = secrets.choice(range(8, 17))  # 8..16 inclusive

    # Guarantee required categories
    chars = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice(SPECIALS),
    ]

    # Fill the remaining characters from the full allowed pool
    all_allowed = string.ascii_letters + string.digits + SPECIALS
    chars += [secrets.choice(all_allowed) for _ in range(length - 4)]

    # Shuffle so required chars are not in predictable positions
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def hash_password_sha256(password: str) -> str:
    """Return SHA-256 hash of password (hex)."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def get_timestamp() -> str:
    """Return a readable timestamp."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def save_password_entry(
    timestamp: str,
    password: str,
    password_hash: str,
    filename: str = "passwords.txt"
) -> None:
    """
    Append entry to passwords.txt (does not overwrite existing entries).
    Required format:
    Timestamp: ...
    Password: ...
    Hash: ...
    """
    try:
        with open(filename, "a", encoding="utf-8") as f:
            f.write(f"Timestamp: {timestamp}\n")
            f.write(f"Password: {password}\n")
            f.write(f"Hash: {password_hash}\n")
            f.write("-" * 40 + "\n")
    except OSError as e:
        # Raise a clean error so the GUI can show messagebox error
        raise RuntimeError(f"Could not write to {filename}: {e}") from e


def check_password_strength(password: str) -> tuple[str, list[str]]:
    """
    Simple strength checker for Milestone 1.
    Returns (rating, tips).

    Improvements:
    - Uses SPECIALS set for special-character requirement (matches assignment)
    - Adds minimum length (8) tip (matches assignment)
    """
    tips: list[str] = []
    score = 0

    # Hard requirement tip for assignment alignment
    if len(password) < 8:
        tips.append("Password must be at least 8 characters (assignment rule).")

    # Strength length rule (stronger threshold)
    if len(password) >= 12:
        score += 1
    else:
        tips.append("Use at least 12 characters for better strength.")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        tips.append("Add an uppercase letter (A–Z).")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        tips.append("Add a lowercase letter (a–z).")

    if re.search(r"\d", password):
        score += 1
    else:
        tips.append("Add a number (0–9).")

    # IMPORTANT: check special characters ONLY from the allowed set
    specials_pattern = f"[{re.escape(SPECIALS)}]"
    if re.search(specials_pattern, password):
        score += 1
    else:
        tips.append(f"Add a special character from this set: {SPECIALS}")

    # Score is 0..5, map to labels
    labels = ["Very Weak", "Weak", "Fair", "Good", "Strong", "Very Strong"]
    return labels[score], tips

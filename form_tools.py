import re
import html
from constants import MAX_EMAIL_LEN, MAX_MESSAGE_LEN, SQL_KEYWORDS, SQL_INJECTION_PATTERN


def sanitize_text_basic(text: str) -> tuple[str, list[str]]:
    """
    Clean text by:
    - stripping extra spaces
    - escaping HTML characters like < and >
    Returns (cleaned_text, notes).
    """
    notes = []
    original = text

    text = "" if text is None else text.strip()
    if original is not None and text != original:
        notes.append("Extra whitespace removed.")

    escaped = html.escape(text)
    if escaped != text:
        notes.append("HTML characters escaped.")

    return escaped, notes


def remove_prohibited_patterns(message: str) -> tuple[str, list[str]]:
    """
    Remove/neutralize suspicious patterns in message:
    - <script>...</script>
    - <img ...>
    - SQL keywords (simple list)
    - classic injection example
    Returns (cleaned_message, notes).
    """
    notes = []

    cleaned = re.sub(r"(?is)<\s*script.*?>.*?<\s*/\s*script\s*>", "", message)
    if cleaned != message:
        notes.append("Script tag removed.")
    message = cleaned

    cleaned = re.sub(r"(?is)<\s*img.*?>", "", message)
    if cleaned != message:
        notes.append("IMG tag removed.")
    message = cleaned

    cleaned = re.sub(SQL_KEYWORDS, "[REMOVED]", message)
    if cleaned != message:
        notes.append("SQL keyword(s) removed.")
    message = cleaned

    cleaned = re.sub(SQL_INJECTION_PATTERN, "[REMOVED]", message)
    if cleaned != message:
        notes.append("SQL injection pattern removed.")
    message = cleaned

    return message, notes


def validate_full_name(name: str) -> tuple[bool, list[str]]:
    """
    Full Name rules:
    - at least 2 characters
    - no numbers
    - only letters, spaces, hyphens, apostrophes
    """
    errors = []

    if len(name) < 2:
        errors.append("Full Name must be at least 2 characters long.")
    if re.search(r"\d", name):
        errors.append("Full Name must not contain numbers.")
    if not re.fullmatch(r"[A-Za-z\s\-']+", name):
        errors.append("Full Name can only use letters, spaces, hyphens, and apostrophes.")

    return (len(errors) == 0), errors


def validate_email(email: str) -> tuple[bool, list[str]]:
    """
    Email rules:
    - contains '@'
    - contains a domain like .com/.org
    - no spaces
    - cannot start with special character
    """
    errors = []

    if len(email) > MAX_EMAIL_LEN:
        errors.append("Email is too long.")

    if " " in email:
        errors.append("Invalid email format (contains spaces).")

    if not email or "@" not in email:
        errors.append("Invalid email format (missing '@').")
    else:
        at_index = email.find("@")
        if "." not in email[at_index:]:
            errors.append("Invalid email format (missing domain like .com).")

    if email and not re.match(r"^[A-Za-z0-9]", email):
        errors.append("Email cannot start with a special character.")

    return (len(errors) == 0), errors


def validate_username(username: str) -> tuple[bool, list[str]]:
    """
    Username rules:
    - 4 to 16 characters
    - only letters, numbers, underscore
    - cannot start with a number
    """
    errors = []

    if not (4 <= len(username) <= 16):
        errors.append("Username must be 4–16 characters long.")
    if not re.fullmatch(r"[A-Za-z0-9_]+", username):
        errors.append("Username may only contain letters, numbers, and underscores.")
    if username and username[0].isdigit():
        errors.append("Username cannot start with a number.")

    return (len(errors) == 0), errors


def validate_message(message: str) -> tuple[bool, list[str]]:
    """
    Message rules:
    - not empty
    - max 250 chars
    - must not contain prohibited patterns
    """
    errors = []

    if len(message.strip()) == 0:
        errors.append("Message must not be empty.")
    if len(message) > MAX_MESSAGE_LEN:
        errors.append("Message must not exceed 250 characters.")

    if re.search(r"(?is)<\s*script", message):
        errors.append("The message contains prohibited HTML tag: <script>.")
    if re.search(r"(?is)<\s*img", message):
        errors.append("The message contains prohibited HTML tag: <img>.")
    if re.search(SQL_KEYWORDS, message):
        errors.append("The message contains prohibited SQL keywords.")
    if re.search(SQL_INJECTION_PATTERN, message):
        errors.append("The message contains a prohibited SQL injection pattern.")

    return (len(errors) == 0), errors
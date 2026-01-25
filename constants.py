# Password generator allowed special characters (per assignment set)
SPECIALS = "!@#$%^&*()_-+={}[];:,.?"

# Web form limits (coursework-friendly)
MAX_EMAIL_LEN = 254
MAX_MESSAGE_LEN = 250

# Suspicious SQL keywords (simple coursework-level list)
SQL_KEYWORDS = r"(?i)\b(SELECT|DROP|INSERT|UPDATE|DELETE|UNION|ALTER|CREATE)\b"

# Classic injection pattern example
SQL_INJECTION_PATTERN = r"(?i)(\'|\")\s*OR\s*(\'|\")1(\'|\")\s*=\s*(\'|\")1"

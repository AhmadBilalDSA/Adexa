# ADEXA Web Engine - Signature Database

SIGNATURES = {

    # --- SQL Injection ---
    "SQLI_BASIC": {
        "keywords": ["' OR '1'='1", "\" OR \"1\"=\"1", "'--", "\"--", "UNION SELECT"],
        "description": "Possible SQL Injection attempt",
        "severity": "high"
    },

    "SQLI_TIME": {
        "keywords": ["SLEEP(", "WAITFOR DELAY", "pg_sleep("],
        "description": "Time-based SQL injection indicator",
        "severity": "high"
    },

    # --- XSS ---
    "XSS_BASIC": {
        "keywords": ["<script>", "onerror=", "javascript:"],
        "description": "Reflected or stored XSS payload detected",
        "severity": "medium"
    },

    # --- Command Injection ---
    "CMD_INJECTION": {
        "keywords": ["; ls", "&& whoami", "| id", "; cat /etc/passwd"],
        "description": "Command injection attempt",
        "severity": "critical"
    },

    # --- Path Traversal ---
    "PATH_TRAVERSAL": {
        "keywords": ["../", "..\\", "/etc/passwd", "C:\\Windows\\system.ini"],
        "description": "Directory traversal attack",
        "severity": "high"
    },

    # --- SSTI ---
    "SSTI": {
        "keywords": ["{{7*7}}", "${7*7}", "<%= 7*7 %>"],
        "description": "Server-Side Template Injection attempt",
        "severity": "critical"
    }
}

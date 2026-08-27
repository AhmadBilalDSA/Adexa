from web_engine.signature_db import SIGNATURES

def detect_vulnerabilities(request):
    """
    request = {
        'method': 'GET',
        'path': '/search?q=test',
        'headers': {...},
        'body': '...'
    }
    """
    findings = []

    text = (request.get("path", "") + " " + request.get("body", "")).lower()

    for sig_name, sig in SIGNATURES.items():
        for kw in sig["keywords"]:
            if kw.lower() in text:
                findings.append({
                    "signature": sig_name,
                    "description": sig["description"],
                    "severity": sig["severity"],
                    "keyword": kw
                })

    return findings

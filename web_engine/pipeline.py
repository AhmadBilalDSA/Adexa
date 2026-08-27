from web_engine.web_ai import analyze_web_vulnerability
from web_engine.request_parser import parse_request
from web_engine.vuln_detector import detect_vulnerabilities
from web_engine.poc_generator import generate_poc


def analyze_web_request(raw_input):
    """
    Full ADEXA Web Pipeline:
    1. Parse HTTP request or curl command
    2. Detect vulnerabilities
    3. Generate exploit PoCs
    4. AI reasoning engine
    5. Return structured results
    """

    # 1. PARSE INPUT
    parsed = parse_request(raw_input)
    print("\n[+] Parsed Request:")
    print(parsed)

    # 2. DETECT VULNERABILITIES
    vulns = detect_vulnerabilities(parsed)
    print("\n[+] Detected Vulnerabilities:")
    print(vulns)

    # 3. PoC GENERATION
    pocs = {}
    for v in vulns:
        sig = v["signature"]
        pocs[sig] = generate_poc(v, parsed)

    print("\n[+] Generated PoCs:")
    for vuln, poc in pocs.items():
        print(f"\n--- {vuln} ---")
        print(poc)

    # 4. AI Analysis
    ai_analysis = []
    for v in vulns:
        ai_analysis.append(analyze_web_vulnerability(v, parsed))

    print("\n[+] AI Reasoning:")
    for item in ai_analysis:
        print(f"\n--- {item['signature']} ---")
        print("Reason:", item["explanation"])
        print("Impact:", item["impact"])
        print("Payloads:", item["recommended_payloads"])
        print("Bypasses:", item["waf_bypasses"])

    # 5. RETURN STRUCTURED RESULT
    return {
        "request": parsed,
        "vulnerabilities": vulns,
        "pocs": pocs,
        "ai_analysis": ai_analysis
    }


# Standalone quick tester
if __name__ == "__main__":
    sample = """GET /search?q=test HTTP/1.1
Host: target.com
User-Agent: Mozilla
"""
    analyze_web_request(sample)

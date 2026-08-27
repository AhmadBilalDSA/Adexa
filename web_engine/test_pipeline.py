from web_engine.pipeline import analyze_web_request

test_request = """POST /login HTTP/1.1
Host: victim.com
Content-Type: application/x-www-form-urlencoded

username=admin' OR '1'='1&password=test
"""

print("\n=== RUNNING ADEXA WEB PIPELINE ===\n")

result = analyze_web_request(test_request)

print("\n=== FINAL OUTPUT ===")
print(result)

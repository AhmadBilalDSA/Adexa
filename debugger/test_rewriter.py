import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ai_engine.exploit_rewriter import rewrite_exploit

# Fake exploit for testing
exploit_code = """
buffer = b"A" * 200
payload = buffer
"""

analysis = {
    "offset_fix": 120,
    "badchars": ["00", "0a"]
}

new_code = rewrite_exploit(exploit_code, analysis)

print("=== OLD CODE ===")
print(exploit_code)
print("\n=== NEW CODE (AUTO-FIXED) ===")
print(new_code)


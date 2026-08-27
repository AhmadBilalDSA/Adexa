from request_parser import parse_request

# Test Case 1: Raw HTTP request
raw_http = """POST /login HTTP/1.1
Host: target.com
User-Agent: Mozilla
Content-Type: application/x-www-form-urlencoded

username=admin&password=admin
"""

print("\n=== RAW HTTP TEST ===")
print(parse_request(raw_http))


# Test Case 2: curl command
curl_cmd = 'curl -X POST http://example.com/api/login -d "user=test&pass=1234"'

print("\n=== CURL TEST ===")
print(parse_request(curl_cmd))


# Test Case 3: GET request
raw_get = """GET /search?q=test HTTP/1.1
Host: site.com
Accept: */*
"""

print("\n=== GET REQUEST TEST ===")
print(parse_request(raw_get))

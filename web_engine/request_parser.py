# ADEXA Web Engine - Request Parser
# This module converts raw HTTP requests (from Burp, curl, browser copy/paste)
# into structured Python dictionaries for analysis.

import re

def parse_raw_http(data):
    """
    Convert raw HTTP request text into a structured dict.
    
    Returns:
    {
        "method": "GET",
        "path": "/login?user=admin",
        "headers": { "Host": "example.com", ... },
        "body": "username=admin&password=pass"
    }
    """

    lines = data.splitlines()
    if not lines:
        return None

    # --- 1. Parse request line (GET /path HTTP/1.1) ---
    request_line = lines[0].strip().split()
    if len(request_line) < 2:
        return None

    method = request_line[0]
    path = request_line[1]

    # --- 2. Parse headers ---
    headers = {}
    body = ""
    reached_body = False

    for line in lines[1:]:
        if line.strip() == "" and not reached_body:
            reached_body = True
            continue

        if not reached_body:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip()] = value.strip()
        else:
            body += line + "\n"

    body = body.strip()

    return {
        "method": method,
        "path": path,
        "headers": headers,
        "body": body
    }


def parse_curl(cmd):
    """
    Convert a curl command into a structured request dictionary.
    Example:
    curl -X POST https://site.com/login -d "user=admin&pass=123"
    """

    method = "GET"
    body = ""
    url = ""

    # Method override: -X POST
    match = re.search(r"-X\s+(\w+)", cmd)
    if match:
        method = match.group(1)

    # Data: -d "..."
    match = re.search(r"-d\s+\"(.*?)\"", cmd)
    if match:
        body = match.group(1)

    # URL at the end of the command
    parts = cmd.split()
    for p in parts:
        if p.startswith("http://") or p.startswith("https://"):
            url = p
            break

    # Extract path from URL
    path = "/"
    if "/" in url[8:]:  # after http://
        path = "/" + url.split("/", 3)[3]

    return {
        "method": method,
        "path": path,
        "headers": {},
        "body": body
    }


def parse_request(data):
    """
    Automatically detect whether the request is:
      ✓ Raw HTTP request
      ✓ curl command
      ✓ Possibly malformed but still parsable
    """

    data = data.strip()

    if data.startswith("GET ") or data.startswith("POST "):
        return parse_raw_http(data)

    if data.startswith("curl "):
        return parse_curl(data)

    return None


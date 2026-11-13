#!/usr/env/bin python3
import datetime
import socket
import ssl
import urllib.error
import urllib.request

try:
    from cvss import CVSS3

    HAS_CVSS_LIB = True

except ImportError:
    HAS_CVSS_LIB = False


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def log_finding(title, default_severity, cvss_vector, default_score, remediation):
    if HAS_CVSS_LIB:
        c = CVSS3(cvss_vector)
        score = c.scores()[0]
        severity = c.severities()[0].upper()
    else:
        score = default_score
        severity = default_severity

    print(f"[{severity}] {title} (CVSS: {score} | {cvss_vector})")
    print(f"       Fix: {remediation}")


def check_http_redirect(hostname):
    print("\n[HTTP -> HTTPS Redirect Check]")
    opener = urllib.request.build_opener(NoRedirectHandler)
    req = urllib.request.Request(
        f"http://{hostname}",
        method="GET",
        headers={"User-Agent": "Mozilla/5.0 (Security-Audit-Script)"},
    )
    try:
        with opener.open(req, timeout=5):
            log_finding(
                title="Unencrypted HTTP accessible without HTTPS redirect",
                default_severity="HIGH",
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                default_score=7.4,
                remediation=f"Configure server to return a 301 redirect to https://{hostname}",
            )
    except urllib.error.HTTPError as e:
        location = e.headers.get("Location", "")
        if e.code in (301, 302, 307, 308) and location.startswith("https://"):
            print(f"[PASS] Redirects properly ({e.code} -> {location})")
        else:
            log_finding(
                title=f"Insecure or unexpected HTTP redirect (Status: {e.code})",
                default_severity="MEDIUM",
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
                default_score=5.3,
                remediation=f"Ensure port 80 redirects directly to https://{hostname}",
            )
    except OSError as e:
        print(f"[INFO] Port 80 unreachable or closed ({e})")


def check_cookies(raw_headers):
    print("\n[Cookie Security Flags]")
    cookies = [v for k, v in raw_headers if k.lower() == "set-cookie"]
    if not cookies:
        print("[INFO] No Set-Cookie headers returned.")
        return

    for cookie in cookies:
        cookie_name = cookie.split("=", 1)[0].strip()
        cookie_lower = cookie.lower()

        missing_flags = []
        if "secure" not in cookie_lower:
            missing_flags.append("Secure")
        if "httponly" not in cookie_lower:
            missing_flags.append("HttpOnly")
        if "samesite" not in cookie_lower:
            missing_flags.append("SameSite")

        if not missing_flags:
            print(f"[PASS] Cookie '{cookie_name}' has Secure, HttpOnly, and SameSite")
        else:
            log_finding(
                title=f"Cookie '{cookie_name}' missing flags: {', '.join(missing_flags)}",
                default_severity="MEDIUM",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                default_score=5.4,
                remediation=f"Append {'; '.join(missing_flags)} attributes to Set-Cookie header.",
            )


def audit_target(hostname, port=443):
    print(f"--- Security Audit for {hostname} ---")
    context = ssl.create_default_context()

    try:
        with (
            socket.create_connection((hostname, port), timeout=5) as sock,
            context.wrap_socket(sock, server_hostname=hostname) as ssock,
        ):
            cert = ssock.getpeercert()
            protocol = ssock.version()
            cipher = ssock.cipher()

            not_after = datetime.datetime.strptime(
                cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=datetime.UTC)
            now = datetime.datetime.now(datetime.UTC)
            days_left = (not_after - now).days

            print(f"[TLS] Protocol: {protocol} (Cipher: {cipher[0]})")
            print(f"[TLS] Certificate expires in {days_left} days ({cert['notAfter']})")

            if protocol in ("TLSv1", "TLSv1.1"):
                log_finding(
                    title=f"Outdated TLS protocol detected ({protocol})",
                    default_severity="HIGH",
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    default_score=5.9,
                    remediation="Upgrade server configuration to TLS 1.2 or 1.3.",
                )
            if days_left < 30:
                log_finding(
                    title=f"Certificate expires soon ({days_left} days left)",
                    default_severity="LOW",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                    default_score=3.7,
                    remediation="Renew TLS certificate before expiration.",
                )

    except ssl.SSLCertVerificationError as e:
        log_finding(
            title=f"Certificate verification failed: {e}",
            default_severity="CRITICAL",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            default_score=9.1,
            remediation="Install a valid certificate signed by a trusted CA.",
        )
        return

    except OSError as e:
        print(f"[ERROR] Connection failed: {e}")
        return

    check_http_redirect(hostname)

    expected_headers = {
        "Strict-Transport-Security": (
            "Enforces HTTPS connections (HSTS)",
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
            5.3,
            "Add Strict-Transport-Security: max-age=31536000; includeSubDomains",
        ),
        "Content-Security-Policy": (
            "Mitigates Cross-Site Scripting (XSS) and data injection",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            6.1,
            "Define a strict Content-Security-Policy header.",
        ),
        "X-Content-Type-Options": (
            "Prevents MIME-sniffing vulnerabilities",
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",
            3.1,
            "Set X-Content-Type-Options: nosniff",
        ),
        "X-Frame-Options": (
            "Protects against clickjacking attacks",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
            4.3,
            "Set X-Frame-Options: DENY or SAMEORIGIN",
        ),
        "Referrer-Policy": (
            "Controls how much referrer information is shared",
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
            3.1,
            "Set Referrer-Policy: strict-origin-when-cross-origin",
        ),
    }

    try:
        url = f"https://{hostname}"
        req = urllib.request.Request(
            url,
            method="GET",
            headers={"User-Agent": "Mozilla/5.0 (Security-Audit-Script)"},
        )

        try:
            response = urllib.request.urlopen(req, timeout=5)
            status_code = response.status
            raw_headers = response.getheaders()

        except urllib.error.HTTPError as e:
            status_code = e.code
            raw_headers = e.headers.items()
            print(
                f"\n[INFO] Server returned HTTP {status_code}, inspecting headers"
                " anyway..."
            )

        headers = {k.lower(): v for k, v in raw_headers}

        print(f"\n[HTTP Security Headers] (Status: {status_code})")
        for header, (description, vector, score, fix) in expected_headers.items():
            if header.lower() in headers:
                print(f"[PASS] {header}: {headers[header.lower()]}")
            else:
                severity = "MEDIUM" if score >= 4.0 else "LOW"
                log_finding(
                    title=f"Missing {header} ({description})",
                    default_severity=severity,
                    cvss_vector=vector,
                    default_score=score,
                    remediation=fix,
                )

        check_cookies(raw_headers)

    except OSError as e:
        print(f"[ERROR] HTTP request failed: {e}")


if __name__ == "__main__":
    targets = [
        "github.com",
        "dallascollege.edu",
        "tccd.edu",
        "uta.edu",
        "utsa.edu",
        "dsu.edu",
        "acmuta.com",
        "utacsec.com",
        "lugtnuts.org",
        "dsucomputer.club",
        "ctf.club",
        "offsec.club",
        "defsec.club",
        "disa.mil",
        "nsa.gov",
        "fbi.gov",
        "cia.gov",
        "cisa.gov",
        "nga.mil",
        "chatgpt.com",
        "chat.openai.com",
        "api.openai.com",
        "openai.com",
        "openai.org",
        "patchtheplanet.org",
        "claude.ai",
        "claude.com",
        "anthropic.com",
        "cloudflare.com",
        "google.com",
    ]

    for domain in targets:
        audit_target(domain)
        print("\n" + "=" * 45 + "\n")

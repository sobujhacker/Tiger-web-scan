import re
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup

def item(name, status, severity, url, evidence, fix, category="OWASP review"):
    return {"name": name, "status": status, "severity": severity, "url": url,
            "evidence": evidence[:350], "fix": fix, "category": category}

def analyze_response(url, resp, soup, body):
    out, h = [], {k.lower(): v for k, v in resp.headers.items()}
    if urlparse(url).scheme == "https" and "strict-transport-security" not in h:
        out.append(item("Missing HSTS", "Finding", "Medium", url,
                        "HTTPS response did not include Strict-Transport-Security.",
                        "Enable HSTS after confirming all subdomains support HTTPS.",
                        "Security Misconfiguration"))
    if "content-security-policy" not in h:
        out.append(item("Missing Content-Security-Policy", "Finding", "Medium", url,
                        "CSP response header was not observed.",
                        "Define a restrictive CSP and test it in report-only mode first.",
                        "Security Misconfiguration"))
    for header, label, sev, fix in [
        ("x-content-type-options", "Missing X-Content-Type-Options", "Low",
         "Set X-Content-Type-Options: nosniff."),
        ("referrer-policy", "Missing Referrer-Policy", "Low",
         "Set a privacy-appropriate Referrer-Policy."),
        ("permissions-policy", "Missing Permissions-Policy", "Info",
         "Restrict browser features not required by the application."),
        ("x-frame-options", "Missing clickjacking protection header", "Low",
         "Use CSP frame-ancestors; consider X-Frame-Options for legacy clients.")
    ]:
        if header not in h:
            out.append(item(label, "Finding", sev, url, f"{header} header not observed.",
                            fix, "Security Misconfiguration"))
    if "server" in h:
        out.append(item("Server banner disclosure", "Finding", "Low", url,
                        "Server response header: " + h["server"][:100],
                        "Minimize unnecessary server/version disclosure.",
                        "Security Misconfiguration"))
    if "set-cookie" in h:
        sc = h["set-cookie"].lower()
        for flag, label in [("secure", "Secure"), ("httponly", "HttpOnly"), ("samesite", "SameSite")]:
            if flag not in sc:
                out.append(item(f"Cookie missing {label}", "Finding", "Low", url,
                                f"Set-Cookie response did not visibly include {label}.",
                                "Set appropriate Secure, HttpOnly, and SameSite attributes.",
                                "Authentication"))
    if "location" in h and 300 <= resp.status_code < 400:
        out.append(item("Redirect response", "Manual review", "Info", url,
                        "A redirect was returned; the destination was not followed.",
                        "Verify redirect destinations are allowlisted and cannot be user-controlled.",
                        "Open Redirect"))
    if soup:
        for form in soup.find_all("form"):
            method = (form.get("method") or "get").lower()
            if method == "post":
                has_token = bool(form.find("input", attrs={"name": re.compile(r"csrf|token", re.I)}))
                if not has_token:
                    out.append(item("CSRF token not apparent in form", "Manual review", "Medium", url,
                                    "A POST form had no input with a typical CSRF/token name. "
                                    "Tokens may be implemented elsewhere.",
                                    "Verify anti-CSRF protection on state-changing requests.",
                                    "CSRF"))
            for field in form.find_all("input"):
                if (field.get("type") or "").lower() == "file":
                    accept = field.get("accept", "")
                    out.append(item("File upload form detected", "Manual review", "Medium", url,
                                    f"File input found; accept hint: {accept or 'not specified'}. "
                                    "The scanner did not upload a file.",
                                    "Validate type/content server-side, limit size, randomize names, "
                                    "store outside web root, and scan uploads.",
                                    "File Upload"))
    # Passive reflection signal only: compare query values with returned body.
    query = parse_qs(urlparse(url).query)
    for key, values in query.items():
        for value in values[:2]:
            if len(value) >= 4 and value in body:
                out.append(item("Query value reflected in response", "Manual review", "Medium", url,
                                f"Value for parameter '{key}' appears in the response. "
                                "No script payload was sent; reflection alone is not proof of XSS.",
                                "Use context-aware output encoding and validate input.",
                                "XSS"))
                break
    signatures = ["sql syntax", "mysql_fetch", "ora-00933", "sqlite error",
                  "odbc sql", "postgresql error"]
    if any(s in body.lower() for s in signatures):
        out.append(item("Possible verbose database error", "Finding", "Medium", url,
                        "A common database error phrase appeared in the response.",
                        "Return generic errors to users and log details securely server-side.",
                        "Injection"))
    if "index of /" in body.lower() or "directory listing for" in body.lower():
        out.append(item("Possible directory listing", "Finding", "Medium", url,
                        "Response body contains a common directory-listing title.",
                        "Disable directory indexing and restrict sensitive directories.",
                        "Security Misconfiguration"))
    return out

def manual_review_items(pages):
    if not pages:
        return []
    url = pages[0]["url"]
    return [
        item("SQL Injection (SQLi)", "Manual review", "High", url,
             "Not actively tested. Safe passive browsing cannot confirm SQL injection.",
             "Review parameterized queries and ORM usage; test only in an isolated staging environment.",
             "Injection"),
        item("IDOR / Broken Access Control", "Manual review", "High", url,
             "Requires comparing authorization across test users and object ownership.",
             "Enforce server-side object-level authorization on every request.",
             "Broken Access Control"),
        item("SSRF", "Manual review", "High", url,
             "Requires code/configuration review; no internal network requests were attempted.",
             "Use strict destination allowlists, block private/link-local ranges, and validate redirects.",
             "SSRF"),
        item("Broken Authentication", "Manual review", "High", url,
             "A page crawl cannot establish password, MFA, session, or recovery security.",
             "Review MFA, session rotation, rate limits, recovery flows, and logout invalidation.",
             "Authentication"),
        item("Path Traversal", "Manual review", "High", url,
             "No traversal strings or file access probes were sent.",
             "Canonicalize paths, enforce base-directory boundaries, and avoid user-controlled paths.",
             "Path Traversal"),
        item("API Security / BOLA", "Manual review", "High", url,
             "API authorization and schema behavior require endpoint-specific review.",
             "Inventory API routes, enforce object/function authorization, validate schemas, "
             "and minimize returned data.",
             "API Security")
    ]

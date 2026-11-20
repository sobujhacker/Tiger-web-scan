import ipaddress
import socket
from urllib.parse import urlparse, urljoin, urldefrag
import requests
from bs4 import BeautifulSoup
from checks import analyze_response, manual_review_items

MAX_PAGES = 40
TIMEOUT = 8
UA = "TigerWebScanner/6.0 (authorized defensive review)"

def validate_target(raw):
    p = urlparse(raw.strip())
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("পূর্ণ URL দিন, যেমন https://example.com")
    if p.username or p.password:
        raise ValueError("URL-এর মধ্যে username/password দেওয়া যাবে না।")
    port = p.port
    if port not in (None, 80, 443):
        raise ValueError("শুধু standard HTTP/HTTPS port 80 বা 443 অনুমোদিত।")
    host = p.hostname
    try:
        infos = socket.getaddrinfo(host, port or (443 if p.scheme == "https" else 80))
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if not ip.is_global:
                raise ValueError("শুধু public, অনুমতিপ্রাপ্ত hostname স্ক্যান করা যাবে।")
    except socket.gaierror:
        raise ValueError("Hostname resolve করা যায়নি।")
    return p

def same_origin(a, b):
    x, y = urlparse(a), urlparse(b)
    return (x.scheme, x.hostname, x.port or (443 if x.scheme == "https" else 80)) == (
        y.scheme, y.hostname, y.port or (443 if y.scheme == "https" else 80)
    )

def scan_site(target, auth_header="", cookie_header="", max_pages=MAX_PAGES):
    parsed = validate_target(target)
    start = target.strip()
    if parsed.fragment:
        start = start.split("#", 1)[0]
    headers = {"User-Agent": UA, "Accept": "text/html,application/json,*/*"}
    if auth_header.strip():
        if "\r" in auth_header or "\n" in auth_header:
            raise ValueError("Authorization header format invalid.")
        headers["Authorization"] = auth_header.strip()
    if cookie_header.strip():
        if "\r" in cookie_header or "\n" in cookie_header:
            raise ValueError("Cookie header format invalid.")
        headers["Cookie"] = cookie_header.strip()

    session = requests.Session()
    session.trust_env = False
    session.headers.update(headers)
    queue, seen, pages, findings = [start], set(), [], []
    while queue and len(pages) < min(max_pages, MAX_PAGES):
        url = queue.pop(0)
        url, _ = urldefrag(url)
        if url in seen or not same_origin(start, url):
            continue
        seen.add(url)
        try:
            resp = session.get(url, timeout=TIMEOUT, allow_redirects=False, verify=True,
                               stream=False)
        except requests.RequestException as exc:
            pages.append({"url": url, "status": "Request failed", "content_type": "",
                          "title": "", "note": str(exc)[:180]})
            continue

        content_type = resp.headers.get("Content-Type", "")
        soup = None
        title = ""
        body = resp.text[:500000] if "text" in content_type or "json" in content_type else ""
        if "html" in content_type.lower():
            soup = BeautifulSoup(body, "html.parser")
            title = (soup.title.get_text(" ", strip=True) if soup.title else "")[:120]

        pages.append({"url": url, "status": resp.status_code,
                      "content_type": content_type[:100], "title": title, "note": ""})
        findings.extend(analyze_response(url, resp, soup, body))

        if soup:
            for a in soup.find_all("a", href=True):
                nxt = urljoin(url, a["href"])
                np = urlparse(nxt)
                if np.scheme in ("http", "https") and same_origin(start, nxt):
                    clean = nxt.split("#", 1)[0]
                    if clean not in seen and clean not in queue:
                        queue.append(clean)
            # Forms are reviewed on-page only; never submitted.
            for form in soup.find_all("form"):
                action = urljoin(url, form.get("action") or url)
                if same_origin(start, action) and action not in seen and action not in queue:
                    queue.append(action) if form.get("method", "get").lower() == "get" else None

    findings.extend(manual_review_items(pages))
    # Deduplicate by issue and URL.
    unique, keys = [], set()
    for f in findings:
        key = (f["name"], f["url"], f["status"])
        if key not in keys:
            keys.add(key)
            unique.append(f)
    return {"target": start, "pages": pages, "findings": unique,
            "page_count": len(pages), "finding_count": len(unique)}

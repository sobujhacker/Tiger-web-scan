#!/usr/bin/env python3
# TIGER WEB SCANNER V7 - TERMINAL EDITION
# Created by Sobuj Hossen
# Passive, non-destructive checks only. Use only on systems you own or are authorized to assess.

import json
import re
import socket
import ssl
import sys
import time
from datetime import datetime
from getpass import getpass
from pathlib import Path
from urllib.parse import urljoin, urlparse, urldefrag, parse_qs

import requests
from bs4 import BeautifulSoup

APP_NAME = "TIGER WEB SCANNER V7"
AUTHOR = "Sobuj Hossen"
BASE = Path(__file__).resolve().parent
REPORT_DIR = BASE / "reports"
HISTORY_FILE = REPORT_DIR / "history.json"
REPORT_DIR.mkdir(exist_ok=True)
TIMEOUT = 8
MAX_PAGES = 40
HEADERS = {"User-Agent": "TigerWebScanner/7.0 (passive-authorized-security-review)"}

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    GREEN, RED, YELLOW, CYAN, RESET = Fore.GREEN, Fore.RED, Fore.YELLOW, Fore.CYAN, Style.RESET_ALL
except Exception:
    GREEN = RED = YELLOW = CYAN = RESET = ""

def say(text="", color=""):
    print(f"{color}{text}{RESET}")

def banner():
    print()
    say("╔══════════════════════════════════════════════════════╗", CYAN)
    say("║                 TIGER WEB SCANNER V7                 ║", CYAN)
    say("║                  TERMINAL EDITION                    ║", CYAN)
    say("╚══════════════════════════════════════════════════════╝", CYAN)
    say(f"                 Created by {AUTHOR}", GREEN)
    print("       নিরাপদ • Passive Scan • বাংলা রিপোর্ট")
    print()

def normalize_url(raw):
    raw = raw.strip()
    if not raw:
        raise ValueError("URL খালি রাখা যাবে না।")
    if "://" not in raw:
        raw = "https://" + raw
    p = urlparse(raw)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("শুধু বৈধ HTTP/HTTPS URL ব্যবহার করুন।")
    if p.username or p.password:
        raise ValueError("URL-এর মধ্যে username/password দেওয়া যাবে না।")
    if p.port not in (None, 80, 443):
        raise ValueError("নিরাপত্তার জন্য শুধু standard HTTP/HTTPS port অনুমোদিত।")
    return raw.rstrip("/")

def public_target_check(url):
    host = urlparse(url).hostname
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise ValueError("ডোমেইন resolve করা যায়নি।")
    import ipaddress
    ips = {x[4][0] for x in infos}
    for ip in ips:
        addr = ipaddress.ip_address(ip)
        if not addr.is_global:
            raise ValueError("Private/local/internal network target নিরাপত্তার কারণে ব্লক করা হয়েছে।")
    return True

def load_history():
    try:
        return json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []

def save_history(entry):
    history = load_history()
    history.append(entry)
    HISTORY_FILE.write_text(json.dumps(history[-100:], ensure_ascii=False, indent=2), encoding="utf-8")

def add_finding(findings, name, status, severity, url, evidence, explanation, fix):
    findings.append({
        "বিষয়": name, "অবস্থা": status, "ঝুঁকি": severity, "পেজ": url,
        "প্রমাণ": evidence, "ব্যাখ্যা": explanation, "সমাধান": fix
    })

def scan(url, mode="full", cookie=None):
    public_target_check(url)
    origin = urlparse(url)
    origin_host = origin.hostname.lower()
    session = requests.Session()
    session.headers.update(HEADERS)
    if cookie:
        # User-provided authorized test-session cookie remains in memory only.
        session.headers["Cookie"] = cookie

    queue = [url]
    visited = set()
    findings = []
    page_count = 0
    print()
    say("[*] অনুমোদিত টার্গেট যাচাই করা হয়েছে। Passive scan শুরু হচ্ছে...", CYAN)

    while queue and page_count < (MAX_PAGES if mode == "full" else 1):
        current = queue.pop(0)
        current, _ = urldefrag(current)
        if current in visited:
            continue
        visited.add(current)
        try:
            response = session.get(current, timeout=TIMEOUT, allow_redirects=False, stream=False)
        except requests.RequestException as e:
            say(f"[!] পেজ খোলা যায়নি: {current} ({type(e).__name__})", YELLOW)
            continue
        page_count += 1
        say(f"[{page_count}] পরীক্ষা হচ্ছে: {current}", GREEN)

        h = response.headers
        is_https = current.lower().startswith("https://")
        if not is_https:
            add_finding(findings, "HTTPS / এনক্রিপশন", "সমস্যা পাওয়া গেছে", "উচ্চ", current,
                        "পেজটি HTTP দিয়ে খোলা হয়েছে।",
                        "HTTP সংযোগে ডেটা এনক্রিপ্টেড থাকে না; মাঝপথে তথ্য দেখা বা পরিবর্তনের ঝুঁকি থাকে।",
                        "সাইটে বৈধ TLS সার্টিফিকেট চালু করে HTTP থেকে HTTPS-এ রিডাইরেক্ট করুন।")
        elif "strict-transport-security" not in {k.lower() for k in h.keys()}:
            add_finding(findings, "HSTS নিরাপত্তা হেডার", "অনুপস্থিত", "মাঝারি", current,
                        "Strict-Transport-Security হেডার পাওয়া যায়নি।",
                        "ব্রাউজারকে ভবিষ্যতে HTTPS ব্যবহার করতে বাধ্য করার নির্দেশ অনুপস্থিত।",
                        "HTTPS পুরোপুরি চালু ও যাচাই করার পর উপযুক্ত HSTS header দিন।")

        security_headers = [
            ("Content-Security-Policy", "Content Security Policy", "মাঝারি",
             "CSP ব্রাউজারে অনুমোদিত content source সীমিত করতে সাহায্য করে.",
             "সাইটের প্রয়োজন অনুযায়ী Content-Security-Policy নির্ধারণ করুন।"),
            ("X-Content-Type-Options", "MIME Sniffing সুরক্ষা", "নিম্ন",
             "এই হেডার অনুপস্থিত থাকলে কিছু ব্রাউজার content type অনুমান করতে পারে।",
             "X-Content-Type-Options: nosniff যোগ করুন।"),
            ("X-Frame-Options", "Clickjacking প্রতিরোধ", "মাঝারি",
             "পেজ অন্য সাইটের frame-এ দেখানো নিয়ন্ত্রণের হেডার পাওয়া যায়নি।",
             "প্রয়োজন অনুযায়ী X-Frame-Options অথবা CSP frame-ancestors সেট করুন।"),
            ("Referrer-Policy", "Referrer Policy", "নিম্ন",
             "ব্রাউজার কতটুকু referrer তথ্য পাঠাবে তা নির্দিষ্ট করা নেই।",
             "উপযুক্ত Referrer-Policy সেট করুন, যেমন strict-origin-when-cross-origin।")
        ]
        lower_headers = {k.lower() for k in h.keys()}
        for header, label, severity, explanation, fix in security_headers:
            if header.lower() not in lower_headers:
                add_finding(findings, label, "অনুপস্থিত", severity, current,
                            f"{header} header পাওয়া যায়নি।", explanation, fix)

        server = h.get("Server", "")
        if server and re.search(r"\d+\.\d+", server):
            add_finding(findings, "Server Banner তথ্য প্রকাশ", "তথ্য প্রকাশিত", "নিম্ন", current,
                        f"Server: {server[:120]}",
                        "সার্ভারের সফটওয়্যার/ভার্সনের তথ্য প্রকাশ পেলে আক্রমণকারী প্রযুক্তি শনাক্ত করতে পারে।",
                        "অপ্রয়োজনীয় server version banner লুকিয়ে রাখুন।")

        for raw_cookie in response.raw.headers.getlist("Set-Cookie") if hasattr(response.raw.headers, "getlist") else []:
            c = raw_cookie.lower()
            cname = raw_cookie.split("=", 1)[0][:60]
            if "secure" not in c and is_https:
                add_finding(findings, "Cookie Secure Flag", "অনুপস্থিত", "মাঝারি", current,
                            f"{cname} cookie-তে Secure flag নেই।",
                            "HTTPS ব্যবহারের সময়ও Secure flag না থাকলে cookie ভুল করে HTTP-তে পাঠানোর ঝুঁকি থাকতে পারে।",
                            "সংবেদনশীল cookie-তে Secure flag যোগ করুন।")
            if "httponly" not in c:
                add_finding(findings, "Cookie HttpOnly Flag", "অনুপস্থিত", "মাঝারি", current,
                            f"{cname} cookie-তে HttpOnly flag নেই।",
                            "JavaScript দিয়ে cookie পড়া সম্ভব হতে পারে; XSS ঘটলে ঝুঁকি বাড়ে।",
                            "যে cookie JavaScript-এর প্রয়োজন নেই, তাতে HttpOnly যোগ করুন।")
            if "samesite" not in c:
                add_finding(findings, "Cookie SameSite Flag", "অনুপস্থিত", "নিম্ন", current,
                            f"{cname} cookie-তে SameSite attribute নেই।",
                            "Cross-site request-এর সময় cookie পাঠানো সীমিত করার নির্দেশ নেই।",
                            "প্রয়োজন অনুযায়ী SameSite=Lax বা Strict ব্যবহার করুন।")

        content_type = h.get("Content-Type", "").lower()
        body = ""
        if "text/html" in content_type or not content_type:
            body = response.text[:1_000_000]
            soup = BeautifulSoup(body, "html.parser")
            for form in soup.find_all("form"):
                method = (form.get("method") or "get").lower()
                if method == "post":
                    names = [x.get("name", "").lower() for x in form.find_all(["input", "textarea"])]
                    token_names = ("csrf", "token", "_token", "authenticity")
                    if not any(any(t in n for t in token_names) for n in names):
                        add_finding(findings, "CSRF Token যাচাই প্রয়োজন", "ম্যানুয়াল যাচাই প্রয়োজন", "মাঝারি", current,
                                    "একটি POST form-এ পরিচিত CSRF token field শনাক্ত হয়নি।",
                                    "এটি CSRF দুর্বলতার নিশ্চিত প্রমাণ নয়; token অন্যভাবে প্রয়োগ হতে পারে।",
                                    "Server-side CSRF token বা SameSite cookie protection যাচাই করুন।")
            if re.search(r"Index of /|Directory listing for", body, re.I):
                add_finding(findings, "Directory Listing", "সম্ভাব্য সমস্যা", "মাঝারি", current,
                            "পেজে directory listing-এর পরিচিত শিরোনাম পাওয়া গেছে।",
                            "ফোল্ডারের ফাইল তালিকা প্রকাশ পেলে অনাকাঙ্ক্ষিত তথ্য দেখা যেতে পারে।",
                            "Web server-এ directory listing বন্ধ করুন এবং ফাইল access সীমিত করুন।")
            if re.search(r"SQL syntax.*(error|warning)|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR", body, re.I):
                add_finding(findings, "Verbose Database Error", "সম্ভাব্য তথ্য প্রকাশ", "মাঝারি", current,
                            "রেসপন্সে database error-এর পরিচিত signature পাওয়া গেছে।",
                            "এটি database configuration বা error handling সম্পর্কে তথ্য প্রকাশ করতে পারে।",
                            "ব্যবহারকারীকে generic error দেখান; বিস্তারিত error শুধু server log-এ রাখুন।")

            if mode == "full":
                for a in soup.find_all("a", href=True):
                    nxt = urljoin(current, a["href"])
                    p = urlparse(nxt)
                    if p.scheme in ("http", "https") and p.hostname and p.hostname.lower() == origin_host:
                        if p.port in (None, 80, 443) and nxt not in visited and len(queue) < MAX_PAGES:
                            queue.append(nxt.split("#", 1)[0])

        # Manual-review categories are always clearly labelled; no exploit payloads are sent.
    manual = [
        ("SQL Injection (SQLi)", "ম্যানুয়াল যাচাই প্রয়োজন", "নিরাপদ passive scan দিয়ে SQLi নিশ্চিত করা হয়নি।",
         "কোড রিভিউ, parameterized query এবং অনুমোদিত staging test দিয়ে যাচাই করুন।"),
        ("Cross-Site Scripting (XSS)", "ম্যানুয়াল যাচাই প্রয়োজন", "কোনো payload পাঠানো হয়নি; XSS নিশ্চিত বা বাতিল করা যায়নি।",
         "Output encoding, input handling ও CSP পর্যালোচনা করুন।"),
        ("IDOR / Broken Access Control", "ম্যানুয়াল যাচাই প্রয়োজন", "অন্য ব্যবহারকারীর তথ্য অ্যাক্সেস করার চেষ্টা করা হয়নি।",
         "নিজস্ব test account দিয়ে server-side object-level authorization যাচাই করুন।"),
        ("SSRF", "ম্যানুয়াল যাচাই প্রয়োজন", "অভ্যন্তরীণ নেটওয়ার্কে কোনো request পাঠানো হয়নি।",
         "URL fetch feature-এ allowlist, DNS/IP validation ও egress control ব্যবহার করুন।"),
        ("Path Traversal", "ম্যানুয়াল যাচাই প্রয়োজন", "ফাইল path পরিবর্তন বা পড়ার চেষ্টা করা হয়নি।",
         "Canonical path যাচাই ও নির্দিষ্ট directory allowlist প্রয়োগ করুন।"),
        ("Authentication / Session", "ম্যানুয়াল যাচাই প্রয়োজন", "লগইন bypass বা brute-force পরীক্ষা করা হয়নি।",
         "MFA, session rotation, expiry এবং server-side authorization পর্যালোচনা করুন।"),
        ("API Security / BOLA", "ম্যানুয়াল যাচাই প্রয়োজন", "API endpoint ও object permission আলাদাভাবে যাচাই করা প্রয়োজন।",
         "প্রতিটি API request-এ server-side object authorization নিশ্চিত করুন।")
    ]
    for name, status, evidence, fix in manual:
        add_finding(findings, name, status, "যাচাই প্রয়োজন", url, evidence,
                    "এটি স্বয়ংক্রিয়ভাবে নিশ্চিত করা হয়নি; অনুমতিপ্রাপ্ত পরিবেশে আলাদা যাচাই প্রয়োজন।", fix)

    result = {
        "tool": APP_NAME, "creator": AUTHOR, "target": url,
        "scan_time": datetime.now().astimezone().isoformat(timespec="seconds"),
        "mode": mode, "pages_checked": page_count, "findings": findings,
        "note": "Passive/non-destructive review. 'ম্যানুয়াল যাচাই প্রয়োজন' মানে দুর্বলতা নিশ্চিত নয়।"
    }
    return result

def severity_color(s):
    if s == "উচ্চ": return RED
    if s == "মাঝারি": return YELLOW
    return CYAN

def show_results(result):
    print()
    say("════════════ বাংলা স্ক্যান রিপোর্ট ════════════", CYAN)
    say(f"টার্গেট: {result['target']}")
    say(f"পরীক্ষিত পেজ: {result['pages_checked']}")
    print()
    for i, f in enumerate(result["findings"], 1):
        print(f"{i}. {f['বিষয়']}  [{f['ঝুঁকি']}]")
        say(f"   অবস্থা: {f['অবস্থা']}", severity_color(f["ঝুঁকি"]))
        print(f"   পেজ: {f['পেজ']}")
        print(f"   প্রমাণ: {f['প্রমাণ']}")
        print(f"   ব্যাখ্যা: {f['ব্যাখ্যা']}")
        print(f"   সমাধান: {f['সমাধান']}")
        print()
    say("নোট: ম্যানুয়াল যাচাই প্রয়োজন মানে দুর্বলতা নিশ্চিতভাবে পাওয়া গেছে—এমন নয়।", YELLOW)

def export_report(result):
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    stem = REPORT_DIR / f"tiger_report_{stamp}"
    (stem.with_suffix(".json")).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    lines = [APP_NAME, f"Created by {AUTHOR}", f"Target: {result['target']}",
             f"সময়: {result['scan_time']}", f"পরীক্ষিত পেজ: {result['pages_checked']}", ""]
    for i, f in enumerate(result["findings"], 1):
        lines += [f"{i}. {f['বিষয়']} | ঝুঁকি: {f['ঝুঁকি']} | অবস্থা: {f['অবস্থা']}",
                  f"পেজ: {f['পেজ']}", f"প্রমাণ: {f['প্রমাণ']}", f"ব্যাখ্যা: {f['ব্যাখ্যা']}",
                  f"সমাধান: {f['সমাধান']}", ""]
    lines.append(result["note"])
    (stem.with_suffix(".txt")).write_text("\n".join(lines), encoding="utf-8")
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        # PDF is generated with built-in fonts; Bengali glyph support depends on installed fonts.
        doc = SimpleDocTemplate(str(stem.with_suffix(".pdf")), pagesize=A4)
        styles = getSampleStyleSheet()
        story = [Paragraph(APP_NAME, styles["Title"]), Paragraph(f"Created by {AUTHOR}", styles["Normal"]),
                 Paragraph(f"Target: {result['target']}", styles["Normal"]), Spacer(1, 12)]
        for f in result["findings"]:
            safe = lambda x: str(x).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            story.append(Paragraph(safe(f"{f['বিষয়']} — {f['ঝুঁকি']}"), styles["Heading3"]))
            for key in ("অবস্থা", "পেজ", "প্রমাণ", "ব্যাখ্যা", "সমাধান"):
                story.append(Paragraph(safe(f"{key}: {f[key]}"), styles["BodyText"]))
            story.append(Spacer(1, 8))
        doc.build(story)
        pdf_note = "PDF"
    except Exception:
        pdf_note = "PDF তৈরি হয়নি (বাংলা ফন্ট/ReportLab সেটআপ); TXT ও JSON তৈরি হয়েছে।"
    say(f"রিপোর্ট সেভ: {stem}.txt এবং {stem}.json ({pdf_note})", GREEN)

def view_history():
    history = load_history()
    if not history:
        say("এখনো কোনো scan history নেই।", YELLOW)
        return
    for i, item in enumerate(history[-20:], 1):
        print(f"{i}. {item.get('scan_time')} | {item.get('target')} | {item.get('pages_checked')} পেজ")

def main():
    last_result = None
    while True:
        banner()
        print("[1] Full Website Scan (একই ডোমেইনের সর্বোচ্চ ৪০ পেজ)")
        print("[2] Quick Security Scan (শুধু দেওয়া পেজ)")
        print("[3] Login Session Review (নিজস্ব test account cookie)")
        print("[4] Scan History")
        print("[5] Export Last Report")
        print("[6] Exit")
        choice = input("\nঅপশন নির্বাচন করুন: ").strip()
        if choice in ("1", "2", "3"):
            target = input("অনুমতিপ্রাপ্ত ওয়েবসাইটের URL দিন: ").strip()
            cookie = None
            if choice == "3":
                say("শুধু নিজের অনুমোদিত test account-এর session cookie দিন। এটি সংরক্ষণ বা রিপোর্টে লেখা হবে না।", YELLOW)
                cookie = getpass("Session Cookie (খালি রাখলে anonymous scan): ").strip() or None
            try:
                url = normalize_url(target)
                last_result = scan(url, "full" if choice in ("1", "3") else "quick", cookie)
                show_results(last_result)
                save_history({k: v for k, v in last_result.items() if k != "findings"} |
                             {"finding_count": len(last_result["findings"])})
                ans = input("এখন রিপোর্ট Export করবেন? (y/n): ").strip().lower()
                if ans == "y":
                    export_report(last_result)
            except Exception as e:
                say(f"সমস্যা: {e}", RED)
        elif choice == "4":
            view_history()
        elif choice == "5":
            if last_result:
                export_report(last_result)
            else:
                say("এই সেশনে এখনো কোনো report নেই।", YELLOW)
        elif choice == "6":
            say("TIGER WEB SCANNER বন্ধ করা হলো। ধন্যবাদ!", GREEN)
            break
        else:
            say("সঠিক অপশন নির্বাচন করুন।", YELLOW)
        input("\nচালিয়ে যেতে Enter চাপুন...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nবন্ধ করা হয়েছে।")

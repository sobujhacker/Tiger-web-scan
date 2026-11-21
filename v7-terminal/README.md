# 🐯 TIGER WEB SCANNER V7 — TERMINAL EDITION
**Created by Sobuj Hossen**

Kali Linux-এর Terminal থেকে চালানোর জন্য Python-ভিত্তিক passive web security review tool।

## Features
- Terminal-only interface; Flask dashboard বা browser-based control নেই
- বাংলা ভাষায় findings, ব্যাখ্যা, ঝুঁকির মাত্রা ও remediation
- Quick scan এবং same-origin limited crawl (সর্বোচ্চ ৪০ পেজ)
- HTTPS/HSTS ও security headers review
- Cookie flag review
- সম্ভাব্য directory listing / verbose database error signature
- POST form-এ CSRF token field-এর উপস্থিতি নিয়ে manual-review warning
- SQLi, XSS, IDOR, SSRF, Path Traversal, Authentication ও API/BOLA-এর manual-review checklist
- TXT, JSON এবং ঐচ্ছিক PDF report
- Scan history
- Optional authorized test-session cookie (memory only; report/history-তে সংরক্ষণ করা হয় না)

## Safety limits
- শুধু নিজের বা লিখিত অনুমতিপ্রাপ্ত সাইটে ব্যবহার করুন।
- কেবল HTTP/HTTPS standard ports (80/443)।
- Private/local/internal IP target ব্লক করা হয়।
- সর্বোচ্চ ৪০টি same-origin page।
- শুধু GET request; form submit, file upload, brute force, exploit payload, destructive test, redirect following বা অন্য ব্যবহারকারীর data access করা হয় না।
- SQLi/XSS/IDOR/SSRF ইত্যাদি এখানে নিশ্চিতভাবে exploit/test করা হয় না; এগুলো manual review হিসেবে দেখানো হয়।
- Scan output একটি প্রাথমিক review, পূর্ণাঙ্গ security audit নয়।

## Kali Linux setup
```bash
sudo apt update
sudo apt install -y python3 python3-venv
unzip tiger-web-scanner-v7-terminal.zip
cd tiger-web-scanner-v7-terminal
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 tiger.py
```

## GitHub upload
ZIP extract করে folder-এর ভেতরের সব ফাইল ও `reports/` folder একসাথে GitHub repository-তে upload করুন। `venv/` upload করবেন না।

## Reports
রিপোর্ট `reports/` folder-এ তৈরি হবে। PDF-এর বাংলা glyph support system font-এর ওপর নির্ভর করতে পারে; TXT ও JSON সবচেয়ে নির্ভরযোগ্য।

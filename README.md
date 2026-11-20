# TIGER WEB SCANNER V6

A local-first, authorization-focused web security review tool.

## What it does
- Same-origin page discovery with a strict page limit.
- Passive checks for security headers, cookies, HTTPS, exposed server banners,
  directory listing indicators, form/CSRF indicators, upload form controls,
  reflected query values, verbose server errors, and redirect parameters.
- OWASP Top 10 review checklist for access control, authentication, injection,
  SSRF, file upload, API configuration, and other issues.
- Optional authenticated review using a test account's session cookie or
  Authorization header. Credentials are held in process memory only while the
  app runs and are not written to scan reports.
- Affected-page URLs, evidence summaries, severity, and remediation guidance.
- JSON, TXT, and PDF reports plus local scan history.

## Important limitations
This is a defensive review assistant, not a guarantee that every vulnerability
will be found. It does NOT exploit vulnerabilities, run SQL injection payloads,
execute JavaScript, bypass authentication, alter data, upload files, fuzz
parameters, or test other users' records. IDOR, SSRF, authentication flaws,
and many injection issues require source-code review or a dedicated staging
test plan. Such items are labelled "Manual review" when they cannot be
verified safely from public responses.

## Run (Windows PowerShell)
```powershell
cd "$HOME\Desktop\tiger-web-scanner-v6"
python -m pip install -r requirements.txt
python main.py
```
Open http://127.0.0.1:5000

## Safe use
1. Scan only a website you own or have explicit written permission to assess.
2. Use a staging/test environment and test account.
3. Keep the scanner bound to localhost. Do not expose it to the public internet.
4. Authenticated review: paste a short-lived test session cookie or test
   Authorization header. It is held only in server memory and cleared when the
   app restarts. Do not paste real passwords or personal account cookies.
5. Maximum 40 pages, same-origin only, one request per discovered page.
6. Redirects are not followed. Only HTTP/HTTPS on standard ports are accepted.

## Result meanings
- Finding: a passive indicator was observed; verify before treating it as a
  confirmed vulnerability.
- Manual review: the issue cannot be safely confirmed by this scanner.
- Not observed: this limited scan did not detect the indicator; it is not proof
  that the site is secure.

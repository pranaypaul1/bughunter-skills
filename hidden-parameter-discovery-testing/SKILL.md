---
name: hidden-parameter-discovery-testing
description: Finding undocumented/hidden request parameters (query string, POST body, JSON field, header, or cookie) that an application's own frontend never sends but its backend still reads and acts on — debug flags, admin/internal-only toggles, legacy API fields, cache-bypass params. Covers automated tools (Arjun, x8, Burp Param Miner, GetAllParams/GAP), candidate-name sourcing (JS-file enumeration, HTML hidden input fields, Google dorking, Wayback Machine legacy-parameter mining, mobile-app source), and the response-diffing discipline for confirming a fuzzed parameter actually did something. This is the discovery step that feeds directly into `http-parameter-pollution-testing`, `mass-assignment-testing`, `web-cache-poisoning-testing`, and `blind-xss-testing` once a candidate parameter is found — this skill owns finding it, those own exploiting it. Use this during Phase 2/3 (Enumeration/Vulnerability Testing) of bughunting-workflow on any endpoint before concluding its only inputs are the ones visible in the rendered form/UI. Also trigger on mentions of Arjun, x8 fuzzer, Param Miner, GetAllParams, GAP-Burp-Extension, hidden parameter, or undocumented parameter discovery.
---

# Hidden Parameter Discovery Testing

Technique library for finding request parameters an app's UI never exposes but its backend still processes. Each dated entry below is a validated technique pulled from a real writeup — add new entries here (don't create a new skill) whenever a new writeup covers a different discovery source or tool than what's already recorded. This skill is a **discovery-phase** lens, not a vuln class itself — once a hidden parameter is found, hand it off to whichever exploitation skill matches what it turns out to control (`http-parameter-pollution-testing`, `mass-assignment-testing`, `web-cache-poisoning-testing`, `advanced-access-control-testing`, `blind-xss-testing`, or straightforward SQLi/XSS testing on the newly-found input).

## Core theory

Most input validation and access-control logic gets written against the parameters a developer *remembers* the frontend sends — a debug flag added during development and never removed, an internal admin toggle wired up for one release and forgotten, a legacy API field kept for backward compatibility, all frequently ship with weaker (or zero) server-side validation than the parameters visible in the actual rendered form, because "security through obscurity" (nobody will guess this parameter exists) substitutes for real validation in the developer's mental model. The backend still reads and acts on these parameters exactly the same as any documented one — the only thing "hidden" about them is that the frontend never sends them, so a black-box tester who only interacts with the rendered UI never discovers they exist.

## Discovery method 1 — HTML hidden input fields and DOM enumeration

Parse every page's HTML for `id`/`name` attributes across **all** elements, not just visible form fields — `<input type="hidden">` fields that preserve state between page loads are a classic injection point precisely because they're invisible in the UI but still submitted with the form:
```bash
gospider -s "https://target.com" -o output -c 10 -d 3   # crawl + collect endpoints/params at scale
```
**GetAllParams (GAP)** — extracts every parameter name it finds in scraped HTML/JS across a crawl. **Burp Suite's proxy history** does the same passively while you browse normally — right-click any request and look at hidden `<input>` values Burp's own rendering surfaces even when the browser hides them visually.

## Discovery method 2 — JavaScript file enumeration

The richest source of candidate parameter names on any modern app — JS bundles reference every parameter the frontend *could* send, including ones gated behind feature flags or admin-only UI paths that never render for a normal test account:
- Grep JS bundles for API endpoint references, function calls that parse `req.query`/`req.body`/`URLSearchParams`, and variable names that look parameter-shaped — cross-reference `recon-scanning-toolkit`'s JS-secret-hunting section for the grep/LinkFinder pipeline already covered there; run it with an eye for parameter names, not just secrets.
- **Eval Villain** (browser extension) — hooks `eval()`/`Function()`/similar dynamic-execution calls at runtime and shows you what's actually being evaluated, which surfaces client-side parameter processing/validation logic that a static grep alone might miss.

## Discovery method 3 — search engines and web archives

**Google dorking:**
```
site:.example.com inurl:? || inurl:&
```
Surfaces indexed URLs carrying query parameters across the entire target domain, including old/forgotten pages.

**Wayback Machine / Internet Archive:**
1. Search `web.archive.org` for the target domain, filter to indexed URLs containing query parameters.
2. Check **legacy/older versions of the same JS file** specifically — a parameter present in a JS bundle from a year ago but absent from the current one is a strong signal of a *discontinued-but-still-backend-accepted* parameter: frontends get updated to stop sending old fields, but the backend's handling code for them frequently isn't removed at the same time, leaving a still-live but now-completely-undocumented input.
Cross-reference `recon-scanning-toolkit`'s Wayback CDX API deep-dive section for the full command reference on pulling historical URLs/JS at scale — this is that same technique aimed specifically at parameter-name harvesting.

## Discovery method 4 — automated fuzzing tools

**Arjun** (Python — `s0md3v/Arjun`) — the standard purpose-built tool for this; supports multiple content types and HTTP methods in one pass:
```bash
arjun -u https://target.com/api/endpoint
arjun -u https://target.com/api/endpoint -m POST --headers "Authorization: Bearer <token>"
arjun -u https://target.com/api/endpoint -w /path/to/custom-wordlist.txt
```

**x8** (Rust — `sh1yo/x8`) — built for speed at scale, supports custom wordlists:
```bash
x8 -u https://target.com/api/endpoint -w wordlist.txt
```

**Burp Param Miner** (Java, Burp extension — `portswigger/param-miner`) — ships extensive built-in wordlists and integrates directly into Burp's request flow; already the standard automation reference in `web-cache-poisoning-testing` for unkeyed-header discovery, but its parameter-guessing mode is this skill's use case specifically.

**GetAllParams (GAP)** (Burp extension — `xnl-h4ck3r/GAP-Burp-Extension`) — combines active fuzzing with passive extraction (method 1 above) and can generate a target-tailored custom wordlist from what it observes during a crawl, rather than relying purely on a generic list.

**ffuf** — general-purpose fuzzing already covers this use case too; see `recon-scanning-toolkit`'s "GET/POST parameter fuzzing" section for the exact command pattern (`-fs <baseline-size>` filtering, since most apps return `200` regardless of whether a fuzzed parameter did anything — response *size*, not status code, is the actual signal).

**Wordlist strategy:** combine a generic parameter wordlist (SecLists' `Discovery/Web-Content` parameter lists, Assetnote's — both already referenced in `recon-scanning-toolkit`) with a **custom** wordlist built from the target's own naming conventions, framework, and language — a Rails app's hidden parameters skew toward `snake_case` and Rails-specific reserved names, a Java/Spring backend skews toward camelCase and Spring-specific conventions; generic lists alone systematically under-perform against any single target's actual style.

## Discovery method 5 — parameter reuse across endpoints

Once you've found *any* parameter on *any* endpoint (via any method above, or just from normal manual testing), don't assume it's scoped to that one endpoint — export the full crawl/request history from Burp Suite or ZAProxy and test that same parameter name against every *other* endpoint the target exposes. A parameter that's properly validated on the endpoint where it was originally found is frequently left unvalidated on a different endpoint that happens to read the same parameter name but was implemented by a different developer/at a different time.

## Discovery method 6 — mobile app source

If a mobile app companion exists, decompile it (cross-reference `mobile-app-testing`) and grep the decompiled source/strings for parameter names the mobile client sends that the web client never does — mobile and web frontends frequently diverge on which subset of the backend's actual accepted parameters each one happens to use, so the mobile client is an independent source of candidate names the web-only recon above will never surface.

## Confirming impact once a candidate parameter is found

Discovery alone isn't a finding — a hidden parameter that does nothing is noise. Confirm impact with this loop:
1. Capture a baseline response **without** the candidate parameter.
2. Add the candidate parameter with a benign test value, and diff the response (size, status code, timing, body content) against the baseline — any difference confirms the backend actually reads and acts on it.
3. Once confirmed live, test it against every relevant vuln class rather than assuming its type from its name alone: SQLi/XSS test strings first (cheapest to try), then hand off to the specific exploitation skill that matches what the parameter turns out to control — duplicate it for `http-parameter-pollution-testing` if the app already accepts it more than once, try mass-assignment-style privileged-field values (`isAdmin`, `role`) per `mass-assignment-testing` if it looks state-controlling, or treat it as an unkeyed cache input per `web-cache-poisoning-testing` if the endpoint is cacheable.

## Recorded techniques

### 1. Full discovery-method sweep — HTML/JS/dorking/Wayback/fuzzing-tools/reuse (baseline)
Source: [Finding Hidden Input Parameters](https://www.intigriti.com/researchers/blog/hacking-tools/finding-hidden-input-parameters)

**Where:** any endpoint, before concluding its input surface is limited to what the rendered form/UI shows — run this as a standing Phase 2 step on every in-scope host, not just ones that already look promising.

**Root cause:** see Core theory above — obscurity substitutes for validation in the developer's mental model, so hidden parameters systematically receive weaker scrutiny than documented ones.

**Exploit steps:** run discovery methods 1-6 above in parallel (HTML/DOM enumeration, JS-file grep, Google dorking + Wayback historical-JS-diffing, Arjun/x8/Param Miner/GAP automated fuzzing, cross-endpoint parameter reuse, mobile-app source if applicable); confirm every candidate via the baseline-diff loop above before investing further testing time; route confirmed-live parameters to the exploitation skill matching their apparent function.

**Impact framing:** the parameter itself is never the finding — report whatever vuln class it turns out to enable (SQLi/XSS/IDOR/command injection/cache poisoning/mass assignment) with the hidden-parameter discovery framed as *how you found the injection point*, not as the vulnerability.

**Generalize note:** this fills a standing gap several other skills in this hunting workflow already assumed was covered — `recon-scanning-toolkit`, `blind-xss-testing`, `http-parameter-pollution-testing`, `web-cache-poisoning-testing`, and `csp-misconfig-xss-testing` all reference Arjun/Param Miner for hidden-parameter discovery without any of them owning the actual discovery methodology; this skill is that home, and those cross-references now resolve to something real instead of dangling.

<!-- Add new recorded techniques below this line as new hidden-parameter-discovery writeups are processed. Keep the same structure: Where / Root cause / Exploit steps / Impact framing / Generalize note. -->

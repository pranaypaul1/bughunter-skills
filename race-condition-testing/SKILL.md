---
name: race-condition-testing
description: Race condition (TOCTOU) exploitation techniques for web/API targets — checking single-use tokens, codes, coupons, balances, or state transitions that get validated-then-consumed without transactional isolation. Use this during Phase 3 (Vulnerability Testing) of bughunting-workflow whenever the hunter is testing OAuth/SSO account-linking, password reset, invite/magic links, coupon redemption, balance/wallet operations, or any endpoint that reads state then writes state a moment later. Also trigger on mentions of race condition, TOCTOU, Turbo Intruder, single-packet attack, concurrency bugs, or double-spend.
---

# Race Condition (TOCTOU) Testing

General technique library for finding and exploiting check-then-consume race conditions. Each dated entry below is a validated technique pulled from a real writeup/source — add new entries here (don't create a new skill) whenever a new race-condition writeup covers a *different* endpoint type or trigger method than what's already recorded.

## Core theory

Almost every instance of this bug class has the same shape:

1. **Check** — server reads some state (is this code used? is this coupon redeemed? is this balance sufficient?)
2. **Slow gap** — server does something that takes time (network call to a third party, disk I/O, a computation)
3. **Consume** — server writes the new state (mark used, deduct balance, bind identity)

If steps 1 and 3 aren't wrapped in a single atomic transaction (row lock / unique constraint / idempotency key), any request that reaches step 1 before another request's step 3 completes will also pass the check — letting the same one-time thing be used more than once.

**Recon signal:** look for any step in a flow that visibly takes 100ms+ — a call out to a third-party API (OAuth provider, payment processor, email service), a slow DB write, a file operation. That's your race window. The bigger the gap, the more reliable the race.

**Attack signal:** if a request pair or burst produces *more than one* "success" response where only one should be possible, you've won the race.

## Trigger technique: HTTP/2 single-packet attack (primary method)

Don't rely on naive concurrent HTTP/1.1 requests over separate connections — normal network jitter often desyncs them enough that the race window is missed. Instead:

- Use **Burp Suite's Turbo Intruder** with its HTTP/2 single-packet / race-condition engine (multiplexes many request frames into one TCP packet so they all arrive at the target within ~1-2ms of each other, independent of client-side threading jitter).
- Split requests into groups that differ only in the variable you're testing (e.g. session cookie A vs session cookie B), all using the identical single-use value (code/token/coupon).
- Fire the full burst, then inspect all responses for more than one "success."

If HTTP/2 isn't supported by the target, fall back to HTTP/1.1 with as many pre-opened keep-alive connections as request count, sent as close to simultaneously as the tooling allows — expect a lower win rate and multiple attempts.

## Recorded techniques

### 1. OAuth2/SSO account-linking race → account takeover
Source: [$11,500 Account Takeover via Race Condition in OAuth2 State Verification](https://medium.com/@t4nv1/11-500-account-takeover-via-race-condition-in-oauth2-state-verification-single-use-54cd5d544e10)

**Where:** "Connect account" / "link identity provider" endpoints in SSO flows — not the primary login endpoint, the *account-linking* one, since a won race there directly binds attacker-controlled identity to a victim's account.

**Root cause:** backend checked `code` consumption status, then made a 150–300ms network call to exchange the code with the OAuth provider, then marked it consumed and bound the identity — all without transactional isolation:
```python
if db.query("SELECT consumed FROM oauth_codes WHERE code = %s").consumed:
    return error_response("Code already used", 400)
tokens = oauth_provider.exchange_code(code)   # <-- race window, 150-300ms
db.execute("UPDATE oauth_codes SET consumed = TRUE WHERE code = %s")
bind_sso_account(current_user.id, user_info['id'])
```

**Exploit steps:**
1. Start the OAuth linking flow, intercept the `code` before the natural callback request consumes it.
2. Build two groups of requests to the connect/exchange endpoint (e.g. `POST /api/v1/sso/connect`), identical `code`, differing only in session cookie:
   - Group A: attacker's session cookie
   - Group B: victim's session cookie
3. Fire ~10 requests per group (20 total) via Turbo Intruder's HTTP/2 single-packet attack, landing within ~2ms of each other.
4. Check for split-brain success (code accepted on more than one session) → the same code got bound to two accounts.
5. Confirm impact by logging in as the victim via the hijacked SSO binding — this bypasses both password and MFA.

**Impact framing for report:** "Persistent Account Takeover / SSO Identity Hijacking." CVSS used: `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H` (High — AC:H because the race isn't 100% reliable, UI:R because it needs the linking flow triggered). Bounty: $11,500, rated Critical.

**Generalize beyond OAuth:** the same check-then-consume gap shows up in password reset tokens, email verification links, invite acceptance, coupon/promo code redemption, and wallet/balance debits. Whenever testing any of those, apply this same methodology (two-group burst race via single-packet attack) even without a specific writeup for that exact endpoint type.

<!-- Add new recorded techniques below this line as new race-condition writeups are processed. Keep the same structure: Where / Root cause / Exploit steps / Impact framing / Generalize note. -->

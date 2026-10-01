---
name: business-logic-abuse-testing
description: Business-logic abuse in transactional/e-commerce/subscription flows — coupon/discount abuse, payment/price manipulation, workflow/sequence-step bypass, client-controlled state-field tampering, aggregate-stat manipulation via replayed single-use actions, differential validation across entry points, and authorization-mistaken-for-data-authenticity flaws (a record-ownership check treated as proof the record's content is real), all rooted in the same core failure of trusting frontend-supplied values, assumed step ordering, or an authorization pass as if it were content validation, instead of re-validating everything server-side. Use this during Phase 3 (Vulnerability Testing — Business logic) of bughunting-workflow on any checkout, cart, coupon/discount, subscription/plan-upgrade, order-confirmation, multi-step-wizard flow, or any profile/identity-data feature that stores user-submitted entity data (vehicle/business/organization records) for reuse elsewhere. Cross-references `race-condition-testing` for the TOCTOU/concurrency angle on these same endpoints and `mass-assignment-testing` for the JSON-field-injection angle — this skill covers the single-request value/sequence tampering that doesn't need either of those techniques. Also trigger on mentions of coupon abuse, price manipulation, payment tampering, workflow bypass, state manipulation, fabricated/unverified profile data, "never trust the frontend total," or business logic testing.
---

# Business-Logic Abuse Testing (Transactional Flows)

General technique library for business-logic bugs in money-moving and multi-step flows. Each dated entry below is a validated technique pulled from a real writeup/source — add new entries here (don't create a new skill) whenever a new writeup covers a *different* transactional flow or tampering angle than what's already recorded.

## Core theory

Every technique in this skill traces back to one sentence: **never trust frontend totals, discount math, or step ordering — always test whether the backend actually re-validates them.** A frontend exists to make a good UX, not to enforce security; if the price, discount, currency, or "have you completed step N" check only ever happens in JS/the mobile client, the backend request that JS eventually sends is fully attacker-controlled the moment you open Burp.

Work through any transactional flow by systematically trying, at every step:
1. **Value modification** — change a price/amount/discount/currency field to something the frontend would never send.
2. **Reordering/skipping** — call a later step's endpoint directly without having called the earlier ones.
3. **Repetition** — replay a request/token that's supposed to be single-use.
4. **State tampering** — flip a status field (`pending`→`paid`, `unverified`→`verified`) directly in the request body.

## Trigger technique: map the flow, then attack each step independently

1. Walk the full flow once normally (cart → coupon → payment → confirmation, or signup → plan-select → payment → activation) with Burp/proxy capturing every request.
2. For each captured request, ask: does this value get recalculated/re-validated server-side, or just carried through from what the previous step sent? Test by resending with a tampered value and diffing the response/behavior against the honest flow.
3. Identify the single request that represents "the moment of value transfer" (the actual charge, the actual entitlement grant) — that's the one worth attacking hardest, since everything upstream of it is just UX.

## Recorded techniques

### 1. Coupon/discount abuse — frontend discount value trusted without recalculation
Source: [Advanced Business Logic Attacks — Part 5](https://medium.com/bug-bounty-hunting-a-comprehensive-guide-in/advanced-business-logic-attacks-part-5-613438cea280)

**Where:** any cart/checkout flow with a coupon or promo-code field.

**Root cause:** the backend trusts a frontend-supplied discount value instead of recalculating it from the coupon code + cart contents server-side, and/or doesn't re-verify the discount still applies after the cart state changes (items removed, quantity increased).

**Exploit steps:**
1. Apply a valid coupon normally, capture the request in Burp.
2. Remove/replace cart items after applying the coupon, then check the checkout total — if the discount persists on a now-different cart, the discount wasn't recalculated.
3. Increase quantity after the discount was applied — check whether the discount recalculates proportionally or just carries forward the original flat amount.
4. Directly tamper the discount value in the request itself:
   ```
   POST /api/cart/apply
   {"coupon": "SAVE50", "discount": 500}
   ```
   If the backend trusts the `discount` field from the client rather than looking up `SAVE50`'s actual value server-side, this alone is the bug.

**Impact:** unauthorized discount up to 100%+ off (negative-price orders in the worst case) — direct, quantifiable revenue loss, easy to frame in a report.

### 2. Payment/price manipulation — server trusts frontend-supplied financial parameters
Source: same as above.

**Where:** the actual payment-submission/charge-confirmation request in any checkout flow.

**Root cause:** the backend charges (or records as charged) whatever amount/currency the client sends, instead of recomputing the amount from the order server-side and only accepting a payment-gateway-confirmed charge.

**Exploit steps:**
1. Intercept the payment request and reduce the amount: `"amount": 499.99` → `"amount": 4.99`.
2. Try a currency swap without a corresponding conversion: change `USD` to `JPY` (or any low-value currency) on the same numeric amount, checking whether the backend does currency-aware conversion or just records the raw number.
3. Call the order-confirmation endpoint directly without ever completing the payment step at all — see Technique 3 below, since this overlaps with workflow bypass.

**Impact:** underpayment or complete payment bypass — direct financial loss, one of the highest-severity classes in this skill since it's unambiguous monetary theft.

### 3. Workflow/sequence-step bypass — no server-side enforcement of step ordering
Source: same as above.

**Where:** any multi-step flow that assumes the client completes steps in order (subscription signup → payment → activation; order → payment → confirmation → fulfillment).

**Root cause:** the application assumes sequential completion because the *frontend* only exposes the next step's button after the previous one succeeds — but the backend endpoint for a later step doesn't itself check that the prerequisite step actually completed.

**Exploit steps:**
1. Identify the "activation"/"confirmation"/"fulfillment" endpoint that's supposed to run only after payment.
2. Call it directly, skipping the payment step entirely: `POST /api/order/confirm` with no preceding successful payment call.
3. Try modifying the plan/order ID in the request to a higher-tier plan than what was actually paid for.
4. Replay an old, previously-valid "success" token/callback (e.g. a payment-gateway webhook payload you captured from a prior legitimate low-value transaction) against the activation endpoint for a new, unpaid order.

**Impact:** service/subscription activation with zero payment — subscription fraud, directly quantifiable by the plan price.

### 4. State-field manipulation — client-controlled status field, no server-side verification
Source: same as above.

**Where:** any request where an order/transaction/verification status is included as a field in the request body rather than being purely server-derived.

**Root cause:** the backend reads a status field from the request instead of deriving it from its own record of what actually happened (payment gateway callback, verification service response, etc.).

**Exploit steps:**
1. Intercept any request touching an order/transaction object and look for a status-shaped field (`status`, `state`, `paid`, `verified`, `is_complete`).
2. Change `status=pending` (or `false`) to `status=paid`/`status=verified` (or `true`) directly in the request.
3. Check whether that alone triggers fulfillment/entitlement logic downstream — order shipped, feature unlocked, verification badge granted — without the actual underlying condition (payment received, email confirmed) ever having been true.

**Impact:** unauthorized order completion / fulfillment without payment or verification ever actually occurring.

**Cross-reference — race conditions on these same endpoints:** all four techniques above are single-request tampering. The *same* endpoints (coupon apply, payment confirm, activation) are also prime race-condition targets — see `race-condition-testing` for the check-then-consume TOCTOU angle (e.g. redeeming a single-use coupon twice via concurrent requests rather than tampering with its value in one request). Test both angles independently on any flow found here; they're different bugs even when they hit the same endpoint.

**Impact framing for report (all four techniques):** the article's own framing — "Never trust frontend totals. Always test backend trust." Quantify impact in real currency/revenue terms wherever possible (exact discount %, exact underpayment amount, exact plan price bypassed) rather than a generic severity label; a business-logic finding with a concrete dollar-loss calculation triages faster and rates higher than an abstract "logic flaw" description.

**Generalize note:** this article is Part 5 of a series (references Part 4 on IDOR/Broken Access Control); if earlier/later parts of the same series surface, check them for additional business-logic sub-techniques not yet recorded here before assuming full coverage.

### 5. Differential validation across entry points — the same logical field, validated strictly at one endpoint and not at another
Source: [Exploiting Business Logic Error Vulnerabilities](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-business-logic-error-vulnerabilities)

**Where:** any field that can be set or changed through more than one endpoint/flow — an email address settable at signup *and* changeable later through an account-preferences/unsubscribe-management portal; a shipping address settable at checkout *and* editable from a separate address-book page; any value with a "primary" heavily-tested entry point and a "secondary" one added later or by a different team.

**Root cause:** input validation gets implemented per-endpoint rather than as a shared, centrally-enforced rule — the primary entry point (signup) received careful validation/sanitization attention (rejects XSS/SQLi payloads in the email field), but a secondary entry point that logically writes to the *same* underlying field/column (the preferences portal's "update your email" or "manage unsubscribe" flow) was built later, by different code, and never inherited the same validation.

**Exploit steps:**
1. For any field that visibly rejects a test payload (`<script>`, a SQLi probe, template-injection syntax) at its obvious/primary entry point, don't stop — enumerate every *other* place in the application that can write to the same underlying field (secondary settings pages, preference portals, admin-assisted update flows, bulk-import features, API endpoints separate from the main form).
2. Retry the exact payload that got rejected at the primary entry point against each secondary one.
3. If a secondary endpoint accepts it, confirm where the now-unsanitized value gets consumed downstream — an email template that interpolates the stored email address unescaped is a common template-injection/XSS sink; a report/export/admin-panel view that renders it is another.

**Impact framing:** this converts what looks like a solved input-validation problem (the primary form is "protected") into a live injection vector purely by finding the unprotected sibling — frame the report around the specific downstream sink that fires (stored XSS in an admin-viewed page, SSTI in an email template) rather than "validation missing on endpoint X," since that sink is what proves actual impact per this skill's CIA-triad framing below.

**Generalize note:** cross-reference `email-field-injection-testing`'s test-matrix approach and `registration-flow-testing` for other places the same "test every entry point, not just the obvious one" principle applies to fields tied to a user's identity. This is a distinct discovery angle from every existing entry in this skill — those are all about a *single* endpoint trusting a client-supplied value too much; this one is about *multiple* endpoints writing to the same value with inconsistent trust levels between them.

### 6. Rating/review manipulation — "one vote per user" enforced only in the UI
Source: [How I Was Able To Modify Ratings On A Target And Cause Business Impact](https://medium.com/bugbountywriteup/how-i-was-able-to-modify-ratings-on-a-target-and-cause-business-impact-f690fa0695b8)

**Where:** any rating/review/vote/like feature on a product, challenge, course, or listing where the UI limits each user to one submission (the target here was a coding-exam platform's challenge ratings, 1–5 stars). The intended workflow: rate once; to change it, delete the previous rating first.

**Root cause:** the one-rating-per-user-per-object constraint exists only as a frontend workflow. The backend never records or checks who already rated, so each replayed submission is counted as a new vote and the aggregate is recalculated on every one. There is also no rate limiting on the endpoint.

**Exploit steps:**
1. Submit one legitimate rating (`{"score":1}`) and capture the request in the proxy.
2. Note the baseline aggregate: average rating and total vote count (4.1 average, 14 votes in the writeup).
3. Replay the same request repeatedly (Burp Repeater or Intruder with a null payload).
4. Re-read the aggregate. Score distribution, total count, and average all shifted (2.9 average, 27 votes) without any delete-then-rate step.
5. Also try the opposite score (5) to inflate, and other objects' IDs to target a competitor's item.

**Impact framing:** integrity of a public trust signal. Show the before/after aggregate numbers in a PoC video and describe who relies on the rating (buyers, learners, ranking or recommendation logic). This report was marked duplicate, so check for prior reports of this pattern on the same program, and test every vote-like endpoint on the target (likes, upvotes, helpful-votes, polls) since the same missing check tends to recur.

**Generalize note:** related to the "repetition" attack in the core theory and to `race-condition-testing` (concurrent submissions may bypass a weak server-side check where sequential replays fail). Also try replaying after the delete-rating step to see whether the deletion decrements the count correctly.

## Severity framework for business-logic findings specifically

Per this source, a business-logic finding is reportable only when it demonstrably impacts one of the CIA triad — treat this as the same self-check as `bughunting-workflow` Phase 5's general reporting bar, applied to this vuln class specifically:
- **Confidentiality** — unauthorized access to another user's/tenant's data as a result of the logic flaw.
- **Integrity** — unauthorized modification of data or state that benefits the attacker (price/discount tampering, step-skipping to an unpaid "completed" state).
- **Availability** — denial of service or application crash triggered by the flaw.

**Explicitly called out as usually NOT reportable, even though they're technically "flaws":**
- Modifying your *own* data in a way the UI tries to restrict, with no privilege escalation and no other user affected — this is the account owner acting on their own account, not a security bypass.
- An incorrect calculation with no authorization gap and no financial/other concrete impact — a display bug, not a vulnerability.
- Performance degradation from unlimited/unthrottled object creation, absent an actual DoS demonstration — treat as a low-priority hardening note rather than a standalone finding unless you can show it actually degrades service.

### 6. Aggregate-stat manipulation via replayed single-use action — no server-side per-user dedup on a "once only" submission
Source: [How I Was Able To Modify Ratings On A Target And Cause Business Impact](https://medium.com/bugbountywriteup/how-i-was-able-to-modify-ratings-on-a-target-and-cause-business-impact-f690fa0695b8)

**Where:** any feature the UI presents as "you can only do this once" against a shared/public aggregate value — a 1–5 star rating on a product/challenge/listing, a like/upvote count, a review count, a poll vote — where the frontend enforces the once-only rule (hides the rating widget after submission, requires deleting the old rating before submitting a new one) but never proves the backend does.

**Root cause:** the rating-submission endpoint recalculates the aggregate (average score, vote count) from every request it receives, but never checks whether *this user* has already submitted a rating for *this object* before accepting and counting another one — no per-user-per-object uniqueness constraint, no idempotency key, not even basic rate limiting on the endpoint.

**Exploit steps:**
1. Submit one legitimate rating normally (`{"score":1}`) and capture the request in an intercepting proxy.
2. Replay the identical captured request repeatedly (simple sequential resend — no race condition or concurrency needed, since there's no dedup check at all to race against).
3. Watch the object's public aggregate fields after each replay: score-distribution bucket count, total vote/review count, and computed average — if all three keep moving on every replay, the endpoint has zero duplicate-submission protection.
4. Push the average as far as it will go in either direction to make the business impact concrete: in the source case, 20+ replays of a 1-star rating dropped a target's public average from 4.1 (14 votes) to 2.9 (27 votes).

**Impact:** any anonymous/authenticated user can single-handedly and repeatably tank (or inflate) a public-facing rating/reputation number that customers use to make purchasing/trust decisions — direct, quantifiable business/reputational impact even though no data is exfiltrated and no other user's account is touched. Frame the report around the before/after aggregate numbers exactly as in this technique's exploit steps 3–4, not just "missing duplicate check."

**Generalize note:** distinct from technique #3 (workflow-step bypass) because there's no sequence being skipped — it's pure repetition of a single already-valid request against an endpoint that should be single-use per user but isn't. Distinct from `race-condition-testing`'s TOCTOU angle because no timing/concurrency trick is required — the check is simply absent, not merely racy, so sequential replay alone is sufficient. Reporting outcome note: this exact finding was triaged as a duplicate on the source program despite a full PoC video — don't assume a clean repro guarantees acceptance; this vuln class (unauthenticated aggregate-stat tampering) may already be a known/accepted-risk item on some programs, so check program history/notes before investing heavy PoC effort.

### 7. Authorization ("can you write this") mistaken for data authenticity ("is this data real") — unverified identity/entity data persisted and trusted downstream
Source: [When "Verified" Doesn't Mean Verified: Finding a Business Logic Flaw in a Citizen Data Platform](https://freedium-mirror.cfd/https://medium.com/@espadar.julian/when-verified-doesnt-mean-verified-finding-a-business-logic-flaw-in-a-citizen-data-platform-fc91a3e12dfe)

**Where:** any platform that stores structured identity/entity records on a user's behalf and later reuses that data elsewhere — a citizen-data/government-adjacent platform pre-filling administrative forms from a stored profile, a KYC/onboarding flow storing claimed employer/business details, or any "add your vehicle/company/organization" profile feature whose stored value later flows into a report, an official document, or a downstream trust decision.

**Root cause:** the API's `"ownershipValid": true`-style response genuinely proves one thing — *this authenticated user is authorized to write to this record* — and the application silently treats that as proof of a completely different thing: *this record's content is real*. Authentication and authorization worked exactly as designed; there was simply no separate validation step checking the submitted content (a vehicle registration number, a company name, a business registration ID) against any authoritative source before persisting it as trusted, first-class profile data. The bug isn't a broken access-control check — it's the *absence* of a data-authenticity check that the application's own downstream behavior assumes exists.

**Exploit steps:**
1. Identify every record type the platform lets an authenticated user add/edit to their own profile (vehicle records, business/company records, association/organization records, employment records — any structured "add an entity you're affiliated with" feature).
2. For each record type, submit content that is syntactically well-formed but semantically fabricated: a non-existent vehicle registration number, an invented company name, a fabricated business registration identifier, a random association registration number — no injection payloads, no auth bypass, just fictitious-but-plausible data through the normal submission flow.
3. Confirm the record is accepted, persisted, and returned as part of the user's normal profile data (not rejected, not flagged, not queued for review).
4. Trace where that stored value is subsequently consumed — pre-filled into an official/administrative form, surfaced to a downstream system or third party, or used as an input to any automated decision — to establish that fabricated data doesn't just sit inertly in a profile but actively propagates as if it were verified.

**Impact:** fictitious identity/entity records become persistent, first-class data that downstream systems and officially-generated documents treat as authentic — enabling identity/entity impersonation, fraudulent administrative submissions pre-filled with fabricated details, and poisoning of any process (reporting, verification, cross-referencing) that assumes profile data on this platform has been validated because the feature name or a `verified`/`valid` field implies it has.

**Impact framing for report:** don't frame this as "missing input validation" (reads as low-severity, cosmetic) — frame it around the specific downstream consequence of trusting fabricated data: name the exact administrative process, form, or third party that receives the false information as if it were authentic, and if possible show a concrete generated artifact (a pre-filled form, an exported record) containing the fabricated content to prove the data actively propagates rather than sitting unused.

**Generalize:** whenever an API response includes a field that *sounds* like a data-quality guarantee (`verified`, `valid`, `confirmed`, `ownershipValid`) — stop and ask specifically what condition that field actually checks. It's extremely common for such a field to only assert an authorization fact ("you're allowed to write this") while the application's own UI/downstream logic treats it as an authenticity fact ("this content is true"). This is a different bug from mass-assignment-testing's "Verification / workflow-state bypass" entry (flipping an existing verified flag directly) and from `registration-flow-testing`'s email-verification entries (a token/link proving control of an address) — here there is no flag to flip and no token to steal; the gap is a validation step that was simply never built for the record's *content*, only for the request's *authorization*. Worth a dedicated pass on any platform whose core value proposition is storing "your" data for reuse elsewhere (government/citizen services, HR/employment platforms, KYC-heavy fintech, professional-licensing/credentialing sites).

<!-- Add new recorded techniques below this line as new business-logic writeups are processed. Keep the same structure: Where / Root cause / Exploit steps / Impact framing / Generalize note. -->

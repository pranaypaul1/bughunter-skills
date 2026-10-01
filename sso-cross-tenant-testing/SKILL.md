---
name: sso-cross-tenant-testing
description: Cross-tenant SSO/IdP authentication-confusion testing for multi-tenant B2B SaaS platforms — exploiting a missing binding between the identity provider a login flow actually uses and the tenant/organization it's supposed to authenticate into, so an attacker's own self-controlled IdP (configured under their own trial/free tenant) can be substituted into a victim organization's login flow and used to mint an authenticated session as any email address the attacker chooses, including a target admin's. Covers the discovery methodology (creating an attacker-controlled tenant + IdP, capturing its SSO routing/config values, then splicing them into a different tenant's login transaction), the five specific server-side bindings whose absence causes this (SSO-config-to-tenant, login-transaction-to-tenant, IdP-to-tenant, auth-response-to-transaction, identity-resolution-to-tenant), and a concrete test checklist. Use this during Phase 3 (Vulnerability Testing — Auth) of bughunting-workflow on any target offering "Login with SSO"/"Enterprise SSO"/SAML/OIDC federation per-organization, especially when the platform lets anyone self-serve a trial org and configure their own IdP for it. Also trigger on mentions of cross-tenant SSO, IdP confusion, tenant isolation bypass, SAML/OIDC organization takeover, multi-tenant identity provider, or "which IdP authenticates which tenant."
---

# SSO Cross-Tenant Authentication Confusion Testing

Technique library for cross-tenant SSO/IdP identity-confusion attacks on multi-tenant SaaS. Each dated entry below is a validated technique pulled from a real writeup — add new entries here (don't create a new skill) whenever a new writeup covers a different SSO protocol (SAML vs OIDC), a different binding gap, or a different discovery mechanic than what's already recorded.

## Core theory

Multi-tenant B2B SaaS platforms that offer "bring your own IdP" enterprise SSO have to correctly answer one question on every single login attempt: **which specific identity provider is authorized to vouch for identities inside *this* tenant?** The vulnerability class exists whenever the answer to that question can be influenced by anything the client controls — a query parameter, a hidden form field, an intercepted-and-modified response, a redirect URL — rather than being looked up purely from trusted server-side state the moment the login flow starts and held fixed for the rest of the transaction.

When that binding is missing, the attack is almost embarrassingly simple for anyone who can self-serve a trial/free tenant on the platform:
1. Attacker creates their own Organization A (often free/self-service, no special access needed).
2. Attacker configures their own fully-attacker-controlled identity provider (SAML or OIDC) for Organization A — they own it end-to-end, so it will issue whatever identity assertion they want.
3. Attacker creates a user inside their own IdP whose email address is set to the *victim's* — e.g. `admin@target-org.com`, the email of an administrator in a completely different Organization B they don't own.
4. Attacker captures the SSO routing/configuration values (IdP entity ID, SSO URL, metadata, whatever the app returns during login discovery) that point at *their* IdP for Organization A.
5. Attacker starts a login attempt scoped to Organization B (the victim's), then substitutes Organization A's captured SSO values into that flow — either via a modifiable client-side parameter, an intercepted response, or a manipulated redirect.
6. The browser gets sent to the attacker's own IdP (not Organization B's real one) and authenticates.
7. The attacker's IdP happily issues a "valid" assertion for `admin@target-org.com` — it's the attacker's IdP, they can assert anything.
8. The application, having resolved the assertion's identity globally by email rather than strictly within the tenant context that was fixed when the flow started, matches that email to the real admin account in Organization B and hands the attacker an authenticated session as them.

The single sentence that captures the whole bug class: **the app trusted a valid identity assertion without confirming the identity provider that issued it was actually authorized for the tenant receiving the resulting session.** Nothing here requires forging a signature or breaking cryptography — the attacker's own IdP signs its own assertions completely legitimately; the failure is purely in *which* IdP the server let govern *whose* login.

**The five bindings that must all hold, checked in order:**
1. SSO configuration returned to the client must belong to the tenant that's actually authenticating (not attacker-substitutable).
2. The login transaction itself must be bound server-side to one specific tenant for its entire lifetime.
3. The identity provider that responds must be verified as *that tenant's* configured provider — not just *some* provider on the platform.
4. The authentication response received must be matched back to the exact server-side transaction that initiated it (not just "a" pending transaction).
5. The identity string inside a valid response (typically an email) must be resolved *only* within the tenant that was fixed in step 2 — never looked up globally across all tenants on the platform.

Any one of these five missing is enough; this writeup's target had all five missing simultaneously.

## Discovery methodology (black-box, no source access needed)

1. Sign up for a trial/self-service organization if the platform allows it — this is often the only "privileged" step required and needs no special access.
2. Configure a self-controlled IdP (a free SAML/OIDC test IdP you fully control, e.g. a self-hosted SimpleSAMLphp instance or a free-tier IdP-testing service) for your own trial org.
3. Walk through your own org's SSO login flow once, capturing every value the application returns during the pre-authentication "discovery" step (SSO URL, IdP entity ID/issuer, metadata blob, a `RelayState`/state param, anything that identifies *which* IdP to redirect to) — proxy this through Burp/an intercepting proxy so nothing is missed.
4. In your own IdP, create a test identity whose email matches a plausible admin at the target victim organization (use a target admin's known/guessed email — this is the step that requires the target's admin email be discoverable, e.g. from a support page, LinkedIn, or breach data).
5. Start a *fresh* login attempt scoped to the victim's organization/tenant (their login URL, their org slug/subdomain — whatever selects tenant on this platform) and intercept the discovery response.
6. Replace the victim-tenant SSO values in that intercepted response/redirect with your own org's captured values from step 3 — test every field you can reach: hidden form fields, query parameters, `RelayState`, redirect `Location` headers, even fields that came back `null`/empty for the victim tenant (a null field is often the laziest possible binding gap — the client can just supply any value it wants there).
7. Let the redirect complete to your own IdP, authenticate as the spoofed-email test identity, and follow the response back into the application.
8. Check whether the resulting session is authenticated as the target admin inside the victim's tenant, not your own.

## Test checklist to run against any per-tenant SSO implementation

- Test identical email addresses registered across two unrelated/self-controlled identity providers — does the app resolve by email alone regardless of which IdP asserted it?
- Attempt SSO configuration/value reuse between two tenants you control, to confirm the binding gap exists in a safe sandbox before ever touching a real victim tenant.
- Modify every field returned by the authentication-discovery step, one at a time, watching for which ones the server actually re-validates versus blindly trusts back.
- Specifically hunt for and replace any `null`/empty SSO-related field with a real value pulled from a different tenant — a lazily-implemented "no SSO configured, fall through" path is a common place this binding is skipped entirely.
- Verify the tenant identifier chosen at the *start* of the flow is still the one enforced at the *end* — capture it at step 1 of the redirect chain and diff it against whatever's used when the final identity is resolved.
- Test whether a syntactically valid, correctly-signed assertion from an IdP that is *not* the one configured for the target tenant is still accepted — this is the core check; if yes, the finding is confirmed regardless of which specific field carried the substitutable value.

## Recorded techniques

### 1. Trial-tenant self-controlled IdP substitution → full cross-tenant admin takeover
Source: [I Used My Own Identity Provider to Take Over Another Tenant](https://freedium-mirror.cfd/https://yaseenzubair.medium.com/i-used-my-own-identity-provider-to-take-over-another-tenant-5f356ef77d3b)

**Where:** any multi-tenant B2B SaaS platform offering self-service enterprise SSO configuration per organization, especially one where a trial/free organization can be created without sales/admin gatekeeping — that self-service tenant creation is itself the only privileged capability the attack needs.

**Root cause:** all five bindings in Core theory were missing at once — SSO configuration wasn't scoped to the authenticating tenant, the login transaction didn't stay bound to the tenant chosen at the start, the IdP that responded was never checked against what the target tenant actually had configured, and the returned identity (an email) was resolved globally across the whole platform instead of only inside the tenant the flow was fixed to.

**Exploit steps:** create Organization A under attacker control → configure an attacker-owned IdP for it → create an identity in that IdP using the target admin's email → capture Organization A's SSO discovery/routing values via an intercepting proxy → start a login for the target admin scoped to Organization B → replace/inject Organization A's captured SSO values into that flow → complete authentication against the attacker's own IdP → application resolves the asserted email globally and hands back a session as the Organization B admin.

**Impact framing:** full administrative takeover of a completely unrelated organization on the platform — access to that org's users/roles/business data, tenant-scoped integrations and settings, potential API credentials and billing data, and the ability to create further privileged accounts inside the victim tenant. Reported as a black-box finding (no source-code access used), which strengthens the report — an attacker with zero insider knowledge and only self-service trial access could execute the full chain.

**Generalize note:** this is the SAML/OIDC-federation-specific sibling of `oauth-redirect-uri-bypass-testing` (that skill covers redirect_uri/callback-URL manipulation in a single-tenant OAuth flow; this one covers *which whole identity provider* governs *which tenant* in a multi-tenant SSO setup) and of `race-condition-testing`'s OAuth/SSO account-linking entry (that's a TOCTOU race on a linking endpoint; this is a straight logic/binding flaw with no race window needed at all). Also distinct from `session-auth-testing`'s email-verification-swap entries (#4/#5/#15/#17) — those exploit a *single-tenant* app trusting an unconfirmed email change; this exploits a *multi-tenant* app failing to scope identity resolution to the right tenant in the first place.

<!-- Add new recorded techniques below this line as new SSO cross-tenant writeups are processed. Keep the same structure: Where / Root cause / Exploit steps / Impact framing / Generalize note. -->

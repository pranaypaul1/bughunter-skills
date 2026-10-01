---
name: application-dos-testing
description: Application-level Denial-of-Service testing within bug bounty scope — finding legacy/non-standard HTTP server software on a target's own IP ranges via Shodan banner anomalies, then confirming (never at production-breaking scale) a connection-handling flaw such as missing per-request timeouts that lets a handful of held-open connections exhaust the worker pool. Covers responsible-scope PoC methodology (low connection counts, `timeout`-wrapped requests, immediate cleanup) so a DoS finding stays a reportable PoC rather than an actual outage — never run this beyond the minimum connections needed to prove impact, and only within an authorized program's scope/rules. Use this during Phase 1/3 (Recon/Vulnerability Testing — Availability) of bughunting-workflow whenever Shodan/infrastructure recon on a target's IP range turns up a server banner that doesn't match the rest of the fleet (a non-nginx/non-standard HTTP server module on an otherwise uniform range). Also trigger on mentions of DoS vulnerability, denial of service, connection exhaustion, worker-thread exhaustion, Shodan net: search, or method-specific hang (GET works, POST hangs).
---

# Application-Level DoS Testing (Bug-Bounty-Scoped)

General technique library for finding and *responsibly* proving application-layer DoS vulnerabilities within an authorized program's scope. Each dated entry below is a validated technique pulled from a real writeup/source — add new entries here (don't create a new skill) whenever a new writeup covers a *different* connection-exhaustion mechanism or discovery method than what's already recorded.

## Core theory

Most DoS findings in bug bounty come from one of two shapes:
1. **Missing rate limiting / resource caps** on an expensive operation (covered by `rate-limit-bypass-testing` and `registration-flow-testing` for the brute-force/signup-flood angle) — the fix is a limiter, not a protocol bug.
2. **A connection-handling defect** in the server/framework itself — a request that the server accepts but never finishes handling, holding a worker thread/connection slot open indefinitely. A small number of such requests (5–20, not thousands) can exhaust a bounded worker pool and deny service to everyone else. This second shape is what this skill covers.

**Why legacy/non-standard software matters here:** a mainstream, actively-maintained web server (nginx, standard Apache config) has had this class of bug hammered out over decades. A bespoke or legacy HTTP server module — something a company wrote or vendored in-house years ago and forgot about — is exactly where a missing-timeout defect survives, because it gets essentially zero security review compared to the rest of the stack. Finding *that* one odd server in an otherwise-uniform fleet is most of the work.

**Responsible-scope discipline (read before testing):** this class of bug is real DoS — confirming it necessarily degrades the target's availability for the connections you hold open. Keep every PoC to the smallest number of connections that still proves the point (5, scaling to at most 10–20 only if the program's scope explicitly allows a DoS category and asks for full-exhaustion proof), always wrap test requests in `timeout` so nothing lingers past your own test window, and close/release every connection immediately after capturing evidence. Never scale this toward an actual sustained outage, never test outside a program's explicit DoS-in-scope rules (many programs explicitly exclude DoS — check `notes/scope.md` first), and never point it at anything you haven't confirmed is in-scope production infrastructure you're authorized to test.

## Trigger technique: Shodan IP-range banner-anomaly hunt

Rather than searching Shodan for a product/CVE (that's `recon-scanning-toolkit`'s mass-CVE-hunting technique), search the target's *own* IP range and look for the one host that doesn't match the rest:

```bash
# Once you have a target's ASN/IP range (from Phase 1b infrastructure discovery):
shodan search net:<TARGET_CIDR>
```

Scan the results for a server banner that stands out from the fleet's otherwise-uniform stack (e.g. ten hosts all reporting standard nginx, one reporting an obscure/legacy HTTP server module with a version string nobody's seen before, or an unusually high open-port count relative to its siblings). That outlier is disproportionately likely to be an old, unmonitored, custom-built service — worth a manual pass regardless of which vuln class you end up finding on it.

## Recorded techniques

### 1. Legacy "Pike" HTTP server — missing POST-handler timeout → worker-pool exhaustion
Source: [Found a Denial of Service Vulnerability in a Major Company's Production Infrastructure Using Shodan](https://infosecwriteups.com/found-a-denial-of-service-vulnerability-in-a-major-companys-production-infrastructure-using-shodan-e5f766a4df79)

**Where:** discovered by searching Shodan for the target's own IP range (`net:185.26.x.x/22`) — one host stood out from the surrounding nginx fleet by reporting `Pike v8.0 release 908: HTTP Server module` with eleven open ports, a clear banner anomaly worth manual investigation on its own.

**Root cause:** Pike's `ext` HTTP module had no timeout enforcement specifically on POST request handling. Method-specific behavior confirmed the bug:
- `GET` requests returned an immediate error ("Don't know how to handle request in ext") — normal, fast-failing behavior.
- `POST` requests were accepted (connection established, data acknowledged) but the server **never sent a response** — the connection just hung, indefinitely, consuming a worker slot the whole time.

**Confirmation steps:**
```bash
# Baseline: confirm GET fails fast (rules out "server is just generally down")
curl -X POST -d "test" http://<TARGET_IP>:8888/

# Confirm the hang is real and sustained, not just slow — wrap in timeout so your own client doesn't hang forever
timeout 300 curl -X POST -d "test" http://<TARGET_IP>:8888/
# -> no output for the full 300s, exits with code 124 (timeout killed it) — server never responded
```

**Minimal impact PoC (kept intentionally small — see responsible-scope discipline above):**
```bash
for i in {1..5}; do
  timeout 60 curl -X POST -d "test$i" http://<TARGET_IP>:8888/ &
done

# In a second terminal, confirm the connections are actually held open server-side:
netstat -tn | grep <TARGET_IP>:8888
# -> 5 ESTABLISHED connections, none progressing/closing — each is pinning a worker thread
```
The report noted (without needing to actually execute it) that scaling this same loop to 10–20 concurrent POSTs would exhaust the worker pool entirely and deny legitimate traffic — the 5-connection PoC was sufficient to prove the mechanism without pushing the target into an actual outage.

**CVSS used:** 7.5 (High), `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` — network-exploitable, no auth, low complexity, pure availability impact with no confidentiality/integrity component.

**Reporting note — anticipate GET-vs-POST triage confusion:** the program's first triage pass tested with GET (which fails fast and looks "fine"), initially missing the bug. Be explicit in the report that the vulnerability is method-specific and spell out the GET-vs-POST contrast directly, rather than assuming a triager will re-derive it — this exact writeup called that confusion out as the reason the first triage pass almost bounced the report. Result: P2 (High) under Bugcrowd VRT.

**Generalize note:** the discovery method (Shodan `net:` search across the target's own range, looking for the one banner that doesn't match the fleet) generalizes to any forgotten/legacy service, not just DoS-prone ones — cross-reference `recon-scanning-toolkit`'s asset-discovery-via-cert-pivoting technique for the sibling approach (finding unlinked infra via SSL cert search rather than banner anomaly). Once you've found an odd legacy server, always test both GET and POST (and other methods) explicitly rather than assuming uniform behavior — a connection-handling bug that's invisible on one HTTP method and total on another is an easy false-negative if you only ever probe with GET.

<!-- Add new recorded techniques below this line as new DoS writeups are processed. Keep the same structure: Where / Root cause / Exploit steps / Impact framing / Generalize note. -->

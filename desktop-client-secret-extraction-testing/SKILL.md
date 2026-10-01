---
name: desktop-client-secret-extraction-testing
description: Secret/credential extraction from desktop client applications — Electron apps (unpacking `app.asar`) and Windows desktop software (unpacking installers with innounp) — as a distinct client-artifact category alongside mobile APK/IPA extraction. Covers the unpack commands, what files/patterns to search once unpacked, and the general extract→grep→curl-validate pipeline that turns a found-looking string into a fundable bug. Use this during Phase 1/3 (Recon/Vulnerability Testing — Info disclosure) of bughunting-workflow whenever a target ships an Electron-based desktop app (Slack/Discord/VS Code-style bundle) or a native Windows installer, alongside `mobile-app-testing`'s equivalent Android/iOS extraction and `github-recon-testing`'s key-validation methodology. Also trigger on mentions of app.asar, asar extract, Electron secrets, innounp, or desktop app reverse engineering.
---

# Desktop Client Secret Extraction

General technique library for extracting hardcoded secrets from desktop client application binaries. Each dated entry below is a validated technique pulled from a real writeup/source — add new entries here (don't create a new skill) whenever a new writeup covers a *different* desktop-client artifact format or extraction angle than what's already recorded.

## Core theory

Desktop client apps are a compiled/packaged artifact exactly like a mobile APK/IPA — a different container format around the same underlying failure: developers embed API keys, service tokens, and internal config values as plain strings in code that ships to every user's machine, assuming (wrongly) that "it's not a web page, nobody's going to unpack it." A desktop installer is trivially unpackable with the right tool, at which point the same string-grep methodology that works against a decompiled APK works identically here.

## Recorded techniques

### 1. Electron `app.asar` extraction and Windows installer unpacking
Source: [Extract-Grep-Curl: A $50,000 Bug POC Methodology](https://infosecwriteups.com/extract-grep-curl-a-50000-bug-poc-methodology-16365489de92)

**Where:** any target shipping an Electron-based desktop app (common for chat/collaboration tools, internal admin desktop clients, and cross-platform companion apps — recognizable by an `Electron`/`Chromium` framework signature in the installed app's `About` dialog or process list) or a native Windows desktop application distributed via an installer executable.

**Root cause:** Electron apps bundle their entire JS/HTML/CSS application source into a single `app.asar` archive (a tar-like format, not encrypted or obfuscated by default) shipped inside the installed app's resources directory — any config file, `.env`, or hardcoded credential the web-equivalent app would have kept server-side ends up shipped to every user's disk instead. Windows desktop installers similarly bundle DLLs and config files that frequently contain the same category of embedded secrets, protected only by the mild friction of needing an installer-unpacking tool rather than any real access control.

**Exploit steps — Electron:**
```bash
# Default install location varies by OS; on macOS:
# /Applications/App.app/Contents/Resources/app.asar
npx asar extract app.asar out
# Search the unpacked source tree for config/secret files:
find out -iname "*.env" -o -iname "config.json" -o -iname "settings.js" -o -iname "*.db"
```

**Exploit steps — Windows desktop (installer-packaged apps):**
```bash
innounp -x setup.exe
# Search extracted DLLs and config files:
grep -rE 'KEY|SECRET|TOKEN' --include=*.{ini,cfg} .
```
`innounp` specifically targets Inno Setup-packaged installers (a very common Windows installer framework); other installer frameworks (NSIS, WiX/MSI) need their own matching unpacker (`7z x` frequently works generically against NSIS installers; `msiexec /a` extracts an MSI without installing it) — identify the installer framework first (file properties, strings on the installer binary itself) before assuming `innounp` applies.

**Follow-up — same grep/curl pipeline as any other client artifact:**
```bash
grep -rE --include=*.{env,json,js,xml,ini,cfg} \
  'ghp_|AKIA|sk_live|eyJ|client_secret|api_key|token' \
  ./out
```
Then validate any hit exactly as in `github-recon-testing`'s Key validation section (Keyhacks command per provider) before reporting — an unvalidated found-looking string is not a finding.

**Impact:** identical category of impact to the mobile/web equivalents once a live, write-capable credential is confirmed — this source's own headline example (a $50,000 GitHub token) was extracted via exactly this pipeline, though not confirmed to be from a desktop client specifically vs. mobile in the source's own account; treat this skill's extraction methods and `mobile-app-testing`'s as parallel tracks worth running against any target that ships more than one client type, since secret hygiene is frequently inconsistent across a company's different client codebases.

**Generalize note:** cross-reference `mobile-app-testing`'s iOS `.ipa`/Android `.apk` extraction entries for the mobile-equivalent techniques from this same source, and `github-recon-testing`'s Key validation section for the concrete GitHub-token escalating-permission-check curl chain used to turn a found token into a reportable, quantified-impact finding.

<!-- Add new recorded techniques below this line as new desktop-client-extraction writeups are processed. Keep the same structure: Where / Root cause / Exploit steps / Impact framing / Generalize note. -->

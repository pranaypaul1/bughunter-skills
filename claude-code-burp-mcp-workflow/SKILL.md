---
name: claude-code-burp-mcp-workflow
description: Using AI as the testing assistant during a live bug bounty engagement — either Claude Code wired directly into Burp Suite's proxy history via MCP (Model Context Protocol) so it can read traffic, propose attack surface, run through vuln classes, and draft reports without copy-pasting requests back and forth, or Burp Suite Professional's own native agentic feature ("Burp AT") driving Burp's tools directly from an investigative goal. Covers the exact MCP connection steps, the four-phase Claude prompt structure (traffic analysis → attack surface mapping → active testing → report generation), Burp AT's scope/autonomy/effort controls and five-part prompt structure (Target/Question/Context/Limits/Evidence criteria), an evidence-first validation gate for any AI-proposed finding, and a no-MCP fallback for working off raw saved requests/JS files instead. Use this at the start of ANY engagement, alongside `bughunting-workflow`, to decide how AI assistance should be looped into the hunt — not a vuln-class skill, a meta/tooling skill for how to run the other skills through an AI agent faster. Also trigger on mentions of Burp MCP, claude mcp add burp, MCP extension, PortSwigger MCP server, Auto-Approved HTTP Targets, Burp AT, Burp AI Testing, or "how do I use Claude/AI with Burp".
---

# Claude Code + Burp Suite MCP Workflow

Meta/tooling skill, not a vuln-class skill — this is about how to point Claude Code *at* the target's traffic so it can assist across every phase of `bughunting-workflow`, rather than a technique for a specific bug class. Each dated entry below is a validated setup/workflow pulled from a real writeup — add new entries here (don't create a new skill) whenever a new writeup covers a materially different AI-assisted workflow than what's already recorded.

## Core theory

Copy-pasting individual requests into a chat window doesn't scale past a handful of endpoints. Wiring Claude directly into Burp's proxy history via MCP means it can read the *entire* traffic history in place, hold the whole app's surface in context at once, and get asked to move through phases the way a human would: understand the app → prioritize targets → test systematically → write it up — instead of being fed one request at a time with no memory of the last fifty.

The failure mode to guard against is the opposite one: an LLM that's eager to call something a "finding" from a plausible-looking request/response pair alone. Every prompt template below ends by demanding a proof/evidence standard, and the workflow has an explicit validation gate (see below) specifically to keep Claude's output honest — separating confirmed vulnerabilities from suspected issues from mere observations, and requiring deterministic reproduction before anything gets written up.

## Recorded techniques

### 1. Full Burp MCP setup + four-phase prompt workflow
Source: [The Best Claude Code Setup for Bug Bounty Hunting](https://infosecwriteups.com/the-best-claude-code-setup-for-bug-bounty-hunting-a16a0a50e811)

**Setup — connecting Claude Code to Burp:**
1. Install the MCP extension from Burp's BApp Store (search "MCP").
2. In the extension's MCP tab, add the target domain(s)/wildcard (e.g. `*.test-target.com`) to "Auto-Approved HTTP Targets" so Claude isn't prompted for permission on every single request it reads.
3. If running Claude Code from the terminal, extract/build the JAR from the official PortSwigger MCP server repo (`github.com/PortSwigger/mcp-server`) and load it in Burp's Extensions tab; confirm the server is listening on localhost with an assigned port.
4. Connect Claude to it:
   ```bash
   claude mcp add burp --transport sse http://127.0.0.1:9876
   ```
5. In Burp's HTTP history, turn on "Show only in-scope items" and "Show only parameterized requests" before starting — keeps what Claude reads limited to what actually matters instead of every static asset request.

**Project folder layout** (mirrors this hunter's existing per-target structure — see `HunterY`/`HunterZ` targets):
```
target/
├── recon/        (subdomains.txt, alive.txt, urls.txt)
├── requests/     (login.txt, profile.txt, api.txt — saved raw requests)
├── javascript/   (app.js, dashboard.js, auth.js)
├── source/
└── notes/
```

**Phase 1 — Traffic Analysis.** Prompt Claude with: "List the requests in my Burp proxy history, showing method, URL, and status code for each. Then summarize the application, filter to target domain requests, list API endpoints in a table with method/path/parameters, scan for sensitive data, and summarize testable endpoints." This is the app-understanding pass — run it before anything else so every later prompt has context on what the app actually does.

**Phase 2 — Attack Surface Mapping.** Prompt: "Analyze Burp proxy history to identify attack surface: find search/q parameters, numeric ID parameters, admin/profile/upload endpoints, fetch JavaScript files for secrets, output prioritized endpoint list grouped by bug type (SQLi, XSS, IDOR, auth)." Output feeds directly into `bughunting-workflow` Phase 2's prioritized target list.

**Phase 3 — Active Testing.** Prompt: "Test for vulnerabilities one class at a time: SQL injection, Reflected XSS, IDOR, weak credentials, user enumeration, rate limiting, broken access control, business logic. Report one-line results after each test. List every confirmed/suspected finding with severity, endpoint, and proof." Note the "one class at a time" instruction — this is deliberate, it keeps Claude from conflating findings across classes and forces a one-line accounting per test so nothing gets silently skipped.

**Phase 4 — Report Generation.** Prompt: "Write professional pentest-style summary including vulnerability name, severity (Critical/High/Medium/Low), affected endpoint, exploitation method, proof (request + response), save interesting requests to Burp Organizer for evidence." Report structure: executive summary (3-4 lines) → per-finding entries (title, CVSS 3.1 vector/score, affected endpoint, vuln class, numbered reproducible steps, request/response evidence, business impact, specific remediation) → chained-findings section → severity-ranked summary table → appendix with Burp Organizer request IDs.

**Validation gate — run before trusting ANY Claude-proposed finding:**
- Replay it with a clean, minimal request in Repeater; it must reproduce deterministically, twice.
- Prove impact in the actual response (leaked data, executed code, a real state change, a privileged action taken) — not just "this looks injectable."
- Kill (discard) any finding that can't be stood behind under that bar.
- Store every surviving PoC request in Burp Organizer as the evidence trail.

**No-MCP fallback (no Burp integration available):** Claude can still assist working off static artifacts instead of live proxy history:
- Analyze individual raw HTTP requests saved as `.txt` files (prompt: "Identify all user-controlled inputs, authentication/authorization mechanisms, interesting IDs, IDOR/BOLA candidates, injection points, business-logic parameters, security headers/cookies, and unusual behavior. Rank by severity. Separate observations from hypotheses. Explain required evidence to confirm issues.")
- Extract endpoints/secrets from JS bundles (prompt: "Analyze this JavaScript file: extract API endpoints, HTTP methods, parameters, authentication logic, hardcoded secrets, admin endpoints, upload/download features, debug endpoints, hidden functionality, DOM sources/sinks, third-party integrations. Explain why each discovery deserves investigation. Avoid assuming vulnerabilities without evidence.") — same job `recon-scanning-toolkit`'s JSRecon section does with dedicated tools; use this when you want Claude's reasoning over the extracted surface rather than just a grep-style tool pass.
- Review source code for auth/authz flaws directly.
- Correlate multiple artifacts (recon data, saved requests, JS, source) into one unified assessment when no single source tells the whole story.

**Custom Skills referenced for further automation:** the article points to open-source Claude Code Skill collections for bug hunting — skills.sh (directory), `github.com/SnailSploit/Claude-Red`, `github.com/elementalsouls/Claude-BugHunter`, `github.com/Awarexone/Agentic-Bug-Hunter` — as sources of reusable payload/validation/reporting skills beyond what's recorded in this hunter's own skill set. Worth a periodic look for techniques not yet captured here, but treat anything pulled from them the same as any other source writeup: verify before recording as a technique here.

**Generalize beyond Burp specifically:** the four-phase structure (understand → prioritize → test class-by-class → report) and the evidence-first validation gate are the reusable part — apply that shape even when the live-traffic source is something other than Burp (e.g. an MCP-less proxy log export, a HAR file), by substituting the no-MCP fallback prompts above.

### 2. Burp AI Testing ("Burp AT") — Burp Suite Professional's native agentic testing feature
Source: [Burp AT Isn't an AI Scanner, It's a Pentesting Agent](https://freedium-mirror.cfd/https://medium.com/@aryan351985/burp-at-isnt-an-ai-scanner-it-s-a-pentesting-agent-86ce9f44334d)

**What it is / how it differs from this skill's other entry:** Burp AT is PortSwigger's own agentic AI built directly into Burp Suite Professional (currently public beta) — not Claude wired in via MCP. Where entry #1 above is "point an external LLM at Burp's traffic," Burp AT is "the AI lives inside Burp itself and drives Burp's own tools (Scanner, Intruder, Repeater, Collaborator) directly." Core distinction from a traditional automated scanner: "A scanner executes predefined checks. Burp AT pursues a question" — you give it an investigative goal, it plans and adaptively reasons its way toward answering it rather than running a fixed check list. Requests still originate from your own machine/Burp install, not from PortSwigger's infrastructure.

**Three control mechanisms to configure before any run:**
- **Scope** — the authorized-target boundary, checked before every tool execution; changing it mid-task requires manual re-approval.
- **Autonomy** — how much runs without your sign-off: **Manual** (every tool call needs individual Ask/Act approval), **Smart** (routine actions proceed automatically, risky ones still stop for approval), **Autonomous** (most permitted actions run unattended).
- **Effort** — investigation depth (Low/Medium/High/Max), trading AI-credit consumption for exploration breadth; note a broad/vague task doesn't get better just by cranking effort up — the prompt quality matters more than the effort dial.

**Five-part prompt structure for an effective task** (the actual technique to reuse, regardless of which agentic tool you're driving):
1. **Target** — the specific host/endpoint/attached resource, not "the whole app."
2. **Question** — the exact security behavior to confirm or reject (not "find bugs").
3. **Context** — what correct/expected behavior looks like, and what observation prompted the investigation.
4. **Limits** — explicit actions to avoid and the acceptable impact scope (non-destructive, no data modification, etc.).
5. **Evidence criteria** — what response/behavior counts as confirmation vs. rejection vs. inconclusive, and the explicit stopping point.

**Worked example (cross-account IDOR/authorization check):** rather than manually spinning up two test accounts and diffing responses by hand, hand Burp AT a task naming both accounts, the target endpoint, the exact comparison to run (account A's session requesting account B's resource), and a non-destructive constraint — it executes the baseline-request → controlled-variation → response-comparison → alternative-explanation-evaluation → confirm/reject workflow autonomously and returns the finding with the supporting request/response pairs and highlighted evidence regions attached, structured as a standard Burp issue (name, URL, severity, confidence, description, evidence) that remains fully editable — the tester still determines final severity/validity, exactly the same discipline as entry #1's validation gate above.

**Skills system:** Burp AT has its own internal "skills" (bundled instructions + supporting code for a focused technique) that it invokes automatically mid-task, shown via a banner naming which skill fired and which tools it called — conceptually the same idea as this hunter's own `~/.claude/skills/` topic-skill library, just built into the product itself rather than hand-authored.

**Privacy/data-handling constraints before using this on a live engagement:** target requests stay local (Burp itself makes them), but task data — prompts, requests, responses, tool results — is transmitted to PortSwigger and its AI providers, encrypted in transit (TLS 1.2+) and at rest (AES-256); AI providers are contractually barred from training on it, but PortSwigger retains conversation audit data indefinitely and processes in US data centers with no region selection available. **Confirm the program's/client's rules of engagement explicitly permit third-party data sharing before pointing Burp AT at any in-scope target** — this is a distinct authorization question from "am I allowed to test this target at all."

**Audit trail:** every Burp AT action stays inspectable after the fact via the conversation's "Show details" expansion, Burp's own Logger entries, Dashboard scan records, site-map updates, and a task-findings export — useful for reconstructing exactly what an autonomous run actually did if a finding needs re-verification later.

**First-use recommendation (start conservative):** a controlled test environment, single-host scope, Manual approval mode, Medium effort, non-destructive impact only, one specific security question, and explicit stopping criteria — then review the tool-call history, scope adherence, and request log, and manually reproduce the finding before raising autonomy/effort on a real engagement.

**Caution — prompt injection surface:** application content the agent reads (JavaScript, response bodies, headers) can attempt to influence the agent's own behavior mid-task — the same general prompt-injection risk as entry #1's guard against an over-eager LLM calling a plausible-looking response a "finding," but here the injection source is the *target application itself*, not just the agent's own eagerness. Treat any instruction-shaped content the agent reports back from a response body with the same suspicion `github-recon-testing`/`loxs-medium`'s own untrusted-data handling already applies to fetched content.

**Generalize:** same evidence-first, human-verifies-the-final-call discipline as entry #1, now built natively into the tool rather than bolted on externally — whichever agentic-AI-in-Burp approach is available on a given engagement, treat the five-part prompt structure (Target/Question/Context/Limits/Evidence criteria) as the reusable technique, and start every new agentic tool the same way: narrow scope, manual approval, one question, explicit stop condition, before trusting it with anything broader.

<!-- Add new recorded techniques below this line as new Claude-Code-for-bugbounty workflow writeups are processed. Keep the same structure: Setup / Phase prompts / Validation gate / Generalize note. -->

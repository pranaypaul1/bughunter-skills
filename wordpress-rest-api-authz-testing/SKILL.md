---
name: wordpress-rest-api-authz-testing
description: WordPress/WordPress-plugin REST API endpoints (`/wp-json/<namespace>/v1/...`) that skip the `permission_callback` check on route registration, letting unauthenticated POST/PUT/DELETE requests read or write plugin/site settings, options, or data with zero auth. This is a distinct, extremely common WordPress plugin CVE pattern — a plugin author registers a REST route via `register_rest_route()` and either omits `permission_callback` entirely, sets it to `__return_true`, or only checks `current_user_can()` on the *admin UI* that calls the route rather than the route itself. Use this during Phase 1/3 (Recon/Vulnerability Testing — Access control) of bughunting-workflow the moment a target fingerprints as WordPress with third-party plugins active (theme/plugin JS references, `wp-content/plugins/` paths, an admin JS file making `jQuery.ajax` calls to a `/wp-json/` URL). Also trigger on mentions of wp-json, register_rest_route, permission_callback, WordPress REST API, X-WP-Nonce, or "unauthenticated WordPress plugin settings write".
---

# WordPress Plugin REST API — Missing Authorization

Command/technique library for a specific, recurring WordPress bug class: a plugin exposes a REST API route intended only for its own admin settings page, but the route itself never checks who's calling it — only the admin page's UI hid the button from non-admins. Each dated entry is a validated finding from a real report — add new entries here (don't create a duplicate skill) when a different plugin/endpoint shows the same missing-`permission_callback` pattern, or a genuinely new WP-REST-specific bypass technique.

## Core theory

Every WordPress REST route is registered with three pieces: a namespace/route path, a callback (what runs), and a `permission_callback` (who's allowed to call it). WordPress does **not** default to requiring authentication if `permission_callback` is omitted — historically it defaulted to `__return_true` (public) unless the plugin author explicitly wired in a capability check, and even now a lazy/wrong `permission_callback` (checking the wrong capability, or none) reaches the same result. This means:

- The route can be **completely unauthenticated** even though the only way a normal user reaches it is by being logged in as an admin and clicking a button in `wp-admin` — the auth "check" that matters to the developer's mental model (you have to be on this admin page to see the button) is not a check the server itself enforces.
- The endpoint often **does validate input shape** (rejects malformed JSON, enforces expected keys) — which can create false confidence during recon ("it's clearly parsing/processing real logic, so it must be gated") when in fact input validation and authorization are two completely independent checks, and only one of them was implemented.
- The same vulnerable pattern frequently repeats **across multiple plugins by the same vendor** — if one Crocoblock/Jet-family plugin has it, check every other plugin from that vendor active on the target; they tend to share a settings-registration helper/pattern.

## Trigger technique: confirm processing, then confirm authorization — separately

Don't conflate "the endpoint does something" with "the endpoint is protected." Test the two independently:

1. **Discovery** — fingerprint active plugins (readme.txt version disclosure, enqueued JS/CSS filenames, `wp-content/plugins/<slug>/` paths from page source) and their REST namespaces. Most plugins register routes under their own namespace, guessable from the plugin slug: `/wp-json/<plugin-slug>-api/v1/...` or similar. Read the plugin's own admin JS (often unminified or easily readable) for the exact `jQuery.ajax`/`fetch` call it makes to its settings endpoint — this hands you the exact URL, method, and expected body shape without any guessing.
2. **Confirm the route actively processes input** — send deliberately malformed JSON. A `400`/parse-error response (rather than a generic 404/501) proves the route exists, is wired to a real handler, and inspects the body — ruling out "this route doesn't really do anything" before investing more effort.
3. **Confirm authorization independently** — send a *valid*, minimal request with **no cookies, no `X-WP-Nonce` header, no Authorization header** at all. A `200`/success response with no auth material sent proves the `permission_callback` is missing or broken — this is a separate finding from step 2, not a continuation of it.
4. **Check every route in the same family** — a vendor's plugin suite frequently registers several near-identical routes (one per plugin) using the same insecure helper. Test each one the same way rather than stopping at the first confirmed instance; each additional confirmed endpoint strengthens the report (same-vendor pattern, not an isolated one-off).

## Recorded techniques

### 1. Unauthenticated plugin-settings write across three Crocoblock/Jet plugins (WordPress/Elementor ecosystem)
Source: HackerOne report [#3839914 — Unauthenticated Plugin Settings Modification on Three Crocoblock/Jet Plugins](https://hackerone.com/reports/3839914), program: Essity. Reported by matty69v, 2026-07-03. Severity: **Medium (4–6.9)**. Weakness: Missing Authorization. Bounty: undisclosed (hidden). Resolved.

**Where:** JetElements, JetWooBuilder, and JetWooProductGallery (Crocoblock/Jet plugin family for Elementor) each registered a `plugin-settings` REST route:
```
POST /wp-json/jet-elements-api/v1/plugin-settings
POST /wp-json/jet-woo-builder-api/v1/plugin-settings
POST /wp-json/jet-woo-product-gallery-api/v1/plugin-settings
```

**Root cause:** these routes persist submitted key-value pairs straight into the WordPress `wp_options` table with no `permission_callback` requiring `manage_options` (or any capability) and no `X-WP-Nonce` verification — despite validating that the POST body is well-formed. The admin panel's own JS (`jet-elements-admin.js`) calls the identical endpoint via `jQuery.ajax` POST without ever sending a nonce, confirming the omission was in the route registration itself, not just a client bug.

**Exploit steps (exact PoC from the report):**
```bash
# Step 1 — confirm the endpoint actively processes input (not a no-op/404)
curl -s "https://target/wp-json/jet-elements-api/v1/plugin-settings" \
  -X POST -H "Content-Type: application/json" -d '{invalid json!!!'
# → 400 {"code":"rest_invalid_json", ...} — proves real parsing/handling exists

# Step 2 — send valid data with zero authentication
curl -s "https://target/wp-json/jet-elements-api/v1/plugin-settings" \
  -X POST -d "api_key=TEST_FROM_POC_12345"
# → 200 {"status":"success","message":"Settings have been saved"} — no cookies, no nonce, no auth of any kind

# Step 3 — repeat against sibling plugins from the same vendor
curl -s "https://target/wp-json/jet-woo-builder-api/v1/plugin-settings" \
  -X POST -H "Content-Type: application/json" -d '{}'
curl -s "https://target/wp-json/jet-woo-product-gallery-api/v1/plugin-settings" \
  -X POST -H "Content-Type: application/json" -d '{}'
# → both: 200 {"status":"success","message":"Settings have been saved"}
```

**Exploitable settings identified by reading the admin JS source** (`jet-elements-admin.js`) rather than guessing field names:
| Setting key | Type | Impact |
|---|---|---|
| `avaliable_widgets` | `{widget_slug: "true"/"false"}` | Enable/disable any/all JetElements widgets site-wide |
| `api_key` | string | Overwrite the Google Maps API key with an attacker-controlled one |

Disabling every widget key (`avaliable_widgets[jet-animated-text]=false&avaliable_widgets[jet-slider]=false&...`) breaks every page using JetElements (sliders/carousels/counters) — a straightforward unauthenticated DoS via configuration corruption, no injection or crash required.

**Impact framing:** three-pronged — (1) **DoS** via disabling widgets site-wide, (2) **API key hijacking** — replacing `api_key` (Google Maps) with an attacker-controlled key redirects billing to the attacker's account and lets them harvest whatever geolocation query data flows through it, (3) **configuration corruption** — arbitrary key-value writes into `wp_options` beyond the two analyzed keys, so the actual blast radius depends on every other option key the vulnerable routes accept. Rated Medium here (not Critical) because the exposed settings were config/availability-impacting rather than directly compromising confidentiality of user data or enabling code execution — contrast with a similar missing-auth REST route that touches PII or auth state, which would score higher.

**Remediation the program applied:** add `permission_callback` requiring `manage_options` to each route registration, and add `X-WP-Nonce` verification — i.e., implement the two independent checks (authn/authz vs. input validation) that were conflated in the original code.

**Generalize:** whenever an admin-only settings page in a WordPress plugin makes an AJAX call, read the request in the browser Network tab (or the JS source directly) and replay it with all auth material stripped — if it still succeeds, the "protection" was UI-only. Cross-reference `recon-scanning-toolkit`'s WordPress-specific scanning section for plugin/version fingerprinting to seed this technique, and check the vendor's *other* plugins on the same site once one instance is confirmed.

<!-- Add new recorded techniques below this line as new WordPress REST API authorization writeups are processed. Keep the same structure: Where / Root cause / Exploit steps / Impact framing / Generalize note. -->

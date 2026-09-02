# WP-CLI Security Scan

Read-only WP-CLI diagnostics for compromised WordPress sites.

The package is designed for a workflow where a site's `wp-content` directory and database are restored into a clean local WordPress installation before analysis.

## What it scans

A standard scan runs in separate stages:

1. Scanner-owned WordPress core checksum verification against the official WordPress.org manifest
2. Plugin source/repository reputation
3. WordPress.org plugin checksum verification
4. Regular plugins in the selected scan scope (active only by default)
5. MU plugins and WordPress drop-ins
6. Themes in the selected scan scope (active theme + parent by default)
7. Uploads
8. Other directories/files inside `wp-content`
9. Database content
10. Users and persistence data

The scanner is **read-only**. It does not remove, quarantine, edit, or repair files or database records.

The scanner intentionally does **not** bootstrap WordPress with `wp-settings.php`. It evaluates WP-CLI's stripped `wp-config.php` code only to obtain the trusted local database/path configuration, opens its own read-only-enforcing database connection, and reads plugin/theme metadata directly from files. PHP error display is suppressed for the scan process; `wp-config.php` is not edited. The workflow therefore assumes the local WordPress core and `wp-config.php` used for analysis are trusted, while the restored `wp-content` and database are treated as suspect.

## Isolated scanner runtime

The restored `wp-content` directory is treated as untrusted input. The scanner therefore avoids normal `load_wordpress()` / `wp-settings.php` bootstrap and does not execute regular plugins, themes, MU plugins, or `wp-content` drop-ins in order to inspect the site.

Runtime data is obtained without loading suspect application code:

- WP-CLI's stripped `wp-config.php` code supplies database credentials, table prefix, and configured content paths;
- a scanner-owned `mysqli` adapter reads WordPress tables directly instead of loading `db.php` or object-cache drop-ins, and rejects non-read SQL at the adapter boundary;
- plugin and theme headers are parsed from file text rather than by including PHP files;
- active plugin/theme state, users, roles, cron, and scan targets are resolved from direct database reads;
- WordPress.org core/plugin checksum and reputation requests use scanner-owned HTTPS clients with TLS verification, an explicit WordPress.org destination allowlist, trusted `WP_PROXY_*` cURL proxy/bypass settings, `WP_HTTP_BLOCK_EXTERNAL` / `WP_ACCESSIBLE_HOSTS` policy, and a 16 MiB response-size limit.
- WordPress core version metadata is parsed from `wp-includes/version.php` as text; the file is never included or executed by the scanner.

If active plugin/theme state is malformed or cannot be trusted, the scanner fails safe to the broader installed-code scan scope instead of assuming that no code is active. Active plugin main files remain in scope even if their metadata header has been removed. Multisite `--url` resolution must match the canonical domain/path stored in the network `blogs` table; the scanner carries the resolved blog/network pair through network options, sitewide plugin activation, locale, super-admin, and uploads-path handling. It does not execute `sunrise.php` or domain-mapping code to resolve custom aliases.

Because the scanner deliberately does not execute application runtime filters/drop-ins, it cannot reproduce behavior that exists only inside custom `db.php`, `sunrise.php`, plugin-registered external theme directories, or `upload_dir` filters. The restore workflow should therefore expose the suspect database through the trusted `DB_*` configuration and keep the content being investigated inside the configured scanner paths. This limitation is intentional: executing those runtime extensions would break the isolation boundary.

The trusted boundary for this workflow is the clean local WordPress core, WP-CLI installation, and local `wp-config.php`. The restored `wp-content` and database remain suspect and are not trusted as executable configuration.

## Detection layers

The scanner combines exact indicators and behavioral heuristics instead of treating a single function such as `base64_decode()` as proof of malware.

Current checks include:

- known malware and web-shell indicators (`e2sky`, `chhimi`, FilesMan, WSO, b374k, r57, c99, IndoXploit, ALFA, AnonymousFox, current public WordPress campaign IOCs, and others);
- encoded payload execution (`eval` + Base64/gzip/ROT13/URL decoding);
- request-controlled command execution;
- request-controlled dynamic function execution and callback invocation;
- request-controlled `include` / `require` paths;
- `php://input` payloads passed toward code/command execution;
- remote payload download followed by execution or an executable PHP drop;
- decoded/decrypted payloads passed to `eval`, `assert`, `include`, or `require`;
- request-controlled/decoded/remote payloads written to executable PHP paths or request-controlled arbitrary paths;
- heavy `chr()` obfuscation and hexadecimal payloads when combined with execution context;
- long obfuscated PHP lines combined with execution primitives;
- deprecated `preg_replace(... /e ...)` execution;
- suspicious administrator creation/promotion code;
- plugins attempting to hide themselves from the Plugins screen;
- PHP/script files inside `uploads`;
- validated PHP code hidden inside images, SVG, PDF, text, CSS, JS, and similar files; binary files are not treated as PHP from random byte matches;
- suspicious double extensions such as `image.jpg.php`;
- `.htaccess` rules enabling PHP execution for additional file types;
- `.user.ini` / `php.ini` `auto_prepend_file` or `auto_append_file` persistence;
- JavaScript `eval`/`atob`/`Function` obfuscation;
- hidden iframes and decoded/obfuscated redirects;
- long hexadecimal/Unicode JavaScript payloads only when combined with dynamic execution context;
- symlinks escaping `wp-content`;
- plugin checksum mismatches;
- PHP, JavaScript, command-execution, iframe, encoded, and known-IOC payloads stored in the database;
- suspicious cron payloads;

Rules live in `rules/*.json` so exact indicators and signatures can be expanded without rewriting the scanner engine.

## Deep PHP semantic analysis

Version `0.2.0` adds a second PHP analysis layer based on `token_get_all()`. It does not execute scanned code. Instead, it follows variable state through common malware data-flow patterns and combines that with the existing IOC/regex rules.

The semantic analyzer can follow patterns such as:

- `$_GET` / `$_POST` / `$_REQUEST` / `$_COOKIE` aliases across multiple assignments;
- request data passed through Base64/gzip/ROT13/URL decoders before execution;
- dangerous function names assembled with string concatenation, `chr()`, Base64, `strrev()`, and similar transformations;
- variable functions and request-controlled array elements used as callbacks;
- indirect execution through `call_user_func()`, callback APIs, `array_*` callback functions, shutdown/error handlers, and similar callback sinks;
- `extract()` / one-argument `parse_str()` on request data followed by dangerous use of dynamically created variables;
- request-controlled `include` / `require`;
- local helper functions where an untrusted argument is forwarded to command execution, dynamic PHP execution, include/require, dangerous callbacks, or executable file writes;
- `php://input` flowing toward execution;
- remote payloads flowing into `eval`/command execution or executable PHP files;
- uploaded/request-controlled payloads written to executable PHP paths;
- nested statically decodable payloads, including multiple layers of Base64, gzip, ROT13, reverse strings, URL encoding, hex, and UU encoding;
- custom local decoder helpers, including hex/XOR/`ord()`/`chr()` loops, when their result later becomes a dynamic callback or reaches another dangerous sink;
- whitespace-to-binary steganography patterns and dense request-controlled callback obfuscation.

The analyzer deliberately does **not** treat normal variable-variable assignment, ordinary callbacks, Base64 decoding, remote API reads, or remote JSON caching as malware by themselves. The goal is to report the dangerous data flow, not merely the presence of a suspicious-looking function.

Broad standalone regex checks for `php://input`, `openssl_decrypt()`, `move_uploaded_file()`, and long hexadecimal strings are intentionally avoided where the semantic analyzer can prove the actual data flow. This keeps strong detection while reducing false positives from payment gateways, cryptography libraries, upload interfaces, and documentation/template files.

Small and normal PHP files are analyzed as a complete unit so state can be followed across the file. Very large PHP files use overlapping analysis windows to keep memory bounded while retaining the existing streaming signature scan as a fallback.

Standalone semantic smoke tests can be run with:

```bash
php tests/data-flow-smoke.php
```

## Installation

From the package directory:

```bash
wp package install .
```

Or after publishing the repository:

```bash
wp package install https://github.com/mgenchev/wp-cli-security-scan.git
```

## Full scan

```bash
wp security-scan
```

The command runs at `before_wp_load` and deliberately never calls the normal WordPress bootstrap. Startup work uses a lightweight child-process spinner so synchronous configuration, rule loading, and inventory preparation remain visibly active:

```text
⠋ Security Scan — initializing isolated scanner...
⠙ Security Scan — preparing rules...
⠹ Security Scan — preparing scan inventory...
```

The staged flow then continues with a single updating status line. Plugin reputation lookups and WordPress.org checksum-manifest downloads are performed in parallel when cURL multi is available, with a TLS-verified sequential HTTP fallback owned by the scanner:

```text
⠸ Scanning plugins... 1,842 files
```

Completed stages remain visible. Normal scan stages show findings rather than repeating file/row totals, while plugin integrity keeps a concise completed-status line with verification states so the checklist remains clear during long scans:

```text
✓ Core checksums completed — no integrity issues found
✓ Plugin reputation checked — no threats found
⚠ Plugin integrity checked — 12 verified, 1 unavailable
⚠ Plugins scanned — 3 threats found
✓ Uploads scanned — no threats found
⠋ Scanning database... 18,500 rows
```

The live spinner may show progress counts while a stage is running; scan-volume totals are kept for the final Summary only.

## Scan individual areas

```bash
wp security-scan plugins
wp security-scan themes
wp security-scan uploads
wp security-scan database
wp security-scan core
```

`plugins` also checks plugin reputation, WordPress.org plugin checksums, and MU plugins/drop-ins.

## Example report

```text
Summary
----------------------------------------
✓ Checksums   no integrity issues
✓ Themes      no threats
⚠ Plugins     4 threats
⚠ Uploads     1 threat
✓ Database    no threats

  Critical         1
  High             4
  Medium           0
  Low              0

  Files scanned    18,114
  DB rows scanned  184,158
  Admin users      2
  Threats found    5
  Scan time        2.50s
----------------------------------------
Success: Security scan completed.

Detailed findings saved to /path/from/which/the/scan/was/run/security-scan.log
```

Detailed findings are intentionally not printed in the interactive terminal report. File-content findings, affected paths and source lines are preserved in `security-scan.log`; filename-only, checksum, symlink, and database findings may not have a line number.

The final terminal summary includes severity counts, files scanned, database rows scanned, administrator count, total findings, and scan duration. Detailed Findings and Recommendations are kept in `security-scan.log` so the console remains concise while the evidence and remediation guidance stay together for incident review.


## Plugin and theme scan scope

The default scope remains intentionally focused on code that can currently execute:

- only **active regular plugins** are reputation-checked, checksum-verified, and statically scanned;
- only the **active theme** is scanned; when a child theme is active, its parent theme is scanned as well;
- inactive plugins/themes are still inventoried so cleanup guidance can be shown.

Use `--full-scan` when the incident requires coverage of inactive installed code as well:

- inactive regular plugins enter the same reputation, WordPress.org checksum-integrity, and static-analysis pipeline as active plugins;
- inactive themes are added to the static malware scan; theme checksum/integrity verification is intentionally not added;
- MU plugins and WordPress drop-ins remain in scope in both modes because they load independently of the normal active-plugin list.

Example startup scope feedback:

```text
Plugin scope: active plugins only.
Theme scope: active theme and parent theme only, when applicable.
```

With `--full-scan`:

```text
Plugin scope: all installed regular plugins.
Theme scope: all installed themes.
```

Inactive plugin/theme cleanup guidance is intentionally shown only once in the final Recommendations block. In full-scan mode it states that the inactive code was included in the scan while still recommending removal when it is not needed.


## Full scan mode

The default scan remains active-only for regular plugins/themes. To include inactive installed code:

```bash
wp security-scan --full-scan
```

The flag is also supported by the focused commands:

```bash
wp security-scan plugins --full-scan
wp security-scan themes --full-scan
```

For plugins, full-scan mode includes inactive plugins in reputation checks, official checksum verification when available, and static malware analysis. For themes, it adds inactive themes to static malware analysis only.


## `node_modules`

`node_modules` directories are skipped by default in all `wp-content` file stages. They are normally development dependencies rather than production WordPress runtime code, can contain tens of thousands of files, and minified/bundled libraries produce a large amount of low-value JavaScript heuristic noise.

To include them explicitly:

```bash
wp security-scan --include-node-modules
```

Composer `vendor` directories are **not** skipped because their PHP code can be part of the production runtime. `.drone-backups` directories are ignored as internal backup/tooling data.


## Users & persistence

The users stage also treats recent account creation as an incident-review signal:

- every account created within the last 2 months is reported as `HIGH`;
- 5 or more accounts created within a 10-minute window are reported as `CRITICAL`;
- for privileged accounts, 2 or more created within the same 10-minute window are enough for `CRITICAL`;
- users in a rapid-registration cluster are shown only once at the higher `CRITICAL` severity.

User findings include the user ID, login, email, role(s), and UTC registration timestamp. In the detailed scan log, repeated users/persistence findings are grouped by problem while every affected user or cron location is preserved; rapid-registration locations retain the detected cluster size. On multisite, network `site_admins` are treated as privileged for burst detection without loading WordPress user APIs. Burst detection is limited to the same 2-month incident window so historical imports and migrations do not dominate the report. Cron persistence scanning continues to run in the same stage.

## Database scanning

The scanner checks common WordPress content/meta tables in batches, including:

- `wp_posts.post_content`
- `wp_posts.post_excerpt`
- `wp_postmeta.meta_value`
- `wp_options.option_value`
- `wp_comments.comment_content`
- `wp_commentmeta.meta_value`
- `wp_termmeta.meta_value`
- `wp_usermeta.meta_value`

The actual WordPress table prefix is used automatically.

Patterns include PHP code, `eval()`, `base64_decode()`, gzip decoders, `phpinfo()`, contextual `system()` / `exec()` / `shell_exec()` / `passthru()`, hidden iframes, JavaScript URIs, obfuscated JavaScript behavior, encoded payloads, and known IOCs. A plain `<script>` tag is not treated as malware by itself because WordPress commonly stores legitimate custom scripts in options/meta. Large Base64 values are decoded and inspected; they are reported only when the decoded content contains strong executable/malware indicators.

## Non-executable backup/data files

Raw contents of database dumps, source maps and compressed archives are skipped by the static code scanner (`.sql`, `.dump`, `.zip`, `.gz`, `.tar`, `.7z`, `.rar`, `.map`, etc.). These files can legitimately contain historical malware strings or bundled source text but are not directly executable by WordPress/PHP. Executable files placed beside them are still scanned normally.


## Plugin reputation

Before checksum verification, the scanner classifies plugin sources for the selected scan scope. It sends one read-only bulk update-check request to WordPress.org for that plugin inventory, then resolves remaining repository lookups concurrently when cURL multi is available. When parallel cURL is unavailable, the scanner uses its own TLS-verified sequential HTTPS fallback rather than loading the WordPress HTTP API.

Reputation currently distinguishes:

- **WordPress.org** — the plugin is recognized by the official plugin directory/update API;
- **External** — the plugin declares a non-WordPress.org `Update URI`, typical for premium/vendor-managed plugins;
- **Unknown** — the source cannot be verified automatically;
- **Repository risk** — WordPress.org reports the plugin as closed/disabled;
- **Known malicious** — the slug/version matches one of the package's own high-confidence reputation rules.

Repository/reputation rules are independent from checksums. This means a plugin can match official checksums but still remain visible when there is a strong upstream/source risk. Reputation rules live in `rules/plugin-reputation.json` and can be extended without changing the scanner engine.

The reputation stage is read-only and does not call `wp_update_plugins()`, so it does not write WordPress update transients.

## Plugin integrity and remediation

Plugin reputation is evaluated first, then local plugin integrity is checked directly against the official WordPress.org checksum manifest for the exact plugin slug/version. The scanner no longer starts a second WP-CLI/WordPress subprocess for this stage. Checksum manifests are downloaded concurrently when possible, then local files are hashed with SHA-256 (falling back to MD5 only when required by the official manifest).

Integrity remains an **internal remediation signal**. The live checklist shows only a concise completed integrity status, while detailed checksum state and raw manifest metadata remain internal rather than being exposed as standalone report fields:

- matching official checksums suppress ordinary static heuristics from that WordPress.org plugin;
- a local mismatch causes a strong fresh-copy recommendation;
- unavailable checksums, common for premium/custom plugins, leave static findings visible and use the internal risk assessment.

For plugins without trusted checksums, finding severity is combined internally to choose between manual review and a fresh-copy recommendation. The decision mechanics are not exposed in reports or recommendation messages.

Human-readable finding reports group evidence by the human-readable problem type and preserve every affected path/line beneath that problem. This applies consistently to Themes, Plugins, MU plugins/drop-ins, Uploads, Other `wp-content`, Database, Core checksums, and Users/Persistence. Plugin paths keep the full `plugins/<slug>/...` prefix, while remediation remains plugin-specific so replacement/review recommendations are not lost. JSON output remains raw per-finding evidence rather than grouped presentation data.

All remediation guidance is collected once in the **Recommendations** block in the detailed report, including fresh-copy actions, manual-review actions, and inactive plugin/theme cleanup notices. Internal decision criteria are not exposed in recommendation messages.

Recommendation messages stay short and describe the observed condition rather than the internal scoring rule used to select an action. Examples:

```text
[REINSTALL] modified-plugin
  Reason: Plugin files do not match the official package.

[REINSTALL] suspicious-plugin
  Reason: Multiple high-risk findings were detected.

[REVIEW] premium-plugin
  Reason: Suspicious findings require manual review.

[REVIEW] verified-plugin
  Reason: High-confidence findings remain despite verified files.
```


### Verified but still suspicious plugins

A successful checksum proves that the local files match the upstream WordPress.org release; it does **not** prove that the upstream release itself is safe. To preserve this distinction, verified plugins suppress ordinary heuristics but still allow independent plugin-risk signals:

- WordPress.org reports the plugin as closed or disabled;
- the plugin matches an exact high-confidence rule from `rules/plugin-reputation.json`;
- a `CRITICAL` exact known IOC with at least 97% confidence is present in executable PHP/JavaScript code.

Repository closure is treated separately from malware heuristics because a plugin can be closed for reasons other than security. If the WordPress.org response explicitly indicates a security-related closure, the finding is raised accordingly.



## Severity and confidence

Every finding has both a severity and confidence value:

```text
CRITICAL · 99%
HIGH · 92%
MEDIUM · 62%
LOW · 45%
```

A suspicious function alone is not automatically considered malware. Higher-confidence rules use combinations such as user-controlled input + command execution or encoded data + dynamic execution.

Filter the final report:

```bash
wp security-scan --min-severity=high
```

Supported values: `low`, `medium`, `high`, `critical`.

## Export

JSON for automation:

```bash
wp security-scan --format=json
wp security-scan --format=json --output=security-report.json
```

Human-readable Markdown:

```bash
wp security-scan --format=markdown --output=security-report.md
```

Spinner/progress output is disabled for export modes, so JSON stdout remains machine-readable.

## Core checksum scope

Core integrity is scanner-owned. The scanner reads the installed version/locale from `wp-includes/version.php` as text, downloads the official MD5 manifest from `api.wordpress.org`, and compares the local core files directly. It preserves the previous WP-CLI default root scope: `wp-admin`, `wp-includes`, and root `wp-*` files are checked for unexpected files, while arbitrary unrelated root files/directories are not treated as core-integrity findings. `wp-content` entries from the core manifest are intentionally excluded because `wp-content` is handled by the package's dedicated malware/integrity stages. Remote manifest paths are validated as safe relative paths before any filesystem access.

## Optional checksum flags

Skip core integrity verification:

```bash
wp security-scan --skip-core-checksums
```

Skip plugin source/repository reputation checks:

```bash
wp security-scan --skip-plugin-reputation
```

Skip WordPress.org plugin checksum verification:

```bash
wp security-scan --skip-plugin-checksums
```

Premium/custom plugins without WordPress.org checksums are still scanned by the static malware engine and use the weighted risk score. If plugin checksum verification is skipped entirely, installed plugins are treated as unverified rather than trusted.

## Extending known indicators

Exact indicators are stored in:

```text
rules/iocs.json
rules/plugin-reputation.json
```

These include public malware/web-shell fingerprints and field indicators observed during real cleanup work. New confirmed indicators can be added without modifying `SecurityScanCommand.php`.

## Version

```bash
wp security-scan version
```

## Important limitation

No static scanner can prove that a site is clean. Malware can be novel, encrypted, environment-dependent, stored in custom database tables, or intentionally designed to mimic legitimate code. Findings should be reviewed in the context of the affected site.


### Variable-variable detection

Legitimate variable-variable assignments such as `$$key = $value` are not reported. Findings are limited to dynamic execution patterns such as `$$func()` / `${$func}()`.

### Automatic scan log

Every completed scan overwrites `security-scan.log` in the directory from which the scan was launched. The log is intended for manual incident review and uses separate Summary, Findings, and Recommendations blocks. Findings use a compact numbered layout showing severity, confidence, the problem, and every affected path/line. All human-readable finding sections are grouped consistently by problem type, including Themes, Plugins, MU plugins/drop-ins, Uploads, Other `wp-content`, Database, Core checksums, and Users/Persistence. Plugin checksum/integrity changes are also grouped by problem while preserving every affected plugin path. `Local file is not part of the official plugin package` means the local file exists inside the plugin directory but is absent from the official WordPress.org checksum manifest for that exact slug/version; it is an integrity mismatch, not by itself proof of malware. Symlinked plugin roots/paths are treated as modified integrity rather than eligible for verified-plugin suppression. Interactive scans keep the console concise with the Summary only, then print the scan-log path; detailed Findings and Recommendations remain in `security-scan.log`.

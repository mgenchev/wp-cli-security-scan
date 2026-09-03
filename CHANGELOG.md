# Changelog

## [1.1.0] - 2026-09-03

### Added

- Added opt-in `--deep-database` mode to the main and `database` commands. It discovers current-site custom tables, excludes WordPress core/global and other multisite-blog tables, and scans text-like columns with the existing IOC/database/JavaScript rules.
- Deep custom-table scans use numeric-primary-key keyset pagination when possible and bounded `LIMIT/OFFSET` fallback for unconventional schemas.
- Added PHP semantic outbound-transfer detection for sensitive request/session data reaching WordPress HTTP calls, cURL, mail, remote URL reads, and socket writes. The layer tracks credential/session/payment-like sources through assignments and local helper functions without treating ordinary form/webhook forwarding as suspicious by itself.
- Added upload media/container validation for common JPEG, PNG, GIF, WebP, AVIF, ICO, BMP, TIFF, and PDF extensions using bounded signature/structure checks without image/PDF libraries. Media files whose bytes do not match the declared extension are reported, and PNG/JPEG/WebP/PDF containers are checked for truncation or suspicious script/executable payloads appended after the logical container end.
- Expanded persistence auditing with recent application-password review on privileged accounts, direct administrative capability grants, modified/custom role capability checks, and active Action Scheduler IOC/persistence scanning.
- Added cross-layer exact-IOC correlation so the detailed log/Markdown report can show when the same known indicator appears across multiple scan layers without inflating finding counts or severity totals.

### Changed

- Scan-log timestamps now use the site-local WordPress timezone (`timezone_string`, with `gmt_offset` fallback) while the normalized report timestamp remains UTC for machine-readable output.
- Inactive plugin/theme CLEANUP recommendations in `security-scan.log` now list each affected plugin/theme by name and slug, plus concise scan status and removal guidance.
- Simplified the scan-log header to a single timestamped `WORDPRESS SECURITY SCAN:` line followed by a 68-character ASCII separator.
- Reformatted plugin integrity log entries as explicit `[CRITICAL] Plugin integrity changes` blocks with separate `Plugins`, `Problem`, and `Files` fields.
- Reformatted structured Users & persistence findings into aligned plain-text columns for account, direct-capability, and application-password details while keeping cron/Action Scheduler locations in the standard layout.
- Cached direct-DB table existence and column metadata lookups within a scan run, removed redundant recent-user filtering before burst analysis, and removed obsolete unused helper code.
- Removed the Summary block from `security-scan.log`; Summary remains console-only while the log now focuses on Findings and Recommendations.
- Marked grouped plugin integrity changes as `CRITICAL` in the scan log without changing checksum verification or remediation behavior.
- Grouped Recommendations by action and user-facing reason so plugins with the same remediation are listed under one concise recommendation in scan logs, Markdown, and detailed terminal renderers.
- Added a checksum-verified plugin fast path: verified WordPress.org plugins skip static/semantic/density analysis that would be suppressed anyway and retain only executable-file exact `CRITICAL` IOC coverage at 97%+ confidence, matching the existing reportability policy.
- Removed the unused suspicious-file modification-time clustering pass; cross-layer IOC correlation now provides explicit report context instead of computing unrendered timestamp buckets.

### Tests

- Added regression coverage for verified-plugin fast-path equivalence, grouped recommendation rendering, current-site custom-table deep database discovery/scanning, sensitive outbound data-flow with false-positive controls for ordinary webhook/contact traffic, upload container signature/boundary validation, expanded persistence checks, Action Scheduler scanning, and cross-layer IOC correlation.
- Expanded report/DB regression coverage for the timestamped log header, critical plugin-integrity `Plugins/Problem/Files` layout, aligned Users & persistence columns, and cached table-column metadata.

## [1.0.0] - 2026-09-02

### Changed

- Replaced normal WordPress `load_wordpress()` bootstrap with an isolated scanner runtime that stops after evaluating WP-CLI's stripped local `wp-config.php` configuration.
- Added a scanner-owned direct `mysqli` adapter so database, option, user, role, cron, and persistence checks no longer require `wpdb`, `db.php`, object-cache, or other `wp-content` runtime code.
- Plugin/theme metadata and active-code inventory are now read from filesystem text and direct database values without executing plugin/theme PHP.
- WordPress.org reputation and checksum requests now use scanner-owned TLS-verified HTTP clients instead of the WordPress HTTP API fallback.
- Added fail-safe scan-scope handling: malformed plugin/theme activation state expands to installed-code scanning rather than risking an active-only false negative.
- Active plugin files remain in static scan scope even when their `Plugin Name` header has been removed.
- Multisite `--url` resolution now refuses an unresolved canonical site instead of silently scanning the wrong blog prefix.
- Added support for additional WordPress-compatible `DB_HOST` forms and `BLOGUPLOADDIR` in the isolated runtime.
- Reworked the users/persistence stage to process users and capability metadata in bounded batches of 100 instead of loading the complete account/capability dataset into memory.
- Added an explicit users/persistence error boundary so isolated DB failures are reported instead of ending the scan silently.
- Added bounded serialized-value recursion depth, raw cron IOC fallback when safe decoding is not possible, and support for trusted `CUSTOM_USER_TABLE` / `CUSTOM_USER_META_TABLE` configuration.
- Enforced the scanner database adapter's read-only contract by rejecting non-read SQL, statement separators, and `SELECT ... INTO OUTFILE/DUMPFILE` server-file writes.
- Restricted scanner-owned outbound HTTP to TLS-verified official WordPress.org API/checksum hosts and added trusted `WP_PROXY_*` cURL proxy/bypass compatibility without loading WordPress HTTP classes.
- Kept the startup spinner animated during synchronous rule loading and separated rule preparation from plugin/theme inventory preparation.
- Grouped `Users & persistence` log findings by human-readable problem while preserving each affected user/cron location; rapid-registration cluster size remains attached to each user location.
- Added isolated-runtime parity for trusted `WP_HOME` / `WP_SITEURL` host overrides and multisite `site_admins` so network super administrators participate in privileged-user burst detection without loading `WP_User`.
- Replaced the nested `wp core verify-checksums` subprocess with scanner-owned core integrity verification: core version metadata is parsed as text, the official WordPress.org checksum manifest is fetched through the isolated HTTP client, and local files are hashed directly without launching a second WP-CLI process.
- Added strict validation for remote core checksum manifest paths before filesystem access, explicit findings for missing core files and core symlinks, and preserved WP-CLI's default unexpected-core-file scope.
- Completed isolated multisite parity by resolving the selected blog's actual network ID, network main site, primary network, network-level plugin activation, locale fallback, and multisite uploads base directory without loading WordPress network objects.
- Matched WordPress multisite detection semantics for legacy `SUBDOMAIN_INSTALL` / `VHOST` / `SUNRISE` configurations while continuing to refuse execution of `sunrise.php`.
- Hardened plugin source classification so an explicit non-WordPress.org `Update URI` remains external even if the same slug appears in the WordPress.org update response.
- Hardened plugin integrity against symlink trust: symlinked plugin roots/paths now force `modified` integrity instead of being eligible for `verified` suppression.
- Extended symlink coverage to MU plugins, drop-ins, and other `wp-content` paths instead of silently skipping those links.
- Added `WP_HTTP_BLOCK_EXTERNAL` / `WP_ACCESSIBLE_HOSTS` compatibility to scanner-owned HTTP and capped JSON responses at 16 MiB across cURL, cURL-multi, and stream transports.
- Optimized scanner-owned cURL transport by restoring native `CURLOPT_RETURNTRANSFER` buffering and enforcing the 16 MiB response guard through lightweight transfer-progress callbacks plus a final body-size check instead of processing every response chunk in PHP.
- Cached SHA-256 availability for plugin integrity so the runtime hash capability is resolved once rather than re-checking `hash_algos()` for every plugin file.
- Unified all human-readable finding reports around problem-type grouping: Themes, Plugins, MU/drop-ins, Uploads, Other `wp-content`, Database, Core, and Users/Persistence now render each problem once with every affected location preserved; JSON remains raw per-finding evidence.
- Removed the final Recommendations block from the interactive console; recommendations remain fully preserved in `security-scan.log` and detailed exports, while the console now ends with Summary, completion status, and the log path.
- Simplified user-facing remediation reasons so Recommendations describe the observed risk or integrity problem without exposing internal score/threshold criteria.

### Tests

- Added isolated-runtime regression coverage proving plugin metadata parsing does not execute plugin code, serialized database objects are not instantiated, WordPress runtime APIs are absent, and common DB host formats remain supported.
- Added isolated-runtime regression coverage for read-only SQL enforcement, outbound HTTP destination allowlisting, and `WP_PROXY_*` proxy/bypass handling.
- Added regression coverage for animated rule preparation, grouped users/persistence log findings, trusted home URL overrides, and multisite super-administrator privilege resolution.
- Added scanner-owned core checksum regression coverage for non-executing version metadata parsing, safe manifest-path validation, default unexpected-file scope, and removal of nested `WP_CLI::runcommand()` checksum execution.
- Expanded active/full-scope regression coverage with malformed activation data, unsafe theme paths, and active plugins with removed metadata headers.
- Replaced the obsolete pre-manifest plugin-checksum parser smoke test with current direct-checksum/source-classification coverage, so the complete test suite no longer contains a known stale failure.
- Added isolated parity coverage for multi-network context, locale/uploads resolution, HTTP host policy, bounded HTTP responses, and symlink coverage across plugin integrity/MU/drop-in/other-content stages.

## [0.3.11] - 2026-09-02

### Added

- Added opt-in `--full-scan` mode for the main scan and focused plugin/theme commands.
- Full-scan mode includes inactive regular plugins in reputation, WordPress.org checksum-integrity, and static malware scans.
- Full-scan mode includes inactive themes in static malware scans while leaving theme checksum/integrity verification intentionally out of scope.

### Changed

- Startup scope messages now state whether the scan covers active-only code or all installed regular plugins/themes.
- Inactive-code cleanup recommendations now distinguish between code that was not scanned in default mode and code that was included by `--full-scan`.

## [0.3.10] - 2026-09-02

### Changed

- Reworded plugin and core checksum findings so integrity problems are explicit without requiring internal rule IDs.
- `File was added` is now reported as `Local file is not part of the official plugin package`; checksum mismatches now state whether the local plugin/core file differs from the official checksum.
- Exact IOC descriptions now identify the matched malware family, web shell, domain, option, or trigger so human-readable logs remain self-contained after rule IDs were removed.
- Clarified several filename, PHP configuration, `.htaccess`, and plugin repository findings without changing their detection logic, severity, or confidence.

## [0.3.9] - 2026-09-02

### Changed

- Plugin integrity now keeps an explicit completed-status line in the live scan checklist, updates the spinner while local files are hashed, and keeps the spinner animated during blocking sequential HTTP fallbacks.
- `security-scan.log` is now written to the directory from which the WP-CLI scan was launched instead of always using the WordPress root.
- Core checksum log findings are grouped by checksum problem while preserving every affected path.
- Scan-log main sections use consistent extra spacing and portable ASCII hyphen separators; terminal separators use ASCII hyphens as well.

## [0.3.8] - 2026-09-02

### Changed

- Simplified `security-scan.log` metadata by removing the package version and scan duration.
- Removed rule IDs and occurrence labels from detailed finding entries while preserving severity, confidence, problem descriptions, and all affected locations.
- Plugin checksum/integrity changes are now grouped by problem, with every affected plugin path retained under the corresponding integrity issue.

## [0.3.7] - 2026-09-02

### Changed

- Reformatted `security-scan.log` as a clearer incident-review report with distinct Summary, Findings, and Recommendations blocks.
- Findings now use consistent numbered entries with severity, confidence, occurrence counts, and preserved affected locations; repeated Uploads/plugin issues remain grouped where the existing grouping is lossless.
- Detection rule IDs are included in the detailed log to make triage and regression debugging easier.
- Plugin checksum/integrity changes are formatted as separate per-plugin file lists with the corresponding integrity message.

## [0.3.6] - 2026-09-02

### Changed

- Interactive terminal output now keeps detailed Findings out of the console and shows only the final Summary and Recommendations.
- Detailed reportable findings remain available in the automatically generated `security-scan.log` in the WordPress root.
- The completed terminal report now points to the detailed findings log path.
- Removed the generic `High-confidence security findings require review.` warning from the end of scans.

## [0.3.5] - 2026-09-01

### Changed

- Plugin checksum integrity problems are summarized as a concise plugin list at the end of the Plugins findings section.
- Upload findings are grouped by problem type while preserving every affected path.
- Recommendations are grouped by remediation reason and priority instead of repeating the same instruction for each plugin.
- Inactive plugin/theme cleanup guidance remains in the final grouped Recommendations block.
- Markdown plugin details preserve all affected paths, including replacement candidates.

### Added

- Every completed scan overwrites a human-readable `security-scan.log` in the WordPress root.
- The scan log includes detailed reportable findings, plugin checksum mismatch paths, grouped upload findings, summary metrics, and remediation guidance.

## [0.3.4] - 2026-09-01

### Changed

- Plugin integrity verification is now an internal remediation signal and is no longer printed as a stage, Findings section, checksum-status label, risk score, or report section.
- Plugin reputation and checksum HTTP lookups now use bounded parallel requests when cURL multi is available, with secure sequential fallback.
- Plugin checksums are verified directly against official WordPress.org checksum manifests for the exact slug/version, removing the second WP-CLI/WordPress subprocess.
- WordPress.org checksum manifests prefer SHA-256 and fall back to MD5 only when necessary.
- Stage completion lines now show only threat/integrity results instead of repeating scanned file/row/item counts.
- Database row counts are shown only once in the final Summary, not again in the Database Findings section.
- Plugin group headers now show only the number of findings; source/checksum/risk metadata remains internal.
- All remediation guidance is collected in one final Recommendations block at the end of the report.
- Inactive plugin/theme cleanup notices moved to the final Recommendations block while startup scope output now states only that active code is scanned.
- The Summary checksum row now represents core checksum integrity only; plugin-integrity state influences recommendations without being exposed separately.

### Performance

- Unresolved WordPress.org reputation lookups are performed concurrently instead of one network wait per plugin where supported.
- Plugin checksum manifests are downloaded concurrently and verified in-process, eliminating subprocess bootstrap overhead.

## [0.3.3] - 2026-09-01

### Changed

- Plugin recommendations are now collected once at the end of the Plugins section.
- Plugins that cross the replacement threshold no longer flood terminal output with individual findings; the terminal goes directly to the replacement recommendation.
- Checksum-modified plugins now show a concise integrity-change count in the terminal instead of every checksum row before the replacement recommendation.
- Plugins below the replacement threshold continue to show grouped findings with every affected path.
- Plugin finding paths now keep the full `plugins/<slug>/...` prefix for clearer copy/paste and triage.
- Markdown and JSON reports retain detailed affected paths, including plugins that the terminal collapses to a replacement recommendation.

## [0.3.2] - 2026-09-01

### Changed

- Regular plugin reputation, checksum verification, and static file scanning now cover active plugins only.
- Inactive plugins are explicitly reported as not scanned with a recommendation to remove them when they are no longer needed.
- Theme scanning now covers only the active theme and its parent theme when a child theme is active.
- Inactive themes are explicitly reported as not scanned with a recommendation to remove them when they are no longer needed.
- Plugin checksum verification targets only active plugin slugs instead of using `--all`.
- Unavailable/unverified checksum labels and numeric plugin risk scores are now internal-only decision signals and are no longer printed in terminal, Markdown, or JSON reports.

## [0.3.1] - 2026-09-01

### Added

- Added a dedicated plugin reputation stage before checksum verification.
- Added source classification for WordPress.org, external/vendor-managed, and unknown plugins.
- Added a read-only bulk WordPress.org plugin inventory request, with individual repository probes only for unresolved slugs.
- Added extensible exact plugin reputation rules in `rules/plugin-reputation.json`.
- Added plugin reputation/source metadata to the existing plugin integrity state and JSON report.
- Added plugin reputation regression tests.

### Changed

- Moved WordPress.org closed/disabled repository checks out of the checksum stage, so plugin integrity timing now reflects checksum verification rather than additional per-plugin reputation requests.
- Verified plugin findings continue to be suppressed normally, while independent reputation risks remain reportable even when checksums match.
- Human-readable grouped plugin findings now show the detected plugin source.

### Performance

- Replaced the previous one repository HTTP request per verified plugin with one bulk WordPress.org update-check request plus follow-up requests only for unresolved plugins.

## [0.3.0] - 2026-09-01

### Added

- Added per-plugin integrity states: `verified`, `modified`, `unavailable`, and `unverified`.
- Added structured parsing of `wp plugin verify-checksums --all --strict --format=json` so checksum failures are associated with the exact plugin and file.
- Added a weighted risk score for plugins without trusted checksums: `CRITICAL=4`, `HIGH=3`, `MEDIUM=2`, `LOW=1`; score `10+` triggers a strong fresh-copy recommendation.
- Added WordPress.org repository-status checks for verified plugins so closed/disabled upstream plugins can still be surfaced independently of local checksum integrity.
- Added plugin-integrity metadata to JSON reports.
- Added plugin-integrity regression tests.

### Changed

- Ordinary static findings from checksum-verified WordPress.org plugins are suppressed from reports.
- Checksum-failed plugins receive a direct strong recommendation to replace the complete plugin with a fresh trusted copy and rescan.
- Unavailable/unverified plugins keep grouped static findings and use weighted scoring to choose manual review vs reinstall guidance.
- Critical exact known IOCs in executable plugin code remain reportable even when checksums match, preserving a narrow defense against a compromised upstream release.
- Terminal plugin reports now print every affected path; issue grouping no longer truncates locations.
- Plugin integrity progress reports verified, unavailable, modified, and unverified plugin counts instead of only a flat issue total.

## [0.2.3] - 2026-09-01

### Changed

- Plugin findings in terminal and Markdown reports are grouped by plugin and then by issue type.
- Repeated instances of the same plugin rule are collapsed into one issue with occurrence counts.
- Plugins with 3+ high/critical findings or 5+ total findings receive a fresh trusted copy recommendation.
- Terminal plugin reports show a bounded number of example paths per issue while Markdown/JSON preserve complete details.
- Plugins requiring the strongest remediation are shown first.


## [0.2.2] - 2026-09-01

### Added

- Added recent-user incident checks in `Users & persistence`: every account created within the last two months is reported as `HIGH`.
- Added rapid-registration detection: 5+ accounts created within ten minutes are reported as `CRITICAL`; for privileged accounts, 2+ in the same window are enough.
- User findings include ID, login, email, roles and registration time for faster manual review.
- Added a standalone burst-detection smoke test.

### Changed

- Users participating in a rapid-registration cluster are reported only at `CRITICAL`, avoiding duplicate `HIGH` recent-user findings.
- Users & persistence stage item counts now include scanned user accounts plus cron hooks instead of only administrator accounts plus cron hooks.

## [0.2.1] - 2026-09-01

### Changed

- WordPress debug display/logging is disabled in memory for the duration of the scan without modifying `wp-config.php`.
- Removed broad standalone `php://input`, decrypted-payload, and generic upload-handler regex findings where the semantic data-flow analyzer already verifies the dangerous flow.
- Hexadecimal PHP payloads now require nearby dynamic execution context instead of being treated as malicious solely for containing long `\xNN` sequences.
- PHP density heuristics now require execution + obfuscation + untrusted-input signals together, reducing false positives in legitimate libraries while preserving stronger semantic findings.
- Documentation/JavaScript/CSS files no longer receive a generic critical finding merely for containing a valid PHP example/template block; embedded PHP is still semantically scanned for dangerous behavior. PHP embedded in uploads and image/binary-style files remains reportable.

### Tests

- Added regression tests for benign raw-body parsing, normal OpenSSL decryption, PSR upload interfaces, legitimate hexadecimal constants, embedded PHP examples, and malicious equivalents.

## [0.2.0] - 2026-09-01

### Added

- Added an original token-based PHP data-flow analyzer using `token_get_all()`; scanned PHP is never executed.
- Tracks request/cookie taint across variable assignments, array references, decoder chains, and dynamic callbacks.
- Added simple interprocedural function summaries so untrusted arguments can be followed through named local helper functions into dangerous sinks.
- Resolves common obfuscated function names built with concatenation, `chr()`, Base64, ROT13, reverse strings, URL decoding, hex, and related transformations.
- Detects tainted/decoded data reaching command execution, dynamic code execution, include/require, callback executors, and executable PHP file writes.
- Detects request-controlled array callables and callback abuse through common PHP callback APIs.
- Detects `extract()` / `parse_str()` request-data symbol-table taint followed by dangerous execution.
- Recursively inspects safely decodable static payloads without evaluating them.
- Tags local custom decoder helpers (including hex/XOR/`ord()`/`chr()` loops) so decoded function names can still be followed into dangerous dynamic calls.
- Added whitespace-steganography behavior detection.
- Added standalone semantic analyzer smoke tests covering malicious data flows and known benign false-positive cases.

### Changed

- PHP files up to 8 MB receive whole-file semantic analysis; larger PHP files use overlapping 2 MB semantic windows in addition to the existing streaming scan.
- Semantic findings suppress equivalent regex findings where both engines identify the same behavior.
- Remote/request-controlled file writes are now judged by destination and data flow; normal remote JSON/cache writes are not treated as malware merely for writing downloaded data.

## [0.1.8] - 2026-09-01

### Changed

- Database dumps, source maps, and compressed archives are no longer raw-content scanned, preventing historical IOC strings inside `.sql`/archive data from being reported as live executable threats.
- Large Base64 database values are now decoded and inspected instead of being reported merely for their size/encoding.
- Plain database `<script>` tags are no longer standalone findings; stronger JavaScript behavior rules still detect obfuscated execution, hidden iframes, decoded redirects, and other dangerous patterns.
- Added stronger PHP behavioral rules for request-controlled includes, `php://input` execution, decoded/decrypted payload execution, and request-controlled callbacks.
- Added current public WordPress malware campaign indicators and several high-confidence malicious uploader/plugin filename checks.

### Fixed

- Reduced false positives from SQL database dumps containing historical web-shell strings such as `IndoXploit`.
- Reduced false positives from legitimate plugin configuration such as Admin Menu Editor / other large Base64-encoded settings.
- Reduced false positives from legitimate header/footer/custom-JavaScript fields stored in WordPress options/meta.

## [0.1.7] - 2026-09-01

### Changed

- WordPress bootstrap feedback now uses an independent background spinner process, so `Security Scan — loading WordPress...` continues animating while the main process is blocked loading WordPress.
- Removed the leading space before clean `✓` stage/checksum status icons because terminals do not support reliable half-character spacing.

## [0.1.6] - 2026-09-01

### Changed

- Findings sections now use a fixed human-readable order: checksums first, then themes, plugins, uploads, other wp-content checks, database, and persistence checks.
- Clean stage and summary rows add one leading space before `✓` for better visual alignment with `⚠`.
- Terminal findings now show the problem description first and the file/database location on the following indented line.

## [0.1.5] - 2026-08-31

### Changed

- Scan stage completion lines now use `⚠` when findings are present and `✓` only for clean stages.
- Terminal summary now lists Checksums, Themes, Plugins, Uploads and Database in a fixed order with matching status icons.

## [0.1.4] - 2026-08-31

### Changed

- Security scan commands now start before WordPress loads and immediately show a `Security Scan — loading WordPress...` status line on interactive runs.
- Core checksum verification now uses `wp core verify-checksums` without `--include-root`, keeping arbitrary WordPress-root tooling/backup directories outside the scanner scope.
- Core/plugin checksum stages now report integrity issues without displaying a misleading `0 files` count.
- `.drone-backups` directories are ignored by `wp-content` filesystem scans.
- Database OS-command findings now require executable PHP-like context instead of matching plain-text `system()` / `exec()` mentions alone.
- WP All Export / WP All Import session Base64 data is suppressed when benign, while decoded content is still inspected for strong malware indicators.

### Fixed

- Reduced critical database false positives in comments, ACF/meta content, trip reports, and other text that merely contains command-like strings.
- Reduced Base64 false positives from `_wpallexport_session_*` and `_wpallimport_session_*` options.

## [0.1.3] - 2026-08-31

### Fixed

- Avoided false positives for legitimate variable-variable assignment such as `$$key = $value`.
- Variable-variable detection now reports only dynamic function execution forms such as `$$func()` and `${$func}()`.

## [0.1.2] - 2026-08-31

### Changed

- `node_modules` directories are skipped by default to reduce scan time and dependency-bundle false positives; use `--include-node-modules` to scan them explicitly.
- JavaScript long Unicode/hex rules now require nearby dynamic execution instead of treating encoded character tables as standalone malware evidence.
- Browser redirect heuristics now require a tighter relationship between decoding and redirect behavior.
- File-content findings now include the detected source line in terminal, JSON, and Markdown reports when available.
- File scanning now updates the spinner while processing large individual files, not only between files.
- Checksum subprocess output is captured through temporary files so the spinner can continue repainting reliably on Windows.

### Fixed

- Reduced false positives from legitimate `emoji-regex`, Sass, Vite, and similar bundled JavaScript dependencies.
- Fixed checksum-stage spinners appearing frozen on environments where `proc_open()` pipes remain blocking.

## [0.1.1] - 2026-08-31

### Changed

- Core and plugin checksum stages now keep the terminal spinner alive while the WP-CLI checksum subprocess is running.
- Database scan results are always represented in the human-readable Findings report, including rows scanned when no threats are found.
- Suspicious modification clusters are retained internally but no longer printed in terminal or Markdown reports.
- Non-PHP binary files now require a validated text-like PHP block before PHP heuristics are applied.
- Embedded PHP in uploads is reported once as an embedded-payload finding instead of duplicated generic upload/PHP findings.

### Fixed

- Reduced false positives caused by random binary byte sequences matching PHP variable-variable or execution patterns.

## [0.1.0] - 2026-08-31

### Added

- Initial read-only WP-CLI security scanner.
- Staged scanning for core checksums, plugin integrity, plugins, MU plugins/drop-ins, themes, uploads, other `wp-content`, database, users, and persistence.
- Terminal spinner and live stage status.
- Exact IOC rule set including field indicators.
- PHP malware/backdoor/obfuscation heuristics.
- JavaScript injection/obfuscation heuristics.
- Database payload scanning in batches.
- Upload executable and hidden-PHP detection.
- `.htaccess` and PHP auto-prepend persistence checks inside `wp-content`.
- Severity and confidence scoring.
- JSON and Markdown reports.
- Suspicious finding modification-time clustering.

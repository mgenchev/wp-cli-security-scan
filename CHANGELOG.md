# Changelog

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

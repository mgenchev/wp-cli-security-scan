# Changelog

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

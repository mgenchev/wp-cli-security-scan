# WP-CLI Security Scan

Read-only WP-CLI diagnostics for compromised WordPress sites.

The package is designed for a workflow where a site's `wp-content` directory and database are restored into a clean local WordPress installation before analysis.

## What it scans

A full scan runs in separate stages:

1. WordPress core checksum verification (`wp core verify-checksums`)
2. WordPress.org plugin checksum verification
3. Plugins
4. MU plugins and WordPress drop-ins
5. Themes
6. Uploads
7. Other directories/files inside `wp-content`
8. Database content
9. Users and persistence data

The scanner is **read-only**. It does not remove, quarantine, edit, or repair files or database records.

During the scan process, `WP_DEBUG`, `WP_DEBUG_DISPLAY`, and `WP_DEBUG_LOG` are forced off in memory before WordPress is loaded. The package does not edit `wp-config.php`; the change applies only to the current WP-CLI process.

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

The command starts before WordPress is bootstrapped. The startup indicator runs in a lightweight child process, so it keeps animating even while the main PHP process is blocked loading a very large WordPress installation:

```text
⠋ Security Scan — loading WordPress...
```

After WordPress loads, the existing staged flow continues with a single updating status line. Checksum subprocesses write their output to temporary files while the parent process keeps the spinner alive, which also avoids blocking-pipe issues on Windows:

```text
⠸ Scanning plugins... 1,842 files
```

Completed stages remain visible. Checksum stages intentionally do not display a fake file count because WP-CLI does not expose the number of files it verified:

```text
✓ Core checksums completed — no integrity issues found
⚠ Plugin integrity completed — 2 integrity issues found
⚠ Plugins scanned — 3,210 files, 3 threats found
✓ Uploads scanned — 8,409 files, no threats found
⠋ Scanning database... 18,500 rows
```

## Scan individual areas

```bash
wp security-scan plugins
wp security-scan themes
wp security-scan uploads
wp security-scan database
wp security-scan core
```

`plugins` also checks MU plugins/drop-ins and WordPress.org plugin checksums.

## Example report

```text
Plugins
------------------------------------------------------------------------
3 threats found

CRITICAL · 99%  Encoded payload executed with eval
                plugins/example/inc/class-loader.php:184

HIGH · 92%      File doesn't verify against checksum: example/file.php
                Plugins

Uploads
------------------------------------------------------------------------
1 threat found

CRITICAL · 99%  PHP code embedded inside a non-PHP upload
                uploads/2024/08/logo.jpg:1
```

File-content findings include the source line when it can be determined, for example `plugins/example/file.php:184`. Filename-only, checksum, symlink, and database findings may not have a line number.

The final summary includes severity counts, files scanned, database rows scanned, administrator count, total findings, and scan duration. The Findings report always includes a Database section when the database stage runs, including the number of rows scanned even when no database threats are found. Findings are displayed in a fixed order beginning with checksum integrity, followed by themes, plugins, uploads, other wp-content checks, database findings, and persistence checks. Each terminal finding prints the problem first and the affected path/line underneath it for faster review.


## `node_modules`

`node_modules` directories are skipped by default in all `wp-content` file stages. They are normally development dependencies rather than production WordPress runtime code, can contain tens of thousands of files, and minified/bundled libraries produce a large amount of low-value JavaScript heuristic noise.

To include them explicitly:

```bash
wp security-scan --include-node-modules
```

Composer `vendor` directories are **not** skipped because their PHP code can be part of the production runtime. `.drone-backups` directories are ignored as internal backup/tooling data.

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

Core integrity uses `wp core verify-checksums` without `--include-root`. This verifies WordPress core files but does not treat unrelated files/directories in the WordPress root (for example `.drone-backups`) as security threats. The custom malware scan remains scoped to `wp-content` and the database.

## Optional checksum flags

Skip core integrity verification:

```bash
wp security-scan --skip-core-checksums
```

Skip WordPress.org plugin checksum verification:

```bash
wp security-scan --skip-plugin-checksums
```

Premium/custom plugins without WordPress.org checksums are still scanned by the static malware engine.

## Extending known indicators

Exact indicators are stored in:

```text
rules/iocs.json
```

This includes public malware/web-shell fingerprints and field indicators observed during real cleanup work. New confirmed indicators can be added without modifying `SecurityScanCommand.php`.

## Version

```bash
wp security-scan version
```

## Important limitation

No static scanner can prove that a site is clean. Malware can be novel, encrypted, environment-dependent, stored in custom database tables, or intentionally designed to mimic legitimate code. Findings should be reviewed in the context of the affected site.


### Variable-variable detection

Legitimate variable-variable assignments such as `$$key = $value` are not reported. Findings are limited to dynamic execution patterns such as `$$func()` / `${$func}()`.

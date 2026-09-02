<?php
/** Regression tests for grouped uploads, integrity list, and scan log. */
define( 'WP_CLI', true );
define( 'ABSPATH', __DIR__ . DIRECTORY_SEPARATOR . 'tmp-root' . DIRECTORY_SEPARATOR );

class WP_CLI {
	public static $logs = [];
	public static function add_command( $name, $class ) {}
	public static function log( $message = '' ) { self::$logs[] = (string) $message; }
	public static function warning( $message ) { self::$logs[] = 'Warning: ' . $message; }
	public static function success( $message ) { self::$logs[] = 'Success: ' . $message; }
}

require dirname( __DIR__ ) . '/src/SecurityScanCommand.php';
@mkdir( ABSPATH, 0777, true );
$command = new Security_Scan_Command();
$launch_directory = new ReflectionProperty( $command, 'launch_directory' );
$launch_directory->setAccessible( true );
$launch_directory->setValue( $command, rtrim( ABSPATH, DIRECTORY_SEPARATOR ) );
$integrity = new ReflectionProperty( $command, 'plugin_integrity' );
$integrity->setAccessible( true );
$integrity->setValue( $command, [
	'bad-plugin' => [
		'status' => 'modified', 'source' => 'wordpress.org',
		'checksum_errors' => [
		[ 'file' => 'a.php', 'message' => 'Local file is not part of the official plugin package' ],
		[ 'file' => 'b.php', 'message' => 'File differs from the official plugin checksum' ],
	],
	],
] );

$uploads = [
	[ 'section'=>'Uploads','severity'=>'high','confidence'=>96,'description'=>'Executable/script file found inside uploads','location'=>'uploads/a/index.php','line'=>null,'rule'=>'upload_exec' ],
	[ 'section'=>'Uploads','severity'=>'high','confidence'=>96,'description'=>'Executable/script file found inside uploads','location'=>'uploads/b/index.php','line'=>null,'rule'=>'upload_exec' ],
];
$method = new ReflectionMethod( $command, 'render_terminal_grouped_findings' );
$method->setAccessible( true );
WP_CLI::$logs = [];
$method->invoke( $command, $uploads );
$out = implode("\n", WP_CLI::$logs);
if ( 1 !== substr_count( $out, 'Executable/script file found inside uploads' ) || false === strpos( $out, 'uploads/a/index.php' ) || false === strpos( $out, 'uploads/b/index.php' ) ) {
	fwrite( STDERR, "Terminal findings must be grouped by human-readable problem while preserving all paths.\n" ); exit(1);
}
$theme_terminal = [
	[ 'section'=>'Themes','severity'=>'critical','confidence'=>98,'description'=>'Decoded or remotely sourced payload reaches dynamic PHP code execution','location'=>'themes/obsidians/vendor/doctrine/dbal/src/Types/BinaryType.php','line'=>39,'rule'=>'theme_a' ],
	[ 'section'=>'Themes','severity'=>'critical','confidence'=>98,'description'=>'Decoded or remotely sourced payload reaches dynamic PHP code execution','location'=>'themes/obsidians/vendor/doctrine/dbal/src/Types/BlobType.php','line'=>39,'rule'=>'theme_b' ],
];
WP_CLI::$logs = [];
$method->invoke( $command, $theme_terminal );
$out = implode("\n", WP_CLI::$logs);
if ( 1 !== substr_count( $out, 'Decoded or remotely sourced payload reaches dynamic PHP code execution' ) || false === strpos( $out, 'BinaryType.php:39' ) || false === strpos( $out, 'BlobType.php:39' ) ) {
	fwrite( STDERR, "Theme terminal findings must be grouped by problem while preserving all paths.\n" ); exit(1);
}

$method = new ReflectionMethod( $command, 'render_terminal_plugin_integrity_list' );
$method->setAccessible( true );
WP_CLI::$logs = [];
$method->invoke( $command );
if ( false === strpos( implode("\n", WP_CLI::$logs), 'bad-plugin' ) ) {
	fwrite( STDERR, "Modified plugin list is missing.\n" ); exit(1);
}

$core = [
	[ 'section'=>'Core checksums','severity'=>'high','confidence'=>96,'description'=>'Core file differs from the official WordPress checksum','location'=>'wp-includes/a.php','line'=>null,'rule'=>'core_checksum_mismatch' ],
	[ 'section'=>'Core checksums','severity'=>'high','confidence'=>96,'description'=>'Core file differs from the official WordPress checksum','location'=>'wp-includes/b.php','line'=>null,'rule'=>'core_checksum_mismatch' ],
	[ 'section'=>'Core checksums','severity'=>'high','confidence'=>96,'description'=>'Unexpected file found in WordPress core','location'=>'wp-admin/extra.php','line'=>null,'rule'=>'core_checksum_mismatch' ],
];
$users = [
	[ 'section'=>'Users & persistence','severity'=>'critical','confidence'=>96,'description'=>'Users were created in a rapid-registration cluster','location'=>'user #10 · first · first@example.test · roles: none · registered 2026-09-01 10:00:00 UTC · cluster: 5 accounts within 10 minutes','line'=>null,'rule'=>'rapid_user_registration' ],
	[ 'section'=>'Users & persistence','severity'=>'critical','confidence'=>96,'description'=>'Users were created in a rapid-registration cluster','location'=>'user #11 · second · second@example.test · roles: none · registered 2026-09-01 10:02:00 UTC · cluster: 6 accounts within 10 minutes','line'=>null,'rule'=>'rapid_user_registration' ],
];
$themes = [
	[ 'section'=>'Themes','severity'=>'critical','confidence'=>98,'description'=>'Decoded or remotely sourced payload reaches dynamic PHP code execution','location'=>'themes/obsidians/vendor/doctrine/dbal/src/Types/BinaryType.php','line'=>39,'rule'=>'semantic_dynamic_exec_a' ],
	[ 'section'=>'Themes','severity'=>'critical','confidence'=>98,'description'=>'Decoded or remotely sourced payload reaches dynamic PHP code execution','location'=>'themes/obsidians/vendor/doctrine/dbal/src/Types/BlobType.php','line'=>39,'rule'=>'semantic_dynamic_exec_b' ],
	[ 'section'=>'Themes','severity'=>'high','confidence'=>91,'description'=>'Request/cookie data is used through an array element as a dynamic callable','location'=>'themes/live-theme-bak-300520205/includes/woocommerce/notifications.php','line'=>287,'rule'=>'semantic_callable_a' ],
	[ 'section'=>'Themes','severity'=>'high','confidence'=>91,'description'=>'Request/cookie data is used through an array element as a dynamic callable','location'=>'themes/obsidians/includes/woocommerce/notifications.php','line'=>221,'rule'=>'semantic_callable_b' ],
];
$plugins = [
	[ 'section'=>'Plugins','severity'=>'high','confidence'=>91,'description'=>'Shared plugin problem','location'=>'plugins/plugin-a/a.php','line'=>10,'rule'=>'plugin_rule_a' ],
	[ 'section'=>'Plugins','severity'=>'high','confidence'=>91,'description'=>'Shared plugin problem','location'=>'plugins/plugin-b/b.php','line'=>20,'rule'=>'plugin_rule_b' ],
];
$mu = [
	[ 'section'=>'MU plugins & drop-ins','severity'=>'high','confidence'=>90,'description'=>'Shared MU problem','location'=>'mu-plugins/a.php','line'=>1,'rule'=>'mu_a' ],
	[ 'section'=>'MU plugins & drop-ins','severity'=>'high','confidence'=>90,'description'=>'Shared MU problem','location'=>'object-cache.php','line'=>2,'rule'=>'mu_b' ],
];
$other = [
	[ 'section'=>'Other wp-content','severity'=>'high','confidence'=>90,'description'=>'Shared other-content problem','location'=>'custom/a.php','line'=>3,'rule'=>'other_a' ],
	[ 'section'=>'Other wp-content','severity'=>'high','confidence'=>90,'description'=>'Shared other-content problem','location'=>'custom/b.php','line'=>4,'rule'=>'other_b' ],
];
$database = [
	[ 'section'=>'Database','severity'=>'high','confidence'=>90,'description'=>'Shared database problem','location'=>'wp_options #1 · option_value','line'=>null,'rule'=>'db_a' ],
	[ 'section'=>'Database','severity'=>'high','confidence'=>90,'description'=>'Shared database problem','location'=>'wp_options #2 · option_value','line'=>null,'rule'=>'db_b' ],
];
$report = [
	'scanned_at'=>gmdate('c'),'duration_seconds'=>1.2,
	'severity'=>['critical'=>4,'high'=>17,'medium'=>0,'low'=>0],
	'files_scanned'=>20,'database_rows'=>2,'administrator_users'=>1,'total_findings'=>21,
	'stages'=>['Core checksums'=>['findings'=>3],'Themes'=>['findings'=>4],'Plugins'=>['findings'=>2],'MU plugins & drop-ins'=>['findings'=>2],'Uploads'=>['findings'=>2],'Other wp-content'=>['findings'=>2],'Database'=>['findings'=>2],'Users & persistence'=>['findings'=>2]],'findings'=>array_merge( $core, $themes, $plugins, $mu, $uploads, $other, $database, $users ),
];
$log = new ReflectionMethod( $command, 'write_scan_log' );
$log->setAccessible( true );
$path = $log->invoke( $command, $report );
if ( ! is_string( $path ) || ! is_file( $path ) ) { fwrite(STDERR,"Scan log was not written.\n"); exit(1); }
if ( realpath( dirname( $path ) ) !== realpath( rtrim( ABSPATH, DIRECTORY_SEPARATOR ) ) ) { fwrite(STDERR,"Scan log must be written to the launch directory.\n"); exit(1); }
$content = file_get_contents($path);
if ( false === strpos($content,'uploads/a/index.php') || false === strpos($content,'uploads/b/index.php') ) { fwrite(STDERR,"Scan log must contain all paths.\n"); exit(1); }
if ( false === strpos( $content, 'FINDINGS' ) || false === strpos( $content, 'UPLOADS (2 findings)' ) ) { fwrite(STDERR,"Scan log must use clear findings section headers.\n"); exit(1); }
if ( false === strpos( $content, '[1] HIGH | 96% confidence' ) || false === strpos( $content, 'Locations:' ) ) { fwrite(STDERR,"Grouped scan-log issues must expose severity, confidence, and locations.\n"); exit(1); }
if ( false !== strpos( $content, 'Rule:' ) || false !== strpos( $content, 'Occurrences:' ) || false !== strpos( $content, 'Version:' ) || false !== strpos( $content, 'Duration:' ) ) { fwrite(STDERR,"Scan log must omit version, duration, rule IDs, and occurrence labels.\n"); exit(1); }
if ( false === strpos( $content, "Plugin integrity changes\n  File differs from the official plugin checksum\n    - plugins/bad-plugin/b.php" ) || false === strpos( $content, "  Local file is not part of the official plugin package\n    - plugins/bad-plugin/a.php" ) ) { fwrite(STDERR,"Plugin integrity changes must be grouped by problem while preserving affected paths.\n"); exit(1); }
if ( false === strpos( $content, 'Reason: Plugin files do not match the official package.' ) || false !== stripos( $content, 'replacement threshold' ) ) { fwrite(STDERR,"Scan-log recommendations must stay concise and must not expose internal decision criteria.\n"); exit(1); }

if ( 1 !== substr_count( $content, "Problem: Core file differs from the official WordPress checksum" ) || false === strpos( $content, 'wp-includes/a.php' ) || false === strpos( $content, 'wp-includes/b.php' ) || false === strpos( $content, 'Problem: Unexpected file found in WordPress core' ) || false === strpos( $content, 'wp-admin/extra.php' ) ) { fwrite(STDERR,"Core checksum findings must be grouped by problem while preserving all affected paths.\n"); exit(1); }
if ( 1 !== substr_count( $content, 'Problem: Users were created in a rapid-registration cluster' ) || false === strpos( $content, 'user #10' ) || false === strpos( $content, 'cluster: 5 accounts within 10 minutes' ) || false === strpos( $content, 'user #11' ) || false === strpos( $content, 'cluster: 6 accounts within 10 minutes' ) ) { fwrite(STDERR,"Users & persistence findings must be grouped by problem while preserving per-user cluster context.\n"); exit(1); }
if ( 1 !== substr_count( $content, 'Problem: Decoded or remotely sourced payload reaches dynamic PHP code execution' ) || false === strpos( $content, 'BinaryType.php:39' ) || false === strpos( $content, 'BlobType.php:39' ) ) { fwrite(STDERR,"Theme findings must be grouped by problem across all affected theme paths.\n"); exit(1); }
if ( 1 !== substr_count( $content, 'Problem: Request/cookie data is used through an array element as a dynamic callable' ) || false === strpos( $content, 'live-theme-bak-300520205/includes/woocommerce/notifications.php:287' ) || false === strpos( $content, 'obsidians/includes/woocommerce/notifications.php:221' ) ) { fwrite(STDERR,"Theme callable findings must be grouped by problem across themes.\n"); exit(1); }
if ( 1 !== substr_count( $content, 'Problem: Shared plugin problem' ) || false === strpos( $content, 'plugins/plugin-a/a.php:10' ) || false === strpos( $content, 'plugins/plugin-b/b.php:20' ) ) { fwrite(STDERR,"Plugin findings must be grouped by problem across plugin paths.\n"); exit(1); }
if ( 1 !== substr_count( $content, 'Problem: Shared MU problem' ) || false === strpos( $content, 'mu-plugins/a.php:1' ) || false === strpos( $content, 'object-cache.php:2' ) ) { fwrite(STDERR,"MU/drop-in findings must be grouped by problem.\n"); exit(1); }
if ( 1 !== substr_count( $content, 'Problem: Shared other-content problem' ) || false === strpos( $content, 'custom/a.php:3' ) || false === strpos( $content, 'custom/b.php:4' ) ) { fwrite(STDERR,"Other wp-content findings must be grouped by problem.\n"); exit(1); }
if ( 1 !== substr_count( $content, 'Problem: Shared database problem' ) || false === strpos( $content, 'wp_options #1' ) || false === strpos( $content, 'wp_options #2' ) ) { fwrite(STDERR,"Database findings must be grouped by problem.\n"); exit(1); }
$markdown_method = new ReflectionMethod( $command, 'render_markdown' );
$markdown_method->setAccessible( true );
$markdown = $markdown_method->invoke( $command, $report );
if ( 1 !== substr_count( $markdown, 'Decoded or remotely sourced payload reaches dynamic PHP code execution' ) || false === strpos( $markdown, 'BinaryType.php:39' ) || false === strpos( $markdown, 'BlobType.php:39' ) ) { fwrite(STDERR,"Markdown theme findings must be grouped by problem.\n"); exit(1); }
if ( 1 !== substr_count( $markdown, 'Shared plugin problem' ) || false === strpos( $markdown, 'plugins/plugin-a/a.php:10' ) || false === strpos( $markdown, 'plugins/plugin-b/b.php:20' ) ) { fwrite(STDERR,"Markdown plugin findings must be grouped by problem across plugin paths.\n"); exit(1); }
if ( false === strpos( $content, "\n\nSUMMARY\n" ) || false === strpos( $content, "\n\nFINDINGS\n" ) ) { fwrite(STDERR,"Main scan-log sections must use consistent extra spacing.\n"); exit(1); }
if ( false !== strpos( $content, '═' ) || false !== strpos( $content, '─' ) ) { fwrite(STDERR,"Scan log separators must use portable ASCII hyphens.\n"); exit(1); }
@unlink($path); @rmdir(ABSPATH);
echo "Grouped report smoke tests passed.\n";

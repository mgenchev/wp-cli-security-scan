<?php
/** Regression tests for grouped uploads, integrity list, and scan log. */
define( 'WP_CLI', true );
define( 'ABSPATH', __DIR__ . DIRECTORY_SEPARATOR . 'tmp-root' . DIRECTORY_SEPARATOR );
$previous_tz = getenv( 'TZ' );
putenv( 'TZ=Europe/Sofia' );

class Fake_Scan_Log_Database {
	private $options;
	public function __construct( array $options ) { $this->options = $options; }
	public function get_option_raw( $name ) { return array_key_exists( $name, $this->options ) ? (string) $this->options[ $name ] : null; }
}

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
$database = new ReflectionProperty( $command, 'database' );
$database->setAccessible( true );
$database->setValue( $command, new Fake_Scan_Log_Database( [ 'timezone_string' => 'Europe/Sofia' ] ) );
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

$inactive_plugins = new ReflectionProperty( $command, 'inactive_plugins' );
$inactive_plugins->setAccessible( true );
$inactive_plugins->setValue( $command, [
	[ 'slug' => 'hello-dolly', 'name' => 'Hello Dolly', 'file' => 'hello-dolly/hello.php' ],
	[ 'slug' => 'akismet', 'name' => 'Akismet Anti-spam', 'file' => 'akismet/akismet.php' ],
] );
$inactive_themes = new ReflectionProperty( $command, 'inactive_themes' );
$inactive_themes->setAccessible( true );
$inactive_themes->setValue( $command, [
	[ 'slug' => 'twentytwentyfour', 'name' => 'Twenty Twenty-Four' ],
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
	[ 'section'=>'Themes','severity'=>'critical','confidence'=>98,'description'=>'Shared theme execution problem','location'=>'themes/obsidians/vendor/doctrine/dbal/src/Types/BinaryType.php','line'=>39,'rule'=>'theme_a' ],
	[ 'section'=>'Themes','severity'=>'critical','confidence'=>98,'description'=>'Shared theme execution problem','location'=>'themes/obsidians/vendor/doctrine/dbal/src/Types/BlobType.php','line'=>39,'rule'=>'theme_b' ],
];
WP_CLI::$logs = [];
$method->invoke( $command, $theme_terminal );
$out = implode("\n", WP_CLI::$logs);
if ( 1 !== substr_count( $out, 'Shared theme execution problem' ) || false === strpos( $out, 'BinaryType.php:39' ) || false === strpos( $out, 'BlobType.php:39' ) ) {
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
	[ 'section'=>'Themes','severity'=>'critical','confidence'=>98,'description'=>'Shared theme execution problem','location'=>'themes/obsidians/vendor/doctrine/dbal/src/Types/BinaryType.php','line'=>39,'rule'=>'semantic_dynamic_exec_a' ],
	[ 'section'=>'Themes','severity'=>'critical','confidence'=>98,'description'=>'Shared theme execution problem','location'=>'themes/obsidians/vendor/doctrine/dbal/src/Types/BlobType.php','line'=>39,'rule'=>'semantic_dynamic_exec_b' ],
	[ 'section'=>'Themes','severity'=>'high','confidence'=>91,'description'=>'Shared theme callback problem','location'=>'themes/live-theme-bak-300520205/includes/woocommerce/notifications.php','line'=>287,'rule'=>'semantic_callable_a' ],
	[ 'section'=>'Themes','severity'=>'high','confidence'=>91,'description'=>'Shared theme callback problem','location'=>'themes/obsidians/includes/woocommerce/notifications.php','line'=>221,'rule'=>'semantic_callable_b' ],
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
	'scanned_at'=>'2026-09-03T06:53:36+00:00','duration_seconds'=>1.2,
	'severity'=>['critical'=>4,'high'=>17,'medium'=>0,'low'=>0],
	'files_scanned'=>20,'database_rows'=>2,'administrator_users'=>1,'total_findings'=>21,
	'stages'=>['Core checksums'=>['findings'=>3],'Themes'=>['findings'=>4],'Plugins'=>['findings'=>2],'MU plugins & drop-ins'=>['findings'=>2],'Uploads'=>['findings'=>2],'Other wp-content'=>['findings'=>2],'Database'=>['findings'=>2],'Users & persistence'=>['findings'=>2]],'findings'=>array_merge( $core, $themes, $plugins, $mu, $uploads, $other, $database, $users ),
	'correlations'=>[
		[
			'rule'=>'ioc_test','description'=>'Known malicious domain indicator: example.test','severity'=>'critical','confidence'=>99,
			'sections'=>['Database','Plugins'],
			'locations'=>[
				['section'=>'Database','location'=>'wp_options #9 · option_value'],
				['section'=>'Plugins','location'=>'plugins/bad-plugin/c2.php:5'],
			],
		],
	],
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
if ( false === strpos( $content, "[CRITICAL] Plugin integrity changes\n    Plugins: bad-plugin\n    Problem: File differs from the official plugin checksum\n    Files:\n      - plugins/bad-plugin/b.php" ) || false === strpos( $content, "[CRITICAL] Plugin integrity changes\n    Plugins: bad-plugin\n    Problem: Local file is not part of the official plugin package\n    Files:\n      - plugins/bad-plugin/a.php" ) ) { fwrite(STDERR,"Plugin integrity changes must use the critical Plugins/Problem/Files layout and preserve affected paths.\n"); exit(1); }
if ( false === strpos( $content, "[REINSTALL] Plugin files do not match the official package.\n    Plugins:\n      - bad-plugin" ) || false !== stripos( $content, 'replacement threshold' ) ) { fwrite(STDERR,"Scan-log recommendations must be grouped by reason and must not expose internal decision criteria.\n"); exit(1); }

if ( false === strpos( $content, "CORRELATED INDICATORS\n" ) || false === strpos( $content, 'Indicator: Known malicious domain indicator: example.test' ) || false === strpos( $content, '[Database] wp_options #9 · option_value' ) || false === strpos( $content, '[Plugins] plugins/bad-plugin/c2.php:5' ) ) { fwrite(STDERR,"Scan log must render cross-layer exact-IOC correlations with all locations.\n"); exit(1); }

if ( 1 !== substr_count( $content, "Problem: Core file differs from the official WordPress checksum" ) || false === strpos( $content, 'wp-includes/a.php' ) || false === strpos( $content, 'wp-includes/b.php' ) || false === strpos( $content, 'Problem: Unexpected file found in WordPress core' ) || false === strpos( $content, 'wp-admin/extra.php' ) ) { fwrite(STDERR,"Core checksum findings must be grouped by problem while preserving all affected paths.\n"); exit(1); }
if ( 1 !== substr_count( $content, 'Problem: Users were created in a rapid-registration cluster' ) || false === strpos( $content, 'ID   Login' ) || false === strpos( $content, '#10' ) || false === strpos( $content, 'first@example.test' ) || false === strpos( $content, '5 accounts within 10 minutes' ) || false === strpos( $content, '#11' ) || false === strpos( $content, '6 accounts within 10 minutes' ) ) { fwrite(STDERR,"Users & persistence findings must be grouped by problem and rendered in aligned columns while preserving cluster context.\n"); exit(1); }
if ( 1 !== substr_count( $content, 'Problem: Shared theme execution problem' ) || false === strpos( $content, 'BinaryType.php:39' ) || false === strpos( $content, 'BlobType.php:39' ) ) { fwrite(STDERR,"Theme findings must be grouped by problem across all affected theme paths.\n"); exit(1); }
if ( 1 !== substr_count( $content, 'Problem: Shared theme callback problem' ) || false === strpos( $content, 'live-theme-bak-300520205/includes/woocommerce/notifications.php:287' ) || false === strpos( $content, 'obsidians/includes/woocommerce/notifications.php:221' ) ) { fwrite(STDERR,"Theme callable findings must be grouped by problem across themes.\n"); exit(1); }
if ( 1 !== substr_count( $content, 'Problem: Shared plugin problem' ) || false === strpos( $content, 'plugins/plugin-a/a.php:10' ) || false === strpos( $content, 'plugins/plugin-b/b.php:20' ) ) { fwrite(STDERR,"Plugin findings must be grouped by problem across plugin paths.\n"); exit(1); }
if ( 1 !== substr_count( $content, 'Problem: Shared MU problem' ) || false === strpos( $content, 'mu-plugins/a.php:1' ) || false === strpos( $content, 'object-cache.php:2' ) ) { fwrite(STDERR,"MU/drop-in findings must be grouped by problem.\n"); exit(1); }
if ( 1 !== substr_count( $content, 'Problem: Shared other-content problem' ) || false === strpos( $content, 'custom/a.php:3' ) || false === strpos( $content, 'custom/b.php:4' ) ) { fwrite(STDERR,"Other wp-content findings must be grouped by problem.\n"); exit(1); }
if ( 1 !== substr_count( $content, 'Problem: Shared database problem' ) || false === strpos( $content, 'wp_options #1' ) || false === strpos( $content, 'wp_options #2' ) ) { fwrite(STDERR,"Database findings must be grouped by problem.\n"); exit(1); }
$markdown_method = new ReflectionMethod( $command, 'render_markdown' );
$markdown_method->setAccessible( true );
$markdown = $markdown_method->invoke( $command, $report );
if ( 1 !== substr_count( $markdown, 'Shared theme execution problem' ) || false === strpos( $markdown, 'BinaryType.php:39' ) || false === strpos( $markdown, 'BlobType.php:39' ) ) { fwrite(STDERR,"Markdown theme findings must be grouped by problem.\n"); exit(1); }
if ( 1 !== substr_count( $markdown, 'Shared plugin problem' ) || false === strpos( $markdown, 'plugins/plugin-a/a.php:10' ) || false === strpos( $markdown, 'plugins/plugin-b/b.php:20' ) ) { fwrite(STDERR,"Markdown plugin findings must be grouped by problem across plugin paths.\n"); exit(1); }
if ( false === strpos( $markdown, '## Correlated indicators' ) || false === strpos( $markdown, 'Known malicious domain indicator: example.test' ) || false === strpos( $markdown, 'plugins/bad-plugin/c2.php:5' ) ) { fwrite(STDERR,"Markdown must render cross-layer exact-IOC correlations.\n"); exit(1); }
if ( false === strpos( $content, "WORDPRESS SECURITY SCAN:      2026-09-03T09:53:36+03:00\n" ) ) { fwrite(STDERR,"Scan-log header must use the machine/CLI timezone.\n"); exit(1); }
if ( false === strpos( $content, "[CLEANUP] Inactive plugins\n    Status: Not scanned.\n    Action: Remove if not needed.\n    Plugins:\n      - Akismet Anti-spam (akismet)\n      - Hello Dolly (hello-dolly)" ) ) { fwrite(STDERR,"Cleanup recommendations must list inactive plugins by name and slug.\n"); exit(1); }
if ( false === strpos( $content, "[CLEANUP] Inactive themes\n    Status: Not scanned.\n    Action: Remove if not needed.\n    Themes:\n      - Twenty Twenty-Four (twentytwentyfour)" ) ) { fwrite(STDERR,"Cleanup recommendations must list inactive themes by name and slug.\n"); exit(1); }
if ( 0 !== strpos( $content, 'WORDPRESS SECURITY SCAN:      ' ) || false === strpos( $content, "\n--------------------------------------------------------------------\n" ) ) { fwrite(STDERR,"Scan log must start with the timestamped scan title and 68-character ASCII separator.\n"); exit(1); }
if ( false !== strpos( $content, "\nSUMMARY\n" ) || false === strpos( $content, "\n\nFINDINGS\n" ) ) { fwrite(STDERR,"Scan log must omit Summary and keep consistent spacing before Findings.\n"); exit(1); }
if ( false !== strpos( $content, '═' ) || false !== strpos( $content, '─' ) ) { fwrite(STDERR,"Scan log separators must use portable ASCII hyphens.\n"); exit(1); }
@unlink($path); @rmdir(ABSPATH);
if ( false === $previous_tz ) {
	putenv( 'TZ' );
} else {
	putenv( 'TZ=' . $previous_tz );
}
echo "Grouped report smoke tests passed.\n";

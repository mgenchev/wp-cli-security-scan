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
if ( false === strpos( $out, '(2 occurrences)' ) || false === strpos( $out, 'uploads/a/index.php' ) || false === strpos( $out, 'uploads/b/index.php' ) ) {
	fwrite( STDERR, "Uploads must be grouped by issue while preserving all paths.\n" ); exit(1);
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
$report = [
	'scanned_at'=>gmdate('c'),'duration_seconds'=>1.2,
	'severity'=>['critical'=>0,'high'=>5,'medium'=>0,'low'=>0],
	'files_scanned'=>5,'database_rows'=>0,'administrator_users'=>1,'total_findings'=>5,
	'stages'=>['Core checksums'=>['findings'=>3],'Uploads'=>['findings'=>2]],'findings'=>array_merge( $core, $uploads ),
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

if ( 1 !== substr_count( $content, "Problem: Core file differs from the official WordPress checksum" ) || false === strpos( $content, 'wp-includes/a.php' ) || false === strpos( $content, 'wp-includes/b.php' ) || false === strpos( $content, 'Problem: Unexpected file found in WordPress core' ) || false === strpos( $content, 'wp-admin/extra.php' ) ) { fwrite(STDERR,"Core checksum findings must be grouped by problem while preserving all affected paths.\n"); exit(1); }
if ( false === strpos( $content, "\n\nSUMMARY\n" ) || false === strpos( $content, "\n\nFINDINGS\n" ) ) { fwrite(STDERR,"Main scan-log sections must use consistent extra spacing.\n"); exit(1); }
if ( false !== strpos( $content, '═' ) || false !== strpos( $content, '─' ) ) { fwrite(STDERR,"Scan log separators must use portable ASCII hyphens.\n"); exit(1); }
@unlink($path); @rmdir(ABSPATH);
echo "Grouped report smoke tests passed.\n";

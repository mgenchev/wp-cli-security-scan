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
$integrity = new ReflectionProperty( $command, 'plugin_integrity' );
$integrity->setAccessible( true );
$integrity->setValue( $command, [
	'bad-plugin' => [
		'status' => 'modified', 'source' => 'wordpress.org',
		'checksum_errors' => [ [ 'file' => 'a.php', 'message' => 'File was added' ] ],
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

$report = [
	'scanned_at'=>gmdate('c'),'duration_seconds'=>1.2,
	'severity'=>['critical'=>0,'high'=>2,'medium'=>0,'low'=>0],
	'files_scanned'=>2,'database_rows'=>0,'administrator_users'=>1,'total_findings'=>2,
	'stages'=>['Uploads'=>['findings'=>2]],'findings'=>$uploads,
];
$log = new ReflectionMethod( $command, 'write_scan_log' );
$log->setAccessible( true );
$path = $log->invoke( $command, $report );
if ( ! is_string( $path ) || ! is_file( $path ) ) { fwrite(STDERR,"Scan log was not written.\n"); exit(1); }
$content = file_get_contents($path);
if ( false === strpos($content,'uploads/a/index.php') || false === strpos($content,'uploads/b/index.php') ) { fwrite(STDERR,"Scan log must contain all paths.\n"); exit(1); }
@unlink($path); @rmdir(ABSPATH);
echo "Grouped report smoke tests passed.\n";

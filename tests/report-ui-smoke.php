<?php
/**
 * Standalone regression tests for concise terminal reporting.
 */

define( 'WP_CLI', true );

class WP_CLI {
	public static $logs = [];

	public static function add_command( $name, $class ) {}
	public static function log( $message = '' ) { self::$logs[] = (string) $message; }
	public static function warning( $message ) { self::$logs[] = 'Warning: ' . $message; }
	public static function success( $message ) { self::$logs[] = 'Success: ' . $message; }
}

require dirname( __DIR__ ) . '/src/SecurityScanCommand.php';

$command_source = file_get_contents( dirname( __DIR__ ) . '/src/SecurityScanCommand.php' );
if ( false !== strpos( $command_source, '$reportable_findings = $this->filter_findings_for_plugin_integrity' ) || false === strpos( $command_source, 'Security Scan — finalizing report...' ) || false === strpos( $command_source, 'prepare_finalization_guard' ) ) {
	fwrite( STDERR, "Report finalization must avoid the old duplicate finding array and retain the finalization diagnostics.\n" );
	exit( 1 );
}

$command = new Security_Scan_Command();

$version = new ReflectionMethod( $command, 'version' );
$version->setAccessible( true );
WP_CLI::$logs = [];
$version->invoke( $command );
if ( false === strpos( implode( "\n", WP_CLI::$logs ), 'WP-CLI Security Scan 1.1.0' ) ) {
	fwrite( STDERR, "Version command must report 1.1.0.\n" );
	exit( 1 );
}

$interactive = new ReflectionProperty( $command, 'interactive' );
$interactive->setAccessible( true );
$interactive->setValue( $command, true );

$stage_stats = new ReflectionProperty( $command, 'stage_stats' );
$stage_stats->setAccessible( true );
$stage_stats->setValue( $command, [ 'Plugins' => [ 'items' => 0, 'findings' => 0 ] ] );

$stage_finish = new ReflectionMethod( $command, 'stage_finish' );
$stage_finish->setAccessible( true );
WP_CLI::$logs = [];
ob_start();
$stage_finish->invoke( $command, 'Plugins', 18114, 4, 'files' );
ob_end_clean();
$stage_output = implode( "\n", WP_CLI::$logs );
if ( false === strpos( $stage_output, '⚠ Plugins scanned — 4 threats found' ) || false !== strpos( $stage_output, '18,114' ) ) {
	fwrite( STDERR, "Stage completion output must show findings only, not scan volume.\n" );
	exit( 1 );
}

$plugin_integrity = new ReflectionProperty( $command, 'plugin_integrity' );
$plugin_integrity->setAccessible( true );
$plugin_integrity->setValue( $command, [
	'good-plugin' => [ 'status' => 'verified' ],
	'bad-plugin' => [ 'status' => 'modified' ],
] );
$stage_stats->setValue( $command, [ 'Plugin integrity' => [ 'items' => 0, 'findings' => 0 ] ] );
$finish_integrity = new ReflectionMethod( $command, 'plugin_checksum_stage_finish' );
$finish_integrity->setAccessible( true );
WP_CLI::$logs = [];
ob_start();
$finish_integrity->invoke( $command, 'Plugin integrity' );
ob_end_clean();
if ( false === strpos( implode( "\n", WP_CLI::$logs ), '⚠ Plugin integrity checked — 1 verified, 1 modified' ) ) {
	fwrite( STDERR, "Plugin integrity completion must remain visible in the scan checklist.\n" );
	exit( 1 );
}

$plugin_integrity->setValue( $command, [] );
$inactive_plugins = new ReflectionProperty( $command, 'inactive_plugins' );
$inactive_plugins->setAccessible( true );
$inactive_plugins->setValue( $command, [ [ 'slug' => 'inactive-example' ] ] );
$report = [
	'severity' => [ 'critical' => 0, 'high' => 2, 'medium' => 0, 'low' => 0 ],
	'files_scanned' => 100,
	'database_rows' => 184158,
	'administrator_users' => 2,
	'total_findings' => 2,
	'duration_seconds' => 2.5,
	'stages' => [
		'Core checksums' => [ 'findings' => 0, 'items' => null ],
		'Themes' => [ 'findings' => 0, 'items' => 10 ],
		'Plugins' => [ 'findings' => 0, 'items' => 20 ],
		'Uploads' => [ 'findings' => 1, 'items' => 30 ],
		'Database' => [ 'findings' => 1, 'items' => 184158 ],
	],
	'findings' => [
		[ 'section' => 'Uploads', 'severity' => 'high', 'confidence' => 90, 'description' => 'Upload issue', 'location' => 'uploads/a.php', 'line' => 1, 'rule' => 'a' ],
		[ 'section' => 'Database', 'severity' => 'high', 'confidence' => 90, 'description' => 'DB issue', 'location' => 'wp_options #1', 'line' => null, 'rule' => 'b' ],
	],
];

$render = new ReflectionMethod( $command, 'render_terminal_report' );
$render->setAccessible( true );
WP_CLI::$logs = [];
$render->invoke( $command, $report, '/var/www/html/security-scan.log' );
$output = implode( "\n", WP_CLI::$logs );

if ( 1 !== substr_count( $output, '184,158' ) || false === strpos( $output, 'DB rows scanned  184,158' ) ) {
	fwrite( STDERR, "Database row count must appear only in Summary.\n" );
	exit( 1 );
}


if ( false !== strpos( $output, 'Findings' ) || false !== strpos( $output, 'Upload issue' ) || false !== strpos( $output, 'uploads/a.php' ) || false !== strpos( $output, 'DB issue' ) ) {
	fwrite( STDERR, "Detailed findings must not be printed in the terminal report.\n" );
	exit( 1 );
}

if ( false === strpos( $output, 'Summary' ) ) {
	fwrite( STDERR, "Summary must remain in the terminal report.\n" );
	exit( 1 );
}

if ( false !== strpos( $output, 'Recommendations' ) || false !== strpos( $output, '[REINSTALL]' ) || false !== strpos( $output, '[REVIEW]' ) || false !== strpos( $output, '[CLEANUP]' ) ) {
	fwrite( STDERR, "Recommendations must not be printed in the terminal report.\n" );
	exit( 1 );
}

if ( false !== strpos( $output, 'High-confidence security findings require review.' ) ) {
	fwrite( STDERR, "The high-confidence terminal warning must not be rendered.\n" );
	exit( 1 );
}

if ( false === strpos( $output, 'Detailed findings saved to /var/www/html/security-scan.log' ) ) {
	fwrite( STDERR, "Terminal report must point to the detailed findings log.\n" );
	exit( 1 );
}
echo "Report UI smoke tests passed.\n";

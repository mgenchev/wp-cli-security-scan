<?php
/**
 * Scanner-owned output files must not be re-scanned as evidence.
 */

define( 'WP_CLI', true );

class WP_CLI {
	public static function add_command( $name, $class ) {}
	public static function error( $message ) {
		throw new RuntimeException( $message );
	}
	public static function log( $message = '' ) {}
	public static function warning( $message ) {}
}

require dirname( __DIR__ ) . '/src/PhpDataFlowAnalyzer.php';
require dirname( __DIR__ ) . '/src/SecurityScanCommand.php';

$root = sys_get_temp_dir() . '/wp-security-scan-self-output-' . getmypid();
$nested = $root . '/custom';
@mkdir( $nested, 0777, true );

$owned_log = $root . '/security-scan.log';
$other_log = $nested . '/security-scan.log';
file_put_contents( $owned_log, "Known web shell fingerprint: FilesMan\n" );
file_put_contents( $other_log, "Known web shell fingerprint: FilesMan\n" );

$command = new Security_Scan_Command();
$reflection = new ReflectionClass( $command );

$properties = [
	'interactive' => false,
	'content_dir' => $root,
	'plugin_dir' => $root . '/plugins',
	'theme_dir' => $root . '/themes',
	'uploads_dir' => $root . '/uploads',
	'mu_plugin_dir' => $root . '/mu-plugins',
	'launch_directory' => $root,
	'scan_log_path' => $owned_log,
];

foreach ( $properties as $property => $value ) {
	$ref = $reflection->getProperty( $property );
	$ref->setAccessible( true );
	$ref->setValue( $command, $value );
}

$load_rules = $reflection->getMethod( 'load_rules' );
$load_rules->setAccessible( true );
$load_rules->invoke( $command );

$scan = $reflection->getMethod( 'scan_other_wp_content' );
$scan->setAccessible( true );
$scan->invoke( $command );

$findings_ref = $reflection->getProperty( 'findings' );
$findings_ref->setAccessible( true );
$findings = $findings_ref->getValue( $command );

$locations = array_column( $findings, 'location' );
$owned_found = in_array( 'security-scan.log', $locations, true );
$other_found = in_array( 'custom/security-scan.log', $locations, true );

$failed = 0;

if ( $owned_found ) {
	echo "FAIL  scanner-owned security-scan.log was scanned\n";
	$failed++;
} else {
	echo "PASS  scanner-owned security-scan.log excluded\n";
}

if ( ! $other_found ) {
	echo "FAIL  unrelated same-named log was incorrectly excluded\n";
	$failed++;
} else {
	echo "PASS  unrelated same-named log remains in scope\n";
}

$scanned_ref = $reflection->getProperty( 'scanned_files' );
$scanned_ref->setAccessible( true );
if ( 1 !== $scanned_ref->getValue( $command ) ) {
	echo "FAIL  scanner-owned output affected file count incorrectly\n";
	$failed++;
} else {
	echo "PASS  file count excludes scanner-owned output\n";
}

@unlink( $owned_log );
@unlink( $other_log );
@rmdir( $nested );
@rmdir( $root );

if ( $failed > 0 ) {
	exit( 1 );
}

echo PHP_EOL . 'Scanner-output scope smoke tests passed.' . PHP_EOL;

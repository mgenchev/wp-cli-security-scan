<?php
/**
 * Standalone regression tests for compact plugin terminal reporting.
 */

define( 'WP_CLI', true );

class WP_CLI {
	public static $logs = [];

	public static function add_command( $name, $class ) {}

	public static function log( $message = '' ) {
		self::$logs[] = (string) $message;
	}
}

require dirname( __DIR__ ) . '/src/SecurityScanCommand.php';

$command = new Security_Scan_Command();
$property = new ReflectionProperty( $command, 'plugin_integrity' );
$property->setAccessible( true );
$property->setValue(
	$command,
	[
		'review-plugin' => [
			'status' => 'unavailable',
			'source' => 'unknown',
			'checksum_errors' => [],
		],
		'reinstall-plugin' => [
			'status' => 'unavailable',
			'source' => 'unknown',
			'checksum_errors' => [],
		],
		'modified-plugin' => [
			'status' => 'modified',
			'source' => 'wordpress.org',
			'checksum_errors' => [
				[ 'file' => 'a.php', 'message' => 'File was added' ],
				[ 'file' => 'b.php', 'message' => 'File was added' ],
			],
		],
	]
);

$findings = [
	[
		'section' => 'Plugins', 'severity' => 'high', 'confidence' => 91,
		'location' => 'plugins/review-plugin/inc/a.php', 'line' => 10,
		'rule' => 'review_rule', 'description' => 'Review finding',
	],
	[
		'section' => 'Plugins', 'severity' => 'medium', 'confidence' => 80,
		'location' => 'plugins/review-plugin/inc/b.php', 'line' => 20,
		'rule' => 'review_rule_2', 'description' => 'Second review finding',
	],
	[
		'section' => 'Plugins', 'severity' => 'critical', 'confidence' => 99,
		'location' => 'plugins/reinstall-plugin/a.php', 'line' => 1,
		'rule' => 'r1', 'description' => 'Critical finding',
	],
	[
		'section' => 'Plugins', 'severity' => 'high', 'confidence' => 95,
		'location' => 'plugins/reinstall-plugin/b.php', 'line' => 2,
		'rule' => 'r2', 'description' => 'High finding',
	],
	[
		'section' => 'Plugins', 'severity' => 'medium', 'confidence' => 80,
		'location' => 'plugins/reinstall-plugin/c.php', 'line' => 3,
		'rule' => 'r3', 'description' => 'Medium finding',
	],
	[
		'section' => 'Plugins', 'severity' => 'low', 'confidence' => 60,
		'location' => 'plugins/reinstall-plugin/d.php', 'line' => 4,
		'rule' => 'r4', 'description' => 'Low finding',
	],
];

$render = new ReflectionMethod( $command, 'render_terminal_plugin_findings' );
$render->setAccessible( true );
WP_CLI::$logs = [];
$render->invoke( $command, $findings );
$output = implode( "\n", WP_CLI::$logs );

if ( false === strpos( $output, 'plugins/review-plugin/inc/a.php:10' ) ) {
	fwrite( STDERR, "Review finding paths must keep the plugins/<slug>/ prefix.\n" );
	exit( 1 );
}

if ( false !== strpos( $output, 'plugins/reinstall-plugin/a.php:1' ) ) {
	fwrite( STDERR, "Replacement candidates should not flood terminal output with individual paths.\n" );
	exit( 1 );
}

if ( false !== strpos( $output, 'Source: Unknown' ) || false !== strpos( $output, 'Risk score:' ) ) {
	fwrite( STDERR, "Internal plugin source/risk metadata must not be printed.\n" );
	exit( 1 );
}

if ( false === strpos( $output, '  2 findings' ) || false !== strpos( $output, '2 findings ·' ) ) {
	fwrite( STDERR, "Plugin summary must show only the finding count.\n" );
	exit( 1 );
}

if ( false !== strpos( $output, 'Recommendations' ) ) {
	fwrite( STDERR, "Recommendations must be rendered globally at the end of the report, not inside Plugins.\n" );
	exit( 1 );
}

$groups_method = new ReflectionMethod( $command, 'group_plugin_findings' );
$groups_method->setAccessible( true );
$groups = $groups_method->invoke( $command, $findings );

$inactive_plugins = new ReflectionProperty( $command, 'inactive_plugins' );
$inactive_plugins->setAccessible( true );
$inactive_plugins->setValue( $command, [ [ 'slug' => 'old-plugin' ], [ 'slug' => 'old-plugin-2' ] ] );

$inactive_themes = new ReflectionProperty( $command, 'inactive_themes' );
$inactive_themes->setAccessible( true );
$inactive_themes->setValue( $command, [ [ 'slug' => 'old-theme' ] ] );

$recommendations = new ReflectionMethod( $command, 'render_terminal_plugin_recommendations' );
$recommendations->setAccessible( true );
WP_CLI::$logs = [];
$recommendations->invoke( $command, $groups );
$recommendation_output = implode( "\n", WP_CLI::$logs );

if ( false === strpos( $recommendation_output, 'HIGH PRIORITY — Suspicious findings exceeded the replacement threshold' ) || false === strpos( $recommendation_output, '  ⚠ reinstall-plugin' ) ) {
	fwrite( STDERR, "Threshold replacement recommendation is missing or not grouped.\n" );
	exit( 1 );
}

if ( false === strpos( $recommendation_output, 'HIGH PRIORITY — Plugin integrity verification failed' ) || false === strpos( $recommendation_output, '  ⚠ modified-plugin' ) ) {
	fwrite( STDERR, "Checksum-modified plugin recommendation is missing or not grouped.\n" );
	exit( 1 );
}

if ( false === strpos( $recommendation_output, '2 inactive plugins detected — not scanned; remove them if not needed.' ) ) {
	fwrite( STDERR, "Inactive plugin recommendation is missing.\n" );
	exit( 1 );
}

if ( false === strpos( $recommendation_output, '1 inactive theme detected — not scanned; remove it if not needed.' ) ) {
	fwrite( STDERR, "Inactive theme recommendation is missing.\n" );
	exit( 1 );
}

echo "Plugin report smoke tests passed.\n";

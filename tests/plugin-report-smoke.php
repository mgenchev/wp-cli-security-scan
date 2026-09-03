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
		'rule' => 'review_rule_2', 'description' => 'Review finding',
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

if ( 1 !== substr_count( $output, 'Review finding' ) || false === strpos( $output, 'plugins/review-plugin/inc/a.php:10' ) || false === strpos( $output, 'plugins/review-plugin/inc/b.php:20' ) ) {
	fwrite( STDERR, "Plugin terminal findings must be grouped by problem while preserving every visible path.\n" );
	exit( 1 );
}

if ( false !== strpos( $output, 'Recommendations' ) ) {
	fwrite( STDERR, "Recommendations must be rendered globally at the end of the report, not inside Plugins.\n" );
	exit( 1 );
}

$groups_method = new ReflectionMethod( $command, 'group_plugin_findings' );
$groups_method->setAccessible( true );
$groups = $groups_method->invoke( $command, $findings );


$recommendation_builder = new ReflectionMethod( $command, 'plugin_recommendations' );
$recommendation_builder->setAccessible( true );
$built_recommendations = $recommendation_builder->invoke( $command, $groups );
$reason_by_slug = [];
foreach ( $built_recommendations as $item ) {
	$reason_by_slug[ $item['slug'] ] = $item['reason'];
}
if ( 'Multiple high-risk findings were detected.' !== ( $reason_by_slug['reinstall-plugin'] ?? null ) ) {
	fwrite( STDERR, "Reinstall recommendation must describe the observed risk without exposing internal thresholds.\n" );
	exit( 1 );
}
if ( 'Suspicious findings require manual review.' !== ( $reason_by_slug['review-plugin'] ?? null ) ) {
	fwrite( STDERR, "Review recommendation wording is not concise or clear.\n" );
	exit( 1 );
}
if ( 'Plugin files do not match the official package.' !== ( $reason_by_slug['modified-plugin'] ?? null ) ) {
	fwrite( STDERR, "Integrity recommendation wording is not concise or clear.\n" );
	exit( 1 );
}

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

if ( false === strpos( $recommendation_output, 'HIGH PRIORITY — Multiple high-risk findings were detected' ) || false === strpos( $recommendation_output, '  ⚠ reinstall-plugin' ) ) {
	fwrite( STDERR, "High-risk reinstall recommendation is missing or not grouped.\n" );
	exit( 1 );
}

if ( false === strpos( $recommendation_output, 'HIGH PRIORITY — Plugin files do not match the official package' ) || false === strpos( $recommendation_output, '  ⚠ modified-plugin' ) ) {
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


$grouped_recommendations = [
	[ 'slug' => 'one', 'action' => 'review', 'reason' => 'Suspicious findings require manual review.', 'count' => 1 ],
	[ 'slug' => 'two', 'action' => 'review', 'reason' => 'Suspicious findings require manual review.', 'count' => 1 ],
	[ 'slug' => 'three', 'action' => 'review', 'reason' => 'High-confidence findings remain despite verified files.', 'count' => 1 ],
];
$group_method = new ReflectionMethod( $command, 'group_plugin_recommendations' );
$group_method->setAccessible( true );
$recommendation_groups = $group_method->invoke( $command, $grouped_recommendations );
if ( 2 !== count( $recommendation_groups ) || [ 'one', 'two' ] !== $recommendation_groups[1]['slugs'] ) {
	fwrite( STDERR, "Recommendations must group plugins by action and user-facing reason.\n" );
	exit( 1 );
}

echo "Plugin report smoke tests passed.\n";

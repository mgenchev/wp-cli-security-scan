<?php
/**
 * Standalone regression tests for plugin-integrity suppression and scoring.
 */

define( 'WP_CLI', true );

class WP_CLI {
	public static function add_command( $name, $class ) {}
}

require dirname( __DIR__ ) . '/src/SecurityScanCommand.php';

$command = new Security_Scan_Command();
$property = new ReflectionProperty( $command, 'plugin_integrity' );
$property->setAccessible( true );
$property->setValue(
	$command,
	[
		'verified-plugin' => [ 'status' => 'verified' ],
		'modified-plugin' => [ 'status' => 'modified' ],
		'unverified-nine' => [ 'status' => 'unavailable' ],
		'unverified-ten' => [ 'status' => 'unavailable' ],
	]
);

$filter = new ReflectionMethod( $command, 'filter_findings_for_plugin_integrity' );
$filter->setAccessible( true );
$group = new ReflectionMethod( $command, 'group_plugin_findings' );
$group->setAccessible( true );

$findings = [
	[
		'section' => 'Plugins', 'severity' => 'high', 'confidence' => 91,
		'location' => 'plugins/verified-plugin/file.php', 'line' => 10,
		'rule' => 'semantic_dynamic_call', 'description' => 'Static heuristic',
	],
	[
		'section' => 'Plugins', 'severity' => 'critical', 'confidence' => 99,
		'location' => 'plugins/verified-plugin/backdoor.php', 'line' => 20,
		'rule' => 'ioc_chhimi', 'description' => 'Known exact IOC',
	],
	[
		'section' => 'Plugins', 'severity' => 'medium', 'confidence' => 75,
		'location' => 'plugins/modified-plugin/file.php', 'line' => 30,
		'rule' => 'some_rule', 'description' => 'Modified plugin finding',
	],
];

$filtered = $filter->invoke( $command, $findings );
if ( 2 !== count( $filtered ) ) {
	fwrite( STDERR, "Verified ordinary heuristics should be suppressed while exact critical IOCs remain.\n" );
	exit( 1 );
}

$score_findings = [];
foreach ( [ 'high', 'medium', 'medium', 'medium' ] as $index => $severity ) { // 3+2+2+2 = 9.
	$score_findings[] = [
		'section' => 'Plugins', 'severity' => $severity, 'confidence' => 80,
		'location' => 'plugins/unverified-nine/file-' . $index . '.php', 'line' => $index + 1,
		'rule' => 'rule_' . $index, 'description' => 'Finding ' . $index,
	];
}
foreach ( [ 'critical', 'high', 'medium', 'low' ] as $index => $severity ) { // 4+3+2+1 = 10.
	$score_findings[] = [
		'section' => 'Plugins', 'severity' => $severity, 'confidence' => 80,
		'location' => 'plugins/unverified-ten/file-' . $index . '.php', 'line' => $index + 1,
		'rule' => 'ten_rule_' . $index, 'description' => 'Finding ' . $index,
	];
}
$score_findings[] = [
	'section' => 'Plugins', 'severity' => 'low', 'confidence' => 60,
	'location' => 'plugins/modified-plugin/changed.php', 'line' => 50,
	'rule' => 'modified_rule', 'description' => 'Modified plugin finding',
];

$groups = $group->invoke( $command, $score_findings );
$by_slug = [];
foreach ( $groups as $item ) {
	$by_slug[ $item['slug'] ] = $item;
}

if ( 9 !== $by_slug['unverified-nine']['risk_score'] || 'review' !== $by_slug['unverified-nine']['action'] ) {
	fwrite( STDERR, "Risk score 9 must remain manual review.\n" );
	exit( 1 );
}

if ( 10 !== $by_slug['unverified-ten']['risk_score'] || 'reinstall' !== $by_slug['unverified-ten']['action'] ) {
	fwrite( STDERR, "Risk score 10 must recommend reinstall.\n" );
	exit( 1 );
}

if ( 'reinstall' !== $by_slug['modified-plugin']['action'] ) {
	fwrite( STDERR, "Checksum-modified plugins must recommend reinstall regardless of score.\n" );
	exit( 1 );
}

$path_count = 0;
foreach ( $by_slug['unverified-ten']['issues'] as $issue ) {
	$path_count += count( $issue['findings'] );
}
if ( 4 !== $path_count ) {
	fwrite( STDERR, "All plugin finding paths must be preserved.\n" );
	exit( 1 );
}

echo "Plugin integrity smoke tests passed.\n";

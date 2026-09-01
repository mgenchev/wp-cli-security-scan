<?php
/**
 * Standalone regression tests for plugin reputation classification.
 */

define( 'WP_CLI', true );

class WP_CLI {
	public static function add_command( $name, $class ) {}
}

function sanitize_key( $key ) {
	return strtolower( preg_replace( '/[^a-z0-9_\-]/', '', (string) $key ) );
}

require dirname( __DIR__ ) . '/src/SecurityScanCommand.php';

$command = new Security_Scan_Command();
$property = new ReflectionProperty( $command, 'plugin_integrity' );
$property->setAccessible( true );
$property->setValue(
	$command,
	[
		'akismet' => [
			'status' => 'unverified',
			'source' => 'unknown',
			'repository_status' => 'unknown',
			'reputation' => 'unverified',
		],
		'premium-plugin' => [
			'status' => 'unverified',
			'source' => 'unknown',
			'repository_status' => 'unknown',
			'reputation' => 'unverified',
		],
	]
);

$apply = new ReflectionMethod( $command, 'apply_wordpress_org_inventory_response' );
$apply->setAccessible( true );
$apply->invoke(
	$command,
	[
		'plugins' => [],
		'no_update' => [
			'akismet/akismet.php' => [
				'slug' => 'akismet',
			],
		],
	]
);

$state = $property->getValue( $command );
if ( 'wordpress.org' !== $state['akismet']['source'] || 'available' !== $state['akismet']['repository_status'] ) {
	fwrite( STDERR, "Bulk WordPress.org inventory must identify official plugin source.\n" );
	exit( 1 );
}

if ( 'unknown' !== $state['premium-plugin']['source'] ) {
	fwrite( STDERR, "Unmatched plugins must remain unverified before follow-up checks.\n" );
	exit( 1 );
}

$classify = new ReflectionMethod( $command, 'classify_plugin_information_response' );
$classify->setAccessible( true );

$cases = [
	[ 200, [ 'slug' => 'akismet', 'name' => 'Akismet' ], 'available' ],
	[ 200, [ 'error' => 'closed' ], 'closed' ],
	[ 200, [ 'message' => 'Plugin disabled' ], 'disabled' ],
	[ 404, [ 'error' => 'Plugin not found.' ], 'not-found' ],
];

foreach ( $cases as $case ) {
	$result = $classify->invoke( $command, $case[0], $case[1] );
	if ( $case[2] !== $result ) {
		fwrite( STDERR, "Unexpected plugin information classification: {$result}; expected {$case[2]}.\n" );
		exit( 1 );
	}
}

$host = new ReflectionMethod( $command, 'is_wordpress_org_host' );
$host->setAccessible( true );
if ( ! $host->invoke( $command, 'api.wordpress.org' ) || $host->invoke( $command, 'example.org' ) ) {
	fwrite( STDERR, "WordPress.org host classification failed.\n" );
	exit( 1 );
}

echo "Plugin reputation smoke tests passed.\n";

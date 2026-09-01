<?php
/**
 * Standalone smoke tests for WP-CLI plugin checksum output parsing.
 */

define( 'WP_CLI', true );

class WP_CLI {
	public static function add_command( $name, $class ) {}
}

if ( ! function_exists( 'sanitize_key' ) ) {
	function sanitize_key( $key ) {
		$key = strtolower( (string) $key );
		return preg_replace( '/[^a-z0-9_\-]/', '', $key );
	}
}

require dirname( __DIR__ ) . '/src/SecurityScanCommand.php';

$command = new Security_Scan_Command();
$parse_json = new ReflectionMethod( $command, 'parse_plugin_checksum_json' );
$parse_json->setAccessible( true );

$output = '[{"plugin_name":"woocommerce","file":"includes/example.php","message":"Checksum does not match"}]' . PHP_EOL . 'Error: Only verified 9 of 10 plugins.';
$items = $parse_json->invoke( $command, $output );
if ( 1 !== count( $items ) || 'woocommerce' !== $items[0]['plugin_name'] || 'includes/example.php' !== $items[0]['file'] ) {
	fwrite( STDERR, "Structured checksum JSON was not parsed correctly.\n" );
	exit( 1 );
}

$property = new ReflectionProperty( $command, 'plugin_integrity' );
$property->setAccessible( true );
$property->setValue(
	$command,
	[
		'premium-plugin' => [
			'slug' => 'premium-plugin', 'name' => 'Premium Plugin', 'version' => '1.0.0',
			'file' => 'premium-plugin/plugin.php', 'status' => 'unverified',
			'checksum_errors' => [], 'repository_status' => 'unknown',
		],
	]
);

$parse_warnings = new ReflectionMethod( $command, 'parse_plugin_checksum_warnings' );
$parse_warnings->setAccessible( true );
$recognized = $parse_warnings->invoke(
	$command,
	'Warning: Could not retrieve the checksums for version 1.0.0 of plugin premium-plugin, skipping.',
	'Plugin integrity'
);
$state = $property->getValue( $command );
if ( ! $recognized || 'unavailable' !== $state['premium-plugin']['status'] ) {
	fwrite( STDERR, "Unavailable checksum warning was not classified correctly.\n" );
	exit( 1 );
}

echo "Plugin checksum parser smoke tests passed.\n";

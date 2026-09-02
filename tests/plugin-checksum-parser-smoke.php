<?php
/**
 * Regression tests for plugin source classification around direct checksum verification.
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
		'vendor-plugin' => [
			'slug' => 'vendor-plugin',
			'file' => 'vendor-plugin/vendor-plugin.php',
			'version' => '1.0.0',
			'update_uri' => 'https://updates.vendor.example/vendor-plugin',
			'source' => 'unknown',
			'repository_status' => 'unknown',
			'reputation' => 'unverified',
			'status' => 'unverified',
			'checksum_errors' => [],
		],
		'custom-updater' => [
			'slug' => 'custom-updater',
			'file' => 'custom-updater/custom-updater.php',
			'version' => '2.0.0',
			'update_uri' => 'vendor-updater',
			'source' => 'unknown',
			'repository_status' => 'unknown',
			'reputation' => 'unverified',
			'status' => 'unverified',
			'checksum_errors' => [],
		],
		'wporg-plugin' => [
			'slug' => 'wporg-plugin',
			'file' => 'wporg-plugin/wporg-plugin.php',
			'version' => '3.0.0',
			'update_uri' => 'https://wordpress.org/plugins/wporg-plugin/',
			'source' => 'unknown',
			'repository_status' => 'unknown',
			'reputation' => 'unverified',
			'status' => 'unverified',
			'checksum_errors' => [],
		],
	]
);

$local = new ReflectionMethod( $command, 'apply_local_plugin_reputation_signals' );
$local->setAccessible( true );
$local->invoke( $command );
$state = $property->getValue( $command );

foreach ( [ 'vendor-plugin', 'custom-updater' ] as $slug ) {
	if ( 'external' !== $state[ $slug ]['source'] || 'external' !== $state[ $slug ]['repository_status'] ) {
		fwrite( STDERR, "Non-WordPress.org Update URI must classify {$slug} as external.\n" );
		exit( 1 );
	}
}

$inventory = new ReflectionMethod( $command, 'apply_wordpress_org_inventory_response' );
$inventory->setAccessible( true );
$inventory->invoke(
	$command,
	[
		'no_update' => [
			'vendor-plugin/vendor-plugin.php' => [ 'slug' => 'vendor-plugin' ],
			'wporg-plugin/wporg-plugin.php' => [ 'slug' => 'wporg-plugin' ],
		],
	]
);
$state = $property->getValue( $command );

if ( 'external' !== $state['vendor-plugin']['source'] || 'external' !== $state['vendor-plugin']['repository_status'] ) {
	fwrite( STDERR, "WordPress.org slug collisions must not override an explicit external Update URI.\n" );
	exit( 1 );
}
if ( 'wordpress.org' !== $state['wporg-plugin']['source'] || 'available' !== $state['wporg-plugin']['repository_status'] ) {
	fwrite( STDERR, "WordPress.org inventory should still identify WordPress.org plugins.\n" );
	exit( 1 );
}

echo "Plugin source/checksum classification smoke tests passed.\n";

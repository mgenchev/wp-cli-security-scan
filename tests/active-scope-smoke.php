<?php
/**
 * Regression tests for isolated active/full plugin and theme scope discovery.
 */

define( 'WP_CLI', true );

class WP_CLI {
	public static function add_command( $name, $class ) {}
}

class Security_Scan_Fake_Options_Database {
	private $options;

	public function __construct( array $options ) {
		$this->options = $options;
	}

	public function get_option_raw( $name ) {
		return array_key_exists( $name, $this->options ) ? $this->options[ $name ] : null;
	}
}

require dirname( __DIR__ ) . '/src/SecurityScanCommand.php';

$root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'security-scan-active-scope-' . uniqid();
$plugins = $root . DIRECTORY_SEPARATOR . 'plugins';
$themes = $root . DIRECTORY_SEPARATOR . 'themes';
mkdir( $plugins . DIRECTORY_SEPARATOR . 'active-plugin', 0777, true );
mkdir( $plugins . DIRECTORY_SEPARATOR . 'inactive-plugin', 0777, true );
mkdir( $plugins . DIRECTORY_SEPARATOR . 'headerless-active', 0777, true );
mkdir( $themes . DIRECTORY_SEPARATOR . 'child-theme', 0777, true );
mkdir( $themes . DIRECTORY_SEPARATOR . 'parent-theme', 0777, true );
mkdir( $themes . DIRECTORY_SEPARATOR . 'inactive-theme', 0777, true );

file_put_contents( $plugins . DIRECTORY_SEPARATOR . 'active-plugin' . DIRECTORY_SEPARATOR . 'active.php', "<?php\n/*\nPlugin Name: Active Plugin\nVersion: 1.0\n*/\n" );
file_put_contents( $plugins . DIRECTORY_SEPARATOR . 'inactive-plugin' . DIRECTORY_SEPARATOR . 'inactive.php', "<?php\n/*\nPlugin Name: Inactive Plugin\nVersion: 1.0\n*/\n" );
file_put_contents( $plugins . DIRECTORY_SEPARATOR . 'headerless-active' . DIRECTORY_SEPARATOR . 'loader.php', "<?php\n// Active PHP can still be loaded even if the metadata header is removed.\n" );
file_put_contents( $themes . DIRECTORY_SEPARATOR . 'child-theme' . DIRECTORY_SEPARATOR . 'style.css', "/*\nTheme Name: Child Theme\n*/\n" );
file_put_contents( $themes . DIRECTORY_SEPARATOR . 'parent-theme' . DIRECTORY_SEPARATOR . 'style.css', "/*\nTheme Name: Parent Theme\n*/\n" );
file_put_contents( $themes . DIRECTORY_SEPARATOR . 'inactive-theme' . DIRECTORY_SEPARATOR . 'style.css', "/*\nTheme Name: Inactive Theme\n*/\n" );

$set_property = static function ( Security_Scan_Command $command, $name, $value ) {
	$property = new ReflectionProperty( $command, $name );
	$property->setAccessible( true );
	$property->setValue( $command, $value );
};

$get_property = static function ( Security_Scan_Command $command, $name ) {
	$property = new ReflectionProperty( $command, $name );
	$property->setAccessible( true );
	return $property->getValue( $command );
};

$initialize = static function ( Security_Scan_Command $command ) {
	foreach ( [ 'initialize_plugin_integrity_inventory', 'initialize_theme_inventory' ] as $method_name ) {
		$method = new ReflectionMethod( $command, $method_name );
		$method->setAccessible( true );
		$method->invoke( $command );
	}
};

$get_theme_scope = static function ( Security_Scan_Command $command ) {
	$method = new ReflectionMethod( $command, 'theme_slugs_for_scan' );
	$method->setAccessible( true );
	return $method->invoke( $command );
};

$configure = static function ( Security_Scan_Command $command, $full_scan = false ) use ( $set_property, $plugins, $themes ) {
	$set_property( $command, 'plugin_dir', $plugins );
	$set_property( $command, 'theme_dir', $themes );
	$set_property( $command, 'active_plugin_files', [ 'active-plugin/active.php' ] );
	$set_property( $command, 'database', new Security_Scan_Fake_Options_Database( [
		'stylesheet' => 'child-theme',
		'template'   => 'parent-theme',
	] ) );
	$set_property( $command, 'full_scan', $full_scan );
};

$command = new Security_Scan_Command();
$configure( $command );
$initialize( $command );

$plugin_integrity = $get_property( $command, 'plugin_integrity' );
$inactive_plugins = $get_property( $command, 'inactive_plugins' );
$inactive_themes = $get_property( $command, 'inactive_themes' );

if ( [ 'active-plugin' ] !== array_keys( $plugin_integrity ) ) {
	fwrite( STDERR, "Default scan should keep inactive regular plugins out of integrity/scanner inventory.\n" );
	exit( 1 );
}

if ( 1 !== count( $inactive_plugins ) || 'inactive-plugin' !== $inactive_plugins[0]['slug'] ) {
	fwrite( STDERR, "Inactive plugins should be tracked separately.\n" );
	exit( 1 );
}

if ( [ 'child-theme', 'parent-theme' ] !== $get_theme_scope( $command ) ) {
	fwrite( STDERR, "Default theme scope should contain the active child theme and parent only.\n" );
	exit( 1 );
}

if ( 1 !== count( $inactive_themes ) || 'inactive-theme' !== $inactive_themes[0]['slug'] ) {
	fwrite( STDERR, "Inactive themes should be tracked separately.\n" );
	exit( 1 );
}

$full_command = new Security_Scan_Command();
$configure( $full_command, true );
$initialize( $full_command );

$full_plugin_integrity = $get_property( $full_command, 'plugin_integrity' );
if ( [ 'active-plugin', 'inactive-plugin' ] !== array_keys( $full_plugin_integrity ) ) {
	fwrite( STDERR, "Full scan should include inactive regular plugins in integrity/scanner inventory.\n" );
	exit( 1 );
}

if ( [ 'child-theme', 'parent-theme', 'inactive-theme' ] !== $get_theme_scope( $full_command ) ) {
	fwrite( STDERR, "Full scan should include inactive themes in static scan scope.\n" );
	exit( 1 );
}


$headerless_command = new Security_Scan_Command();
$set_property( $headerless_command, 'plugin_dir', $plugins );
$set_property( $headerless_command, 'theme_dir', $themes );
$set_property( $headerless_command, 'active_plugin_files', [ 'headerless-active/loader.php' ] );
$set_property( $headerless_command, 'database', new Security_Scan_Fake_Options_Database( [
	'stylesheet' => 'child-theme',
	'template'   => 'parent-theme',
] ) );
$initialize( $headerless_command );
$headerless_integrity = $get_property( $headerless_command, 'plugin_integrity' );
if ( ! isset( $headerless_integrity['headerless-active'] ) ) {
	fwrite( STDERR, "An active plugin must remain in scan scope when its Plugin Name header is missing.
" );
	exit( 1 );
}

$malformed_plugin_command = new Security_Scan_Command();
$set_property( $malformed_plugin_command, 'plugin_dir', $plugins );
$set_property( $malformed_plugin_command, 'database', new Security_Scan_Fake_Options_Database( [
	'active_plugins' => 'not-a-serialized-plugin-list',
] ) );
$read_active = new ReflectionMethod( $malformed_plugin_command, 'read_active_plugin_files' );
$read_active->setAccessible( true );
$set_property( $malformed_plugin_command, 'active_plugin_files', $read_active->invoke( $malformed_plugin_command ) );
$plugin_inventory = new ReflectionMethod( $malformed_plugin_command, 'initialize_plugin_integrity_inventory' );
$plugin_inventory->setAccessible( true );
$plugin_inventory->invoke( $malformed_plugin_command );
if ( true === $get_property( $malformed_plugin_command, 'plugin_scope_reliable' ) ) {
	fwrite( STDERR, "Malformed active_plugins data should mark the active-only scope as unreliable.
" );
	exit( 1 );
}
if ( 2 > count( $get_property( $malformed_plugin_command, 'plugin_integrity' ) ) ) {
	fwrite( STDERR, "Unreliable plugin activation state should fail safe to installed plugin scanning.
" );
	exit( 1 );
}

$malformed_theme_command = new Security_Scan_Command();
$set_property( $malformed_theme_command, 'theme_dir', $themes );
$set_property( $malformed_theme_command, 'database', new Security_Scan_Fake_Options_Database( [
	'stylesheet' => '../../outside',
	'template'   => 'parent-theme',
] ) );
$theme_inventory = new ReflectionMethod( $malformed_theme_command, 'initialize_theme_inventory' );
$theme_inventory->setAccessible( true );
$theme_inventory->invoke( $malformed_theme_command );
if ( true === $get_property( $malformed_theme_command, 'theme_scope_reliable' ) ) {
	fwrite( STDERR, "Unsafe active theme data should mark the active-only scope as unreliable.
" );
	exit( 1 );
}
$malformed_theme_scope = $get_theme_scope( $malformed_theme_command );
sort( $malformed_theme_scope );
if ( [ 'child-theme', 'inactive-theme', 'parent-theme' ] !== $malformed_theme_scope ) {
	fwrite( STDERR, "Unreliable active theme state should fail safe to all installed themes.
" );
	exit( 1 );
}

$iterator = new RecursiveIteratorIterator(
	new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ),
	RecursiveIteratorIterator::CHILD_FIRST
);
foreach ( $iterator as $item ) {
	$item->isDir() ? rmdir( $item->getPathname() ) : unlink( $item->getPathname() );
}
rmdir( $root );

echo "Active/full scope smoke tests passed.\n";

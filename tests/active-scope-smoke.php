<?php

define( 'WP_CLI', true );
define( 'ABSPATH', __DIR__ . '/' );

class WP_CLI {
	public static function add_command( $name, $class ) {}
	public static function log( $message = '' ) {}
}

function sanitize_key( $key ) {
	return strtolower( preg_replace( '/[^a-z0-9_\-]/', '', (string) $key ) );
}

function get_plugins() {
	return [
		'active-plugin/active.php'     => [ 'Name' => 'Active Plugin', 'Version' => '1.0' ],
		'inactive-plugin/inactive.php' => [ 'Name' => 'Inactive Plugin', 'Version' => '1.0' ],
	];
}

function is_plugin_active( $file ) {
	return 'active-plugin/active.php' === $file;
}

class Security_Scan_Fake_Theme {
	private $slug;
	private $name;
	private $parent;

	public function __construct( $slug, $name, $parent = null ) {
		$this->slug = $slug;
		$this->name = $name;
		$this->parent = $parent;
	}

	public function exists() {
		return true;
	}

	public function get_stylesheet() {
		return $this->slug;
	}

	public function parent() {
		return $this->parent;
	}

	public function get( $key ) {
		return 'Name' === $key ? $this->name : '';
	}
}

$parent_theme = new Security_Scan_Fake_Theme( 'parent-theme', 'Parent Theme' );
$active_theme = new Security_Scan_Fake_Theme( 'child-theme', 'Child Theme', $parent_theme );
$inactive_theme = new Security_Scan_Fake_Theme( 'inactive-theme', 'Inactive Theme' );

function wp_get_theme( $slug = null ) {
	global $active_theme, $parent_theme, $inactive_theme;

	if ( 'parent-theme' === $slug ) {
		return $parent_theme;
	}
	if ( 'inactive-theme' === $slug ) {
		return $inactive_theme;
	}
	return $active_theme;
}

function wp_get_themes() {
	global $active_theme, $parent_theme, $inactive_theme;
	return [
		'child-theme'    => $active_theme,
		'parent-theme'   => $parent_theme,
		'inactive-theme' => $inactive_theme,
	];
}

require dirname( __DIR__ ) . '/src/SecurityScanCommand.php';

$initialize = static function ( Security_Scan_Command $command ) {
	foreach ( [ 'initialize_plugin_integrity_inventory', 'initialize_theme_inventory' ] as $method_name ) {
		$method = new ReflectionMethod( $command, $method_name );
		$method->setAccessible( true );
		$method->invoke( $command );
	}
};

$get_property = static function ( Security_Scan_Command $command, $name ) {
	$property = new ReflectionProperty( $command, $name );
	$property->setAccessible( true );
	return $property->getValue( $command );
};

$get_theme_scope = static function ( Security_Scan_Command $command ) {
	$method = new ReflectionMethod( $command, 'theme_slugs_for_scan' );
	$method->setAccessible( true );
	return $method->invoke( $command );
};

$command = new Security_Scan_Command();
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
$full_scan = new ReflectionProperty( $full_command, 'full_scan' );
$full_scan->setAccessible( true );
$full_scan->setValue( $full_command, true );
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

if ( 1 !== count( $get_property( $full_command, 'inactive_plugins' ) ) || 1 !== count( $get_property( $full_command, 'inactive_themes' ) ) ) {
	fwrite( STDERR, "Full scan should keep inactive inventory available for cleanup recommendations.\n" );
	exit( 1 );
}

echo "Active/full scope smoke tests passed.\n";

<?php
/**
 * Regression tests for symlink coverage across wp-content scanner stages.
 */

define( 'WP_CLI', true );

class WP_CLI {
	public static function add_command( $name, $class ) {}
	public static function log( $message ) {}
	public static function warning( $message ) {}
}

require dirname( __DIR__ ) . '/src/SecurityScanCommand.php';

if ( ! function_exists( 'symlink' ) ) {
	echo "Symlink scope smoke tests skipped: symlink() unavailable.\n";
	exit( 0 );
}

$base = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'security-scan-symlink-' . uniqid();
$content = $base . DIRECTORY_SEPARATOR . 'wp-content';
$external = $base . DIRECTORY_SEPARATOR . 'external';
$mu = $content . DIRECTORY_SEPARATOR . 'mu-plugins';
mkdir( $mu, 0777, true );
mkdir( $external, 0777, true );
file_put_contents( $external . DIRECTORY_SEPARATOR . 'payload.php', "<?php echo 'x';\n" );

$mu_link = $mu . DIRECTORY_SEPARATOR . 'linked.php';
$dropin_link = $content . DIRECTORY_SEPARATOR . 'object-cache.php';
$other_link = $content . DIRECTORY_SEPARATOR . 'linked-other.php';
if (
	! @symlink( $external . DIRECTORY_SEPARATOR . 'payload.php', $mu_link )
	|| ! @symlink( $external . DIRECTORY_SEPARATOR . 'payload.php', $dropin_link )
	|| ! @symlink( $external . DIRECTORY_SEPARATOR . 'payload.php', $other_link )
) {
	fwrite( STDERR, "Unable to create symlink fixtures.\n" );
	exit( 1 );
}

$command = new Security_Scan_Command();
$set = static function ( $name, $value ) use ( $command ) {
	$property = new ReflectionProperty( $command, $name );
	$property->setAccessible( true );
	$property->setValue( $command, $value );
};
$get = static function ( $name ) use ( $command ) {
	$property = new ReflectionProperty( $command, $name );
	$property->setAccessible( true );
	return $property->getValue( $command );
};

$set( 'interactive', false );
$set( 'content_dir', $content );
$set( 'mu_plugin_dir', $mu );
$set( 'plugin_dir', $content . DIRECTORY_SEPARATOR . 'plugins' );
$set( 'theme_dir', $content . DIRECTORY_SEPARATOR . 'themes' );
$set( 'uploads_dir', $content . DIRECTORY_SEPARATOR . 'uploads' );

$scan_mu = new ReflectionMethod( $command, 'scan_mu_plugins_and_dropins' );
$scan_mu->setAccessible( true );
$scan_mu->invoke( $command );

$scan_other = new ReflectionMethod( $command, 'scan_other_wp_content' );
$scan_other->setAccessible( true );
$scan_other->invoke( $command );

$findings = $get( 'findings' );
$paths = [];
foreach ( $findings as $finding ) {
	if ( 'external_symlink' === ( $finding['rule'] ?? '' ) ) {
		$paths[] = (string) ( $finding['location'] ?? '' );
	}
}

foreach ( [ 'mu-plugins/linked.php', 'object-cache.php', 'linked-other.php' ] as $expected ) {
	if ( ! in_array( $expected, $paths, true ) ) {
		fwrite( STDERR, "Symlink coverage missed {$expected}.\n" );
		exit( 1 );
	}
}

@unlink( $mu_link );
@unlink( $dropin_link );
@unlink( $other_link );
@unlink( $external . DIRECTORY_SEPARATOR . 'payload.php' );
@rmdir( $mu );
@rmdir( $content );
@rmdir( $external );
@rmdir( $base );

echo "Symlink scope smoke tests passed.\n";

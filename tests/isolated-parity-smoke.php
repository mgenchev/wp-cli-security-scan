<?php
/**
 * Regression tests for isolated runtime parity that depends on multisite/network context.
 */

define( 'WP_CLI', true );
define( 'MULTISITE', true );
define( 'WP_HTTP_BLOCK_EXTERNAL', true );
define( 'WP_ACCESSIBLE_HOSTS', '*.wordpress.org' );

class Security_Scan_Parity_Runner {
	public $assoc_args = [ 'url' => 'https://mapped.example.test/site/' ];
}

class WP_CLI {
	public static $runner;
	public static function add_command( $name, $class ) {}
	public static function get_runner() {
		return self::$runner;
	}
	public static function error( $message ) {
		throw new RuntimeException( $message );
	}
}
WP_CLI::$runner = new Security_Scan_Parity_Runner();

class Security_Scan_Parity_Database {
	public $prefix = '';

	public function set_prefix( $prefix ) {
		$this->prefix = $prefix;
	}

	public function table_exists( $table ) {
		return true;
	}

	public function prepare( $query, ...$args ) {
		return $query . ' /* ' . implode( '|', array_map( 'strval', $args ) ) . ' */';
	}

	public function get_results( $query, $associative = false ) {
		if ( false !== strpos( $query, 'WHERE domain =' ) ) {
			return [ [ 'blog_id' => 12, 'site_id' => 7, 'path' => '/site/' ] ];
		}
		return [];
	}

	public function get_var( $query ) {
		if ( false !== strpos( $query, 'SELECT id FROM' ) ) {
			return 1;
		}
		return null;
	}

	public function get_option_raw( $name ) {
		return null;
	}

	public function get_network_option_raw( $name, $site_id ) {
		if ( 7 !== (int) $site_id ) {
			return null;
		}
		if ( 'main_site' === $name ) {
			return '5';
		}
		if ( 'WPLANG' === $name ) {
			return 'fr_FR';
		}
		if ( 'ms_files_rewriting' === $name ) {
			return '0';
		}
		return null;
	}
}

require dirname( __DIR__ ) . '/src/SecurityScanCommand.php';

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

$root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'security-scan-parity-' . uniqid();
mkdir( $root . DIRECTORY_SEPARATOR . 'wp-includes', 0777, true );
mkdir( $root . DIRECTORY_SEPARATOR . 'wp-content' . DIRECTORY_SEPARATOR . 'uploads', 0777, true );
file_put_contents(
	$root . DIRECTORY_SEPARATOR . 'wp-includes' . DIRECTORY_SEPARATOR . 'version.php',
	"<?php\n\$wp_version = '6.9';\n\$wp_local_package = 'de_DE';\n"
);

$set( 'database', new Security_Scan_Parity_Database() );
$set( 'base_table_prefix', 'wp_' );
$set( 'wp_root', $root );
$set( 'content_dir', $root . DIRECTORY_SEPARATOR . 'wp-content' );

$resolve = new ReflectionMethod( $command, 'resolve_current_site_prefix' );
$resolve->setAccessible( true );
$resolve->invoke( $command );

if ( 12 !== $get( 'current_blog_id' ) || 7 !== $get( 'current_network_id' ) || 5 !== $get( 'current_network_main_blog_id' ) ) {
	fwrite( STDERR, "Isolated multisite resolution must preserve the blog/network pair and network main-site ID.\n" );
	exit( 1 );
}
if ( 'wp_12_' !== $get( 'site_table_prefix' ) ) {
	fwrite( STDERR, "Resolved multisite blog should use the correct site table prefix.\n" );
	exit( 1 );
}

$locale = new ReflectionMethod( $command, 'resolve_site_locale' );
$locale->setAccessible( true );
if ( 'fr_FR' !== $locale->invoke( $command ) ) {
	fwrite( STDERR, "Multisite site/network locale options should override the core package locale as WordPress does.\n" );
	exit( 1 );
}

$uploads = new ReflectionMethod( $command, 'resolve_upload_directory' );
$uploads->setAccessible( true );
$expected_uploads = $root . DIRECTORY_SEPARATOR . 'wp-content' . DIRECTORY_SEPARATOR . 'uploads' . DIRECTORY_SEPARATOR . 'sites' . DIRECTORY_SEPARATOR . '12';
if ( $expected_uploads !== $uploads->invoke( $command ) ) {
	fwrite( STDERR, "Isolated uploads resolution should append sites/{blog_id} for a non-main post-MU multisite site.\n" );
	exit( 1 );
}

$http_allowed = new ReflectionMethod( $command, 'scanner_http_url_is_allowed' );
$http_allowed->setAccessible( true );
if ( ! $http_allowed->invoke( $command, 'https://api.wordpress.org/core/checksums/1.0/' ) ) {
	fwrite( STDERR, "WP_ACCESSIBLE_HOSTS wildcard should allow scanner requests to approved WordPress.org endpoints.\n" );
	exit( 1 );
}

$host_matches = new ReflectionMethod( $command, 'scanner_http_host_matches_list' );
$host_matches->setAccessible( true );
if ( ! $host_matches->invoke( $command, 'downloads.wordpress.org', '*.wordpress.org' ) || $host_matches->invoke( $command, 'wordpress.org.evil.test', '*.wordpress.org' ) ) {
	fwrite( STDERR, "HTTP accessible-host wildcard matching must stay host-bound.\n" );
	exit( 1 );
}

$source = (string) file_get_contents( dirname( __DIR__ ) . '/src/SecurityScanCommand.php' );
if (
	false === strpos( $source, 'HTTP_RESPONSE_MAX_BYTES' )
	|| false === strpos( $source, 'scanner_curl_progress_callback' )
	|| false === strpos( $source, 'CURLOPT_RETURNTRANSFER' )
	|| false === strpos( $source, 'CURLOPT_XFERINFOFUNCTION' )
	|| false !== strpos( $source, 'CURLOPT_WRITEFUNCTION' )
) {
	fwrite( STDERR, "Scanner-owned HTTP responses should use native cURL buffering with a bounded progress guard.\n" );
	exit( 1 );
}

$state_method = new ReflectionMethod( $command, 'scanner_curl_response_state' );
$state_method->setAccessible( true );
$callback_method = new ReflectionMethod( $command, 'scanner_curl_progress_callback' );
$callback_method->setAccessible( true );
$state = $state_method->invoke( $command );
$callback = $callback_method->invoke( $command, $state );
if ( 0 !== $callback( null, 1024, 512, 0, 0 ) || $state->too_large ) {
	fwrite( STDERR, "HTTP progress guard should allow bounded responses.\n" );
	exit( 1 );
}
if ( 1 !== $callback( null, 16777217, 0, 0, 0 ) || ! $state->too_large ) {
	fwrite( STDERR, "HTTP progress guard should abort responses above 16 MiB.\n" );
	exit( 1 );
}

unlink( $root . DIRECTORY_SEPARATOR . 'wp-includes' . DIRECTORY_SEPARATOR . 'version.php' );
rmdir( $root . DIRECTORY_SEPARATOR . 'wp-includes' );
rmdir( $root . DIRECTORY_SEPARATOR . 'wp-content' . DIRECTORY_SEPARATOR . 'uploads' );
rmdir( $root . DIRECTORY_SEPARATOR . 'wp-content' );
rmdir( $root );

echo "Isolated parity smoke tests passed.\n";

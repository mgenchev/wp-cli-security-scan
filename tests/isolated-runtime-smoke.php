<?php
/**
 * Regression tests for the isolated scanner runtime.
 */

define( 'WP_CLI', true );

class WP_CLI {
	public static function add_command( $name, $class ) {}
}

require dirname( __DIR__ ) . '/src/SecurityScanCommand.php';

$source = (string) file_get_contents( dirname( __DIR__ ) . '/src/SecurityScanCommand.php' );
if ( false === strpos( $source, "start_background_spinner( 'Security Scan — preparing rules...' )" ) ) {
	fwrite( STDERR, "Rule preparation should use the background spinner so animation continues during synchronous setup.\n" );
	exit( 1 );
}
$forbidden_patterns = [
	'/->load_wordpress\s*\(/',
	'/\bget_plugins\s*\(/',
	'/\bis_plugin_active\s*\(/',
	'/\bwp_get_theme\s*\(/',
	'/\bwp_get_themes\s*\(/',
	'/\bget_option\s*\(/',
	'/\bget_users\s*\(/',
	'/\bget_userdata\s*\(/',
	'/\buser_can\s*\(/',
	'/\bwp_remote_get\s*\(/',
	'/\bwp_remote_post\s*\(/',
	'/WP_CLI::runcommand\s*\(/',
];
foreach ( $forbidden_patterns as $pattern ) {
	if ( preg_match( $pattern, $source ) ) {
		fwrite( STDERR, "Isolated scanner runtime contains a forbidden WordPress runtime dependency: {$pattern}\n" );
		exit( 1 );
	}
}

$command = new Security_Scan_Command();
$decode = new ReflectionMethod( $command, 'decode_stored_value' );
$decode->setAccessible( true );

$decoded = $decode->invoke( $command, serialize( [ 'plugin/plugin.php', 'other/other.php' ] ) );
if ( ! is_array( $decoded ) || 2 !== count( $decoded ) ) {
	fwrite( STDERR, "Scalar/array WordPress option serialization should decode safely.\n" );
	exit( 1 );
}

$object_payload = 'O:8:"stdClass":1:{s:4:"test";s:5:"value";}';
if ( $object_payload !== $decode->invoke( $command, $object_payload ) ) {
	fwrite( STDERR, "Serialized objects from the restored database must not be unserialized.\n" );
	exit( 1 );
}


$db_reflection = new ReflectionClass( 'Security_Scan_Database' );
$db = $db_reflection->newInstanceWithoutConstructor();
$parse_host = $db_reflection->getMethod( 'parse_host' );
$parse_host->setAccessible( true );
$host_parts = $parse_host->invoke( $db, 'localhost:3307:/tmp/mysql.sock' );
if ( 'localhost' !== $host_parts['host'] || 3307 !== $host_parts['port'] || '/tmp/mysql.sock' !== $host_parts['socket'] ) {
	fwrite( STDERR, "Isolated database adapter should support DB_HOST with host, port, and socket.
" );
	exit( 1 );
}
$ipv6_parts = $parse_host->invoke( $db, '[::1]:3308:/tmp/mysql.sock' );
if ( '::1' !== $ipv6_parts['host'] || 3308 !== $ipv6_parts['port'] || '/tmp/mysql.sock' !== $ipv6_parts['socket'] ) {
	fwrite( STDERR, "Isolated database adapter should support bracketed IPv6 DB_HOST values.
" );
	exit( 1 );
}

$assert_read_only = $db_reflection->getMethod( 'assert_read_only_query' );
$assert_read_only->setAccessible( true );
$assert_read_only->invoke( $db, 'SELECT option_value FROM wp_options' );
$assert_read_only->invoke( $db, 'SHOW TABLES' );

foreach ( [ 'DELETE FROM wp_options', "SELECT option_value INTO OUTFILE '/tmp/leak' FROM wp_options", 'SELECT 1; DELETE FROM wp_options' ] as $unsafe_sql ) {
	try {
		$assert_read_only->invoke( $db, $unsafe_sql );
		fwrite( STDERR, "Isolated database adapter must reject write-capable SQL.\n" );
		exit( 1 );
	} catch ( ReflectionException $e ) {
		throw $e;
	} catch ( Throwable $e ) {
		if ( false === strpos( $e->getMessage(), 'blocked' ) ) {
			throw $e;
		}
	}
}

define( 'WP_PROXY_HOST', '127.0.0.1' );
define( 'WP_PROXY_PORT', 8080 );
define( 'WP_PROXY_USERNAME', 'scanner-user' );
define( 'WP_PROXY_PASSWORD', 'scanner-pass' );
define( 'WP_PROXY_BYPASS_HOSTS', 'downloads.wordpress.org' );

$allowed_url = new ReflectionMethod( $command, 'scanner_http_url_is_allowed' );
$allowed_url->setAccessible( true );
if ( ! $allowed_url->invoke( $command, 'https://api.wordpress.org/plugins/info/1.2/' ) ) {
	fwrite( STDERR, "Scanner HTTP allowlist should permit official WordPress.org API endpoints.\n" );
	exit( 1 );
}
if ( $allowed_url->invoke( $command, 'https://example.invalid/payload.json' ) || $allowed_url->invoke( $command, 'http://api.wordpress.org/plugins/info/1.2/' ) ) {
	fwrite( STDERR, "Scanner HTTP allowlist must reject non-WordPress.org or non-HTTPS destinations.\n" );
	exit( 1 );
}

$proxy_method = new ReflectionMethod( $command, 'scanner_http_proxy_for_url' );
$proxy_method->setAccessible( true );
$proxy = $proxy_method->invoke( $command, 'https://api.wordpress.org/plugins/info/1.2/' );
if ( ! is_array( $proxy ) || '127.0.0.1' !== $proxy['host'] || 8080 !== $proxy['port'] || 'scanner-user:scanner-pass' !== $proxy['auth'] ) {
	fwrite( STDERR, "Isolated HTTP client should honor trusted WP_PROXY_* configuration.\n" );
	exit( 1 );
}
if ( null !== $proxy_method->invoke( $command, 'https://downloads.wordpress.org/plugin-checksums/example/1.0.json' ) ) {
	fwrite( STDERR, "Isolated HTTP client should honor WP_PROXY_BYPASS_HOSTS.\n" );
	exit( 1 );
}

if ( ! defined( 'WP_HOME' ) ) {
	define( 'WP_HOME', 'https://override.example.test' );
}
$home_host = new ReflectionMethod( $command, 'resolve_site_home_host' );
$home_host->setAccessible( true );
if ( 'override.example.test' !== $home_host->invoke( $command ) ) {
	fwrite( STDERR, "Isolated runtime should honor trusted WP_HOME before database home/siteurl values.\n" );
	exit( 1 );
}

if ( ! defined( 'MULTISITE' ) ) {
	define( 'MULTISITE', true );
}
class Security_Scan_Test_Database {
	public function get_network_option_raw( $name, $site_id ) {
		return 'site_admins' === $name ? serialize( [ 'network-admin', 'second-admin' ] ) : null;
	}
}
$database_property = new ReflectionProperty( $command, 'database' );
$database_property->setAccessible( true );
$database_property->setValue( $command, new Security_Scan_Test_Database() );
$super_admins = new ReflectionMethod( $command, 'read_multisite_super_admin_logins' );
$super_admins->setAccessible( true );
$admin_logins = $super_admins->invoke( $command );
if ( empty( $admin_logins['network-admin'] ) || empty( $admin_logins['second-admin'] ) ) {
	fwrite( STDERR, "Isolated users scan should account for multisite super administrators without loading WP_User.\n" );
	exit( 1 );
}

$root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'security-scan-header-' . uniqid();
mkdir( $root, 0777, true );
$marker = $root . DIRECTORY_SEPARATOR . 'executed';
$plugin = $root . DIRECTORY_SEPARATOR . 'plugin.php';
file_put_contents(
	$plugin,
	"<?php\n/*\nPlugin Name: Header Test\nVersion: 1.2.3\n*/\nfile_put_contents(" . var_export( $marker, true ) . ", 'executed');\n"
);

$headers = new ReflectionMethod( $command, 'read_file_headers' );
$headers->setAccessible( true );
$data = $headers->invoke( $command, $plugin, [ 'Name' => 'Plugin Name', 'Version' => 'Version' ] );
if ( 'Header Test' !== $data['Name'] || '1.2.3' !== $data['Version'] ) {
	fwrite( STDERR, "Plugin/theme metadata should be parsed from file text.\n" );
	exit( 1 );
}
if ( file_exists( $marker ) ) {
	fwrite( STDERR, "Reading plugin metadata must never execute the plugin file.\n" );
	exit( 1 );
}

unlink( $plugin );
rmdir( $root );

echo "Isolated runtime smoke tests passed.\n";

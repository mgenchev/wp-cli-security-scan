<?php
/** Regression tests for checksum-verified plugin scan fast path. */
define( 'WP_CLI', true );

class WP_CLI {
	public static $logs = [];
	public static function add_command( $name, $class ) {}
	public static function log( $message = '' ) { self::$logs[] = (string) $message; }
	public static function warning( $message ) { self::$logs[] = 'Warning: ' . $message; }
}

require dirname( __DIR__ ) . '/src/SecurityScanCommand.php';

$root = __DIR__ . '/tmp-fast-plugin';
$plugin_dir = $root . '/plugins';
@mkdir( $plugin_dir . '/verified-demo', 0777, true );
file_put_contents(
	$plugin_dir . '/verified-demo/plugin.php',
	"<?php\n\$x = base64_decode(\$_POST['x']); eval(\$x);\n// FilesMan\n"
);
file_put_contents(
	$plugin_dir . '/verified-demo/readme.txt',
	"FilesMan should not be scanned for verified-plugin exact IOC coverage.\n"
);

$command = new Security_Scan_Command();
$set = static function ( $name, $value ) use ( $command ) {
	$property = new ReflectionProperty( $command, $name );
	$property->setAccessible( true );
	$property->setValue( $command, $value );
};
$set( 'plugin_dir', $plugin_dir );
$set( 'content_dir', $root );
$set( 'plugin_integrity', [
	'verified-demo' => [
		'file' => 'verified-demo/plugin.php',
		'status' => 'verified',
		'source' => 'wordpress.org',
		'checksum_errors' => [],
	],
] );
$set( 'rules', [
	'iocs' => [
		[ 'id'=>'ioc_filesman', 'needle'=>'FilesMan', 'severity'=>'critical', 'confidence'=>98, 'description'=>'Known web shell fingerprint: FilesMan' ],
		[ 'id'=>'ioc_low', 'needle'=>'base64_decode', 'severity'=>'high', 'confidence'=>94, 'description'=>'Lower-confidence IOC' ],
	],
	'php' => [
		[ 'id'=>'php_eval_decode', 'regex'=>'~eval\\s*\\(~i', 'severity'=>'critical', 'confidence'=>98, 'description'=>'Heuristic eval finding' ],
	],
	'javascript' => [],
	'database' => [],
] );

$method = new ReflectionMethod( $command, 'scan_regular_plugins' );
$method->setAccessible( true );
$method->invoke( $command );

$findings_property = new ReflectionProperty( $command, 'findings' );
$findings_property->setAccessible( true );
$findings = $findings_property->getValue( $command );

if ( 1 !== count( $findings ) ) {
	fwrite( STDERR, "Verified-plugin fast path must keep only reportable exact IOC findings.\n" );
	exit( 1 );
}
if ( 'ioc_filesman' !== ( $findings[0]['rule'] ?? '' ) || false === strpos( (string) $findings[0]['location'], 'plugin.php' ) ) {
	fwrite( STDERR, "Verified-plugin fast path lost the high-confidence exact IOC.\n" );
	exit( 1 );
}

$scanned_property = new ReflectionProperty( $command, 'scanned_files' );
$scanned_property->setAccessible( true );
if ( 2 !== $scanned_property->getValue( $command ) ) {
	fwrite( STDERR, "Verified-plugin fast path must preserve file-scope accounting.\n" );
	exit( 1 );
}

@unlink( $plugin_dir . '/verified-demo/plugin.php' );
@unlink( $plugin_dir . '/verified-demo/readme.txt' );
@rmdir( $plugin_dir . '/verified-demo' );
@rmdir( $plugin_dir );
@rmdir( $root );

echo "Verified plugin fast-path smoke tests passed.\n";

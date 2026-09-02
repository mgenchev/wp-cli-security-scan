<?php
/**
 * Standalone regression tests for direct WordPress.org plugin checksum verification.
 */

$root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'security-scan-plugin-checksum-' . uniqid();
$plugin_dir = $root . DIRECTORY_SEPARATOR . 'sample-plugin';
mkdir( $plugin_dir, 0777, true );
file_put_contents( $plugin_dir . DIRECTORY_SEPARATOR . 'sample-plugin.php', "<?php\n// clean\n" );
file_put_contents( $plugin_dir . DIRECTORY_SEPARATOR . 'asset.js', "console.log('ok');\n" );

define( 'WP_CLI', true );
define( 'WP_PLUGIN_DIR', $root );

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
		'sample-plugin' => [
			'slug' => 'sample-plugin',
			'file' => 'sample-plugin/sample-plugin.php',
			'status' => 'unverified',
			'checksum_errors' => [],
			'source' => 'unknown',
			'repository_status' => 'unknown',
			'reputation' => 'unverified',
		],
	]
);

$manifest = [
	'sample-plugin.php' => [
		'sha256' => [ hash_file( 'sha256', $plugin_dir . DIRECTORY_SEPARATOR . 'sample-plugin.php' ) ],
		'md5' => [ md5_file( $plugin_dir . DIRECTORY_SEPARATOR . 'sample-plugin.php' ) ],
	],
	'asset.js' => [
		'sha256' => hash_file( 'sha256', $plugin_dir . DIRECTORY_SEPARATOR . 'asset.js' ),
	],
];

$verify = new ReflectionMethod( $command, 'verify_plugin_checksum_manifest' );
$verify->setAccessible( true );
$verify->invoke( $command, 'sample-plugin', $manifest );
$state = $property->getValue( $command );
if ( 'verified' !== $state['sample-plugin']['status'] || ! empty( $state['sample-plugin']['checksum_errors'] ) ) {
	fwrite( STDERR, "Matching direct checksum manifest must verify the plugin.\n" );
	exit( 1 );
}

file_put_contents( $plugin_dir . DIRECTORY_SEPARATOR . 'asset.js', "console.log('modified');\n" );
file_put_contents( $plugin_dir . DIRECTORY_SEPARATOR . 'extra.php', "<?php echo 'extra';\n" );
$property->setValue(
	$command,
	[
		'sample-plugin' => [
			'slug' => 'sample-plugin',
			'file' => 'sample-plugin/sample-plugin.php',
			'status' => 'unverified',
			'checksum_errors' => [],
			'source' => 'unknown',
			'repository_status' => 'unknown',
			'reputation' => 'unverified',
		],
	]
);
$verify->invoke( $command, 'sample-plugin', $manifest );
$state = $property->getValue( $command );
if ( 'modified' !== $state['sample-plugin']['status'] ) {
	fwrite( STDERR, "Changed/added local files must mark the plugin modified.\n" );
	exit( 1 );
}

$messages = array_column( $state['sample-plugin']['checksum_errors'], 'message' );
if ( ! in_array( 'File differs from the official plugin checksum', $messages, true ) || ! in_array( 'Local file is not part of the official plugin package', $messages, true ) ) {
	fwrite( STDERR, "Direct checksum verification must detect modified and added files.\n" );
	exit( 1 );
}

$normalize = new ReflectionMethod( $command, 'normalize_checksum_manifest_entry' );
$normalize->setAccessible( true );
$hashes = $normalize->invoke(
	$command,
	[
		'sha256' => [ str_repeat( 'a', 64 ), str_repeat( 'b', 64 ) ],
		'md5' => str_repeat( 'c', 32 ),
	]
);
if ( 2 !== count( $hashes['sha256'] ) || 1 !== count( $hashes['md5'] ) ) {
	fwrite( STDERR, "Checksum whitelist normalization failed.\n" );
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

echo "Direct plugin checksum smoke tests passed.\n";

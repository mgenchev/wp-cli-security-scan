<?php
/** Regression tests for scanner-owned WordPress core checksum handling. */
define( 'WP_CLI', true );

class WP_CLI {
	public static function add_command( $name, $class ) {}
}

require dirname( __DIR__ ) . '/src/SecurityScanCommand.php';

$command = new Security_Scan_Command();
$root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'security-scan-core-' . uniqid();
mkdir( $root . DIRECTORY_SEPARATOR . 'wp-admin', 0777, true );
mkdir( $root . DIRECTORY_SEPARATOR . 'wp-includes', 0777, true );
mkdir( $root . DIRECTORY_SEPARATOR . 'wp-content', 0777, true );

$marker = $root . DIRECTORY_SEPARATOR . 'version-executed';
file_put_contents(
	$root . DIRECTORY_SEPARATOR . 'wp-includes' . DIRECTORY_SEPARATOR . 'version.php',
	"<?php\n\$wp_version = '6.8.2';\n\$wp_local_package = 'bg_BG';\nfile_put_contents(" . var_export( $marker, true ) . ", 'executed');\n"
);
file_put_contents( $root . DIRECTORY_SEPARATOR . 'wp-admin' . DIRECTORY_SEPARATOR . 'admin.php', '<?php' );
file_put_contents( $root . DIRECTORY_SEPARATOR . 'wp-includes' . DIRECTORY_SEPARATOR . 'load.php', '<?php' );
file_put_contents( $root . DIRECTORY_SEPARATOR . 'wp-load.php', '<?php' );
file_put_contents( $root . DIRECTORY_SEPARATOR . 'wp-cli.yml', "path: .\n" );
file_put_contents( $root . DIRECTORY_SEPARATOR . 'index.php', '<?php' );
file_put_contents( $root . DIRECTORY_SEPARATOR . 'random.txt', 'ignore' );
file_put_contents( $root . DIRECTORY_SEPARATOR . 'wp-content' . DIRECTORY_SEPARATOR . 'evil.php', '<?php' );

$wp_root = new ReflectionProperty( $command, 'wp_root' );
$wp_root->setAccessible( true );
$wp_root->setValue( $command, $root );

$details_method = new ReflectionMethod( $command, 'read_wordpress_core_version_details' );
$details_method->setAccessible( true );
$details = $details_method->invoke( $command );
if ( '6.8.2' !== ( $details['wp_version'] ?? '' ) || 'bg_BG' !== ( $details['wp_local_package'] ?? '' ) ) {
	fwrite( STDERR, "Core version metadata should be parsed from version.php source text.\n" );
	exit( 1 );
}
if ( file_exists( $marker ) ) {
	fwrite( STDERR, "Reading WordPress core version metadata must never execute version.php.\n" );
	exit( 1 );
}

$normalize = new ReflectionMethod( $command, 'normalize_core_manifest_path' );
$normalize->setAccessible( true );
foreach ( [ '../outside.php', '/absolute.php', 'C:/absolute.php', "wp-admin/../evil.php", "wp-admin/evil\0.php" ] as $unsafe ) {
	if ( '' !== $normalize->invoke( $command, $unsafe ) ) {
		fwrite( STDERR, "Unsafe core checksum manifest paths must be rejected before filesystem access.\n" );
		exit( 1 );
	}
}
if ( 'wp-includes/load.php' !== $normalize->invoke( $command, 'wp-includes/load.php' ) ) {
	fwrite( STDERR, "Valid WordPress core manifest paths should remain usable.\n" );
	exit( 1 );
}

$discover = new ReflectionMethod( $command, 'discover_core_checksum_files' );
$discover->setAccessible( true );
$files = $discover->invoke( $command );
foreach ( [ 'wp-admin/admin.php', 'wp-includes/load.php', 'wp-includes/version.php', 'wp-load.php', 'wp-cli.yml' ] as $expected ) {
	if ( ! in_array( $expected, $files, true ) ) {
		fwrite( STDERR, "Core unexpected-file discovery is missing {$expected}.\n" );
		exit( 1 );
	}
}
foreach ( [ 'index.php', 'random.txt', 'wp-content/evil.php' ] as $excluded ) {
	if ( in_array( $excluded, $files, true ) ) {
		fwrite( STDERR, "Core unexpected-file discovery should preserve WP-CLI default scope and exclude {$excluded}.\n" );
		exit( 1 );
	}
}

$source = (string) file_get_contents( dirname( __DIR__ ) . '/src/SecurityScanCommand.php' );
if ( false !== strpos( $source, 'run_wp_cli_process(' ) || preg_match( '/WP_CLI::runcommand\s*\(/', $source ) ) {
	fwrite( STDERR, "Core checksum verification should be scanner-owned and must not launch a nested WP-CLI checksum command.\n" );
	exit( 1 );
}

$iterator = new RecursiveIteratorIterator(
	new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ),
	RecursiveIteratorIterator::CHILD_FIRST
);
foreach ( $iterator as $item ) {
	if ( $item->isDir() && ! $item->isLink() ) {
		@rmdir( $item->getPathname() );
	} else {
		@unlink( $item->getPathname() );
	}
}
@rmdir( $root );

echo "Scanner-owned core checksum smoke tests passed.\n";

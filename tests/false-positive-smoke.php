<?php

$root = dirname( __DIR__ );
$rules = json_decode( file_get_contents( $root . '/rules/php.json' ), true );
$rules = isset( $rules['rules'] ) ? $rules['rules'] : [];

$tests = [
	[
		'label' => 'raw request body parsed without execution',
		'code' => <<<'CODE'
<?php
$body = file_get_contents( 'php://input' );
$data = json_decode( $body, true );
require __DIR__ . '/template.php';
CODE,
		'must_not' => [ 'php_stream_input_execute' ],
	],
	[
		'label' => 'openssl decrypt used as normal crypto operation',
		'code' => <<<'CODE'
<?php
$value = openssl_decrypt( $encrypted, 'aes-256-cbc', $key );
require __DIR__ . '/view.php';
CODE,
		'must_not' => [ 'php_decrypt_execute' ],
	],
	[
		'label' => 'PSR upload interface documentation',
		'code' => <<<'CODE'
<?php
/** Implementations may ultimately call move_uploaded_file($_FILES['file']). */
interface UploadedFileInterface {}
CODE,
		'must_not' => [ 'php_upload_handler' ],
	],
	[
		'label' => 'legitimate long crypto hex constant',
		'code' => <<<'CODE'
<?php
$constant = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12";
CODE,
		'must_not' => [ 'php_hex_obfuscation_execution' ],
	],
	[
		'label' => 'hex payload next to eval remains detected',
		'code' => <<<'CODE'
<?php
$payload = "\x65\x76\x61\x6c\x28\x24\x5f\x50\x4f\x53\x54\x5b\x78\x5d\x29\x3b";
eval( $payload );
CODE,
		'must' => [ 'php_hex_obfuscation_execution' ],
	],
];

$failed = 0;
foreach ( $tests as $test ) {
	$matched = [];
	foreach ( $rules as $rule ) {
		if ( 1 === @preg_match( $rule['regex'], $test['code'] ) ) {
			$matched[] = $rule['id'];
		}
	}

	$ok = true;
	foreach ( isset( $test['must_not'] ) ? $test['must_not'] : [] as $id ) {
		if ( in_array( $id, $matched, true ) ) {
			$ok = false;
		}
	}
	foreach ( isset( $test['must'] ) ? $test['must'] : [] as $id ) {
		if ( ! in_array( $id, $matched, true ) ) {
			$ok = false;
		}
	}

	echo ( $ok ? 'PASS  ' : 'FAIL  ' ) . $test['label'] . PHP_EOL;
	if ( ! $ok ) {
		echo '      matched: ' . implode( ', ', $matched ) . PHP_EOL;
		$failed++;
	}
}

if ( $failed > 0 ) {
	exit( 1 );
}

echo PHP_EOL . 'All false-positive regression tests passed.' . PHP_EOL;

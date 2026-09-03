<?php
/**
 * Context-aware known wp_options persistence key regression tests.
 */

define( 'WP_CLI', true );

class WP_CLI {
	public static function add_command( $name, $class ) {}
}

require dirname( __DIR__ ) . '/src/PhpDataFlowAnalyzer.php';
require dirname( __DIR__ ) . '/src/SecurityScanCommand.php';

$command = new Security_Scan_Command();
$reflection = new ReflectionClass( $command );
$database_property = $reflection->getProperty( 'database' );
$database_property->setAccessible( true );
$database_property->setValue( $command, (object) [ 'options' => 'wp_options' ] );
$findings_property = $reflection->getProperty( 'findings' );
$findings_property->setAccessible( true );
$scan = $reflection->getMethod( 'scan_known_persistence_option_name' );
$scan->setAccessible( true );

$tests = [
	[
		'name' => '_hdra_core exact option key is detected',
		'option_name' => '_hdra_core',
		'expect' => 'db_known_persistence_option_hdra_core',
	],
	[
		'name' => '_pre_user_id exact option key is detected',
		'option_name' => '_pre_user_id',
		'expect' => 'db_known_persistence_option_pre_user_id',
	],
	[
		'name' => 'API_SN_CLOUDSERVER exact option key is detected',
		'option_name' => 'API_SN_CLOUDSERVER',
		'expect' => 'db_known_persistence_option_cloudserver',
	],
	[
		'name' => 'similar custom option name is not treated as an IOC',
		'option_name' => 'my_pre_user_id_backup',
		'expect_none' => true,
	],
];

$failed = 0;
foreach ( $tests as $test ) {
	$findings_property->setValue( $command, [] );
	$seen = [];
	$args = [
		'Database',
		'wp_options',
		[ 'option_name' => $test['option_name'] ],
		'option_value',
		'wp_options.option_value #1 (option_name=' . $test['option_name'] . ')',
		&$seen,
	];
	$scan->invokeArgs( $command, $args );
	$rules = array_column( $findings_property->getValue( $command ), 'rule' );
	$ok = ! empty( $test['expect_none'] ) ? empty( $rules ) : in_array( $test['expect'], $rules, true );

	echo ( $ok ? 'PASS  ' : 'FAIL  ' ) . $test['name'] . PHP_EOL;
	if ( ! $ok ) {
		echo '      rules: ' . implode( ', ', $rules ) . PHP_EOL;
		$failed++;
	}
}

if ( $failed > 0 ) {
	exit( 1 );
}

echo PHP_EOL . 'Known persistence option smoke tests passed.' . PHP_EOL;

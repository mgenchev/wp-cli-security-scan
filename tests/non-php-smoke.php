<?php

define( 'WP_CLI', true );

class WP_CLI {
	public static function add_command( $name, $class ) {}
}

require dirname( __DIR__ ) . '/src/PhpDataFlowAnalyzer.php';
require dirname( __DIR__ ) . '/src/SecurityScanCommand.php';

$command = new Security_Scan_Command();
$root = dirname( __DIR__ );
$rules = [];
foreach ( [ 'iocs', 'php', 'javascript', 'database' ] as $name ) {
	$data = json_decode( file_get_contents( $root . '/rules/' . $name . '.json' ), true );
	$rules[ $name ] = $data['rules'];
}

$reflection = new ReflectionClass( $command );
$rules_property = $reflection->getProperty( 'rules' );
$rules_property->setAccessible( true );
$rules_property->setValue( $command, $rules );

$ioc_needles = [];
foreach ( $rules['iocs'] as $rule ) {
	$ioc_needles[] = $rule['needle'];
}
$analyzer_property = $reflection->getProperty( 'php_data_flow_analyzer' );
$analyzer_property->setAccessible( true );
$analyzer_property->setValue( $command, new Security_Scan_Php_Data_Flow_Analyzer( $ioc_needles ) );

$scan = $reflection->getMethod( 'scan_file_buffer' );
$scan->setAccessible( true );
$findings_property = $reflection->getProperty( 'findings' );
$findings_property->setAccessible( true );

$tests = [
	[
		'name' => 'readme PHP example does not become a critical generic finding',
		'extension' => 'txt',
		'uploads' => false,
		'buffer' => "Example:\n<?php echo esc_html( \$value ); ?>\n",
		'forbid' => 'php_in_non_php',
	],
	[
		'name' => 'JavaScript PHP template string does not become a critical generic finding',
		'extension' => 'js',
		'uploads' => false,
		'buffer' => "const template = '<?php echo esc_js( \$value ); ?>';\n",
		'forbid' => 'php_in_non_php',
	],
	[
		'name' => 'PHP hidden in an image remains reportable',
		'extension' => 'jpg',
		'uploads' => false,
		'buffer' => "JPEGDATA\n<?php echo 'x'; ?>\n",
		'expect' => 'php_in_non_php',
	],
	[
		'name' => 'PHP hidden in an upload remains critical',
		'extension' => 'jpg',
		'uploads' => true,
		'buffer' => "JPEGDATA\n<?php echo 'x'; ?>\n",
		'expect' => 'uploads_embedded_php',
	],
];

$failed = 0;
foreach ( $tests as $test ) {
	$findings_property->setValue( $command, [] );
	$seen = [];
	$args = [ 'Plugins', 'plugins/example/file.' . $test['extension'], $test['extension'], $test['buffer'], $test['uploads'], &$seen, 1 ];
	$scan->invokeArgs( $command, $args );
	$findings = $findings_property->getValue( $command );
	$found_rules = array_column( $findings, 'rule' );
	$ok = true;
	if ( isset( $test['forbid'] ) && in_array( $test['forbid'], $found_rules, true ) ) {
		$ok = false;
	}
	if ( isset( $test['expect'] ) && ! in_array( $test['expect'], $found_rules, true ) ) {
		$ok = false;
	}
	if ( $ok ) {
		echo 'PASS  ' . $test['name'] . PHP_EOL;
	} else {
		echo 'FAIL  ' . $test['name'] . ' — ' . implode( ', ', $found_rules ) . PHP_EOL;
		$failed++;
	}
}

exit( $failed > 0 ? 1 : 0 );

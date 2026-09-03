<?php
/**
 * Smoke tests for expanded persistence auditing and cross-layer IOC correlation.
 */

define( 'WP_CLI', true );

class WP_CLI {
	public static function add_command( $name, $class ) {}
	public static function log( $message = '' ) {}
}

class Security_Scan_Persistence_Fake_DB {
	private $select_calls = 0;

	public function table_exists( $table ) {
		return 'wp_actionscheduler_actions' === $table;
	}

	public function prepare( $query, ...$args ) {
		if ( empty( $args ) ) {
			return $query;
		}
		return preg_replace( '/%d/', (string) (int) $args[0], $query, 1 );
	}

	public function get_results( $query, $associative = false ) {
		if ( 0 === strpos( $query, 'SHOW COLUMNS' ) ) {
			return [
				[ 'Field' => 'action_id' ],
				[ 'Field' => 'hook' ],
				[ 'Field' => 'args' ],
				[ 'Field' => 'status' ],
				[ 'Field' => 'scheduled_date_gmt' ],
				[ 'Field' => 'extended_args' ],
			];
		}

		if ( 0 === strpos( $query, 'SELECT ' ) ) {
			$this->select_calls++;
			if ( 1 === $this->select_calls ) {
				return [
					[
						'action_id'          => 7,
						'hook'               => 'legitimate_hook',
						'args'               => 'payload evil-c2.test',
						'status'             => 'pending',
						'scheduled_date_gmt' => '2026-09-03 08:00:00',
						'extended_args'      => '',
					],
				];
			}
		}

		return [];
	}
}

require dirname( __DIR__ ) . '/src/SecurityScanCommand.php';

$command = new Security_Scan_Command();
$interactive = new ReflectionProperty( $command, 'interactive' );
$interactive->setAccessible( true );
$interactive->setValue( $command, false );

$findings_property = new ReflectionProperty( $command, 'findings' );
$findings_property->setAccessible( true );

$roles_method = new ReflectionMethod( $command, 'scan_role_capability_persistence' );
$roles_method->setAccessible( true );
$roles_method->invoke(
	$command,
	'Users & persistence',
	[
		'administrator' => [ 'manage_options' => true ],
		'subscriber'    => [ 'read' => true, 'manage_options' => true ],
		'ops_manager'   => [ 'read' => true, 'update_plugins' => true ],
	]
);
$findings = $findings_property->getValue( $command );
$descriptions = array_column( $findings, 'description' );
if ( ! in_array( 'Built-in non-administrator role grants administrative capabilities', $descriptions, true ) ) {
	fwrite( STDERR, "Modified built-in roles must be reported.\n" );
	exit( 1 );
}
if ( ! in_array( 'Custom role grants administrative capabilities', $descriptions, true ) ) {
	fwrite( STDERR, "Powerful custom roles must be reported for review.\n" );
	exit( 1 );
}

$resolve_method = new ReflectionMethod( $command, 'resolve_user_security_state' );
$resolve_method->setAccessible( true );
$user_state = $resolve_method->invoke(
	$command,
	[
		'subscriber'     => true,
		'update_plugins' => true,
	],
	[
		'subscriber' => [ 'read' => true ],
	]
);
if ( empty( $user_state['is_privileged'] ) || ! in_array( 'update_plugins', $user_state['direct_capabilities'], true ) ) {
	fwrite( STDERR, "Direct administrative capability state was not preserved.\n" );
	exit( 1 );
}

$direct_method = new ReflectionMethod( $command, 'scan_user_direct_capability_persistence' );
$direct_method->setAccessible( true );
$direct_method->invoke(
	$command,
	'Users & persistence',
	[ 'ID' => 12, 'user_login' => 'quiet-user' ],
	$user_state,
	false
);
$findings = $findings_property->getValue( $command );
if ( ! in_array( 'User has direct administrative capabilities outside assigned roles', array_column( $findings, 'description' ), true ) ) {
	fwrite( STDERR, "Direct administrative user capabilities must be reported.\n" );
	exit( 1 );
}

$app_method = new ReflectionMethod( $command, 'scan_user_application_password_persistence' );
$app_method->setAccessible( true );
$now = time();
$app_method->invoke(
	$command,
	'Users & persistence',
	[ 'ID' => 14, 'user_login' => "admin\nname" ],
	[ 'roles' => [ 'administrator' ], 'is_privileged' => true ],
	[
		[
			'name'      => "REST\nClient",
			'password'  => '$P$not-for-output',
			'created'   => $now - 3600,
			'last_used' => $now - 120,
			'last_ip'   => '127.0.0.1',
		],
	],
	$now - 86400
);
$findings = $findings_property->getValue( $command );
$app_findings = array_values(
	array_filter(
		$findings,
		static function ( $finding ) {
			return 'recent_privileged_application_password' === ( $finding['rule'] ?? '' );
		}
	)
);
if ( 1 !== count( $app_findings ) || false !== strpos( $app_findings[0]['location'], '$P$not-for-output' ) || false !== strpos( $app_findings[0]['location'], "\n" ) ) {
	fwrite( STDERR, "Application-password findings must be recent/privileged, single-line, and must not expose password hashes.\n" );
	exit( 1 );
}

$database_property = new ReflectionProperty( $command, 'database' );
$database_property->setAccessible( true );
$database_property->setValue( $command, new Security_Scan_Persistence_Fake_DB() );
$prefix_property = new ReflectionProperty( $command, 'site_table_prefix' );
$prefix_property->setAccessible( true );
$prefix_property->setValue( $command, 'wp_' );
$rules_property = new ReflectionProperty( $command, 'rules' );
$rules_property->setAccessible( true );
$rules_property->setValue(
	$command,
	[
		'iocs' => [
			[
				'id'          => 'ioc_test_c2',
				'needle'      => 'evil-c2.test',
				'severity'    => 'critical',
				'confidence'  => 99,
				'description' => 'Known malicious domain indicator: evil-c2.test',
			],
		],
		'database' => [],
	]
);
$action_method = new ReflectionMethod( $command, 'scan_action_scheduler_persistence' );
$action_method->setAccessible( true );
$count = 0;
$args = [ 'Users & persistence', &$count ];
$action_method->invokeArgs( $command, $args );
$findings = $findings_property->getValue( $command );
$action_matches = array_values(
	array_filter(
		$findings,
		static function ( $finding ) {
			return 'ioc_test_c2' === ( $finding['rule'] ?? '' ) && false !== strpos( $finding['location'], 'Action Scheduler #7' );
		}
	)
);
if ( 1 !== count( $action_matches ) || 1 !== $count ) {
	fwrite( STDERR, "Active Action Scheduler rows must be scanned with persistence rules.\n" );
	exit( 1 );
}

$correlation_method = new ReflectionMethod( $command, 'build_cross_layer_indicator_correlations' );
$correlation_method->setAccessible( true );
$correlations = $correlation_method->invoke(
	$command,
	[
		[
			'section' => 'Plugins', 'severity' => 'critical', 'confidence' => 99,
			'location' => 'plugins/bad/a.php', 'line' => 12, 'rule' => 'ioc_test_c2',
			'description' => 'Known malicious domain indicator: evil-c2.test',
		],
		[
			'section' => 'Database', 'severity' => 'critical', 'confidence' => 99,
			'location' => 'wp_options #3 · option_value', 'line' => null, 'rule' => 'ioc_test_c2',
			'description' => 'Known malicious domain indicator: evil-c2.test',
		],
		[
			'section' => 'Themes', 'severity' => 'high', 'confidence' => 90,
			'location' => 'themes/a/a.php', 'line' => 3, 'rule' => 'heuristic_test',
			'description' => 'Broad heuristic',
		],
		[
			'section' => 'Database', 'severity' => 'high', 'confidence' => 90,
			'location' => 'wp_options #4 · option_value', 'line' => null, 'rule' => 'heuristic_test',
			'description' => 'Broad heuristic',
		],
	]
);
if ( 1 !== count( $correlations ) || 2 !== count( $correlations[0]['sections'] ) || 2 !== count( $correlations[0]['locations'] ) ) {
	fwrite( STDERR, "Only exact IOC rules spanning multiple scan layers should create correlations.\n" );
	exit( 1 );
}

echo "Persistence/correlation smoke tests passed.\n";

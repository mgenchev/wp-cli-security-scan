<?php
/**
 * Standalone smoke tests for rapid user-registration detection.
 */

define( 'WP_CLI', true );

class WP_CLI {
	public static function add_command( $name, $class ) {}
}

require dirname( __DIR__ ) . '/src/SecurityScanCommand.php';

$command = new Security_Scan_Command();
$method = new ReflectionMethod( $command, 'find_user_burst_members' );
$method->setAccessible( true );
$base = 1700000000;

$regular = [];
for ( $i = 1; $i <= 5; $i++ ) {
	$regular[] = [
		'id'            => $i,
		'timestamp'     => $base + ( $i * 60 ),
		'is_privileged' => false,
	];
}

$regular_result = $method->invoke( $command, $regular );
if ( 5 !== count( $regular_result ) ) {
	fwrite( STDERR, "Expected five regular burst members.\n" );
	exit( 1 );
}

$privileged = [
	[
		'id'            => 10,
		'timestamp'     => $base,
		'is_privileged' => true,
	],
	[
		'id'            => 11,
		'timestamp'     => $base + 300,
		'is_privileged' => true,
	],
];

$privileged_result = $method->invoke( $command, $privileged );
if ( 2 !== count( $privileged_result ) || empty( $privileged_result[10]['privileged'] ) ) {
	fwrite( STDERR, "Expected two privileged burst members.\n" );
	exit( 1 );
}

$clean = [
	[
		'id'            => 20,
		'timestamp'     => $base,
		'is_privileged' => false,
	],
	[
		'id'            => 21,
		'timestamp'     => $base + 1200,
		'is_privileged' => false,
	],
];

$clean_result = $method->invoke( $command, $clean );
if ( ! empty( $clean_result ) ) {
	fwrite( STDERR, "Separated registrations must not form a burst.\n" );
	exit( 1 );
}

echo "User registration smoke tests passed.\n";

<?php
/**
 * Scanner output must not be polluted by non-fatal PHP diagnostics.
 */

define( 'WP_CLI', true );

class WP_CLI {
	public static function add_command( $name, $class ) {}
}

require dirname( __DIR__ ) . '/src/SecurityScanCommand.php';

$command = new Security_Scan_Command();
$method = new ReflectionMethod( $command, 'suppress_wordpress_debug' );
$method->setAccessible( true );

$previous_reporting = error_reporting();
$previous_handler_called = false;
set_error_handler(
	static function () use ( &$previous_handler_called ) {
		$previous_handler_called = true;
		return false;
	}
);

$method->invoke( $command );
$current_reporting = error_reporting();
$failed = 0;

if ( 0 === ( $current_reporting & E_ERROR ) || 0 === ( $current_reporting & E_PARSE ) ) {
	echo "FAIL  fatal PHP error levels must remain enabled\n";
	$failed++;
} else {
	echo "PASS  fatal PHP error levels remain enabled\n";
}

if ( 0 !== ( $current_reporting & ( E_WARNING | E_NOTICE | E_DEPRECATED | E_USER_WARNING | E_USER_NOTICE | E_USER_DEPRECATED ) ) ) {
	echo "FAIL  non-fatal PHP diagnostics must be removed from error_reporting\n";
	$failed++;
} else {
	echo "PASS  non-fatal PHP diagnostics removed from error_reporting\n";
}

trigger_error( 'scanner deprecation test', E_USER_DEPRECATED );
trigger_error( 'scanner notice test', E_USER_NOTICE );
trigger_error( 'scanner warning test', E_USER_WARNING );

if ( $previous_handler_called ) {
	echo "FAIL  suppressed diagnostics leaked to the previous WP-CLI error handler\n";
	$failed++;
} else {
	echo "PASS  suppressed diagnostics do not leak to the previous error handler\n";
}

$config_handler_called = false;
error_reporting( E_ALL );
set_error_handler(
	static function () use ( &$config_handler_called ) {
		$config_handler_called = true;
		return false;
	}
);

$method->invoke( $command );
trigger_error( 'post-config deprecation test', E_USER_DEPRECATED );

if ( $config_handler_called ) {
	echo "FAIL  scanner did not recover after wp-config-style diagnostics override\n";
	$failed++;
} else {
	echo "PASS  scanner recovers after wp-config-style diagnostics override\n";
}

restore_error_handler();
restore_error_handler();
restore_error_handler();
restore_error_handler();
error_reporting( $previous_reporting );

if ( $failed > 0 ) {
	exit( 1 );
}

echo PHP_EOL . 'Runtime diagnostics smoke tests passed.' . PHP_EOL;

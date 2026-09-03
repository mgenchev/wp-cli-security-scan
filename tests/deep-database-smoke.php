<?php
/** Regression tests for opt-in custom-table deep database scanning. */
define( 'WP_CLI', true );

class WP_CLI {
	public static function add_command( $name, $class ) {}
	public static function log( $message = '' ) {}
	public static function warning( $message ) {}
}

class Security_Scan_Database {
	public $users = 'wp_users';
	public $show_columns_calls = 0;
	public $usermeta = 'wp_usermeta';

	public function esc_like( $value ) { return addcslashes( (string) $value, '_%\\' ); }
	public function prepare( $query, ...$args ) {
		foreach ( $args as $arg ) {
			if ( preg_match( '/%d/', $query ) ) {
				$query = preg_replace( '/%d/', (string) (int) $arg, $query, 1 );
			} else {
				$query = preg_replace( '/%s/', "'" . addslashes( (string) $arg ) . "'", $query, 1 );
			}
		}
		return $query;
	}
	public function get_results( $query, $assoc = false ) {
		if ( 0 === stripos( $query, 'SHOW TABLES LIKE' ) ) {
			return [
				[ 'Tables_in_test' => 'wp_posts' ],
				[ 'Tables_in_test' => 'wp_options' ],
				[ 'Tables_in_test' => 'wp_custom_logs' ],
				[ 'Tables_in_test' => 'wp_2_custom_logs' ],
			];
		}
		if ( false !== stripos( $query, 'SHOW COLUMNS FROM `wp_custom_logs`' ) ) {
			$this->show_columns_calls++;
			return [
				[ 'Field'=>'id', 'Type'=>'bigint(20) unsigned', 'Key'=>'PRI' ],
				[ 'Field'=>'label', 'Type'=>'varchar(255)', 'Key'=>'' ],
				[ 'Field'=>'payload', 'Type'=>'longtext', 'Key'=>'' ],
				[ 'Field'=>'amount', 'Type'=>'decimal(10,2)', 'Key'=>'' ],
			];
		}
		if ( false !== stripos( $query, 'FROM `wp_custom_logs`' ) ) {
			if ( false !== stripos( $query, 'WHERE `id` > 0' ) ) {
				return [
					[ 'id'=>1, 'label'=>'normal', 'payload'=>'safe' ],
					[ 'id'=>2, 'label'=>'alert', 'payload'=>'FilesMan' ],
				];
			}
			return [];
		}
		return [];
	}
}

require dirname( __DIR__ ) . '/src/SecurityScanCommand.php';

$command = new Security_Scan_Command();
$set = static function ( $name, $value ) use ( $command ) {
	$property = new ReflectionProperty( $command, $name );
	$property->setAccessible( true );
	$property->setValue( $command, $value );
};
$set( 'database', new Security_Scan_Database() );
$set( 'site_table_prefix', 'wp_' );
$set( 'base_table_prefix', 'wp_' );
$set( 'interactive', false );
$set( 'rules', [
	'iocs' => [
		[ 'id'=>'ioc_filesman', 'needle'=>'FilesMan', 'severity'=>'critical', 'confidence'=>98, 'description'=>'Known web shell fingerprint: FilesMan' ],
	],
	'database' => [],
	'javascript' => [],
] );

$discover = new ReflectionMethod( $command, 'discover_deep_database_tables' );
$discover->setAccessible( true );
$tables = $discover->invoke( $command, [ 'wp_posts', 'wp_options' ] );
if ( [ 'wp_custom_logs' ] !== $tables ) {
	fwrite( STDERR, "Deep database discovery must exclude core and other-blog multisite tables.\n" );
	exit( 1 );
}

$definition_method = new ReflectionMethod( $command, 'deep_database_table_definition' );
$definition_method->setAccessible( true );
$definition = $definition_method->invoke( $command, 'wp_custom_logs' );
$definition_again = $definition_method->invoke( $command, 'wp_custom_logs' );
$database_property = new ReflectionProperty( $command, 'database' );
$database_property->setAccessible( true );
$database = $database_property->getValue( $command );
if ( 1 !== $database->show_columns_calls ) {
	fwrite( STDERR, "Column metadata must be cached within one scan run.\n" );
	exit( 1 );
}
if ( $definition !== $definition_again ) {
	fwrite( STDERR, "Cached deep database definitions must remain stable.\n" );
	exit( 1 );
}
if ( 'id' !== ( $definition['pk'] ?? '' ) || empty( $definition['pk_numeric'] ) || [ 'label', 'payload' ] !== ( $definition['fields'] ?? [] ) ) {
	fwrite( STDERR, "Deep database schema discovery must select a simple primary key and text-like fields only.\n" );
	exit( 1 );
}

$scan = new ReflectionMethod( $command, 'scan_deep_database_table' );
$scan->setAccessible( true );
$count = $scan->invoke( $command, 'Database', $definition );
if ( 2 !== $count ) {
	fwrite( STDERR, "Deep database scan must process all returned custom-table rows.\n" );
	exit( 1 );
}

$findings_property = new ReflectionProperty( $command, 'findings' );
$findings_property->setAccessible( true );
$findings = $findings_property->getValue( $command );
if ( 1 !== count( $findings ) || 'ioc_filesman' !== ( $findings[0]['rule'] ?? '' ) || false === strpos( (string) $findings[0]['location'], 'wp_custom_logs.payload #2' ) ) {
	fwrite( STDERR, "Deep database scan must reuse existing IOC logic and preserve table/row/field context.\n" );
	exit( 1 );
}

echo "Deep database smoke tests passed.\n";

<?php
/**
 * Minimal read-only database adapter for the security scanner.
 *
 * This deliberately avoids loading WordPress or wp-content database drop-ins.
 */

class Security_Scan_Database {
	private $connection;
	private $prefix = '';
	private $base_prefix = '';
	private $table_exists_cache = [];

	public $posts = '';
	public $postmeta = '';
	public $options = '';
	public $comments = '';
	public $commentmeta = '';
	public $termmeta = '';
	public $users = '';
	public $usermeta = '';

	/**
	 * Open a direct database connection using wp-config.php credentials.
	 */
	public function __construct( $name, $user, $password, $host, $charset, $base_prefix, $client_flags = 0 ) {
		if ( ! function_exists( 'mysqli_init' ) ) {
			throw new RuntimeException( 'The mysqli PHP extension is required for isolated database scanning.' );
		}

		$connection = mysqli_init();
		if ( false === $connection ) {
			throw new RuntimeException( 'Unable to initialize a database connection.' );
		}

		$parts = $this->parse_host( (string) $host );
		$connected = @mysqli_real_connect(
			$connection,
			$parts['host'],
			(string) $user,
			(string) $password,
			(string) $name,
			$parts['port'],
			$parts['socket'],
			(int) $client_flags
		);

		if ( ! $connected ) {
			$message = mysqli_connect_error();
			mysqli_close( $connection );
			throw new RuntimeException( 'Unable to connect to the WordPress database' . ( $message ? ': ' . $message : '.' ) );
		}

		if ( '' !== trim( (string) $charset ) ) {
			@mysqli_set_charset( $connection, (string) $charset );
		}

		$this->connection = $connection;
		$this->base_prefix = (string) $base_prefix;
		$this->set_prefix( (string) $base_prefix );
	}

	public function __destruct() {
		if ( $this->connection instanceof mysqli ) {
			@mysqli_close( $this->connection );
		}
	}

	/**
	 * Set the current site table prefix while keeping users/usermeta global.
	 */
	public function set_prefix( $prefix ) {
		$this->prefix = (string) $prefix;
		$this->posts = $this->prefix . 'posts';
		$this->postmeta = $this->prefix . 'postmeta';
		$this->options = $this->prefix . 'options';
		$this->comments = $this->prefix . 'comments';
		$this->commentmeta = $this->prefix . 'commentmeta';
		$this->termmeta = $this->prefix . 'termmeta';
		$this->users = $this->base_prefix . 'users';
		$this->usermeta = $this->base_prefix . 'usermeta';
	}

	public function get_prefix() {
		return $this->prefix;
	}

	public function get_base_prefix() {
		return $this->base_prefix;
	}

	/**
	 * Respect trusted CUSTOM_USER_TABLE/CUSTOM_USER_META_TABLE configuration.
	 */
	public function set_user_tables( $users_table = '', $usermeta_table = '' ) {
		if ( '' !== trim( (string) $users_table ) ) {
			$this->users = (string) $users_table;
		}
		if ( '' !== trim( (string) $usermeta_table ) ) {
			$this->usermeta = (string) $usermeta_table;
		}
	}

	/**
	 * Escape a value for a quoted SQL string.
	 */
	public function escape( $value ) {
		return mysqli_real_escape_string( $this->connection, (string) $value );
	}

	/**
	 * Escape a value for use in a SQL LIKE expression.
	 */
	public function esc_like( $value ) {
		return addcslashes( (string) $value, '_%\\' );
	}

	/**
	 * Minimal placeholder preparation compatible with the scanner's %s/%d/%f use.
	 */
	public function prepare( $query, ...$args ) {
		if ( 1 === count( $args ) && is_array( $args[0] ) ) {
			$args = $args[0];
		}

		$index = 0;
		$result = preg_replace_callback(
			'/%(?:%|s|d|f)/',
			function ( $matches ) use ( &$index, $args ) {
				$placeholder = $matches[0];
				if ( '%%' === $placeholder ) {
					return '%';
				}

				if ( ! array_key_exists( $index, $args ) ) {
					throw new InvalidArgumentException( 'Not enough values supplied for the SQL query.' );
				}

				$value = $args[ $index++ ];
				if ( '%d' === $placeholder ) {
					return (string) (int) $value;
				}
				if ( '%f' === $placeholder ) {
					return (string) (float) $value;
				}

				return "'" . $this->escape( $value ) . "'";
			},
			(string) $query
		);

		if ( $index !== count( $args ) ) {
			throw new InvalidArgumentException( 'Too many values supplied for the SQL query.' );
		}

		return $result;
	}

	/**
	 * Return all rows as associative arrays or objects.
	 */
	public function get_results( $query, $associative = false ) {
		$result = $this->query( $query );
		if ( true === $result ) {
			return [];
		}

		$rows = [];
		while ( $row = $associative ? mysqli_fetch_assoc( $result ) : mysqli_fetch_object( $result ) ) {
			$rows[] = $row;
		}
		mysqli_free_result( $result );
		return $rows;
	}

	/**
	 * Return the first column of the first row.
	 */
	public function get_var( $query ) {
		$result = $this->query( $query );
		if ( true === $result ) {
			return null;
		}

		$row = mysqli_fetch_row( $result );
		mysqli_free_result( $result );
		return is_array( $row ) && array_key_exists( 0, $row ) ? $row[0] : null;
	}

	/**
	 * Return one option value from the current site's options table.
	 */
	public function get_option_raw( $name ) {
		$query = $this->prepare(
			'SELECT option_value FROM ' . $this->quote_identifier( $this->options ) . ' WHERE option_name = %s LIMIT 1',
			$name
		);
		$value = $this->get_var( $query );
		return null === $value ? null : (string) $value;
	}

	/**
	 * Return one network option from sitemeta.
	 */
	public function get_network_option_raw( $name, $site_id = 1 ) {
		$table = $this->base_prefix . 'sitemeta';
		if ( ! $this->table_exists( $table ) ) {
			return null;
		}

		$query = $this->prepare(
			'SELECT meta_value FROM ' . $this->quote_identifier( $table ) . ' WHERE site_id = %d AND meta_key = %s LIMIT 1',
			(int) $site_id,
			$name
		);
		$value = $this->get_var( $query );
		return null === $value ? null : (string) $value;
	}

	public function table_exists( $table ) {
		$table = (string) $table;
		if ( array_key_exists( $table, $this->table_exists_cache ) ) {
			return $this->table_exists_cache[ $table ];
		}

		$like = $this->esc_like( $table );
		$found = $this->get_var( $this->prepare( 'SHOW TABLES LIKE %s', $like ) );
		$this->table_exists_cache[ $table ] = (string) $found === $table;
		return $this->table_exists_cache[ $table ];
	}

	private function query( $query ) {
		$this->assert_read_only_query( $query );

		$result = @mysqli_query( $this->connection, (string) $query );
		if ( false === $result ) {
			throw new RuntimeException( 'Database query failed: ' . mysqli_error( $this->connection ) );
		}
		return $result;
	}

	/**
	 * Enforce the scanner's read-only database contract at the adapter boundary.
	 */
	private function assert_read_only_query( $query ) {
		$sql = ltrim( (string) $query );
		if ( '' === $sql || ! preg_match( '/^(SELECT|SHOW|DESCRIBE|DESC|EXPLAIN)\b/i', $sql ) ) {
			throw new RuntimeException( 'Scanner database adapter blocked a non-read-only SQL statement.' );
		}

		// Scanner queries never need statement separators. Reject them so a future
		// client-flag change cannot turn one read query into multiple statements.
		if ( false !== strpos( $sql, ';' ) ) {
			throw new RuntimeException( 'Scanner database adapter blocked a multi-statement SQL query.' );
		}

		// SELECT ... INTO OUTFILE/DUMPFILE writes to the database server filesystem.
		if ( preg_match( '/\bINTO\s+(?:OUTFILE|DUMPFILE)\b/i', $sql ) ) {
			throw new RuntimeException( 'Scanner database adapter blocked a file-writing SQL statement.' );
		}
	}

	private function quote_identifier( $identifier ) {
		return '`' . str_replace( '`', '``', (string) $identifier ) . '`';
	}

	/**
	 * Parse common DB_HOST forms accepted by WordPress.
	 */
	private function parse_host( $host ) {
		$result = [
			'host'   => '' !== $host ? $host : 'localhost',
			'port'   => null,
			'socket' => null,
		];

		if ( preg_match( '/^\\[([^\\]]+)\\](?::(\\d+))?(?::(\\/.+))?$/', $host, $matches ) ) {
			$result['host'] = $matches[1];
			$result['port'] = isset( $matches[2] ) && '' !== $matches[2] ? (int) $matches[2] : null;
			$result['socket'] = isset( $matches[3] ) && '' !== $matches[3] ? $matches[3] : null;
			return $result;
		}

		if ( preg_match( '/^([^:]+):(\\d+):(\\/.+)$/', $host, $matches ) ) {
			$result['host'] = '' !== $matches[1] ? $matches[1] : 'localhost';
			$result['port'] = (int) $matches[2];
			$result['socket'] = $matches[3];
			return $result;
		}

		if ( preg_match( '/^([^:]*):(.+\\.sock)$/', $host, $matches ) || preg_match( '/^([^:]*):(\\/.+)$/', $host, $matches ) ) {
			$result['host'] = '' !== $matches[1] ? $matches[1] : 'localhost';
			$result['socket'] = $matches[2];
			return $result;
		}

		if ( preg_match( '/^(.+):(\\d+)$/', $host, $matches ) && false === strpos( $matches[1], ':' ) ) {
			$result['host'] = $matches[1];
			$result['port'] = (int) $matches[2];
		}

		return $result;
	}
}

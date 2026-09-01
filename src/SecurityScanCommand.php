<?php
/**
 * WP-CLI Security Scan command.
 *
 * Read-only diagnostics for compromised WordPress sites.
 */

if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
	return;
}

class Security_Scan_Command {
	private const VERSION = '0.3.0';
	private const DB_BATCH_SIZE = 500;
	private const FILE_CHUNK_SIZE = 524288;
	private const FILE_CHUNK_OVERLAP = 8192;
	private const DEEP_PHP_WHOLE_FILE_MAX = 8388608;
	private const DEEP_PHP_CHUNK_SIZE = 2097152;
	private const DEEP_PHP_CHUNK_OVERLAP = 65536;
	private const RECENT_USER_MONTHS = 2;
	private const USER_BURST_WINDOW_SECONDS = 600;
	private const USER_BURST_THRESHOLD = 5;
	private const PRIVILEGED_USER_BURST_THRESHOLD = 2;
	private const PLUGIN_REINSTALL_SCORE_THRESHOLD = 10;

	private const SEVERITY_WEIGHT = [
		'critical' => 4,
		'high'     => 3,
		'medium'   => 2,
		'low'      => 1,
		'info'     => 0,
	];

	private const PHP_EXTENSIONS = [
		'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phar', 'inc',
	];

	private const JS_EXTENSIONS = [
		'js', 'mjs', 'cjs', 'html', 'htm', 'svg',
	];

	private const NON_EXECUTABLE_DATA_EXTENSIONS = [
		'sql', 'dump', 'zip', 'gz', 'tgz', 'bz2', 'xz', 'tar', '7z', 'rar', 'map',
	];

	private const UPLOAD_EXECUTABLE_EXTENSIONS = [
		'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phar', 'cgi', 'pl', 'py', 'sh',
	];

	private const NON_PHP_MEDIA_EXTENSIONS = [
		'jpg', 'jpeg', 'png', 'gif', 'webp', 'avif', 'svg', 'ico', 'bmp', 'tif', 'tiff', 'pdf', 'txt', 'dat', 'log', 'css', 'js',
	];

	private const NON_EXECUTABLE_TEMPLATE_EXTENSIONS = [
		'txt', 'js', 'css',
	];

	private const DROPIN_FILES = [
		'advanced-cache.php',
		'db.php',
		'db-error.php',
		'object-cache.php',
		'sunrise.php',
		'maintenance.php',
		'install.php',
		'php-error.php',
		'fatal-error-handler.php',
	];

	private $rules = [];
	private $findings = [];
	private $stage_stats = [];
	private $scanned_files = 0;
	private $scanned_db_rows = 0;
	private $spinner_index = 0;
	private $last_spinner_at = 0.0;
	private $interactive = true;
	private $format = 'table';
	private $current_stage = '';
	private $start_time = 0.0;
	private $admin_count = 0;
	private $modification_clusters = [];
	private $include_node_modules = false;
	private $background_spinner_process = null;
	private $php_data_flow_analyzer = null;
	private $plugin_integrity = [];

	/**
	 * Run a complete security scan.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : Output format: table, json, markdown.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - markdown
	 * ---
	 *
	 * [--output=<file>]
	 * : Write JSON or Markdown report to a file.
	 *
	 * [--min-severity=<severity>]
	 * : Minimum severity included in the final report.
	 * ---
	 * default: low
	 * options:
	 *   - low
	 *   - medium
	 *   - high
	 *   - critical
	 * ---
	 *
	 * [--skip-core-checksums]
	 * : Skip wp core verify-checksums.
	 *
	 * [--skip-plugin-checksums]
	 * : Skip WordPress.org plugin checksum verification.
	 *
	 * [--include-node-modules]
	 * : Include node_modules directories in file scans. They are skipped by default.
	 *
	 * ## EXAMPLES
	 *
	 *     wp security-scan
	 *     wp security-scan --format=markdown --output=security-report.md
	 *     wp security-scan --format=json
	 *
	 * @when before_wp_load
	 */
	public function __invoke( $args, $assoc_args ) {
		$sections = [
			'core',
			'plugin_checksums',
			'plugins',
			'mu_plugins',
			'themes',
			'uploads',
			'other',
			'database',
			'persistence',
		];

		$this->run( $sections, $assoc_args );
	}

	/**
	 * Scan plugins and plugin integrity only.
	 *
	 * @when before_wp_load
	 */
	public function plugins( $args, $assoc_args ) {
		$this->run( [ 'plugin_checksums', 'plugins', 'mu_plugins' ], $assoc_args );
	}

	/**
	 * Scan themes only.
	 *
	 * @when before_wp_load
	 */
	public function themes( $args, $assoc_args ) {
		$this->run( [ 'themes' ], $assoc_args );
	}

	/**
	 * Scan uploads only.
	 *
	 * @when before_wp_load
	 */
	public function uploads( $args, $assoc_args ) {
		$this->run( [ 'uploads' ], $assoc_args );
	}

	/**
	 * Scan database content only.
	 *
	 * @when before_wp_load
	 */
	public function database( $args, $assoc_args ) {
		$this->run( [ 'database', 'persistence' ], $assoc_args );
	}

	/**
	 * Verify WordPress core checksums.
	 *
	 * @when before_wp_load
	 */
	public function core( $args, $assoc_args ) {
		$this->run( [ 'core' ], $assoc_args );
	}

	/**
	 * Show package version.
	 *
	 * @when before_wp_load
	 */
	public function version() {
		\WP_CLI::log( 'WP-CLI Security Scan ' . self::VERSION );
	}

	/**
	 * Run selected scan stages.
	 *
	 * @param array $sections   Sections to scan.
	 * @param array $assoc_args CLI arguments.
	 */
	private function run( array $sections, array $assoc_args ) {
		$this->reset_state();
		$this->configure_output( $assoc_args );
		$this->include_node_modules = isset( $assoc_args['include-node-modules'] );
		$this->suppress_wordpress_debug();
		$this->start_time = microtime( true );

		if ( $this->interactive ) {
			$this->start_background_spinner( 'Security Scan — loading WordPress...' );
		}

		try {
			\WP_CLI::get_runner()->load_wordpress();
		} finally {
			$this->stop_background_spinner();
		}

		if ( $this->interactive ) {
			$this->render_spinner( 'Security Scan — preparing rules...' );
		}

		$this->load_rules();
		$this->initialize_plugin_integrity_inventory();

		$skip_core = isset( $assoc_args['skip-core-checksums'] );
		$skip_plugin_checksums = isset( $assoc_args['skip-plugin-checksums'] );

		if ( $this->interactive ) {
			$this->clear_spinner();
			\WP_CLI::log( '' );
			\WP_CLI::log( 'Security Scan' );
			\WP_CLI::log( str_repeat( '─', 40 ) );
		}

		foreach ( $sections as $section ) {
			switch ( $section ) {
				case 'core':
					if ( ! $skip_core ) {
						$this->scan_core_checksums();
					}
					break;

				case 'plugin_checksums':
					if ( ! $skip_plugin_checksums ) {
						$this->scan_plugin_checksums();
					}
					break;

				case 'plugins':
					$this->scan_directory_stage( 'Plugins', WP_PLUGIN_DIR, false );
					break;

				case 'mu_plugins':
					$this->scan_mu_plugins_and_dropins();
					break;

				case 'themes':
					$this->scan_directory_stage( 'Themes', get_theme_root(), false );
					break;

				case 'uploads':
					$upload_dir = wp_upload_dir();
					$this->scan_directory_stage( 'Uploads', $upload_dir['basedir'], true );
					break;

				case 'other':
					$this->scan_other_wp_content();
					break;

				case 'database':
					$this->scan_database();
					break;

				case 'persistence':
					$this->scan_users_and_persistence();
					break;
			}
		}

		$this->finalize_report( $assoc_args );
	}

	/**
	 * Reset per-run state.
	 */
	private function reset_state() {
		$this->rules = [];
		$this->findings = [];
		$this->stage_stats = [];
		$this->scanned_files = 0;
		$this->scanned_db_rows = 0;
		$this->spinner_index = 0;
		$this->last_spinner_at = 0.0;
		$this->current_stage = '';
		$this->admin_count = 0;
		$this->modification_clusters = [];
		$this->include_node_modules = false;
		$this->php_data_flow_analyzer = null;
		$this->plugin_integrity = [];
	}

	/**
	 * Disable WordPress debug mode for the lifetime of this scan process.
	 *
	 * The command runs before WordPress is loaded, so defining these constants
	 * here prevents wp-config.php debug settings from enabling display/logging
	 * during the diagnostic run. Nothing is written back to wp-config.php.
	 */
	private function suppress_wordpress_debug() {
		@ini_set( 'display_errors', '0' );
		@ini_set( 'display_startup_errors', '0' );
		error_reporting( 0 );

		if ( ! defined( 'WP_DEBUG' ) ) {
			define( 'WP_DEBUG', false );
		}

		if ( ! defined( 'WP_DEBUG_DISPLAY' ) ) {
			define( 'WP_DEBUG_DISPLAY', false );
		}

		if ( ! defined( 'WP_DEBUG_LOG' ) ) {
			define( 'WP_DEBUG_LOG', false );
		}
	}

	/**
	 * Configure terminal/export output.
	 *
	 * @param array $assoc_args CLI arguments.
	 */
	private function configure_output( array $assoc_args ) {
		$format = isset( $assoc_args['format'] ) ? strtolower( (string) $assoc_args['format'] ) : 'table';

		if ( ! in_array( $format, [ 'table', 'json', 'markdown' ], true ) ) {
			\WP_CLI::error( 'Invalid --format. Use table, json, or markdown.' );
		}

		$this->format = $format;
		$this->interactive = 'table' === $format && ! isset( $assoc_args['output'] );
	}

	/**
	 * Load JSON rules.
	 */
	private function load_rules() {
		$base = dirname( __DIR__ ) . DIRECTORY_SEPARATOR . 'rules';

		foreach ( [ 'iocs', 'php', 'javascript', 'database' ] as $name ) {
			$path = $base . DIRECTORY_SEPARATOR . $name . '.json';
			$data = json_decode( (string) file_get_contents( $path ), true );

			if ( ! is_array( $data ) || ! isset( $data['rules'] ) || ! is_array( $data['rules'] ) ) {
				\WP_CLI::error( 'Invalid rule file: ' . $path );
			}

			$this->rules[ $name ] = $data['rules'];
		}

		$ioc_needles = [];
		foreach ( $this->rules['iocs'] as $rule ) {
			if ( isset( $rule['needle'] ) && '' !== trim( (string) $rule['needle'] ) ) {
				$ioc_needles[] = (string) $rule['needle'];
			}
		}

		$this->php_data_flow_analyzer = new Security_Scan_Php_Data_Flow_Analyzer( $ioc_needles );
	}

	/**
	 * Run a WP-CLI subcommand while keeping the terminal spinner alive.
	 *
	 * Falls back to WP_CLI::runcommand() when proc_open() is unavailable.
	 */
	private function run_wp_cli_process( $command, $spinner_message ) {
		if ( ! $this->interactive || ! function_exists( 'proc_open' ) ) {
			return \WP_CLI::runcommand(
				$command,
				[
					'return'     => 'all',
					'exit_error' => false,
					'launch'     => true,
				]
			);
		}

		$stdout_file = tempnam( sys_get_temp_dir(), 'wpsec-out-' );
		$stderr_file = tempnam( sys_get_temp_dir(), 'wpsec-err-' );

		if ( false === $stdout_file || false === $stderr_file ) {
			if ( is_string( $stdout_file ) ) {
				@unlink( $stdout_file );
			}
			if ( is_string( $stderr_file ) ) {
				@unlink( $stderr_file );
			}

			return \WP_CLI::runcommand(
				$command,
				[
					'return'     => 'all',
					'exit_error' => false,
					'launch'     => true,
				]
			);
		}

		$process_command = $this->build_wp_cli_process_command( $command );

		if ( $this->interactive ) {
			$this->render_spinner( $spinner_message . ' 0:00' );
		}

		$descriptor_spec = [
			0 => [ 'pipe', 'r' ],
			1 => [ 'file', $stdout_file, 'w' ],
			2 => [ 'file', $stderr_file, 'w' ],
		];
		$pipes = [];
		$process = @proc_open( $process_command, $descriptor_spec, $pipes, ABSPATH );

		if ( ! is_resource( $process ) ) {
			@unlink( $stdout_file );
			@unlink( $stderr_file );

			return \WP_CLI::runcommand(
				$command,
				[
					'return'     => 'all',
					'exit_error' => false,
					'launch'     => true,
				]
			);
		}

		if ( isset( $pipes[0] ) && is_resource( $pipes[0] ) ) {
			fclose( $pipes[0] );
		}

		$exit_code = null;
		$started_at = microtime( true );

		while ( true ) {
			$status = proc_get_status( $process );
			$elapsed = max( 0, (int) floor( microtime( true ) - $started_at ) );
			$this->render_spinner( $spinner_message . ' ' . $this->format_elapsed_short( $elapsed ) );

			if ( ! $status['running'] ) {
				if ( isset( $status['exitcode'] ) && $status['exitcode'] >= 0 ) {
					$exit_code = (int) $status['exitcode'];
				}
				break;
			}

			usleep( 80000 );
		}

		$close_code = proc_close( $process );
		if ( null === $exit_code || $exit_code < 0 ) {
			$exit_code = (int) $close_code;
		}

		$stdout = (string) @file_get_contents( $stdout_file );
		$stderr = (string) @file_get_contents( $stderr_file );
		@unlink( $stdout_file );
		@unlink( $stderr_file );

		return (object) [
			'return_code' => $exit_code,
			'stdout'      => $stdout,
			'stderr'      => $stderr,
		];
	}

	/**
	 * Build a command for a separate WP-CLI process.
	 */
	private function build_wp_cli_process_command( $command ) {
		$prefix = 'wp';
		$phar = class_exists( 'Phar' ) ? \Phar::running( false ) : '';

		if ( is_string( $phar ) && '' !== $phar ) {
			$prefix = escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $phar );
		} elseif ( isset( $_SERVER['argv'][0] ) && is_file( $_SERVER['argv'][0] ) ) {
			$argv_zero = (string) $_SERVER['argv'][0];
			if ( preg_match( '~\.(?:phar|php)$~i', $argv_zero ) ) {
				$prefix = escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $argv_zero );
			}
		}

		return $prefix . ' --path=' . escapeshellarg( ABSPATH ) . ' --no-color ' . $command;
	}

	/**
	 * Format a short elapsed timer for long-running subprocess stages.
	 */
	private function format_elapsed_short( $seconds ) {
		$minutes = (int) floor( $seconds / 60 );
		$seconds = $seconds % 60;
		return sprintf( '%d:%02d', $minutes, $seconds );
	}


	/**
	 * Verify WordPress core checksums.
	 */
	private function scan_core_checksums() {
		$stage = 'Core checksums';
		$this->stage_start( $stage );

		try {
			$result = $this->run_wp_cli_process(
				'core verify-checksums',
				'Scanning core checksums...'
			);

			$return_code = isset( $result->return_code ) ? (int) $result->return_code : 1;
			$output = trim( (string) ( $result->stdout ?? '' ) . "\n" . (string) ( $result->stderr ?? '' ) );

			if ( 0 !== $return_code ) {
				$matched = false;
				foreach ( preg_split( '/\\R+/', $output ) as $line ) {
					$line = $this->strip_wp_cli_prefix( trim( $line ) );
					if ( preg_match( "~^(File doesn\\'t verify against checksum|File should not exist):\\s*(.+)$~i", $line, $matches ) ) {
						$matched = true;
						$this->add_finding( $stage, 'high', 96, $matches[2], 'core_checksum_mismatch', $matches[1] );
					}
				}

				if ( ! $matched ) {
					$this->add_finding( $stage, 'high', 90, 'WordPress core', 'core_checksum_failed', 'WordPress core checksum verification failed' );
				}
			}

			$this->checksum_stage_finish( $stage, $this->count_stage_findings( $stage ) );
		} catch ( \Throwable $e ) {
			$this->add_finding( $stage, 'medium', 70, 'WordPress core', 'core_checksum_error', 'Core checksum command could not complete: ' . $e->getMessage() );
			$this->checksum_stage_finish( $stage, $this->count_stage_findings( $stage ) );
		}
	}

	/**
	 * Verify WordPress.org plugin checksums.
	 */
	private function scan_plugin_checksums() {
		$stage = 'Plugin integrity';
		$this->stage_start( $stage );

		try {
			$result = $this->run_wp_cli_process(
				'plugin verify-checksums --all --strict --format=json',
				'Scanning plugin integrity...'
			);

			$stdout = (string) ( $result->stdout ?? '' );
			$stderr = (string) ( $result->stderr ?? '' );
			$output = trim( $stdout . "\n" . $stderr );
			$checksum_errors = $this->parse_plugin_checksum_json( $stdout );
			$recognized_problem = false;

			foreach ( $checksum_errors as $error ) {
				$plugin = isset( $error['plugin_name'] ) ? sanitize_key( (string) $error['plugin_name'] ) : '';
				$file = isset( $error['file'] ) ? ltrim( str_replace( '\\', '/', (string) $error['file'] ), '/' ) : '';
				$message = isset( $error['message'] ) ? (string) $error['message'] : 'Checksum verification failed';

				if ( '' === $plugin ) {
					continue;
				}

				$recognized_problem = true;
				$is_regular_plugin = $this->ensure_regular_plugin_integrity_entry( $plugin );
				if ( $is_regular_plugin ) {
					$this->set_plugin_integrity_status( $plugin, 'modified' );
					$this->plugin_integrity[ $plugin ]['checksum_errors'][] = [
						'file'    => $file,
						'message' => $message,
					];
				}

				$location = ( $is_regular_plugin ? 'plugins/' : 'mu-plugins/' ) . $plugin;
				if ( '' !== $file ) {
					$location .= '/' . $file;
				}

				$this->add_finding(
					$stage,
					'high',
					98,
					$location,
					'plugin_checksum_mismatch',
					$message
				);
			}

			$recognized_problem = $this->parse_plugin_checksum_warnings( $output, $stage ) || $recognized_problem;

			$return_code = isset( $result->return_code ) ? (int) $result->return_code : 1;
			if ( 0 !== $return_code && ! $recognized_problem && empty( $checksum_errors ) ) {
				$this->add_finding(
					$stage,
					'low',
					45,
					'Plugins',
					'plugin_checksum_error',
					'Plugin checksum verification could not be classified; affected plugins remain unverified.'
				);
			} else {
				$this->mark_remaining_plugins_verified();
			}

			$this->scan_verified_plugin_repository_risk();
			$this->plugin_checksum_stage_finish( $stage );
		} catch ( \Throwable $e ) {
			$this->add_finding( $stage, 'low', 45, 'Plugins', 'plugin_checksum_error', 'Plugin checksum verification could not complete: ' . $e->getMessage() );
			$this->plugin_checksum_stage_finish( $stage );
		}
	}

	/**
	 * Build the installed regular-plugin inventory before checksum scanning.
	 */
	private function initialize_plugin_integrity_inventory() {
		if ( ! function_exists( 'get_plugins' ) && defined( 'ABSPATH' ) ) {
			$plugin_file = ABSPATH . 'wp-admin/includes/plugin.php';
			if ( is_file( $plugin_file ) ) {
				require_once $plugin_file;
			}
		}

		if ( ! function_exists( 'get_plugins' ) ) {
			return;
		}

		foreach ( get_plugins() as $file => $data ) {
			$slug = $this->plugin_slug_from_main_file( $file );
			if ( '' === $slug ) {
				continue;
			}

			$this->plugin_integrity[ $slug ] = [
				'slug'              => $slug,
				'name'              => isset( $data['Name'] ) ? (string) $data['Name'] : $slug,
				'version'           => isset( $data['Version'] ) ? (string) $data['Version'] : '',
				'file'              => str_replace( '\\', '/', (string) $file ),
				'status'            => 'unverified',
				'checksum_errors'   => [],
				'repository_status' => 'unknown',
			];
		}
	}

	/**
	 * Extract the WordPress plugin slug from a main plugin file path.
	 */
	private function plugin_slug_from_main_file( $file ) {
		$file = trim( str_replace( '\\', '/', (string) $file ), '/' );
		if ( '' === $file ) {
			return '';
		}

		if ( false !== strpos( $file, '/' ) ) {
			return sanitize_key( dirname( $file ) );
		}

		return sanitize_key( pathinfo( $file, PATHINFO_FILENAME ) );
	}


	/**
	 * Ensure a filesystem plugin directory/file is represented in integrity state.
	 *
	 * WP-CLI checksum verification can discover plugin directories whose headers
	 * are missing or damaged and therefore are absent from get_plugins().
	 */
	private function ensure_regular_plugin_integrity_entry( $plugin ) {
		$plugin = sanitize_key( (string) $plugin );
		if ( '' === $plugin ) {
			return false;
		}

		if ( isset( $this->plugin_integrity[ $plugin ] ) ) {
			return true;
		}

		$directory = defined( 'WP_PLUGIN_DIR' ) ? WP_PLUGIN_DIR . DIRECTORY_SEPARATOR . $plugin : '';
		$single_file = defined( 'WP_PLUGIN_DIR' ) ? WP_PLUGIN_DIR . DIRECTORY_SEPARATOR . $plugin . '.php' : '';
		if ( ( '' === $directory || ! is_dir( $directory ) ) && ( '' === $single_file || ! is_file( $single_file ) ) ) {
			return false;
		}

		$this->plugin_integrity[ $plugin ] = [
			'slug'              => $plugin,
			'name'              => $plugin,
			'version'           => '',
			'file'              => is_file( $single_file ) ? $plugin . '.php' : $plugin,
			'status'            => 'unverified',
			'checksum_errors'   => [],
			'repository_status' => 'unknown',
		];

		return true;
	}

	/**
	 * Decode the structured checksum errors printed by WP-CLI.
	 */
	private function parse_plugin_checksum_json( $output ) {
		$output = trim( (string) $output );
		if ( '' === $output ) {
			return [];
		}

		$start = strpos( $output, '[' );
		$end = strrpos( $output, ']' );
		if ( false === $start || false === $end || $end < $start ) {
			return [];
		}

		$data = json_decode( substr( $output, $start, $end - $start + 1 ), true );
		return is_array( $data ) ? $data : [];
	}

	/**
	 * Parse checksum warnings that represent unavailable or incomplete verification.
	 */
	private function parse_plugin_checksum_warnings( $output, $stage ) {
		$recognized = false;

		foreach ( preg_split( '/\\R+/', (string) $output ) as $line ) {
			$line = $this->strip_wp_cli_prefix( trim( $line ) );
			if ( '' === $line ) {
				continue;
			}

			if ( preg_match( '/Could not retrieve the checksums for version .*? of plugin ([a-z0-9._-]+), skipping\\.?/i', $line, $matches ) ) {
				$recognized = true;
				$plugin = sanitize_key( $matches[1] );
				if ( $this->ensure_regular_plugin_integrity_entry( $plugin ) ) {
					$this->set_plugin_integrity_status( $plugin, 'unavailable' );
				}
				continue;
			}

			if ( preg_match( '/Could not retrieve the version for plugin ([a-z0-9._-]+), skipping\\.?/i', $line, $matches ) ) {
				$recognized = true;
				$plugin = sanitize_key( $matches[1] );
				if ( $this->ensure_regular_plugin_integrity_entry( $plugin ) ) {
					$this->set_plugin_integrity_status( $plugin, 'unavailable' );
				}
				continue;
			}

			if ( preg_match( '/Plugin ([a-z0-9._-]+) main file is missing:\\s*(.+)$/i', $line, $matches ) ) {
				$recognized = true;
				$plugin = sanitize_key( $matches[1] );
				$this->ensure_regular_plugin_integrity_entry( $plugin );
				$this->set_plugin_integrity_status( $plugin, 'modified' );
				$this->add_finding(
					$stage,
					'high',
					98,
					'plugins/' . $plugin . '/' . ltrim( str_replace( '\\', '/', $matches[2] ), '/' ),
					'plugin_checksum_missing_main_file',
					'Plugin main file is missing'
				);
			}
		}

		return $recognized;
	}

	/**
	 * Update a plugin integrity status without downgrading a stronger state.
	 */
	private function set_plugin_integrity_status( $plugin, $status ) {
		$plugin = sanitize_key( (string) $plugin );
		if ( '' === $plugin || ! isset( $this->plugin_integrity[ $plugin ] ) ) {
			return;
		}

		$priority = [
			'unverified'  => 0,
			'verified'    => 1,
			'unavailable' => 2,
			'modified'    => 3,
		];
		$current = $this->plugin_integrity[ $plugin ]['status'];
		if ( ( $priority[ $status ] ?? 0 ) >= ( $priority[ $current ] ?? 0 ) ) {
			$this->plugin_integrity[ $plugin ]['status'] = $status;
		}
	}

	/**
	 * Plugins that produced neither checksum errors nor skip warnings verified successfully.
	 */
	private function mark_remaining_plugins_verified() {
		foreach ( $this->plugin_integrity as $slug => $data ) {
			if ( 'unverified' === $data['status'] ) {
				$this->plugin_integrity[ $slug ]['status'] = 'verified';
			}
		}
	}

	/**
	 * Check repository-level risk for verified WordPress.org plugins.
	 *
	 * This is deliberately separate from static malware heuristics: a checksum
	 * match proves local integrity, but a plugin can still be closed/disabled
	 * upstream and require security review.
	 */
	private function scan_verified_plugin_repository_risk() {
		if ( ! function_exists( 'wp_remote_get' ) ) {
			return;
		}

		$verified = array_keys(
			array_filter(
				$this->plugin_integrity,
				static function ( $data ) {
					return isset( $data['status'] ) && 'verified' === $data['status'];
				}
			)
		);
		$total = count( $verified );

		foreach ( $verified as $index => $slug ) {
			if ( $this->interactive ) {
				$this->render_spinner(
					sprintf( 'Checking plugin repository status... %d/%d', $index + 1, $total )
				);
			}

			$url = 'https://api.wordpress.org/plugins/info/1.2/?' . http_build_query(
				[
					'action'  => 'plugin_information',
					'request' => [
						'slug'   => $slug,
						'fields' => [
							'sections' => false,
							'banners'  => false,
							'icons'    => false,
						],
					],
				]
			);

			$response = wp_remote_get( $url, [ 'timeout' => 10 ] );
			if ( is_wp_error( $response ) ) {
				continue;
			}

			$body = json_decode( (string) wp_remote_retrieve_body( $response ), true );
			if ( ! is_array( $body ) || empty( $body['error'] ) ) {
				$this->plugin_integrity[ $slug ]['repository_status'] = 'available';
				continue;
			}

			$error = strtolower( (string) $body['error'] );
			if ( ! in_array( $error, [ 'closed', 'disabled' ], true ) ) {
				continue;
			}

			$this->plugin_integrity[ $slug ]['repository_status'] = $error;
			$context = strtolower(
				implode(
					' ',
					array_filter(
						[
							(string) ( $body['reason'] ?? '' ),
							(string) ( $body['description'] ?? '' ),
							(string) ( $body['message'] ?? '' ),
						]
					)
				)
			);
			$security_related = false !== strpos( $context, 'security' );
			$severity = $security_related ? 'high' : 'medium';
			$confidence = $security_related ? 94 : 82;
			$description = $security_related
				? 'Plugin is closed/disabled on WordPress.org for a security-related reason'
				: 'Plugin is closed or disabled on WordPress.org and requires review';

			$this->add_finding(
				'Plugins',
				$severity,
				$confidence,
				'plugins/' . $slug,
				'plugin_reputation_repository_' . $error,
				$description
			);
		}
	}

	/**
	 * Finish plugin integrity with status counts rather than a misleading file count.
	 */
	private function plugin_checksum_stage_finish( $stage ) {
		$counts = [
			'verified'    => 0,
			'modified'    => 0,
			'unavailable' => 0,
			'unverified'  => 0,
		];

		foreach ( $this->plugin_integrity as $data ) {
			$status = isset( $data['status'] ) ? $data['status'] : 'unverified';
			if ( isset( $counts[ $status ] ) ) {
				$counts[ $status ]++;
			}
		}

		$findings = $this->count_stage_findings( $stage );
		if ( isset( $this->stage_stats[ $stage ] ) ) {
			$this->stage_stats[ $stage ]['items'] = null;
			$this->stage_stats[ $stage ]['findings'] = $findings;
			$this->stage_stats[ $stage ]['verified_plugins'] = $counts['verified'];
			$this->stage_stats[ $stage ]['modified_plugins'] = $counts['modified'];
			$this->stage_stats[ $stage ]['unavailable_plugins'] = $counts['unavailable'];
			$this->stage_stats[ $stage ]['unverified_plugins'] = $counts['unverified'];
		}

		if ( ! $this->interactive ) {
			return;
		}

		$this->clear_spinner();
		$parts = [];
		if ( $counts['verified'] > 0 ) {
			$parts[] = $counts['verified'] . ' verified';
		}
		if ( $counts['unavailable'] > 0 ) {
			$parts[] = $counts['unavailable'] . ' unavailable';
		}
		if ( $counts['unverified'] > 0 ) {
			$parts[] = $counts['unverified'] . ' unverified';
		}
		if ( $counts['modified'] > 0 ) {
			$parts[] = $counts['modified'] . ' modified';
		}
		$status_text = empty( $parts ) ? 'no plugins detected' : implode( ', ', $parts );

		if ( 0 === $findings && 0 === $counts['modified'] ) {
			\WP_CLI::log( '✓ ' . $stage . ' completed — ' . $status_text . ', no integrity mismatches found' );
			return;
		}

		\WP_CLI::log( '⚠ ' . $stage . ' completed — ' . $status_text . ', ' . $findings . ' integrity issue' . ( 1 === $findings ? '' : 's' ) . ' found' );
	}

	/**
	 * Create a recursive iterator for security scans.
	 *
	 * node_modules is intentionally skipped by default because production
	 * WordPress does not require it and bundled dependencies create a large
	 * amount of low-value scan noise.
	 */
	private function create_scan_iterator( $directory ) {
		$directory_iterator = new \RecursiveDirectoryIterator( $directory, \FilesystemIterator::SKIP_DOTS );
		$filter = new \RecursiveCallbackFilterIterator(
			$directory_iterator,
			function ( $current ) {
				if ( $current->isDir() && ! $current->isLink() ) {
					$name = strtolower( $current->getFilename() );

					if ( '.drone-backups' === $name ) {
						return false;
					}

					if ( ! $this->include_node_modules && 'node_modules' === $name ) {
						return false;
					}
				}

				return true;
			}
		);

		return new \RecursiveIteratorIterator( $filter, \RecursiveIteratorIterator::SELF_FIRST );
	}

	/**
	 * Scan a directory tree.
	 *
	 * @param string $stage      Stage label.
	 * @param string $directory  Directory path.
	 * @param bool   $is_uploads Whether uploads-specific rules apply.
	 */
	private function scan_directory_stage( $stage, $directory, $is_uploads ) {
		$this->stage_start( $stage );
		$count = 0;

		if ( ! is_dir( $directory ) ) {
			$this->stage_finish( $stage, 0, 0 );
			return;
		}

		$iterator = $this->create_scan_iterator( $directory );

		foreach ( $iterator as $item ) {
			$path = $item->getPathname();

			if ( $item->isLink() ) {
				$this->scan_symlink( $stage, $path );
				continue;
			}

			if ( ! $item->isFile() ) {
				continue;
			}

			$count++;
			$this->scanned_files++;
			$this->stage_tick( $stage, $count, 'files' );
			$this->scan_file( $stage, $path, $is_uploads );
		}

		$stage_findings = 'Plugins' === $stage
			? $this->count_reportable_plugin_findings()
			: $this->count_stage_findings( $stage );

		$this->stage_finish( $stage, $count, $stage_findings );
	}

	/**
	 * Scan MU plugins and wp-content drop-ins.
	 */
	private function scan_mu_plugins_and_dropins() {
		$stage = 'MU plugins & drop-ins';
		$this->stage_start( $stage );
		$count = 0;

		if ( defined( 'WPMU_PLUGIN_DIR' ) && is_dir( WPMU_PLUGIN_DIR ) ) {
			$iterator = $this->create_scan_iterator( WPMU_PLUGIN_DIR );

			foreach ( $iterator as $item ) {
				if ( ! $item->isFile() || $item->isLink() ) {
					continue;
				}

				$count++;
				$this->scanned_files++;
				$this->stage_tick( $stage, $count, 'files' );
				$this->scan_file( $stage, $item->getPathname(), false );
			}
		}

		foreach ( self::DROPIN_FILES as $filename ) {
			$path = WP_CONTENT_DIR . DIRECTORY_SEPARATOR . $filename;
			if ( ! is_file( $path ) ) {
				continue;
			}

			$count++;
			$this->scanned_files++;
			$this->stage_tick( $stage, $count, 'files' );
			$this->scan_file( $stage, $path, false );
		}

		$this->stage_finish( $stage, $count, $this->count_stage_findings( $stage ) );
	}

	/**
	 * Scan everything directly under wp-content that is not covered by a dedicated stage.
	 */
	private function scan_other_wp_content() {
		$stage = 'Other wp-content';
		$this->stage_start( $stage );
		$count = 0;
		$excluded = [];

		$upload_dir = wp_upload_dir();
		$known_dirs = [
			WP_PLUGIN_DIR,
			get_theme_root(),
			$upload_dir['basedir'],
		];

		if ( defined( 'WPMU_PLUGIN_DIR' ) ) {
			$known_dirs[] = WPMU_PLUGIN_DIR;
		}

		foreach ( $known_dirs as $dir ) {
			$excluded[] = $this->normalize_path( $dir );
		}

		$top = new \DirectoryIterator( WP_CONTENT_DIR );
		foreach ( $top as $item ) {
			if ( $item->isDot() ) {
				continue;
			}

			$path = $item->getPathname();
			$normalized = $this->normalize_path( $path );

			if ( in_array( $normalized, $excluded, true ) ) {
				continue;
			}

			if ( $item->isFile() ) {
				if ( in_array( $item->getFilename(), self::DROPIN_FILES, true ) ) {
					continue;
				}

				$count++;
				$this->scanned_files++;
				$this->stage_tick( $stage, $count, 'files' );
				$this->scan_file( $stage, $path, false );
				continue;
			}

			if ( ! $item->isDir() || $item->isLink() ) {
				continue;
			}

			if ( ! $this->include_node_modules && 'node_modules' === strtolower( $item->getFilename() ) ) {
				continue;
			}

			$iterator = $this->create_scan_iterator( $path );

			foreach ( $iterator as $child ) {
				if ( ! $child->isFile() || $child->isLink() ) {
					continue;
				}

				$count++;
				$this->scanned_files++;
				$this->stage_tick( $stage, $count, 'files' );
				$this->scan_file( $stage, $child->getPathname(), false );
			}
		}

		$this->stage_finish( $stage, $count, $this->count_stage_findings( $stage ) );
	}

	/**
	 * Scan a single file using streaming chunks.
	 *
	 * @param string $stage      Stage label.
	 * @param string $path       File path.
	 * @param bool   $is_uploads Whether uploads-specific rules apply.
	 */
	private function scan_file( $stage, $path, $is_uploads ) {
		$extension = strtolower( pathinfo( $path, PATHINFO_EXTENSION ) );
		$relative = $this->relative_wp_content_path( $path );
		$seen = [];

		// Database dumps, source maps and compressed archives are not executable
		// by WordPress/PHP. Scanning their raw bytes creates false positives from
		// historical malware strings, bundled source text and archive metadata.
		// Executable files placed alongside them are still scanned normally.
		if ( in_array( $extension, self::NON_EXECUTABLE_DATA_EXTENSIONS, true ) ) {
			return;
		}

		$this->scan_filename_and_location( $stage, $path, $relative, $extension, $is_uploads, $seen );

		if ( in_array( $extension, self::PHP_EXTENSIONS, true ) ) {
			$this->scan_php_data_flow_file( $stage, $path, $relative, $seen );
		}

		$handle = @fopen( $path, 'rb' );
		if ( false === $handle ) {
			$this->add_finding( $stage, 'low', 45, $relative, 'file_unreadable', 'File could not be read during the scan' );
			return;
		}

		$overlap = '';
		$line_at_chunk_start = 1;

		while ( ! feof( $handle ) ) {
			$chunk = fread( $handle, self::FILE_CHUNK_SIZE );
			if ( false === $chunk || '' === $chunk ) {
				break;
			}

			$buffer = $overlap . $chunk;
			$buffer_start_line = max( 1, $line_at_chunk_start - substr_count( $overlap, "\n" ) );
			$this->scan_file_buffer( $stage, $relative, $extension, $buffer, $is_uploads, $seen, $buffer_start_line );
			$overlap = substr( $buffer, -self::FILE_CHUNK_OVERLAP );
			$line_at_chunk_start += substr_count( $chunk, "\n" );
			$this->stage_heartbeat( $stage, 'files' );
		}

		fclose( $handle );
	}

	/**
	 * Apply filename/location rules.
	 */
	private function scan_filename_and_location( $stage, $path, $relative, $extension, $is_uploads, array &$seen ) {
		$filename = basename( $path );
		$lower_filename = strtolower( $filename );

		$known_malicious_filenames = [
			'wp-antymalwary-bot.php' => 'Known malicious fake WordPress plugin filename',
			'wp-apx-upx.php'        => 'Known malicious compact WordPress file-uploader filename',
			'wp-apxupx.php'         => 'Known malicious compact WordPress file-uploader filename',
		];

		if ( isset( $known_malicious_filenames[ $lower_filename ] ) ) {
			$this->add_file_finding_once( $seen, $stage, 'critical', 98, $relative, 'known_malicious_filename', $known_malicious_filenames[ $lower_filename ] );
		}

		if ( $is_uploads && in_array( $extension, self::UPLOAD_EXECUTABLE_EXTENSIONS, true ) ) {
			$this->add_file_finding_once( $seen, $stage, 'high', 96, $relative, 'uploads_executable', 'Executable/script file found inside uploads' );
		}

		if ( preg_match( '~\.(?:jpe?g|png|gif|webp|svg|ico|pdf|zip)\.(?:php\d*|phtml|phar)$~i', $filename ) ) {
			$this->add_file_finding_once( $seen, $stage, 'critical', 99, $relative, 'double_extension', 'Suspicious media/document + executable double extension' );
		}

		if ( preg_match( '~\.php\.(?:bak|old|orig|save|txt|disabled)$~i', $filename ) ) {
			$this->add_file_finding_once( $seen, $stage, 'medium', 70, $relative, 'php_backup_file', 'Backup copy of a PHP file requires review' );
		}

		if ( in_array( strtolower( $filename ), [ '.user.ini', 'php.ini' ], true ) ) {
			$content = @file_get_contents( $path );
			$matches = [];
			if ( is_string( $content ) && 1 === preg_match( '~auto_(?:prepend|append)_file\s*=~i', $content, $matches, PREG_OFFSET_CAPTURE ) ) {
				$line = $this->line_from_buffer_offset( $content, 1, $matches[0][1] );
				$this->add_file_finding_once( $seen, $stage, 'critical', 98, $relative, 'php_auto_prepend', 'PHP auto_prepend/auto_append persistence directive found', $line );
			}
		}

		if ( '.htaccess' === strtolower( $filename ) ) {
			$content = @file_get_contents( $path );
			$matches = [];
			if ( is_string( $content ) && 1 === preg_match( '~(?:AddType|AddHandler|SetHandler)[^\r\n]*(?:php|x-httpd-php)~i', $content, $matches, PREG_OFFSET_CAPTURE ) ) {
				$line = $this->line_from_buffer_offset( $content, 1, $matches[0][1] );
				$this->add_file_finding_once( $seen, $stage, 'critical', 98, $relative, 'htaccess_php_handler', 'htaccess enables PHP execution for additional file types', $line );
			}
		}
	}

	/**
	 * Scan a file chunk.
	 */
	private function scan_file_buffer( $stage, $relative, $extension, $buffer, $is_uploads, array &$seen, $buffer_start_line ) {
		foreach ( $this->rules['iocs'] as $rule ) {
			$match_offset = stripos( $buffer, $rule['needle'] );
			if ( false !== $match_offset ) {
				$this->add_file_rule_once(
					$seen,
					$stage,
					$relative,
					$rule,
					$this->line_from_buffer_offset( $buffer, $buffer_start_line, $match_offset )
				);
			}
		}

		$is_php_extension = in_array( $extension, self::PHP_EXTENSIONS, true );
		$embedded_php = $is_php_extension ? null : $this->extract_validated_php_payload( $buffer );
		$has_embedded_php = null !== $embedded_php;
		$php_buffer = $is_php_extension ? $buffer : ( $has_embedded_php ? $embedded_php['content'] : null );
		$php_buffer_start_line = $buffer_start_line;

		if ( $has_embedded_php ) {
			$php_buffer_start_line = $this->line_from_buffer_offset( $buffer, $buffer_start_line, $embedded_php['offset'] );
		}

		if ( $has_embedded_php && in_array( $extension, self::NON_PHP_MEDIA_EXTENSIONS, true ) ) {
			if ( $is_uploads ) {
				$this->add_file_finding_once( $seen, $stage, 'critical', 99, $relative, 'uploads_embedded_php', 'PHP code embedded inside a non-PHP upload', $php_buffer_start_line );
			} elseif ( ! in_array( $extension, self::NON_EXECUTABLE_TEMPLATE_EXTENSIONS, true ) ) {
				$this->add_file_finding_once( $seen, $stage, 'high', 90, $relative, 'php_in_non_php', 'PHP code detected inside a non-PHP file', $php_buffer_start_line );
			}
		}

		if ( $is_php_extension || $has_embedded_php ) {
			$php_scan_buffer = null !== $php_buffer ? $php_buffer : $buffer;

			if ( $has_embedded_php ) {
				$this->scan_php_data_flow_buffer( $stage, $relative, $php_scan_buffer, $seen, $php_buffer_start_line );
			}

			foreach ( $this->rules['php'] as $rule ) {
				$matches = [];
				if ( 1 === @preg_match( $rule['regex'], $php_scan_buffer, $matches, PREG_OFFSET_CAPTURE ) ) {
					$line = $this->line_from_buffer_offset( $php_scan_buffer, $php_buffer_start_line, $matches[0][1] );
					$this->add_file_rule_once( $seen, $stage, $relative, $rule, $line );
				}
			}

			$this->scan_php_density_heuristics( $stage, $relative, $php_scan_buffer, $seen, $php_buffer_start_line );
		}

		$is_js = in_array( $extension, self::JS_EXTENSIONS, true ) || false !== stripos( $buffer, '<script' );
		if ( $is_js ) {
			foreach ( $this->rules['javascript'] as $rule ) {
				$matches = [];
				if ( 1 === @preg_match( $rule['regex'], $buffer, $matches, PREG_OFFSET_CAPTURE ) ) {
					$line = $this->line_from_buffer_offset( $buffer, $buffer_start_line, $matches[0][1] );
					$this->add_file_rule_once( $seen, $stage, $relative, $rule, $line );
				}
			}
		}
	}

	/**
	 * Run deeper token/data-flow analysis for a PHP file.
	 *
	 * Small/normal files are analyzed as one unit so variable state can be
	 * followed across the whole file. Very large PHP files are analyzed in
	 * overlapping windows to keep memory bounded while preserving coverage.
	 */
	private function scan_php_data_flow_file( $stage, $path, $relative, array &$seen ) {
		if ( ! $this->php_data_flow_analyzer instanceof Security_Scan_Php_Data_Flow_Analyzer ) {
			return;
		}

		$size = @filesize( $path );
		if ( false !== $size && $size <= self::DEEP_PHP_WHOLE_FILE_MAX ) {
			$content = @file_get_contents( $path );
			if ( is_string( $content ) ) {
				$this->scan_php_data_flow_buffer( $stage, $relative, $content, $seen, 1 );
			}
			return;
		}

		$handle = @fopen( $path, 'rb' );
		if ( false === $handle ) {
			return;
		}

		$overlap = '';
		$line_at_chunk_start = 1;
		while ( ! feof( $handle ) ) {
			$chunk = fread( $handle, self::DEEP_PHP_CHUNK_SIZE );
			if ( false === $chunk || '' === $chunk ) {
				break;
			}

			$buffer = $overlap . $chunk;
			$buffer_start_line = max( 1, $line_at_chunk_start - substr_count( $overlap, "\n" ) );
			$this->scan_php_data_flow_buffer( $stage, $relative, $buffer, $seen, $buffer_start_line );
			$overlap = substr( $buffer, -self::DEEP_PHP_CHUNK_OVERLAP );
			$line_at_chunk_start += substr_count( $chunk, "\n" );
			$this->stage_heartbeat( $stage, 'files' );
		}

		fclose( $handle );
	}

	/**
	 * Apply semantic PHP findings and suppress equivalent regex duplicates.
	 */
	private function scan_php_data_flow_buffer( $stage, $relative, $buffer, array &$seen, $base_line ) {
		if ( ! $this->php_data_flow_analyzer instanceof Security_Scan_Php_Data_Flow_Analyzer ) {
			return;
		}

		$aliases = [
			'dataflow_command_taint'            => [ 'php_command_input' ],
			'dataflow_obfuscated_command_taint' => [ 'php_command_input', 'php_long_base64_decoder' ],
			'dataflow_command_payload'          => [ 'php_command_input' ],
			'dataflow_eval_taint'               => [ 'php_eval_decode', 'php_decoded_variable_execute', 'php_stream_input_execute' ],
			'dataflow_eval_payload'             => [ 'php_eval_decode', 'php_decoded_variable_execute', 'php_stream_input_execute', 'php_decrypt_execute' ],
			'dataflow_code_taint'               => [ 'php_assert_input', 'php_dynamic_input_call', 'php_request_callback' ],
			'dataflow_obfuscated_code_taint'    => [ 'php_assert_input', 'php_dynamic_input_call', 'php_request_callback', 'php_long_base64_decoder' ],
			'dataflow_code_payload'             => [ 'php_decrypt_execute', 'php_decoded_variable_execute' ],
			'dataflow_include_taint'            => [ 'php_include_request', 'php_stream_input_execute' ],
			'dataflow_include_remote'           => [ 'php_remote_execute' ],
			'dataflow_tainted_dynamic_callback' => [ 'php_dynamic_input_call', 'php_request_callback', 'php_variable_variables' ],
			'dataflow_decoded_dynamic_callback' => [ 'php_dynamic_input_call', 'php_request_callback', 'php_variable_variables', 'php_long_base64_decoder' ],
			'dataflow_tainted_callback_sink'    => [ 'php_request_callback' ],
			'dataflow_dangerous_callback_sink'  => [ 'php_request_callback' ],
			'dataflow_remote_php_write'         => [ 'php_remote_write' ],
			'dataflow_tainted_php_write'        => [ 'php_request_file_write' ],
		];

		foreach ( $this->php_data_flow_analyzer->analyze( $buffer, $base_line ) as $finding ) {
			$this->add_file_finding_once(
				$seen,
				$stage,
				$finding['severity'],
				$finding['confidence'],
				$relative,
				$finding['rule'],
				$finding['description'],
				$finding['line']
			);

			$alias_rule = $finding['rule'];
			while ( 0 === strpos( $alias_rule, 'decoded_' ) ) {
				$alias_rule = substr( $alias_rule, 8 );
				$seen['php_long_base64_decoder'] = true;
			}

			if ( isset( $aliases[ $alias_rule ] ) ) {
				foreach ( $aliases[ $alias_rule ] as $alias ) {
					$seen[ $alias ] = true;
				}
			}
		}
	}

	/**
	 * Calculate a 1-based file line from a match offset inside the current buffer.
	 */
	private function line_from_buffer_offset( $buffer, $buffer_start_line, $offset ) {
		$offset = max( 0, (int) $offset );
		return $buffer_start_line + substr_count( substr( $buffer, 0, $offset ), "\n" );
	}

	/**
	 * Extract PHP from a non-PHP file only when the bytes around the open tag
	 * look like real text PHP rather than random compressed/binary data.
	 */
	private function extract_validated_php_payload( $buffer ) {
		$offsets = [];
		foreach ( [ '<?php', '<?=' ] as $tag ) {
			$offset = stripos( $buffer, $tag );
			if ( false !== $offset ) {
				$offsets[] = $offset;
			}
		}

		if ( empty( $offsets ) ) {
			return null;
		}

		sort( $offsets, SORT_NUMERIC );
		foreach ( $offsets as $offset ) {
			$candidate = substr( $buffer, $offset, 16384 );
			$close = strpos( $candidate, '?>' );
			$candidate = false !== $close ? substr( $candidate, 0, $close + 2 ) : substr( $candidate, 0, 2048 );

			if ( $this->looks_like_text_php( $candidate ) ) {
				return [
					'content' => $candidate,
					'offset'  => $offset,
				];
			}
		}

		return null;
	}

	/**
	 * Validate an embedded PHP candidate using printable-text density and tokens.
	 */
	private function looks_like_text_php( $candidate ) {
		$length = strlen( $candidate );
		if ( $length < 8 ) {
			return false;
		}

		$sample = substr( $candidate, 0, min( 1024, $length ) );
		$printable = preg_match_all( '/[\x09\x0A\x0D\x20-\x7E]/', $sample, $matches );
		if ( false === $printable || ( $printable / max( 1, strlen( $sample ) ) ) < 0.72 ) {
			return false;
		}

		$tokens = token_get_all( $candidate );
		$has_open_tag = false;
		$meaningful = 0;

		foreach ( $tokens as $token ) {
			if ( ! is_array( $token ) ) {
				if ( in_array( $token, [ ';', '(', ')', '{', '}', '=' ], true ) ) {
					$meaningful++;
				}
				continue;
			}

			if ( T_OPEN_TAG === $token[0] || ( defined( 'T_OPEN_TAG_WITH_ECHO' ) && T_OPEN_TAG_WITH_ECHO === $token[0] ) ) {
				$has_open_tag = true;
				continue;
			}

			if ( in_array( $token[0], [ T_VARIABLE, T_STRING, T_ECHO, T_FUNCTION, T_INCLUDE, T_INCLUDE_ONCE, T_REQUIRE, T_REQUIRE_ONCE ], true ) ) {
				$meaningful++;
			}
		}

		return $has_open_tag && $meaningful >= 2;
	}


	/**
	 * Apply code-density/obfuscation heuristics.
	 */
	private function scan_php_density_heuristics( $stage, $relative, $buffer, array &$seen, $buffer_start_line ) {
		$lower = strtolower( $buffer );

		$execution_tokens = [
			'eval(',
			'assert(',
			'shell_exec(',
			'passthru(',
			'proc_open(',
			'call_user_func(',
		];

		$obfuscation_tokens = [
			'base64_decode(',
			'gzinflate(',
			'gzuncompress(',
			'str_rot13(',
			'strrev(',
			'str_repeat(',
			'openssl_decrypt(',
		];

		$untrusted_tokens = [
			'php://input',
			'$_request',
			'$_post',
			'$_get',
			'$_cookie',
			'$globals',
		];

		$execution_count = $this->count_present_tokens( $lower, $execution_tokens );
		$obfuscation_count = $this->count_present_tokens( $lower, $obfuscation_tokens );
		$untrusted_count = $this->count_present_tokens( $lower, $untrusted_tokens );

		// Density is only a reportable heuristic when several independent
		// malware properties occur together. Common libraries legitimately use
		// crypto/encoding primitives, callbacks and request data in isolation.
		if ( $execution_count >= 1 && $obfuscation_count >= 2 && $untrusted_count >= 1 ) {
			$first_offset = $this->first_present_token_offset(
				$lower,
				array_merge( $execution_tokens, $obfuscation_tokens, $untrusted_tokens )
			);
			$line = null === $first_offset ? null : $this->line_from_buffer_offset( $buffer, $buffer_start_line, $first_offset );
			$this->add_file_finding_once( $seen, $stage, 'high', 88, $relative, 'dense_suspicious_php', 'Execution, obfuscation and untrusted-input primitives occur together', $line );
		}

		$long_line_matches = [];
		if ( $execution_count >= 1 && $obfuscation_count >= 1 && 1 === preg_match( '~[^\r\n]{20000,}~', $buffer, $long_line_matches, PREG_OFFSET_CAPTURE ) ) {
			$line = $this->line_from_buffer_offset( $buffer, $buffer_start_line, $long_line_matches[0][1] );
			$this->add_file_finding_once( $seen, $stage, 'high', 86, $relative, 'long_obfuscated_line', 'Very long PHP line combines obfuscation with an execution primitive', $line );
		}
	}

	/**
	 * Count distinct indicators present in a lower-cased PHP buffer.
	 */
	private function count_present_tokens( $buffer, array $tokens ) {
		$count = 0;
		foreach ( $tokens as $token ) {
			if ( false !== strpos( $buffer, $token ) ) {
				$count++;
			}
		}
		return $count;
	}

	/**
	 * Find the earliest offset for any indicator in a lower-cased buffer.
	 */
	private function first_present_token_offset( $buffer, array $tokens ) {
		$first = null;
		foreach ( $tokens as $token ) {
			$offset = strpos( $buffer, $token );
			if ( false !== $offset && ( null === $first || $offset < $first ) ) {
				$first = $offset;
			}
		}
		return $first;
	}

	/**
	 * Scan a symlink.
	 */
	private function scan_symlink( $stage, $path ) {
		$target = @realpath( $path );
		$relative = $this->relative_wp_content_path( $path );

		if ( false === $target ) {
			$this->add_finding( $stage, 'medium', 65, $relative, 'broken_symlink', 'Broken symlink inside wp-content' );
			return;
		}

		if ( 0 !== strpos( $this->normalize_path( $target ), $this->normalize_path( WP_CONTENT_DIR ) . '/' ) ) {
			$this->add_finding( $stage, 'high', 78, $relative, 'external_symlink', 'Symlink points outside wp-content: ' . $target );
		}
	}

	/**
	 * Scan database content tables in batches.
	 */
	private function scan_database() {
		global $wpdb;

		$stage = 'Database';
		$this->stage_start( $stage );

		$definitions = [
			[
				'table'   => $wpdb->posts,
				'pk'      => 'ID',
				'fields'  => [ 'post_content', 'post_excerpt' ],
				'context' => [ 'post_title', 'post_type' ],
			],
			[
				'table'   => $wpdb->postmeta,
				'pk'      => 'meta_id',
				'fields'  => [ 'meta_value' ],
				'context' => [ 'post_id', 'meta_key' ],
			],
			[
				'table'   => $wpdb->options,
				'pk'      => 'option_id',
				'fields'  => [ 'option_value' ],
				'context' => [ 'option_name' ],
			],
			[
				'table'   => $wpdb->comments,
				'pk'      => 'comment_ID',
				'fields'  => [ 'comment_content' ],
				'context' => [ 'comment_post_ID', 'comment_author' ],
			],
			[
				'table'   => $wpdb->commentmeta,
				'pk'      => 'meta_id',
				'fields'  => [ 'meta_value' ],
				'context' => [ 'comment_id', 'meta_key' ],
			],
			[
				'table'   => $wpdb->termmeta,
				'pk'      => 'meta_id',
				'fields'  => [ 'meta_value' ],
				'context' => [ 'term_id', 'meta_key' ],
			],
			[
				'table'   => $wpdb->usermeta,
				'pk'      => 'umeta_id',
				'fields'  => [ 'meta_value' ],
				'context' => [ 'user_id', 'meta_key' ],
			],
		];

		$total_rows = 0;

		foreach ( $definitions as $definition ) {
			if ( ! $this->database_table_exists( $definition['table'] ) ) {
				continue;
			}

			$total_rows += $this->scan_database_table( $stage, $definition );
		}

		$this->stage_finish( $stage, $total_rows, $this->count_stage_findings( $stage ), 'rows' );
	}

	/**
	 * Scan one database table with keyset pagination.
	 */
	private function scan_database_table( $stage, array $definition ) {
		global $wpdb;

		$table = $definition['table'];
		$pk = $definition['pk'];
		$columns = array_merge( [ $pk ], $definition['fields'], $definition['context'] );
		$columns = array_values( array_unique( $columns ) );
		$select = implode( ', ', array_map( [ $this, 'quote_identifier' ], $columns ) );
		$last_id = 0;
		$count = 0;

		while ( true ) {
			$sql = sprintf(
				'SELECT %s FROM %s WHERE %s > %%d ORDER BY %s ASC LIMIT %d',
				$select,
				$this->quote_identifier( $table ),
				$this->quote_identifier( $pk ),
				$this->quote_identifier( $pk ),
				self::DB_BATCH_SIZE
			);

			$rows = $wpdb->get_results( $wpdb->prepare( $sql, $last_id ), ARRAY_A );
			if ( empty( $rows ) ) {
				break;
			}

			foreach ( $rows as $row ) {
				$last_id = (int) $row[ $pk ];
				$count++;
				$this->scanned_db_rows++;

				foreach ( $definition['fields'] as $field ) {
					$value = isset( $row[ $field ] ) ? (string) $row[ $field ] : '';
					if ( '' === $value ) {
						continue;
					}

					$this->scan_database_value( $stage, $table, $pk, $row, $field, $value, $definition['context'] );
				}

				$this->stage_tick( $stage, $count, 'rows' );
			}
		}

		return $count;
	}

	/**
	 * Scan one database value.
	 */
	private function scan_database_value( $stage, $table, $pk, array $row, $field, $value, array $context_fields ) {
		$seen = [];
		$location = $this->database_location( $table, $pk, $row, $field, $context_fields );

		foreach ( $this->rules['iocs'] as $rule ) {
			if ( false !== stripos( $value, $rule['needle'] ) ) {
				$key = $rule['id'];
				if ( isset( $seen[ $key ] ) ) {
					continue;
				}
				$seen[ $key ] = true;
				$this->add_finding( $stage, $rule['severity'], $rule['confidence'], $location, $rule['id'], $rule['description'] );
			}
		}

		foreach ( $this->rules['database'] as $rule ) {
			if ( ! $this->database_rule_matches( $rule, $value, $table, $row, $field ) ) {
				continue;
			}

			$key = $rule['id'];
			if ( isset( $seen[ $key ] ) ) {
				continue;
			}

			$seen[ $key ] = true;
			$this->add_finding( $stage, $rule['severity'], $rule['confidence'], $location, $rule['id'], $rule['description'] );
		}

		// A <script> tag is normal in many WordPress settings and custom-code
		// fields. Only report JavaScript when it matches a stronger behavioral
		// rule such as obfuscated execution, hidden iframe or decoded redirect.
		if ( preg_match( '~(?:<script\b|<iframe\b|\beval\s*\(|\batob\s*\(|fromCharCode|javascript\s*:|location\.)~i', $value ) ) {
			foreach ( $this->rules['javascript'] as $rule ) {
				if ( ! @preg_match( $rule['regex'], $value ) ) {
					continue;
				}

				$key = 'db_' . $rule['id'];
				if ( isset( $seen[ $key ] ) ) {
					continue;
				}

				$seen[ $key ] = true;
				$this->add_finding( $stage, $rule['severity'], $rule['confidence'], $location, $key, $rule['description'] );
			}
		}
	}

	/**
	 * Apply context-aware database rules.
	 */
	private function database_rule_matches( array $rule, $value, $table = '', array $row = [], $field = '' ) {
		if ( ! @preg_match( $rule['regex'], $value ) ) {
			return false;
		}

		if ( 'db_command_execution' === $rule['id'] ) {
			return $this->has_database_command_execution_context( $value );
		}

		if ( 'db_long_base64' === $rule['id'] ) {
			return $this->should_report_database_base64( $value, $table, $row, $field );
		}

		if ( 'db_script' === $rule['id'] ) {
			return false;
		}

		return true;
	}

	/**
	 * Require executable PHP-like context around OS command functions in DB text.
	 *
	 * Plain text such as documentation, comments, serialized labels, or content
	 * containing "exec(" is not executable by itself and should not be CRITICAL.
	 */
	private function has_database_command_execution_context( $value ) {
		$context_patterns = [
			'~<\\?(?:php|=)~i',
			'~\\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\\b~i',
			'~\\b(?:eval|assert|base64_decode|gzinflate|gzuncompress|str_rot13)\\s*\\(~i',
			'~(?:^|[;{}])\\s*(?:system|exec|shell_exec|passthru|proc_open|popen)\\s*\\(\\s*\\$[A-Za-z_]~im',
		];

		foreach ( $context_patterns as $pattern ) {
			if ( @preg_match( $pattern, $value ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Suppress known benign large Base64 session payloads while still checking
	 * their decoded content for executable indicators.
	 */
	private function should_report_database_base64( $value, $table, array $row, $field ) {
		if ( ! preg_match_all( '~[A-Za-z0-9+/]{800,}={0,2}~', $value, $matches ) ) {
			return false;
		}

		foreach ( $matches[0] as $encoded ) {
			$decoded = base64_decode( $encoded, true );
			if ( false === $decoded || '' === $decoded ) {
				continue;
			}

			if ( $this->decoded_database_payload_is_suspicious( $decoded ) ) {
				return true;
			}
		}

		// Large Base64 values are common in plugin configuration, sessions and
		// serialized settings. By themselves they are not executable. Malicious
		// decoded content is still caught above and loader/decryptor code is
		// detected by the filesystem scanner.
		return false;
	}

	/**
	 * Check decoded DB payloads for strong executable indicators.
	 */
	private function decoded_database_payload_is_suspicious( $decoded ) {
		foreach ( $this->rules['iocs'] as $rule ) {
			if ( false !== stripos( $decoded, $rule['needle'] ) ) {
				return true;
			}
		}

		return (bool) preg_match(
			'~<\\?(?:php|=)|<script\\b|\\b(?:eval|assert|base64_decode|gzinflate|gzuncompress)\\s*\\(|\\$_(?:GET|POST|REQUEST|COOKIE|FILES)\\b|\\b(?:system|exec|shell_exec|passthru)\\s*\\(~i',
			$decoded
		);
	}

	/**
	 * Scan user accounts and cron persistence data.
	 */
	private function scan_users_and_persistence() {
		global $wpdb;

		$stage = 'Users & persistence';
		$this->stage_start( $stage );
		$count = 0;

		$admins = get_users(
			[
				'role'   => 'administrator',
				'fields' => [ 'ID' ],
			]
		);
		$this->admin_count = count( $admins );

		$user_rows = $wpdb->get_results(
			"SELECT ID, user_login, user_email, user_registered FROM {$wpdb->users} WHERE user_registered IS NOT NULL AND user_registered <> '0000-00-00 00:00:00' ORDER BY user_registered ASC"
		);

		$users = [];
		if ( is_array( $user_rows ) ) {
			foreach ( $user_rows as $row ) {
				$timestamp = strtotime( $row->user_registered . ' UTC' );
				if ( false === $timestamp ) {
					continue;
				}

				$user = get_userdata( (int) $row->ID );
				$roles = $user && is_array( $user->roles ) ? array_values( $user->roles ) : [];
				$is_privileged = $user && ( user_can( $user, 'manage_options' ) || user_can( $user, 'edit_others_posts' ) || user_can( $user, 'manage_woocommerce' ) );

				$users[] = [
					'id'            => (int) $row->ID,
					'login'         => (string) $row->user_login,
					'email'         => (string) $row->user_email,
					'registered'    => (string) $row->user_registered,
					'timestamp'     => $timestamp,
					'roles'         => $roles,
					'is_privileged' => (bool) $is_privileged,
				];
			}
		}

		$count += count( $users );
		$this->stage_tick( $stage, $count, 'items' );
		$this->scan_recent_and_burst_users( $stage, $users );

		$cron = get_option( 'cron', [] );
		if ( is_array( $cron ) ) {
			foreach ( $cron as $timestamp => $hooks ) {
				if ( ! is_array( $hooks ) ) {
					continue;
				}

				foreach ( $hooks as $hook => $events ) {
					$count++;
					$serialized = maybe_serialize( $events );
					$location = 'cron hook: ' . $hook;
					$this->scan_persistence_value( $stage, $location, $hook . ' ' . $serialized );
					$this->stage_tick( $stage, $count, 'items' );
				}
			}
		}

		$this->stage_finish( $stage, $count, $this->count_stage_findings( $stage ), 'items' );
	}

	/**
	 * Flag recently created users and rapid-registration clusters.
	 *
	 * Burst analysis is intentionally limited to the same recent-user window so
	 * historical imports/migrations do not dominate an incident report.
	 */
	private function scan_recent_and_burst_users( $stage, array $users ) {
		$recent_cutoff = strtotime( '-' . self::RECENT_USER_MONTHS . ' months', time() );
		$recent_users = array_values(
			array_filter(
				$users,
				static function ( $user ) use ( $recent_cutoff ) {
					return $user['timestamp'] >= $recent_cutoff;
				}
			)
		);

		if ( empty( $recent_users ) ) {
			return;
		}

		$burst_members = $this->find_user_burst_members( $recent_users );

		foreach ( $recent_users as $user ) {
			$location = $this->format_user_location( $user );

			if ( isset( $burst_members[ $user['id'] ] ) ) {
				$burst = $burst_members[ $user['id'] ];
				$description = $burst['privileged']
					? sprintf( 'Privileged user belongs to a rapid-registration cluster (%d privileged accounts within 10 minutes)', $burst['count'] )
					: sprintf( 'User belongs to a rapid-registration cluster (%d accounts within 10 minutes)', $burst['count'] );

				$this->add_finding(
					$stage,
					'critical',
					96,
					$location,
					'rapid_user_registration',
					$description
				);
				continue;
			}

			$this->add_finding(
				$stage,
				'high',
				88,
				$location,
				'recent_user_account',
				'User account was created within the last 2 months'
			);
		}
	}

	/**
	 * Return users that participate in suspicious rapid-registration windows.
	 *
	 * Any 5+ accounts within ten minutes are critical. For privileged users,
	 * two accounts in the same ten-minute window are enough to trigger.
	 */
	private function find_user_burst_members( array $users ) {
		$members = [];
		$this->mark_user_burst_members( $users, self::USER_BURST_THRESHOLD, false, $members );

		$privileged = array_values(
			array_filter(
				$users,
				static function ( $user ) {
					return ! empty( $user['is_privileged'] );
				}
			)
		);
		$this->mark_user_burst_members( $privileged, self::PRIVILEGED_USER_BURST_THRESHOLD, true, $members );

		return $members;
	}

	/**
	 * Mark all users that fall inside a sliding burst-registration window.
	 */
	private function mark_user_burst_members( array $users, $threshold, $privileged, array &$members ) {
		$total = count( $users );
		for ( $start = 0; $start < $total; $start++ ) {
			$end = $start;
			while (
				$end + 1 < $total
				&& $users[ $end + 1 ]['timestamp'] - $users[ $start ]['timestamp'] <= self::USER_BURST_WINDOW_SECONDS
			) {
				$end++;
			}

			$count = $end - $start + 1;
			if ( $count < $threshold ) {
				continue;
			}

			for ( $index = $start; $index <= $end; $index++ ) {
				$user_id = $users[ $index ]['id'];
				$current = $members[ $user_id ] ?? null;

				if ( null === $current || $privileged || $count > $current['count'] ) {
					$members[ $user_id ] = [
						'count'      => $count,
						'privileged' => (bool) $privileged,
					];
				}
			}
		}
	}

	/**
	 * Format a user finding location for quick manual review.
	 */
	private function format_user_location( array $user ) {
		$roles = empty( $user['roles'] ) ? 'none' : implode( ',', $user['roles'] );

		return sprintf(
			'user #%d · %s · %s · role%s: %s · registered %s UTC',
			$user['id'],
			$user['login'],
			$user['email'],
			1 === count( $user['roles'] ) ? '' : 's',
			$roles,
			$user['registered']
		);
	}

	/**
	 * Scan a persistence value using IOC and dangerous code patterns.
	 */
	private function scan_persistence_value( $stage, $location, $value ) {
		foreach ( $this->rules['iocs'] as $rule ) {
			if ( false !== stripos( $value, $rule['needle'] ) ) {
				$this->add_finding( $stage, $rule['severity'], $rule['confidence'], $location, $rule['id'], $rule['description'] );
			}
		}

		foreach ( $this->rules['database'] as $rule ) {
			if ( $this->database_rule_matches( $rule, $value, '', [], '' ) ) {
				$this->add_finding( $stage, $rule['severity'], $rule['confidence'], $location, 'persistence_' . $rule['id'], $rule['description'] );
			}
		}
	}

	/**
	 * Add a rule-driven file finding once per file.
	 */
	private function add_file_rule_once( array &$seen, $stage, $relative, array $rule, $line = null ) {
		$this->add_file_finding_once(
			$seen,
			$stage,
			$rule['severity'],
			$rule['confidence'],
			$relative,
			$rule['id'],
			$rule['description'],
			$line
		);
	}

	/**
	 * Add a file finding once per file/rule.
	 */
	private function add_file_finding_once( array &$seen, $stage, $severity, $confidence, $location, $rule, $description, $line = null ) {
		if ( isset( $seen[ $rule ] ) ) {
			return;
		}

		$seen[ $rule ] = true;
		$this->add_finding( $stage, $severity, $confidence, $location, $rule, $description, $line );
	}

	/**
	 * Add one finding.
	 */
	private function add_finding( $section, $severity, $confidence, $location, $rule, $description, $line = null ) {
		$severity = strtolower( $severity );
		$confidence = max( 0, min( 100, (int) $confidence ) );
		$line = null === $line ? null : max( 1, (int) $line );

		$this->findings[] = [
			'section'     => $section,
			'severity'    => $severity,
			'confidence'  => $confidence,
			'location'    => $location,
			'line'        => $line,
			'rule'        => $rule,
			'description' => $description,
		];
	}

	/**
	 * Start a spinner stage.
	 */
	private function stage_start( $stage ) {
		$this->current_stage = $stage;
		$this->stage_stats[ $stage ] = [
			'items'    => 0,
			'findings' => 0,
		];

		if ( ! $this->interactive ) {
			return;
		}

		$this->render_spinner( 'Scanning ' . strtolower( $stage ) . '...' );
	}

	/**
	 * Update stage spinner.
	 */
	private function stage_tick( $stage, $count, $unit ) {
		if ( isset( $this->stage_stats[ $stage ] ) ) {
			$this->stage_stats[ $stage ]['items'] = $count;
		}

		if ( ! $this->interactive ) {
			return;
		}

		$now = microtime( true );
		if ( $now - $this->last_spinner_at < 0.08 ) {
			return;
		}

		$this->render_spinner( sprintf( 'Scanning %s... %s %s', strtolower( $stage ), number_format( $count ), $unit ) );
	}

	/**
	 * Keep the spinner moving while a single file or operation is busy.
	 */
	private function stage_heartbeat( $stage, $unit = 'files' ) {
		if ( ! $this->interactive ) {
			return;
		}

		$now = microtime( true );
		if ( $now - $this->last_spinner_at < 0.08 ) {
			return;
		}

		$count = isset( $this->stage_stats[ $stage ]['items'] ) ? (int) $this->stage_stats[ $stage ]['items'] : 0;
		$message = 'Scanning ' . strtolower( $stage ) . '...';
		if ( $count > 0 ) {
			$message .= ' ' . number_format( $count ) . ' ' . $unit;
		}

		$this->render_spinner( $message );
	}

	/**
	 * Finish one stage.
	 */
	private function stage_finish( $stage, $count, $findings, $unit = 'files' ) {
		if ( isset( $this->stage_stats[ $stage ] ) ) {
			$this->stage_stats[ $stage ]['items'] = $count;
			$this->stage_stats[ $stage ]['findings'] = $findings;
		}

		if ( ! $this->interactive ) {
			return;
		}

		$this->clear_spinner();
		$icon = 0 === $findings ? '✓' : '⚠';
		$suffix = 0 === $findings ? 'no threats found' : sprintf( '%d threat%s found', $findings, 1 === $findings ? '' : 's' );
		\WP_CLI::log( sprintf( '%s %s scanned — %s %s, %s', $icon, $stage, number_format( $count ), $unit, $suffix ) );
	}

	/**
	 * Finish a checksum stage without pretending that WP-CLI reported a scan count.
	 */
	private function checksum_stage_finish( $stage, $findings ) {
		if ( isset( $this->stage_stats[ $stage ] ) ) {
			$this->stage_stats[ $stage ]['items'] = null;
			$this->stage_stats[ $stage ]['findings'] = $findings;
		}

		if ( ! $this->interactive ) {
			return;
		}

		$this->clear_spinner();

		if ( 0 === $findings ) {
			\WP_CLI::log( sprintf( '✓ %s completed — no integrity issues found', $stage ) );
			return;
		}

		\WP_CLI::log(
			sprintf(
				'⚠ %s completed — %d integrity issue%s found',
				$stage,
				$findings,
				1 === $findings ? '' : 's'
			)
		);
	}

	/**
	 * Start a spinner in a lightweight child PHP process.
	 *
	 * This keeps animation moving while the parent process is blocked by
	 * WordPress bootstrap or another synchronous operation.
	 */
	private function start_background_spinner( $message ) {
		if ( ! $this->interactive ) {
			return;
		}

		$this->stop_background_spinner();

		if ( ! function_exists( 'proc_open' ) || ! defined( 'PHP_BINARY' ) || '' === PHP_BINARY ) {
			$this->render_spinner( $message );
			return;
		}

		$encoded_message = base64_encode( $message );
		$code = <<<'PHP'
$frames = [ '⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏' ];
$message = base64_decode( '__MESSAGE__' );
$index = 0;

while ( true ) {
	fwrite( STDOUT, "\r\033[2K" . $frames[ $index % count( $frames ) ] . ' ' . $message );
	fflush( STDOUT );
	$index++;
	usleep( 100000 );
}
PHP;
		$code = str_replace( '__MESSAGE__', $encoded_message, $code );

		$descriptors = [
			0 => [ 'pipe', 'r' ],
			1 => STDOUT,
			2 => STDERR,
		];

		$pipes = [];
		$process = @proc_open(
			[ PHP_BINARY, '-r', $code ],
			$descriptors,
			$pipes,
			null,
			null,
			[ 'bypass_shell' => true ]
		);

		if ( ! is_resource( $process ) ) {
			$this->render_spinner( $message );
			return;
		}

		if ( isset( $pipes[0] ) && is_resource( $pipes[0] ) ) {
			fclose( $pipes[0] );
		}

		$this->background_spinner_process = $process;
	}

	/**
	 * Stop and clear the background spinner.
	 */
	private function stop_background_spinner() {
		if ( is_resource( $this->background_spinner_process ) ) {
			$status = @proc_get_status( $this->background_spinner_process );

			if ( is_array( $status ) && ! empty( $status['running'] ) ) {
				@proc_terminate( $this->background_spinner_process );
				usleep( 20000 );
			}

			@proc_close( $this->background_spinner_process );
		}

		$this->background_spinner_process = null;

		if ( $this->interactive ) {
			fwrite( STDOUT, "\r\033[2K" );
			@fflush( STDOUT );
		}
	}

	/**
	 * Render spinner line.
	 */
	private function render_spinner( $message ) {
		$frames = [ '⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏' ];
		$frame = $frames[ $this->spinner_index % count( $frames ) ];
		$this->spinner_index++;
		$this->last_spinner_at = microtime( true );
		fwrite( STDOUT, "\r\033[2K" . $frame . ' ' . $message );
		@fflush( STDOUT );
	}

	/**
	 * Clear spinner line.
	 */
	private function clear_spinner() {
		if ( $this->interactive ) {
			fwrite( STDOUT, "\r\033[2K" );
			@fflush( STDOUT );
		}
	}

	/**
	 * Finalize and print/export report.
	 */
	private function finalize_report( array $assoc_args ) {
		$this->clear_spinner();
		$min_severity = isset( $assoc_args['min-severity'] ) ? strtolower( (string) $assoc_args['min-severity'] ) : 'low';

		if ( ! isset( self::SEVERITY_WEIGHT[ $min_severity ] ) || 'info' === $min_severity ) {
			\WP_CLI::error( 'Invalid --min-severity. Use low, medium, high, or critical.' );
		}

		$reportable_findings = $this->filter_findings_for_plugin_integrity( $this->findings );

		$filtered = array_values(
			array_filter(
				$reportable_findings,
				function ( $finding ) use ( $min_severity ) {
					return self::SEVERITY_WEIGHT[ $finding['severity'] ] >= self::SEVERITY_WEIGHT[ $min_severity ];
				}
			)
		);

		usort( $filtered, [ $this, 'sort_findings' ] );

		$this->modification_clusters = $this->build_finding_mtime_clusters( $filtered );
		$report = $this->build_report( $filtered );
		$output_file = isset( $assoc_args['output'] ) ? (string) $assoc_args['output'] : '';

		if ( 'json' === $this->format ) {
			$content = wp_json_encode( $report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES );
			$this->emit_export( $content . PHP_EOL, $output_file );
			return;
		}

		if ( 'markdown' === $this->format ) {
			$content = $this->render_markdown( $report );
			$this->emit_export( $content, $output_file );
			return;
		}

		$this->render_terminal_report( $report );
	}

	/**
	 * Build normalized report structure.
	 */
	private function build_report( array $findings ) {
		$severity_counts = [
			'critical' => 0,
			'high'     => 0,
			'medium'   => 0,
			'low'      => 0,
		];

		foreach ( $findings as $finding ) {
			if ( isset( $severity_counts[ $finding['severity'] ] ) ) {
				$severity_counts[ $finding['severity'] ]++;
			}
		}

		return [
			'package_version'   => self::VERSION,
			'scanned_at'        => gmdate( 'c' ),
			'duration_seconds'  => round( microtime( true ) - $this->start_time, 2 ),
			'files_scanned'     => $this->scanned_files,
			'database_rows'     => $this->scanned_db_rows,
			'administrator_users' => $this->admin_count,
			'severity'          => $severity_counts,
			'total_findings'    => count( $findings ),
			'stages'            => $this->stage_stats,
			'plugin_integrity'  => $this->plugin_integrity,
			'findings'          => $findings,
		];
	}

	/**
	 * Order report sections for predictable human-readable output.
	 */
	private function order_report_sections( array $sections ) {
		$order = [
			'Core checksums',
			'Plugin integrity',
			'Themes',
			'Plugins',
			'MU plugins & drop-ins',
			'Uploads',
			'Other wp-content',
			'Database',
			'Users & persistence',
		];

		$ordered = [];
		foreach ( $order as $section ) {
			if ( array_key_exists( $section, $sections ) ) {
				$ordered[ $section ] = $sections[ $section ];
				unset( $sections[ $section ] );
			}
		}

		foreach ( $sections as $section => $findings ) {
			$ordered[ $section ] = $findings;
		}

		return $ordered;
	}



	/**
	 * Apply plugin checksum trust before human-readable/report findings are built.
	 *
	 * Verified WordPress.org plugins suppress normal static heuristics. Separate
	 * repository-risk findings and extremely strong exact IOCs in executable
	 * files remain visible because checksum equality does not prove the upstream
	 * release itself is safe.
	 */
	private function filter_findings_for_plugin_integrity( array $findings ) {
		$filtered = [];

		foreach ( $findings as $finding ) {
			if ( 'Plugins' !== $finding['section'] ) {
				$filtered[] = $finding;
				continue;
			}

			$plugin = $this->plugin_slug_from_location( $finding['location'] );
			$status = $this->plugin_integrity_status( $plugin );

			if ( 'verified' !== $status || $this->is_verified_plugin_risk_finding( $finding ) ) {
				$filtered[] = $finding;
			}
		}

		return $filtered;
	}

	/**
	 * Count plugin findings that will actually be shown after checksum trust.
	 */
	private function count_reportable_plugin_findings() {
		$count = 0;
		foreach ( $this->filter_findings_for_plugin_integrity( $this->findings ) as $finding ) {
			if ( 'Plugins' === $finding['section'] ) {
				$count++;
			}
		}

		return $count;
	}

	/**
	 * Return the known integrity state for a plugin slug.
	 */
	private function plugin_integrity_status( $plugin ) {
		if ( null === $plugin || '' === $plugin || ! isset( $this->plugin_integrity[ $plugin ] ) ) {
			return 'unverified';
		}

		return isset( $this->plugin_integrity[ $plugin ]['status'] )
			? $this->plugin_integrity[ $plugin ]['status']
			: 'unverified';
	}

	/**
	 * Strong findings that remain meaningful even when local checksums match.
	 */
	private function is_verified_plugin_risk_finding( array $finding ) {
		$rule = isset( $finding['rule'] ) ? (string) $finding['rule'] : '';
		if ( 0 === strpos( $rule, 'plugin_reputation_' ) ) {
			return true;
		}

		if (
			0 !== strpos( $rule, 'ioc_' )
			|| 'critical' !== ( $finding['severity'] ?? '' )
			|| (int) ( $finding['confidence'] ?? 0 ) < 97
		) {
			return false;
		}

		$extension = strtolower( pathinfo( (string) $finding['location'], PATHINFO_EXTENSION ) );
		return in_array( $extension, array_merge( self::PHP_EXTENSIONS, [ 'js', 'mjs', 'cjs' ] ), true );
	}

	/**
	 * Weighted risk score used only when trusted checksums are unavailable.
	 */
	private function plugin_risk_score( array $findings ) {
		$score = 0;
		foreach ( $findings as $finding ) {
			$score += (int) ( self::SEVERITY_WEIGHT[ $finding['severity'] ] ?? 0 );
		}

		return $score;
	}

	/**
	 * Group plugin findings by plugin and then by rule.
	 *
	 * This keeps noisy plugin reports actionable while preserving every
	 * reportable affected path. Verified-plugin heuristics are filtered earlier.
	 */
	private function group_plugin_findings( array $findings ) {
		$groups = [];

		foreach ( $findings as $finding ) {
			$plugin = $this->plugin_slug_from_location( $finding['location'] );
			if ( null === $plugin ) {
				$plugin = 'unknown-plugin';
			}

			if ( ! isset( $groups[ $plugin ] ) ) {
				$groups[ $plugin ] = [
					'slug'       => $plugin,
					'total'      => 0,
					'severity'   => [
						'critical' => 0,
						'high'     => 0,
						'medium'   => 0,
						'low'      => 0,
					],
					'highest'    => 'info',
					'issues'     => [],
					'integrity'  => $this->plugin_integrity_status( $plugin ),
					'risk_score' => 0,
					'action'     => 'review',
				];
			}

			$group =& $groups[ $plugin ];
			$group['total']++;
			$group['risk_score'] += (int) ( self::SEVERITY_WEIGHT[ $finding['severity'] ] ?? 0 );
			if ( isset( $group['severity'][ $finding['severity'] ] ) ) {
				$group['severity'][ $finding['severity'] ]++;
			}
			if ( self::SEVERITY_WEIGHT[ $finding['severity'] ] > self::SEVERITY_WEIGHT[ $group['highest'] ] ) {
				$group['highest'] = $finding['severity'];
			}

			$issue_key = ! empty( $finding['rule'] ) ? $finding['rule'] : md5( $finding['description'] );
			if ( ! isset( $group['issues'][ $issue_key ] ) ) {
				$group['issues'][ $issue_key ] = [
					'rule'        => $finding['rule'],
					'description' => $finding['description'],
					'severity'    => $finding['severity'],
					'confidence'  => (int) $finding['confidence'],
					'findings'    => [],
				];
			}

			$issue =& $group['issues'][ $issue_key ];
			$issue['findings'][] = $finding;
			if (
				self::SEVERITY_WEIGHT[ $finding['severity'] ] > self::SEVERITY_WEIGHT[ $issue['severity'] ]
				|| (
					$finding['severity'] === $issue['severity']
					&& (int) $finding['confidence'] > (int) $issue['confidence']
				)
			) {
				$issue['severity'] = $finding['severity'];
				$issue['confidence'] = (int) $finding['confidence'];
				$issue['description'] = $finding['description'];
			}
			unset( $issue, $group );
		}

		foreach ( $groups as &$group ) {
			if ( 'modified' === $group['integrity'] ) {
				$group['action'] = 'reinstall';
			} elseif ( in_array( $group['integrity'], [ 'unavailable', 'unverified' ], true ) ) {
				$group['action'] = $group['risk_score'] >= self::PLUGIN_REINSTALL_SCORE_THRESHOLD ? 'reinstall' : 'review';
			} else {
				$group['action'] = 'review';
			}

			$issues = array_values( $group['issues'] );
			usort(
				$issues,
				function ( $a, $b ) {
					$severity_compare = self::SEVERITY_WEIGHT[ $b['severity'] ] <=> self::SEVERITY_WEIGHT[ $a['severity'] ];
					if ( 0 !== $severity_compare ) {
						return $severity_compare;
					}

					$confidence_compare = $b['confidence'] <=> $a['confidence'];
					if ( 0 !== $confidence_compare ) {
						return $confidence_compare;
					}

					$count_compare = count( $b['findings'] ) <=> count( $a['findings'] );
					if ( 0 !== $count_compare ) {
						return $count_compare;
					}

					return strcmp( $a['description'], $b['description'] );
				}
			);
			$group['issues'] = $issues;
		}
		unset( $group );

		$groups = array_values( $groups );
		usort(
			$groups,
			function ( $a, $b ) {
				$action_rank = [ 'reinstall' => 2, 'review' => 1 ];
				$action_compare = ( $action_rank[ $b['action'] ] ?? 0 ) <=> ( $action_rank[ $a['action'] ] ?? 0 );
				if ( 0 !== $action_compare ) {
					return $action_compare;
				}

				$score_compare = $b['risk_score'] <=> $a['risk_score'];
				if ( 0 !== $score_compare ) {
					return $score_compare;
				}

				return strcmp( $a['slug'], $b['slug'] );
			}
		);

		return $groups;
	}

	/**
	 * Extract the top-level plugin directory from a wp-content-relative path.
	 */
	private function plugin_slug_from_location( $location ) {
		$location = str_replace( '\\', '/', (string) $location );
		if ( preg_match( '~^plugins/([^/]+)(?:/|$)~i', $location, $matches ) ) {
			return $matches[1];
		}

		return null;
	}

	/**
	 * Build a finding location relative to the plugin directory where possible.
	 */
	private function plugin_relative_finding_location( array $finding, $plugin ) {
		$location = str_replace( '\\', '/', (string) $finding['location'] );
		$prefix = 'plugins/' . $plugin . '/';
		if ( 0 === stripos( $location, $prefix ) ) {
			$location = substr( $location, strlen( $prefix ) );
		}

		if ( ! empty( $finding['line'] ) ) {
			$location .= ':' . $finding['line'];
		}

		return $location;
	}

	/**
	 * Format per-plugin severity counts.
	 */
	private function plugin_severity_summary( array $group ) {
		$parts = [];
		foreach ( [ 'critical', 'high', 'medium', 'low' ] as $severity ) {
			$count = (int) ( $group['severity'][ $severity ] ?? 0 );
			if ( $count > 0 ) {
				$parts[] = $count . ' ' . $severity;
			}
		}

		return implode( ' · ', $parts );
	}

	/**
	 * Render plugin findings in a compact plugin -> issue -> file hierarchy.
	 */
	private function render_terminal_plugin_findings( array $findings ) {
		$groups = $this->group_plugin_findings( $findings );
		$plugin_count = count( $groups );
		\WP_CLI::log(
			sprintf(
				'%d threat%s found across %d plugin%s',
				count( $findings ),
				1 === count( $findings ) ? '' : 's',
				$plugin_count,
				1 === $plugin_count ? '' : 's'
			)
		);
		\WP_CLI::log( '' );

		foreach ( $groups as $group ) {
			\WP_CLI::log( $group['slug'] );
			$summary = $this->plugin_severity_summary( $group );
			\WP_CLI::log(
				sprintf(
					'  %d finding%s%s',
					$group['total'],
					1 === $group['total'] ? '' : 's',
					'' !== $summary ? ' · ' . $summary : ''
				)
			);

			if ( 'verified' === $group['integrity'] ) {
				\WP_CLI::log( '  ✓ Checksums verified — only independent plugin-risk signals are shown.' );
				\WP_CLI::log( '  ⚠ Recommendation: review the plugin status/source; reinstalling the same verified version may not change these findings.' );
			} elseif ( 'modified' === $group['integrity'] ) {
				\WP_CLI::log( '  ⚠ Checksums failed.' );
				\WP_CLI::log( '  ⚠ Strong recommendation: replace the entire plugin with a fresh trusted copy, then rescan.' );
			} else {
				$status_label = 'unavailable' === $group['integrity'] ? 'unavailable' : 'unverified';
				\WP_CLI::log( '  ? Checksums ' . $status_label . '.' );
				\WP_CLI::log( sprintf( '  Risk score: %d / %d', $group['risk_score'], self::PLUGIN_REINSTALL_SCORE_THRESHOLD ) );

				if ( 'reinstall' === $group['action'] ) {
					\WP_CLI::log( '  ⚠ Strong recommendation: replace the entire plugin with a fresh trusted copy, then rescan.' );
				} else {
					\WP_CLI::log( '  ⚠ Recommendation: manually review the grouped findings.' );
				}
			}
			\WP_CLI::log( '' );

			foreach ( $group['issues'] as $issue ) {
				$count = count( $issue['findings'] );
				$label = strtoupper( $issue['severity'] ) . ' · ' . $issue['confidence'] . '%';
				$suffix = $count > 1 ? sprintf( ' (%d occurrences)', $count ) : '';
				\WP_CLI::log( sprintf( '  %-16s %s%s', $label, $issue['description'], $suffix ) );

				foreach ( $issue['findings'] as $finding ) {
					\WP_CLI::log(
						str_repeat( ' ', 19 )
						. $this->plugin_relative_finding_location( $finding, $group['slug'] )
					);
				}
			}
			\WP_CLI::log( '' );
		}
	}

	/**
	 * Render plugin findings for the Markdown report.
	 */
	private function render_markdown_plugin_findings( array $findings ) {
		$lines = [];
		$groups = $this->group_plugin_findings( $findings );
		$lines[] = count( $findings ) . ' threat' . ( 1 === count( $findings ) ? '' : 's' ) . ' found across ' . count( $groups ) . ' plugin' . ( 1 === count( $groups ) ? '' : 's' ) . '.';
		$lines[] = '';

		foreach ( $groups as $group ) {
			$lines[] = '### `' . $this->markdown_escape( $group['slug'] ) . '`';
			$lines[] = '';
			$summary = $this->plugin_severity_summary( $group );
			$lines[] = $group['total'] . ' finding' . ( 1 === $group['total'] ? '' : 's' ) . ( '' !== $summary ? ' — ' . $summary : '' ) . '.';
			$lines[] = '';

			if ( 'verified' === $group['integrity'] ) {
				$lines[] = '- ✓ Checksums verified; ordinary static findings are suppressed.';
				$lines[] = '- ⚠ These are independent plugin-risk signals. Review the plugin status/source; reinstalling the same verified version may not change them.';
			} elseif ( 'modified' === $group['integrity'] ) {
				$lines[] = '- ⚠ Checksums failed.';
				$lines[] = '- ⚠ **Strong recommendation:** Replace the entire plugin with a fresh trusted copy, then rescan.';
			} else {
				$lines[] = '- ? Checksums ' . ( 'unavailable' === $group['integrity'] ? 'unavailable' : 'unverified' ) . '.';
				$lines[] = '- Risk score: **' . $group['risk_score'] . ' / ' . self::PLUGIN_REINSTALL_SCORE_THRESHOLD . '**.';
				if ( 'reinstall' === $group['action'] ) {
					$lines[] = '- ⚠ **Strong recommendation:** Replace the entire plugin with a fresh trusted copy, then rescan.';
				} else {
					$lines[] = '- ⚠ Manual review recommended.';
				}
			}
			$lines[] = '';

			foreach ( $group['issues'] as $issue ) {
				$count = count( $issue['findings'] );
				$lines[] = sprintf(
					'**%s · %d%% — %s%s**',
					strtoupper( $issue['severity'] ),
					$issue['confidence'],
					$this->markdown_escape( $issue['description'] ),
					$count > 1 ? ' (' . $count . ' occurrences)' : ''
				);
				$lines[] = '';

				foreach ( $issue['findings'] as $finding ) {
					$lines[] = '- `' . $this->markdown_escape( $this->plugin_relative_finding_location( $finding, $group['slug'] ) ) . '`';
				}
				$lines[] = '';
			}
		}

		return $lines;
	}

	/**
	 * Render checksum failures grouped by plugin with direct remediation.
	 */
	private function render_terminal_plugin_integrity_findings( array $findings ) {
		$groups = [];
		foreach ( $findings as $finding ) {
			$plugin = $this->plugin_slug_from_location( $finding['location'] );
			if ( null === $plugin ) {
				$plugin = 'plugin-integrity';
			}
			$groups[ $plugin ][] = $finding;
		}

		\WP_CLI::log( sprintf( '%d integrity issue%s found', count( $findings ), 1 === count( $findings ) ? '' : 's' ) );
		\WP_CLI::log( '' );

		foreach ( $groups as $plugin => $plugin_findings ) {
			\WP_CLI::log( $plugin );
			if ( 'modified' === $this->plugin_integrity_status( $plugin ) ) {
				\WP_CLI::log( '  ⚠ Strong recommendation: replace the entire plugin with a fresh trusted copy, then rescan.' );
			}
		\WP_CLI::log( '' );

			foreach ( $plugin_findings as $finding ) {
				$label = strtoupper( $finding['severity'] ) . ' · ' . $finding['confidence'] . '%';
			\WP_CLI::log( sprintf( '  %-16s %s', $label, $finding['description'] ) );
			\WP_CLI::log( str_repeat( ' ', 19 ) . $this->plugin_relative_finding_location( $finding, $plugin ) );
			}
			\WP_CLI::log( '' );
		}
	}

	/**
	 * Render plugin checksum failures for Markdown.
	 */
	private function render_markdown_plugin_integrity_findings( array $findings ) {
		$lines = [];
		$groups = [];
		foreach ( $findings as $finding ) {
			$plugin = $this->plugin_slug_from_location( $finding['location'] );
			if ( null === $plugin ) {
				$plugin = 'plugin-integrity';
			}
			$groups[ $plugin ][] = $finding;
		}

		$lines[] = count( $findings ) . ' integrity issue' . ( 1 === count( $findings ) ? '' : 's' ) . ' found.';
		$lines[] = '';
		foreach ( $groups as $plugin => $plugin_findings ) {
			$lines[] = '### `' . $this->markdown_escape( $plugin ) . '`';
			$lines[] = '';
			if ( 'modified' === $this->plugin_integrity_status( $plugin ) ) {
				$lines[] = '> ⚠ **Strong recommendation:** Replace the entire plugin with a fresh trusted copy, then rescan.';
				$lines[] = '';
			}
			foreach ( $plugin_findings as $finding ) {
				$lines[] = '- **' . strtoupper( $finding['severity'] ) . ' · ' . $finding['confidence'] . '%** — ' . $this->markdown_escape( $finding['description'] );
				$lines[] = '  - `' . $this->markdown_escape( $this->plugin_relative_finding_location( $finding, $plugin ) ) . '`';
			}
			$lines[] = '';
		}

		return $lines;
	}

	/**
	 * Render terminal report grouped by section.
	 */
	private function render_terminal_report( array $report ) {
		\WP_CLI::log( '' );
		\WP_CLI::log( '' );
		\WP_CLI::log( 'Findings' );
		\WP_CLI::log( str_repeat( '═', 72 ) );

		$sections = [];
		foreach ( $report['findings'] as $finding ) {
			$sections[ $finding['section'] ][] = $finding;
		}

		if ( isset( $report['stages']['Database'] ) && ! isset( $sections['Database'] ) ) {
			$sections['Database'] = [];
		}

		if ( empty( $sections ) ) {
			\WP_CLI::success( 'No suspicious findings matched the active rules.' );
		} else {
			$sections = $this->order_report_sections( $sections );

			foreach ( $sections as $section => $findings ) {
				\WP_CLI::log( '' );
				\WP_CLI::log( $section );
				\WP_CLI::log( str_repeat( '─', 72 ) );

				if ( 'Plugins' === $section ) {
					$this->render_terminal_plugin_findings( $findings );
					continue;
				}

				if ( 'Plugin integrity' === $section ) {
					$this->render_terminal_plugin_integrity_findings( $findings );
					continue;
				}

				if ( 'Core checksums' === $section ) {
					\WP_CLI::log( sprintf( '%d integrity issue%s found', count( $findings ), 1 === count( $findings ) ? '' : 's' ) );
				} else {
					\WP_CLI::log( sprintf( '%d threat%s found', count( $findings ), 1 === count( $findings ) ? '' : 's' ) );
				}
				if ( 'Database' === $section && isset( $report['stages']['Database']['items'] ) ) {
					\WP_CLI::log( sprintf( '%s rows scanned', number_format( $report['stages']['Database']['items'] ) ) );
				}
				\WP_CLI::log( '' );

				foreach ( $findings as $finding ) {
					$label = strtoupper( $finding['severity'] ) . ' · ' . $finding['confidence'] . '%';
					$location = $finding['location'];
					if ( ! empty( $finding['line'] ) ) {
						$location .= ':' . $finding['line'];
					}
					\WP_CLI::log( sprintf( '%-16s %s', $label, $finding['description'] ) );
					\WP_CLI::log( str_repeat( ' ', 17 ) . $location );
				}
			}
		}

		\WP_CLI::log( '' );
		\WP_CLI::log( 'Summary' );
		\WP_CLI::log( str_repeat( '─', 40 ) );

		$summary_stages = [
			'Checksums' => [ 'Core checksums', 'Plugin integrity' ],
			'Themes'    => [ 'Themes' ],
			'Plugins'   => [ 'Plugins' ],
			'Uploads'   => [ 'Uploads' ],
			'Database'  => [ 'Database' ],
		];

		foreach ( $summary_stages as $label => $stages ) {
			$findings = 0;
			$has_stage = false;

			foreach ( $stages as $stage ) {
				if ( ! isset( $report['stages'][ $stage ] ) ) {
					continue;
				}

				$has_stage = true;
				$findings += (int) ( $report['stages'][ $stage ]['findings'] ?? 0 );
			}

			if ( ! $has_stage ) {
				continue;
			}

			$icon = 0 === $findings ? '✓' : '⚠';
			if ( 'Checksums' === $label ) {
				$status = 0 === $findings
					? 'no integrity issues'
					: sprintf( '%d integrity issue%s', $findings, 1 === $findings ? '' : 's' );
			} else {
				$status = 0 === $findings
					? 'no threats'
					: sprintf( '%d threat%s', $findings, 1 === $findings ? '' : 's' );
			}

			\WP_CLI::log( sprintf( '%s %-11s %s', $icon, $label, $status ) );
		}

		\WP_CLI::log( '' );
		\WP_CLI::log( sprintf( '  Critical         %d', $report['severity']['critical'] ) );
		\WP_CLI::log( sprintf( '  High             %d', $report['severity']['high'] ) );
		\WP_CLI::log( sprintf( '  Medium           %d', $report['severity']['medium'] ) );
		\WP_CLI::log( sprintf( '  Low              %d', $report['severity']['low'] ) );
		\WP_CLI::log( '' );
		\WP_CLI::log( sprintf( '  Files scanned    %s', number_format( $report['files_scanned'] ) ) );
		\WP_CLI::log( sprintf( '  DB rows scanned  %s', number_format( $report['database_rows'] ) ) );
		\WP_CLI::log( sprintf( '  Admin users      %s', number_format( $report['administrator_users'] ) ) );
		\WP_CLI::log( sprintf( '  Threats found    %s', number_format( $report['total_findings'] ) ) );
		\WP_CLI::log( sprintf( '  Scan time        %.2fs', $report['duration_seconds'] ) );


		\WP_CLI::log( str_repeat( '─', 40 ) );

		if ( $report['severity']['critical'] > 0 || $report['severity']['high'] > 0 ) {
			\WP_CLI::warning( 'High-confidence security findings require review.' );
		} else {
			\WP_CLI::success( 'Security scan completed.' );
		}
	}

	/**
	 * Render Markdown report.
	 */
	private function render_markdown( array $report ) {
		$lines = [];
		$lines[] = '# WordPress Security Scan';
		$lines[] = '';
		$lines[] = '## Summary';
		$lines[] = '';

		$summary_stages = [
			'Checksums' => [ 'Core checksums', 'Plugin integrity' ],
			'Themes'    => [ 'Themes' ],
			'Plugins'   => [ 'Plugins' ],
			'Uploads'   => [ 'Uploads' ],
			'Database'  => [ 'Database' ],
		];

		foreach ( $summary_stages as $label => $stages ) {
			$findings = 0;
			$has_stage = false;

			foreach ( $stages as $stage ) {
				if ( ! isset( $report['stages'][ $stage ] ) ) {
					continue;
				}

				$has_stage = true;
				$findings += (int) ( $report['stages'][ $stage ]['findings'] ?? 0 );
			}

			if ( ! $has_stage ) {
				continue;
			}

			$icon = 0 === $findings ? '✓' : '⚠';
			if ( 'Checksums' === $label ) {
				$status = 0 === $findings
					? 'no integrity issues'
					: sprintf( '%d integrity issue%s', $findings, 1 === $findings ? '' : 's' );
			} else {
				$status = 0 === $findings
					? 'no threats'
					: sprintf( '%d threat%s', $findings, 1 === $findings ? '' : 's' );
			}

			$lines[] = sprintf( '- %s %s: %s', $icon, $label, $status );
		}

		$lines[] = '';
		$lines[] = '- Critical: ' . $report['severity']['critical'];
		$lines[] = '- High: ' . $report['severity']['high'];
		$lines[] = '- Medium: ' . $report['severity']['medium'];
		$lines[] = '- Low: ' . $report['severity']['low'];
		$lines[] = '- Files scanned: ' . $report['files_scanned'];
		$lines[] = '- Database rows scanned: ' . $report['database_rows'];
		$lines[] = '- Administrator users: ' . $report['administrator_users'];
		$lines[] = '- Scan time: ' . $report['duration_seconds'] . 's';
		$lines[] = '';

		$sections = [];
		foreach ( $report['findings'] as $finding ) {
			$sections[ $finding['section'] ][] = $finding;
		}

		if ( isset( $report['stages']['Database'] ) && ! isset( $sections['Database'] ) ) {
			$sections['Database'] = [];
		}

		$sections = $this->order_report_sections( $sections );

		foreach ( $sections as $section => $findings ) {
			$lines[] = '## ' . $section;
			$lines[] = '';

			if ( 'Plugins' === $section ) {
				$lines = array_merge( $lines, $this->render_markdown_plugin_findings( $findings ) );
				continue;
			}

			if ( 'Plugin integrity' === $section ) {
				$lines = array_merge( $lines, $this->render_markdown_plugin_integrity_findings( $findings ) );
				continue;
			}

			if ( 'Core checksums' === $section ) {
				$lines[] = count( $findings ) . ' integrity issue' . ( 1 === count( $findings ) ? '' : 's' ) . ' found.';
			} else {
				$lines[] = count( $findings ) . ' threat' . ( 1 === count( $findings ) ? '' : 's' ) . ' found.';
			}
			if ( 'Database' === $section && isset( $report['stages']['Database']['items'] ) ) {
				$lines[] = '';
				$lines[] = $report['stages']['Database']['items'] . ' database rows scanned.';
			}
			$lines[] = '';

			if ( empty( $findings ) ) {
				continue;
			}

			$lines[] = '| Severity | Confidence | Location | Problem |';
			$lines[] = '| --- | ---: | --- | --- |';
			foreach ( $findings as $finding ) {
				$location = $finding['location'];
				if ( ! empty( $finding['line'] ) ) {
					$location .= ':' . $finding['line'];
				}
				$lines[] = sprintf(
					'| %s | %d%% | %s | %s |',
					strtoupper( $finding['severity'] ),
					$finding['confidence'],
					$this->markdown_escape( $location ),
					$this->markdown_escape( $finding['description'] )
				);
			}
			$lines[] = '';
		}


		return implode( PHP_EOL, $lines ) . PHP_EOL;
	}

	/**
	 * Write export to stdout or file.
	 */
	private function emit_export( $content, $output_file ) {
		if ( '' === $output_file ) {
			fwrite( STDOUT, $content );
			return;
		}

		$directory = dirname( $output_file );
		if ( ! is_dir( $directory ) && ! wp_mkdir_p( $directory ) ) {
			\WP_CLI::error( 'Unable to create export directory: ' . $directory );
		}

		if ( false === file_put_contents( $output_file, $content ) ) {
			\WP_CLI::error( 'Unable to write report: ' . $output_file );
		}

		\WP_CLI::success( 'Report written to ' . $output_file );
	}

	/**
	 * Build clusters based on suspicious file modification times.
	 */
	private function build_finding_mtime_clusters( array $findings ) {
		$buckets = [];

		foreach ( $findings as $finding ) {
			$location = $finding['location'];
			$path = WP_CONTENT_DIR . DIRECTORY_SEPARATOR . str_replace( '/', DIRECTORY_SEPARATOR, $location );
			if ( ! is_file( $path ) ) {
				continue;
			}

			$mtime = @filemtime( $path );
			if ( false === $mtime ) {
				continue;
			}

			$bucket = (int) floor( $mtime / 600 ) * 600;
			$buckets[ $bucket ][ $location ] = true;
		}

		$clusters = [];
		foreach ( $buckets as $timestamp => $paths ) {
			if ( count( $paths ) < 2 ) {
				continue;
			}

			$clusters[] = [
				'time'  => gmdate( 'Y-m-d H:i', $timestamp ) . ' UTC',
				'files' => count( $paths ),
			];
		}

		usort(
			$clusters,
			function ( $a, $b ) {
				return strcmp( $b['time'], $a['time'] );
			}
		);

		return array_slice( $clusters, 0, 10 );
	}

	/**
	 * Count findings for a stage.
	 */
	private function count_stage_findings( $stage ) {
		$count = 0;
		foreach ( $this->findings as $finding ) {
			if ( $finding['section'] === $stage ) {
				$count++;
			}
		}

		return $count;
	}

	/**
	 * Sort findings by severity, confidence, then location.
	 */
	private function sort_findings( $a, $b ) {
		$severity_compare = self::SEVERITY_WEIGHT[ $b['severity'] ] <=> self::SEVERITY_WEIGHT[ $a['severity'] ];
		if ( 0 !== $severity_compare ) {
			return $severity_compare;
		}

		$confidence_compare = $b['confidence'] <=> $a['confidence'];
		if ( 0 !== $confidence_compare ) {
			return $confidence_compare;
		}

		return strcmp( $a['location'], $b['location'] );
	}

	/**
	 * Build a readable database location.
	 */
	private function database_location( $table, $pk, array $row, $field, array $context_fields ) {
		$parts = [];
		foreach ( $context_fields as $context_field ) {
			if ( isset( $row[ $context_field ] ) && '' !== (string) $row[ $context_field ] ) {
				$parts[] = $context_field . '=' . $this->shorten( (string) $row[ $context_field ], 60 );
			}
		}

		$context = empty( $parts ) ? '' : ' (' . implode( ', ', $parts ) . ')';
		return basename( $table ) . '.' . $field . ' #' . $row[ $pk ] . $context;
	}

	/**
	 * Check if a DB table exists.
	 */
	private function database_table_exists( $table ) {
		global $wpdb;
		$like = $wpdb->esc_like( $table );
		$found = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $like ) );
		return $found === $table;
	}

	/**
	 * Quote a SQL identifier.
	 */
	private function quote_identifier( $identifier ) {
		return '`' . str_replace( '`', '``', $identifier ) . '`';
	}

	/**
	 * Return path relative to wp-content.
	 */
	private function relative_wp_content_path( $path ) {
		$base = rtrim( $this->normalize_path( WP_CONTENT_DIR ), '/' ) . '/';
		$normalized = $this->normalize_path( $path );

		if ( 0 === strpos( $normalized, $base ) ) {
			return substr( $normalized, strlen( $base ) );
		}

		return $normalized;
	}

	/**
	 * Normalize a filesystem path.
	 */
	private function normalize_path( $path ) {
		return str_replace( '\\', '/', wp_normalize_path( $path ) );
	}

	/**
	 * Strip common WP-CLI prefixes.
	 */
	private function strip_wp_cli_prefix( $line ) {
		return preg_replace( '~^(?:Warning|Error|Success):\s*~i', '', $line );
	}

	/**
	 * Shorten a string.
	 */
	private function shorten( $value, $length ) {
		$value = preg_replace( '/\s+/', ' ', trim( $value ) );
		if ( strlen( $value ) <= $length ) {
			return $value;
		}

		return substr( $value, 0, $length - 1 ) . '…';
	}

	/**
	 * Escape Markdown table text.
	 */
	private function markdown_escape( $value ) {
		return str_replace( [ '|', "\r", "\n" ], [ '\\|', ' ', ' ' ], $value );
	}
}

\WP_CLI::add_command( 'security-scan', 'Security_Scan_Command' );

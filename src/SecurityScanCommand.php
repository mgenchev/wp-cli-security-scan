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
	private const VERSION = '0.3.11';
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
	private const HTTP_PARALLEL_LIMIT = 6;

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
	private $full_scan = false;
	private $background_spinner_process = null;
	private $php_data_flow_analyzer = null;
	private $plugin_integrity = [];
	private $plugin_scan_files = [];
	private $inactive_plugins = [];
	private $active_theme_slugs = [];
	private $inactive_themes = [];
	private $launch_directory = '';

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
	 * [--skip-plugin-reputation]
	 * : Skip plugin source/repository reputation checks.
	 *
	 * [--skip-plugin-checksums]
	 * : Skip WordPress.org plugin checksum verification.
	 *
	 * [--include-node-modules]
	 * : Include node_modules directories in file scans. They are skipped by default.
	 *
	 * [--full-scan]
	 * : Include inactive regular plugins in reputation/checksum/static scans and inactive themes in static scans.
	 *
	 * ## EXAMPLES
	 *
	 *     wp security-scan
	 *     wp security-scan --format=markdown --output=security-report.md
	 *     wp security-scan --format=json
	 *     wp security-scan --full-scan
	 *
	 * @when before_wp_load
	 */
	public function __invoke( $args, $assoc_args ) {
		$sections = [
			'core',
			'plugin_reputation',
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
	 * ## OPTIONS
	 *
	 * [--full-scan]
	 * : Include inactive regular plugins in reputation, checksum, and static scans.
	 *
	 * @when before_wp_load
	 */
	public function plugins( $args, $assoc_args ) {
		$this->run( [ 'plugin_reputation', 'plugin_checksums', 'plugins', 'mu_plugins' ], $assoc_args );
	}

	/**
	 * Scan themes only.
	 *
	 * ## OPTIONS
	 *
	 * [--full-scan]
	 * : Include inactive themes in the static scan.
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
		$this->full_scan = isset( $assoc_args['full-scan'] );
		$this->suppress_wordpress_debug();
		$this->start_time = microtime( true );
		$this->launch_directory = $this->resolve_launch_directory();

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
		$this->initialize_theme_inventory();

		$skip_core = isset( $assoc_args['skip-core-checksums'] );
		$skip_plugin_reputation = isset( $assoc_args['skip-plugin-reputation'] );
		$skip_plugin_checksums = isset( $assoc_args['skip-plugin-checksums'] );

		if ( $this->interactive ) {
			$this->clear_spinner();
			\WP_CLI::log( '' );
			\WP_CLI::log( 'Security Scan' );
			\WP_CLI::log( str_repeat( '-', 50 ) );
			$this->render_scan_scope_notices( $sections );
		}

		foreach ( $sections as $section ) {
			switch ( $section ) {
				case 'core':
					if ( ! $skip_core ) {
						$this->scan_core_checksums();
					}
					break;

				case 'plugin_reputation':
					if ( ! $skip_plugin_reputation ) {
						$this->scan_plugin_reputation();
					}
					break;

				case 'plugin_checksums':
					if ( ! $skip_plugin_checksums ) {
						$this->scan_plugin_checksums();
					}
					break;

				case 'plugins':
					$this->scan_regular_plugins();
					break;

				case 'mu_plugins':
					$this->scan_mu_plugins_and_dropins();
					break;

				case 'themes':
					$this->scan_themes();
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
		$this->full_scan = false;
		$this->php_data_flow_analyzer = null;
		$this->plugin_integrity = [];
		$this->plugin_scan_files = [];
		$this->inactive_plugins = [];
		$this->active_theme_slugs = [];
		$this->inactive_themes = [];
		$this->launch_directory = '';
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

		foreach ( [ 'iocs', 'php', 'javascript', 'database', 'plugin-reputation' ] as $name ) {
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
						$description = 0 === strcasecmp( $matches[1], "File doesn't verify against checksum" )
							? 'Core file differs from the official WordPress checksum'
							: 'Unexpected file found in WordPress core';

						$this->add_finding( $stage, 'high', 96, $matches[2], 'core_checksum_mismatch', $description );
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

		$urls = [];
		foreach ( $this->plugin_integrity as $slug => $data ) {
			if ( 'external' === ( $data['source'] ?? '' ) ) {
				$this->set_plugin_integrity_status( $slug, 'unavailable' );
				continue;
			}

			$version = trim( (string) ( $data['version'] ?? '' ) );
			if ( '' === $version ) {
				$this->set_plugin_integrity_status( $slug, 'unavailable' );
				continue;
			}

			$urls[ $slug ] = sprintf(
				'https://downloads.wordpress.org/plugin-checksums/%s/%s.json',
				rawurlencode( $slug ),
				rawurlencode( $version )
			);
		}

		$responses = $this->fetch_json_urls_parallel( $urls, 'Scanning plugin integrity...' );
		foreach ( $urls as $slug => $url ) {
			$response = $responses[ $slug ] ?? null;
			if (
				! is_array( $response )
				|| 200 !== (int) ( $response['code'] ?? 0 )
				|| ! is_array( $response['json'] ?? null )
				|| ! isset( $response['json']['files'] )
				|| ! is_array( $response['json']['files'] )
			) {
				$this->set_plugin_integrity_status( $slug, 'unavailable' );
				continue;
			}

			$this->plugin_integrity[ $slug ]['source'] = 'wordpress.org';
			$this->plugin_integrity[ $slug ]['repository_status'] = 'available';
			if ( 'known-malicious' !== ( $this->plugin_integrity[ $slug ]['reputation'] ?? '' ) ) {
				$this->plugin_integrity[ $slug ]['reputation'] = 'known-source';
			}

			$this->verify_plugin_checksum_manifest( $slug, $response['json']['files'] );
		}

		$this->plugin_checksum_stage_finish( $stage );
	}

	/**
	 * Compare an installed plugin against an official WordPress.org checksum manifest.
	 *
	 * WordPress.org may publish more than one valid hash for a file. We prefer
	 * SHA-256 and fall back to MD5, mirroring the official WP-CLI checksum logic.
	 * Missing files from the local copy are not treated as errors because a
	 * named plugin version can have multiple valid package revisions. Local
	 * files absent from the manifest are treated as added files.
	 */
	private function verify_plugin_checksum_manifest( $slug, array $manifest ) {
		if ( ! isset( $this->plugin_integrity[ $slug ] ) ) {
			return;
		}

		$data = $this->plugin_integrity[ $slug ];
		$main_file = str_replace( '\\', '/', (string) ( $data['file'] ?? '' ) );
		$has_directory = false !== strpos( $main_file, '/' );
		$root = $has_directory
			? WP_PLUGIN_DIR . DIRECTORY_SEPARATOR . $slug
			: WP_PLUGIN_DIR;

		if ( ! is_dir( $root ) ) {
			$this->set_plugin_integrity_status( $slug, 'modified' );
			$this->plugin_integrity[ $slug ]['checksum_errors'][] = [
				'file'    => $main_file,
				'message' => 'Plugin directory referenced by the active plugin list could not be found',
			];
			return;
		}

		$normalized_manifest = [];
		foreach ( $manifest as $file => $hashes ) {
			$file = ltrim( str_replace( '\\', '/', (string) $file ), '/' );
			$slug_prefix = $slug . '/';
			if ( 0 === strpos( $file, $slug_prefix ) ) {
				$file = substr( $file, strlen( $slug_prefix ) );
			}
			$normalized_manifest[ $file ] = $hashes;
		}

		$errors = [];
		$iterator = new \RecursiveIteratorIterator(
			new \RecursiveDirectoryIterator( $root, \FilesystemIterator::SKIP_DOTS )
		);

		foreach ( $iterator as $file_info ) {
			if ( ! $file_info->isFile() || $file_info->isLink() ) {
				continue;
			}

			$current_count = isset( $this->stage_stats['Plugin integrity']['items'] )
				? (int) $this->stage_stats['Plugin integrity']['items'] + 1
				: 1;
			$this->stage_tick( 'Plugin integrity', $current_count, 'files' );

			$absolute = $file_info->getPathname();
			$relative = ltrim( str_replace( '\\', '/', substr( $absolute, strlen( $root ) ) ), '/' );
			if ( ! $has_directory ) {
				if ( $relative !== basename( $main_file ) ) {
					continue;
				}
			}

			if ( ! array_key_exists( $relative, $normalized_manifest ) ) {
				$errors[] = [ 'file' => $relative, 'message' => 'Local file is not part of the official plugin package' ];
				continue;
			}

			$hash_sets = $this->normalize_checksum_manifest_entry( $normalized_manifest[ $relative ] );
			$verified = false;

			if ( ! empty( $hash_sets['sha256'] ) && in_array( 'sha256', hash_algos(), true ) ) {
				$actual = @hash_file( 'sha256', $absolute );
				$verified = is_string( $actual ) && in_array( strtolower( $actual ), $hash_sets['sha256'], true );
			} elseif ( ! empty( $hash_sets['md5'] ) ) {
				$actual = @md5_file( $absolute );
				$verified = is_string( $actual ) && in_array( strtolower( $actual ), $hash_sets['md5'], true );
			}

			if ( ! $verified ) {
				$errors[] = [ 'file' => $relative, 'message' => 'File differs from the official plugin checksum' ];
			}
		}

		$this->plugin_integrity[ $slug ]['checksum_errors'] = $errors;
		$this->set_plugin_integrity_status( $slug, empty( $errors ) ? 'verified' : 'modified' );
	}

	/**
	 * Normalize the flexible WordPress.org checksum manifest entry format.
	 */
	private function normalize_checksum_manifest_entry( $entry ) {
		$result = [ 'sha256' => [], 'md5' => [] ];

		if ( is_string( $entry ) ) {
			$hash = strtolower( trim( $entry ) );
			if ( 64 === strlen( $hash ) ) {
				$result['sha256'][] = $hash;
			} elseif ( 32 === strlen( $hash ) ) {
				$result['md5'][] = $hash;
			}
			return $result;
		}

		if ( ! is_array( $entry ) ) {
			return $result;
		}

		foreach ( [ 'sha256', 'md5' ] as $algorithm ) {
			if ( ! array_key_exists( $algorithm, $entry ) ) {
				continue;
			}

			$values = is_array( $entry[ $algorithm ] ) ? $entry[ $algorithm ] : [ $entry[ $algorithm ] ];
			foreach ( $values as $value ) {
				if ( is_string( $value ) && '' !== trim( $value ) ) {
					$result[ $algorithm ][] = strtolower( trim( $value ) );
				}
			}
		}

		if ( empty( $result['sha256'] ) && empty( $result['md5'] ) ) {
			foreach ( $entry as $value ) {
				$nested = $this->normalize_checksum_manifest_entry( $value );
				$result['sha256'] = array_merge( $result['sha256'], $nested['sha256'] );
				$result['md5'] = array_merge( $result['md5'], $nested['md5'] );
			}
		}

		$result['sha256'] = array_values( array_unique( $result['sha256'] ) );
		$result['md5'] = array_values( array_unique( $result['md5'] ) );
		return $result;
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

		if ( ! function_exists( 'get_plugins' ) || ! function_exists( 'is_plugin_active' ) ) {
			return;
		}

		foreach ( get_plugins() as $file => $data ) {
			$file = str_replace( '\\', '/', (string) $file );
			$slug = $this->plugin_slug_from_main_file( $file );
			if ( '' === $slug ) {
				continue;
			}

			$is_active = is_plugin_active( $file );
			if ( ! $is_active ) {
				$this->inactive_plugins[] = [
					'slug' => $slug,
					'name' => isset( $data['Name'] ) ? (string) $data['Name'] : $slug,
					'file' => $file,
				];

				if ( ! $this->full_scan ) {
					continue;
				}
			}

			$this->plugin_scan_files[ $file ] = true;
			$this->plugin_integrity[ $slug ] = [
				'slug'              => $slug,
				'name'              => isset( $data['Name'] ) ? (string) $data['Name'] : $slug,
				'version'           => isset( $data['Version'] ) ? (string) $data['Version'] : '',
				'file'              => $file,
				'update_uri'        => isset( $data['UpdateURI'] ) ? (string) $data['UpdateURI'] : '',
				'plugin_uri'        => isset( $data['PluginURI'] ) ? (string) $data['PluginURI'] : '',
				'status'            => 'unverified',
				'checksum_errors'   => [],
				'repository_status' => 'unknown',
				'source'            => 'unknown',
				'reputation'        => 'unverified',
			];
		}
	}

	/**
	 * Build active/inactive theme inventory.
	 *
	 * The active child theme and its parent, when present, are both scanned.
	 */
	private function initialize_theme_inventory() {
		if ( ! function_exists( 'wp_get_themes' ) || ! function_exists( 'wp_get_theme' ) ) {
			return;
		}

		$active_theme = wp_get_theme();
		if ( $active_theme && $active_theme->exists() ) {
			$stylesheet = (string) $active_theme->get_stylesheet();
			if ( '' !== $stylesheet ) {
				$this->active_theme_slugs[ $stylesheet ] = true;
			}

			$parent = $active_theme->parent();
			if ( $parent && $parent->exists() ) {
				$parent_stylesheet = (string) $parent->get_stylesheet();
				if ( '' !== $parent_stylesheet ) {
					$this->active_theme_slugs[ $parent_stylesheet ] = true;
				}
			}
		}

		foreach ( wp_get_themes() as $slug => $theme ) {
			if ( isset( $this->active_theme_slugs[ (string) $slug ] ) ) {
				continue;
			}

			$this->inactive_themes[] = [
				'slug' => (string) $slug,
				'name' => (string) $theme->get( 'Name' ),
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
	 * Evaluate plugin source/repository reputation before checksum verification.
	 *
	 * A single WordPress.org update-check request identifies plugins currently
	 * known to the official directory. Only unresolved plugins require a
	 * follow-up plugin-information request, which avoids the previous one HTTP
	 * request per verified plugin bottleneck.
	 */
	private function scan_plugin_reputation() {
		$stage = 'Plugin reputation';
		$this->stage_start( $stage );

		$before = $this->count_plugin_reputation_findings();
		$this->apply_local_plugin_reputation_signals();

		$plugins = $this->get_installed_plugin_data();
		if ( ! empty( $plugins ) && function_exists( 'wp_remote_post' ) ) {
			$response = $this->request_wordpress_org_plugin_inventory( $plugins );
			if ( is_array( $response ) ) {
				$this->apply_wordpress_org_inventory_response( $response );
				$this->probe_unresolved_plugin_repository_status();
			}
		}

		$findings = max( 0, $this->count_plugin_reputation_findings() - $before );
		$this->plugin_reputation_stage_finish( $stage, $findings );
	}

	/**
	 * Return installed regular plugin data keyed by plugin main file.
	 */
	private function get_installed_plugin_data() {
		if ( ! function_exists( 'get_plugins' ) ) {
			$plugin_file = defined( 'ABSPATH' ) ? ABSPATH . 'wp-admin/includes/plugin.php' : '';
			if ( '' !== $plugin_file && is_file( $plugin_file ) ) {
				require_once $plugin_file;
			}
		}

		if ( ! function_exists( 'get_plugins' ) ) {
			return [];
		}

		$plugins = get_plugins();
		return array_intersect_key( $plugins, $this->plugin_scan_files );
	}

	/**
	 * Apply high-confidence local reputation signals that need no network call.
	 */
	private function apply_local_plugin_reputation_signals() {
		foreach ( $this->plugin_integrity as $slug => &$data ) {
			$update_uri = trim( (string) ( $data['update_uri'] ?? '' ) );
			if ( '' !== $update_uri ) {
				$host = strtolower( (string) wp_parse_url( $update_uri, PHP_URL_HOST ) );
				if ( '' !== $host && ! $this->is_wordpress_org_host( $host ) ) {
					$data['source'] = 'external';
					$data['repository_status'] = 'external';
					$data['reputation'] = 'unverified-source';
				}
			}

			foreach ( (array) ( $this->rules['plugin-reputation'] ?? [] ) as $rule ) {
				$slugs = isset( $rule['slugs'] ) && is_array( $rule['slugs'] ) ? $rule['slugs'] : [];
				if ( ! in_array( $slug, $slugs, true ) ) {
					continue;
				}

				$versions = isset( $rule['versions'] ) && is_array( $rule['versions'] ) ? $rule['versions'] : [];
				if ( ! empty( $versions ) && ! in_array( (string) ( $data['version'] ?? '' ), $versions, true ) ) {
					continue;
				}

				$data['reputation'] = 'known-malicious';
				$this->add_finding(
					'Plugins',
					(string) ( $rule['severity'] ?? 'critical' ),
					(int) ( $rule['confidence'] ?? 99 ),
					'plugins/' . $slug,
					(string) ( $rule['id'] ?? 'plugin_reputation_known_malicious' ),
					(string) ( $rule['description'] ?? 'Known malicious plugin reputation indicator' )
				);
			}
		}
		unset( $data );
	}

	/**
	 * Send one read-only update-check request for the complete plugin inventory.
	 */
	private function request_wordpress_org_plugin_inventory( array $plugins ) {
		$active = function_exists( 'get_option' ) ? (array) get_option( 'active_plugins', [] ) : [];
		$payload = [
			'plugins' => $plugins,
			'active'  => $active,
		];

		$locales = function_exists( 'get_available_languages' ) ? (array) get_available_languages() : [];
		if ( function_exists( 'get_locale' ) ) {
			$locales[] = get_locale();
		}
		$locales = array_values( array_unique( array_filter( $locales ) ) );

		$timeout = max( 5, 3 + (int) ( count( $plugins ) / 10 ) );
		$response = wp_remote_post(
			'https://api.wordpress.org/plugins/update-check/1.1/',
			[
				'timeout'    => $timeout,
				'body'       => [
					'plugins'      => wp_json_encode( $payload ),
					'translations' => wp_json_encode( [] ),
					'locale'       => wp_json_encode( $locales ),
					'all'          => wp_json_encode( true ),
				],
				'user-agent' => 'WP-CLI Security Scan/' . self::VERSION,
			]
		);

		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return null;
		}

		$body = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		return is_array( $body ) ? $body : null;
	}

	/**
	 * Mark plugins returned by the official update API as WordPress.org source.
	 */
	private function apply_wordpress_org_inventory_response( array $response ) {
		$known_files = [];
		foreach ( [ 'plugins', 'no_update' ] as $bucket ) {
			if ( empty( $response[ $bucket ] ) || ! is_array( $response[ $bucket ] ) ) {
				continue;
			}

			foreach ( $response[ $bucket ] as $plugin_file => $metadata ) {
				$known_files[] = str_replace( '\\', '/', (string) $plugin_file );
			}
		}

		foreach ( $known_files as $plugin_file ) {
			$slug = $this->plugin_slug_from_main_file( $plugin_file );
			if ( '' === $slug || ! isset( $this->plugin_integrity[ $slug ] ) ) {
				continue;
			}

			$this->plugin_integrity[ $slug ]['source'] = 'wordpress.org';
			$this->plugin_integrity[ $slug ]['repository_status'] = 'available';
			if ( 'known-malicious' !== $this->plugin_integrity[ $slug ]['reputation'] ) {
				$this->plugin_integrity[ $slug ]['reputation'] = 'known-source';
			}
		}
	}

	/**
	 * Probe only unresolved slugs individually for closed/disabled status.
	 */
	private function probe_unresolved_plugin_repository_status() {
		$urls = [];
		foreach ( $this->plugin_integrity as $slug => $data ) {
			if ( 'unknown' !== ( $data['repository_status'] ?? 'unknown' ) ) {
				continue;
			}

			$urls[ $slug ] = 'https://api.wordpress.org/plugins/info/1.2/?' . http_build_query(
				[
					'action'  => 'plugin_information',
					'request' => [
						'slug'   => $slug,
						'fields' => [
							'sections'        => false,
							'banners'         => false,
							'icons'           => false,
							'active_installs' => false,
						],
					],
				]
			);
		}

		$responses = $this->fetch_json_urls_parallel( $urls, 'Checking plugin reputation...' );
		foreach ( $urls as $slug => $url ) {
			$response = $responses[ $slug ] ?? null;
			if ( ! is_array( $response ) ) {
				continue;
			}

			$status = $this->classify_plugin_information_response(
				(int) ( $response['code'] ?? 0 ),
				is_array( $response['json'] ?? null ) ? $response['json'] : null
			);

			if ( 'available' === $status ) {
				$this->plugin_integrity[ $slug ]['source'] = 'wordpress.org';
				$this->plugin_integrity[ $slug ]['repository_status'] = 'available';
				if ( 'known-malicious' !== $this->plugin_integrity[ $slug ]['reputation'] ) {
					$this->plugin_integrity[ $slug ]['reputation'] = 'known-source';
				}
				continue;
			}

			if ( in_array( $status, [ 'closed', 'disabled' ], true ) ) {
				$this->plugin_integrity[ $slug ]['source'] = 'wordpress.org';
				$this->plugin_integrity[ $slug ]['repository_status'] = $status;
				$this->plugin_integrity[ $slug ]['reputation'] = 'repository-risk';
				$this->add_finding(
					'Plugins',
					'high',
					94,
					'plugins/' . $slug,
					'plugin_reputation_repository_' . $status,
					'Plugin is ' . $status . ' on WordPress.org; verify the repository status and plugin source'
				);
				continue;
			}

			if ( 'not-found' === $status ) {
				$this->plugin_integrity[ $slug ]['source'] = 'unknown';
				$this->plugin_integrity[ $slug ]['repository_status'] = 'not-found';
				if ( 'known-malicious' !== $this->plugin_integrity[ $slug ]['reputation'] ) {
					$this->plugin_integrity[ $slug ]['reputation'] = 'unverified-source';
				}
			}
		}
	}

	/**
	 * Fetch multiple JSON URLs concurrently when cURL multi is available.
	 *
	 * TLS verification is never disabled. The sequential WordPress HTTP API is
	 * used as a compatibility fallback.
	 */
	private function fetch_json_urls_parallel( array $urls, $spinner_message ) {
		if ( empty( $urls ) ) {
			return [];
		}

		if ( ! function_exists( 'curl_multi_init' ) || ! function_exists( 'curl_init' ) ) {
			return $this->fetch_json_urls_sequential( $urls, $spinner_message );
		}

		$multi = curl_multi_init();
		if ( false === $multi ) {
			return $this->fetch_json_urls_sequential( $urls, $spinner_message );
		}

		$queue = [];
		foreach ( $urls as $key => $url ) {
			$queue[] = [ 'key' => $key, 'url' => $url ];
		}

		$active = [];
		$results = [];
		$total = count( $queue );
		$completed = 0;
		$offset = 0;

		$add_next = function () use ( &$queue, &$offset, &$active, $multi ) {
			if ( ! isset( $queue[ $offset ] ) ) {
				return false;
			}

			$item = $queue[ $offset++ ];
			$handle = curl_init();
			curl_setopt_array(
				$handle,
				[
					CURLOPT_URL            => $item['url'],
					CURLOPT_RETURNTRANSFER => true,
					CURLOPT_FOLLOWLOCATION => false,
					CURLOPT_CONNECTTIMEOUT => 8,
					CURLOPT_TIMEOUT        => 20,
					CURLOPT_SSL_VERIFYPEER => true,
					CURLOPT_SSL_VERIFYHOST => 2,
					CURLOPT_ENCODING       => '',
					CURLOPT_USERAGENT      => 'WP-CLI Security Scan/' . self::VERSION,
				]
			);
			curl_multi_add_handle( $multi, $handle );
			$handle_id = is_object( $handle ) ? spl_object_id( $handle ) : (int) $handle;
			$active[ $handle_id ] = [ 'handle' => $handle, 'key' => $item['key'] ];
			return true;
		};

		while ( count( $active ) < self::HTTP_PARALLEL_LIMIT && $add_next() ) {
		}

		do {
			do {
				$status = curl_multi_exec( $multi, $running );
			} while ( CURLM_CALL_MULTI_PERFORM === $status );

			while ( $info = curl_multi_info_read( $multi ) ) {
				$handle = $info['handle'];
				$id = is_object( $handle ) ? spl_object_id( $handle ) : (int) $handle;
				$item = $active[ $id ] ?? null;
				if ( null === $item ) {
					continue;
				}

				$body = curl_multi_getcontent( $handle );
				$code = (int) curl_getinfo( $handle, CURLINFO_HTTP_CODE );
				$results[ $item['key'] ] = [
					'code'  => $code,
					'body'  => is_string( $body ) ? $body : '',
					'json'  => is_string( $body ) ? json_decode( $body, true ) : null,
					'error' => CURLE_OK === (int) $info['result'] ? '' : curl_error( $handle ),
				];

				curl_multi_remove_handle( $multi, $handle );
				curl_close( $handle );
				unset( $active[ $id ] );
				$completed++;
				while ( count( $active ) < self::HTTP_PARALLEL_LIMIT && $add_next() ) {
				}
			}

			if ( $this->interactive ) {
				$this->render_spinner( sprintf( '%s %d/%d', $spinner_message, $completed, $total ) );
			}

			if ( $running > 0 ) {
				$selected = curl_multi_select( $multi, 0.15 );
				if ( -1 === $selected ) {
					usleep( 10000 );
				}
			}
		} while ( $running > 0 || ! empty( $active ) );

		curl_multi_close( $multi );

		$retry_urls = [];
		foreach ( $urls as $key => $url ) {
			if ( ! isset( $results[ $key ] ) || ( 0 === (int) ( $results[ $key ]['code'] ?? 0 ) && '' !== (string) ( $results[ $key ]['error'] ?? '' ) ) ) {
				$retry_urls[ $key ] = $url;
			}
		}

		if ( ! empty( $retry_urls ) ) {
			$retry_results = $this->fetch_json_urls_sequential( $retry_urls, $spinner_message );
			foreach ( $retry_results as $key => $result ) {
				$results[ $key ] = $result;
			}
		}

		return $results;
	}

	/**
	 * Sequential compatibility fallback for JSON HTTP requests.
	 */
	private function fetch_json_urls_sequential( array $urls, $spinner_message ) {
		$results = [];
		$total = count( $urls );
		$index = 0;

		foreach ( $urls as $key => $url ) {
			$index++;
			if ( $this->interactive ) {
				$this->start_background_spinner( sprintf( '%s %d/%d', $spinner_message, $index, $total ) );
			}

			try {
				$response = wp_remote_get( $url, [ 'timeout' => 20, 'user-agent' => 'WP-CLI Security Scan/' . self::VERSION ] );
			} finally {
				if ( $this->interactive ) {
					$this->stop_background_spinner();
				}
			}
			if ( is_wp_error( $response ) ) {
				$results[ $key ] = [ 'code' => 0, 'body' => '', 'json' => null, 'error' => $response->get_error_message() ];
				continue;
			}

			$body = (string) wp_remote_retrieve_body( $response );
			$results[ $key ] = [
				'code'  => (int) wp_remote_retrieve_response_code( $response ),
				'body'  => $body,
				'json'  => json_decode( $body, true ),
				'error' => '',
			];
		}

		return $results;
	}

	/**
	 * Classify a WordPress.org plugin-information API response.
	 */
	private function classify_plugin_information_response( $http_code, $body ) {
		if ( is_array( $body ) ) {
			if ( ! empty( $body['slug'] ) || ! empty( $body['name'] ) ) {
				return 'available';
			}

			$context = strtolower(
				implode(
					' ',
					array_filter(
						[
							(string) ( $body['error'] ?? '' ),
							(string) ( $body['code'] ?? '' ),
							(string) ( $body['message'] ?? '' ),
							(string) ( $body['reason'] ?? '' ),
						],
					)
				)
			);
			if ( false !== strpos( $context, 'disabled' ) ) {
				return 'disabled';
			}
			if ( false !== strpos( $context, 'closed' ) ) {
				return 'closed';
			}
			if ( false !== strpos( $context, 'not found' ) || false !== strpos( $context, 'not_found' ) ) {
				return 'not-found';
			}
		}

		return 404 === (int) $http_code ? 'not-found' : 'unknown';
	}

	/**
	 * Whether a hostname belongs to WordPress.org.
	 */
	private function is_wordpress_org_host( $host ) {
		$host = strtolower( trim( (string) $host, '.' ) );
		return 'wordpress.org' === $host || substr( $host, -14 ) === '.wordpress.org';
	}

	/**
	 * Count independent plugin reputation findings.
	 */
	private function count_plugin_reputation_findings() {
		$count = 0;
		foreach ( $this->findings as $finding ) {
			if ( 0 === strpos( (string) ( $finding['rule'] ?? '' ), 'plugin_reputation_' ) ) {
				$count++;
			}
		}
		return $count;
	}

	/**
	 * Finish plugin reputation with source-status counts.
	 */
	private function plugin_reputation_stage_finish( $stage, $findings ) {
		$counts = [
			'wordpress.org' => 0,
			'external'      => 0,
			'unknown'       => 0,
			'risky'         => 0,
		];

		foreach ( $this->plugin_integrity as $data ) {
			$source = (string) ( $data['source'] ?? 'unknown' );
			if ( isset( $counts[ $source ] ) ) {
				$counts[ $source ]++;
			} else {
				$counts['unknown']++;
			}
			if ( in_array( (string) ( $data['reputation'] ?? '' ), [ 'repository-risk', 'known-malicious' ], true ) ) {
				$counts['risky']++;
			}
		}

		if ( isset( $this->stage_stats[ $stage ] ) ) {
			$this->stage_stats[ $stage ]['items'] = count( $this->plugin_integrity );
			$this->stage_stats[ $stage ]['findings'] = $findings;
			$this->stage_stats[ $stage ]['wordpress_org_plugins'] = $counts['wordpress.org'];
			$this->stage_stats[ $stage ]['external_plugins'] = $counts['external'];
			$this->stage_stats[ $stage ]['unknown_plugins'] = $counts['unknown'];
			$this->stage_stats[ $stage ]['risky_plugins'] = $counts['risky'];
		}

		if ( ! $this->interactive ) {
			return;
		}

		$this->clear_spinner();
		$risk_count = max( $findings, $counts['risky'] );
		$icon = 0 === $risk_count ? '✓' : '⚠';
		$status = 0 === $risk_count
			? 'no threats found'
			: sprintf( '%d threat%s found', $risk_count, 1 === $risk_count ? '' : 's' );

		\WP_CLI::log( sprintf( '%s Plugin reputation checked — %s', $icon, $status ) );
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

		if ( isset( $this->stage_stats[ $stage ] ) ) {
			$this->stage_stats[ $stage ]['items'] = null;
			$this->stage_stats[ $stage ]['findings'] = 0;
			$this->stage_stats[ $stage ]['verified_plugins'] = $counts['verified'];
			$this->stage_stats[ $stage ]['modified_plugins'] = $counts['modified'];
			$this->stage_stats[ $stage ]['unavailable_plugins'] = $counts['unavailable'];
			$this->stage_stats[ $stage ]['unverified_plugins'] = $counts['unverified'];
		}

		if ( ! $this->interactive ) {
			return;
		}

		$this->clear_spinner();
		$has_integrity_warning = ( $counts['modified'] + $counts['unavailable'] + $counts['unverified'] ) > 0;
		$icon = $has_integrity_warning ? '⚠' : '✓';
		$parts = [];
		if ( $counts['verified'] > 0 ) {
			$parts[] = sprintf( '%d verified', $counts['verified'] );
		}
		if ( $counts['modified'] > 0 ) {
			$parts[] = sprintf( '%d modified', $counts['modified'] );
		}
		if ( $counts['unavailable'] > 0 ) {
			$parts[] = sprintf( '%d unavailable', $counts['unavailable'] );
		}
		if ( $counts['unverified'] > 0 ) {
			$parts[] = sprintf( '%d unverified', $counts['unverified'] );
		}

		$status = empty( $parts ) ? 'no eligible plugins' : implode( ', ', $parts );
		\WP_CLI::log( sprintf( '%s Plugin integrity checked — %s', $icon, $status ) );
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
	 * Print the plugin/theme scan scope selected for this run.
	 */
	private function render_scan_scope_notices( array $sections ) {
		$show_plugins = (bool) array_intersect( [ 'plugin_reputation', 'plugin_checksums', 'plugins' ], $sections );
		$show_themes = in_array( 'themes', $sections, true );

		if ( $show_plugins ) {
			\WP_CLI::log( $this->full_scan
				? 'Plugin scope: all installed regular plugins.'
				: 'Plugin scope: active plugins only.' );
		}

		if ( $show_themes ) {
			\WP_CLI::log( $this->full_scan
				? 'Theme scope: all installed themes.'
				: 'Theme scope: active theme and parent theme only, when applicable.' );
		}

		if ( $show_plugins || $show_themes ) {
			\WP_CLI::log( '' );
		}
	}

	/**
	 * Scan regular plugins selected by the current scan scope.
	 */
	private function scan_regular_plugins() {
		$stage = 'Plugins';
		$this->stage_start( $stage );
		$count = 0;
		$roots = [];

		foreach ( $this->plugin_integrity as $data ) {
			$main_file = str_replace( '/', DIRECTORY_SEPARATOR, (string) ( $data['file'] ?? '' ) );
			if ( '' === $main_file ) {
				continue;
			}

			$relative_dir = dirname( $main_file );
			$root = '.' === $relative_dir
				? WP_PLUGIN_DIR . DIRECTORY_SEPARATOR . $main_file
				: WP_PLUGIN_DIR . DIRECTORY_SEPARATOR . $relative_dir;
			$roots[ $this->normalize_path( $root ) ] = $root;
		}

		foreach ( $roots as $root ) {
			if ( is_file( $root ) ) {
				$count++;
				$this->scanned_files++;
				$this->stage_tick( $stage, $count, 'files' );
				$this->scan_file( $stage, $root, false );
				continue;
			}

			if ( ! is_dir( $root ) ) {
				continue;
			}

			$iterator = $this->create_scan_iterator( $root );
			foreach ( $iterator as $item ) {
				if ( $item->isLink() ) {
					$this->scan_symlink( $stage, $item->getPathname() );
					continue;
				}
				if ( ! $item->isFile() ) {
					continue;
				}

				$count++;
				$this->scanned_files++;
				$this->stage_tick( $stage, $count, 'files' );
				$this->scan_file( $stage, $item->getPathname(), false );
			}
		}

		$this->stage_finish( $stage, $count, $this->count_reportable_plugin_findings() );
	}

	/**
	 * Return theme slugs selected by the current scan scope.
	 */
	private function theme_slugs_for_scan() {
		$slugs = array_keys( $this->active_theme_slugs );

		if ( $this->full_scan ) {
			foreach ( $this->inactive_themes as $theme ) {
				$slug = (string) ( $theme['slug'] ?? '' );
				if ( '' !== $slug ) {
					$slugs[] = $slug;
				}
			}
		}

		return array_values( array_unique( $slugs ) );
	}

	/**
	 * Scan themes selected by the current scan scope.
	 */
	private function scan_themes() {
		$stage = 'Themes';
		$this->stage_start( $stage );
		$count = 0;

		foreach ( $this->theme_slugs_for_scan() as $slug ) {
			$theme = wp_get_theme( $slug );
			if ( ! $theme || ! $theme->exists() ) {
				continue;
			}

			$root = get_theme_root( $slug ) . DIRECTORY_SEPARATOR . $slug;
			if ( ! is_dir( $root ) ) {
				continue;
			}

			$iterator = $this->create_scan_iterator( $root );
			foreach ( $iterator as $item ) {
				if ( $item->isLink() ) {
					$this->scan_symlink( $stage, $item->getPathname() );
					continue;
				}
				if ( ! $item->isFile() ) {
					continue;
				}

				$count++;
				$this->scanned_files++;
				$this->stage_tick( $stage, $count, 'files' );
				$this->scan_file( $stage, $item->getPathname(), false );
			}
		}

		$this->stage_finish( $stage, $count, $this->count_stage_findings( $stage ) );
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
			'wp-antymalwary-bot.php' => 'Filename matches a known malicious fake WordPress plugin',
			'wp-apx-upx.php'        => 'Filename matches a known malicious WordPress file-uploader',
			'wp-apxupx.php'         => 'Filename matches a known malicious WordPress file-uploader',
		];

		if ( isset( $known_malicious_filenames[ $lower_filename ] ) ) {
			$this->add_file_finding_once( $seen, $stage, 'critical', 98, $relative, 'known_malicious_filename', $known_malicious_filenames[ $lower_filename ] );
		}

		if ( $is_uploads && in_array( $extension, self::UPLOAD_EXECUTABLE_EXTENSIONS, true ) ) {
			$this->add_file_finding_once( $seen, $stage, 'high', 96, $relative, 'uploads_executable', 'Executable/script file found inside uploads' );
		}

		if ( preg_match( '~\.(?:jpe?g|png|gif|webp|svg|ico|pdf|zip)\.(?:php\d*|phtml|phar)$~i', $filename ) ) {
			$this->add_file_finding_once( $seen, $stage, 'critical', 99, $relative, 'double_extension', 'File uses a media/document extension followed by an executable PHP extension' );
		}

		if ( preg_match( '~\.php\.(?:bak|old|orig|save|txt|disabled)$~i', $filename ) ) {
			$this->add_file_finding_once( $seen, $stage, 'medium', 70, $relative, 'php_backup_file', 'Backup copy of an executable PHP file requires review' );
		}

		if ( in_array( strtolower( $filename ), [ '.user.ini', 'php.ini' ], true ) ) {
			$content = @file_get_contents( $path );
			$matches = [];
			if ( is_string( $content ) && 1 === preg_match( '~auto_(?:prepend|append)_file\s*=~i', $content, $matches, PREG_OFFSET_CAPTURE ) ) {
				$line = $this->line_from_buffer_offset( $content, 1, $matches[0][1] );
				$this->add_file_finding_once( $seen, $stage, 'critical', 98, $relative, 'php_auto_prepend', 'PHP configuration enables auto_prepend_file/auto_append_file persistence', $line );
			}
		}

		if ( '.htaccess' === strtolower( $filename ) ) {
			$content = @file_get_contents( $path );
			$matches = [];
			if ( is_string( $content ) && 1 === preg_match( '~(?:AddType|AddHandler|SetHandler)[^\r\n]*(?:php|x-httpd-php)~i', $content, $matches, PREG_OFFSET_CAPTURE ) ) {
				$line = $this->line_from_buffer_offset( $content, 1, $matches[0][1] );
				$this->add_file_finding_once( $seen, $stage, 'critical', 98, $relative, 'htaccess_php_handler', '.htaccess enables PHP execution for additional file types', $line );
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
		\WP_CLI::log( sprintf( '%s %s scanned — %s', $icon, $stage, $suffix ) );
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
		$scan_log_path = $this->write_scan_log( $report );
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

		$this->render_terminal_report( $report, $scan_log_path );
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

		$report_stages = $this->stage_stats;
		unset( $report_stages['Plugin integrity'] );

		return [
			'package_version'   => self::VERSION,
			'scanned_at'        => gmdate( 'c' ),
			'duration_seconds'  => round( microtime( true ) - $this->start_time, 2 ),
			'files_scanned'     => $this->scanned_files,
			'database_rows'     => $this->scanned_db_rows,
			'administrator_users' => $this->admin_count,
			'severity'          => $severity_counts,
			'total_findings'    => count( $findings ),
			'stages'            => $report_stages,
			'findings'          => $findings,
		];
	}

	/**
	 * Order report sections for predictable human-readable output.
	 */
	private function order_report_sections( array $sections ) {
		$order = [
			'Core checksums',
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
			if ( 'Plugin integrity' === $finding['section'] ) {
				continue;
			}

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
	 * Return the detected plugin source classification.
	 */
	private function plugin_source_status( $plugin ) {
		if ( null === $plugin || '' === $plugin || ! isset( $this->plugin_integrity[ $plugin ] ) ) {
			return 'unknown';
		}

		return isset( $this->plugin_integrity[ $plugin ]['source'] )
			? (string) $this->plugin_integrity[ $plugin ]['source']
			: 'unknown';
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
					'source'     => $this->plugin_source_status( $plugin ),
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
	 * Build a wp-content-relative plugin finding location.
	 *
	 * Keep the plugins/<slug>/ prefix visible so findings are immediately
	 * understandable when copied out of the grouped plugin report.
	 */
	private function plugin_relative_finding_location( array $finding, $plugin ) {
		$location = ltrim( str_replace( '\\', '/', (string) $finding['location'] ), '/' );

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
	 * Count checksum changes recorded for a plugin.
	 */
	private function plugin_integrity_change_count( $plugin ) {
		if ( ! isset( $this->plugin_integrity[ $plugin ]['checksum_errors'] ) ) {
			return 0;
		}

		return count( (array) $this->plugin_integrity[ $plugin ]['checksum_errors'] );
	}



	/**
	 * Group plugin checksum changes by problem while preserving every affected path.
	 */
	private function group_plugin_integrity_changes_by_problem() {
		$groups = [];

		foreach ( $this->modified_plugin_slugs() as $slug ) {
			$errors = (array) ( $this->plugin_integrity[ $slug ]['checksum_errors'] ?? [] );
			foreach ( $errors as $error ) {
				$problem = trim( (string) ( $error['message'] ?? '' ) );
				if ( '' === $problem ) {
					$problem = 'Integrity mismatch';
				}

				$file = ltrim( str_replace( '\\', '/', (string) ( $error['file'] ?? '' ) ), '/' );
				$location = 'plugins/' . $slug;
				if ( '' !== $file ) {
					$location .= '/' . $file;
				}

				$groups[ $problem ][] = $location;
			}
		}

		ksort( $groups, SORT_STRING );
		foreach ( $groups as &$locations ) {
			sort( $locations, SORT_STRING );
		}
		unset( $locations );

		return $groups;
	}

	/**
	 * Return plugins whose installed files differ from the official checksum manifest.
	 */
	private function modified_plugin_slugs() {
		$slugs = [];
		foreach ( $this->plugin_integrity as $slug => $data ) {
			if ( 'modified' === ( $data['status'] ?? '' ) ) {
				$slugs[] = (string) $slug;
			}
		}

		sort( $slugs, SORT_STRING );
		return $slugs;
	}

	/**
	 * Group findings by the actual problem/rule while preserving every path.
	 */
	private function group_findings_by_issue( array $findings ) {
		$groups = [];
		foreach ( $findings as $finding ) {
			$key = ! empty( $finding['rule'] ) ? (string) $finding['rule'] : md5( (string) $finding['description'] );
			if ( ! isset( $groups[ $key ] ) ) {
				$groups[ $key ] = [
					'rule'        => (string) ( $finding['rule'] ?? '' ),
					'description' => (string) $finding['description'],
					'severity'    => (string) $finding['severity'],
					'confidence'  => (int) $finding['confidence'],
					'findings'    => [],
				];
			}

			$groups[ $key ]['findings'][] = $finding;
			if (
				self::SEVERITY_WEIGHT[ $finding['severity'] ] > self::SEVERITY_WEIGHT[ $groups[ $key ]['severity'] ]
				|| (
					$finding['severity'] === $groups[ $key ]['severity']
					&& (int) $finding['confidence'] > (int) $groups[ $key ]['confidence']
				)
			) {
				$groups[ $key ]['severity'] = (string) $finding['severity'];
				$groups[ $key ]['confidence'] = (int) $finding['confidence'];
				$groups[ $key ]['description'] = (string) $finding['description'];
			}
		}

		$groups = array_values( $groups );
		usort(
			$groups,
			static function ( $a, $b ) {
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

		return $groups;
	}

	/**
	 * Group findings by their human-readable problem while preserving locations.
	 *
	 * Core checksum findings intentionally share a rule ID for multiple checksum
	 * outcomes, so grouping them by rule would merge distinct problems.
	 */
	private function group_findings_by_problem( array $findings ) {
		$groups = [];
		foreach ( $findings as $finding ) {
			$key = (string) ( $finding['description'] ?? '' );
			if ( ! isset( $groups[ $key ] ) ) {
				$groups[ $key ] = [
					'description' => $key,
					'severity'    => (string) $finding['severity'],
					'confidence'  => (int) $finding['confidence'],
					'findings'    => [],
				];
			}

			$groups[ $key ]['findings'][] = $finding;
			if (
				self::SEVERITY_WEIGHT[ $finding['severity'] ] > self::SEVERITY_WEIGHT[ $groups[ $key ]['severity'] ]
				|| (
					$finding['severity'] === $groups[ $key ]['severity']
					&& (int) $finding['confidence'] > (int) $groups[ $key ]['confidence']
				)
			) {
				$groups[ $key ]['severity'] = (string) $finding['severity'];
				$groups[ $key ]['confidence'] = (int) $finding['confidence'];
			}
		}

		$groups = array_values( $groups );
		usort(
			$groups,
			static function ( $a, $b ) {
				$severity_compare = self::SEVERITY_WEIGHT[ $b['severity'] ] <=> self::SEVERITY_WEIGHT[ $a['severity'] ];
				if ( 0 !== $severity_compare ) {
					return $severity_compare;
				}
				$confidence_compare = $b['confidence'] <=> $a['confidence'];
				if ( 0 !== $confidence_compare ) {
					return $confidence_compare;
				}
				return strcmp( $a['description'], $b['description'] );
			}
		);

		return $groups;
	}

	/**
	 * Build a complete finding location with source line when available.
	 */
	private function finding_location( array $finding ) {
		$location = (string) $finding['location'];
		if ( ! empty( $finding['line'] ) ) {
			$location .= ':' . $finding['line'];
		}
		return $location;
	}

	/**
	 * Render a normal section grouped by problem and preserving all locations.
	 */
	private function render_terminal_grouped_findings( array $findings ) {
		foreach ( $this->group_findings_by_issue( $findings ) as $issue ) {
			$count = count( $issue['findings'] );
			$label = strtoupper( $issue['severity'] ) . ' · ' . $issue['confidence'] . '%';
			$suffix = $count > 1 ? sprintf( ' (%d occurrences)', $count ) : '';
			\WP_CLI::log( sprintf( '%-16s %s%s', $label, $issue['description'], $suffix ) );
			foreach ( $issue['findings'] as $finding ) {
				\WP_CLI::log( str_repeat( ' ', 17 ) . $this->finding_location( $finding ) );
			}
			\WP_CLI::log( '' );
		}
	}

	/**
	 * Render grouped findings as Markdown while preserving all locations.
	 */
	private function render_markdown_grouped_findings( array $findings ) {
		$lines = [];
		foreach ( $this->group_findings_by_issue( $findings ) as $issue ) {
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
				$lines[] = '- `' . $this->markdown_escape( $this->finding_location( $finding ) ) . '`';
			}
			$lines[] = '';
		}
		return $lines;
	}

	/**
	 * Show only the names of plugins with checksum integrity problems.
	 */
	private function render_terminal_plugin_integrity_list() {
		$slugs = $this->modified_plugin_slugs();
		if ( empty( $slugs ) ) {
			return;
		}

		\WP_CLI::log( 'Integrity issues' );
		foreach ( $slugs as $slug ) {
			\WP_CLI::log( '  ⚠ ' . $slug );
		}
		\WP_CLI::log( '' );
	}

	/**
	 * Markdown list of plugins with checksum integrity problems.
	 */
	private function render_markdown_plugin_integrity_list() {
		$slugs = $this->modified_plugin_slugs();
		if ( empty( $slugs ) ) {
			return [];
		}

		$lines = [ '### Integrity issues', '' ];
		foreach ( $slugs as $slug ) {
			$lines[] = '- ⚠ `' . $this->markdown_escape( $slug ) . '`';
		}
		$lines[] = '';
		return $lines;
	}

	/**
	 * Build remediation recommendations after plugin findings have been analyzed.
	 *
	 * Recommendations are intentionally separated from individual findings so a
	 * high-volume plugin does not bury the action the operator should take.
	 */
	private function plugin_recommendations( array $groups ) {
		$recommendations = [];

		foreach ( $groups as $group ) {
			$slug = $group['slug'];
			if ( 'reinstall' === $group['action'] ) {
				$reason = 'modified' === $group['integrity']
					? 'Plugin integrity verification failed.'
					: 'Multiple suspicious findings exceeded the replacement threshold.';

				$recommendations[ $slug ] = [
					'slug'   => $slug,
					'action' => 'reinstall',
					'reason' => $reason,
					'count'  => max( (int) $group['total'], $this->plugin_integrity_change_count( $slug ) ),
				];
				continue;
			}

			$reason = 'verified' === $group['integrity']
				? 'Independent plugin-risk signals remain despite verified checksums.'
				: 'Grouped suspicious findings require manual review.';

			$recommendations[ $slug ] = [
				'slug'   => $slug,
				'action' => 'review',
				'reason' => $reason,
				'count'  => (int) $group['total'],
			];
		}

		foreach ( $this->plugin_integrity as $slug => $data ) {
			if ( 'modified' !== ( $data['status'] ?? '' ) || isset( $recommendations[ $slug ] ) ) {
				continue;
			}

			$recommendations[ $slug ] = [
				'slug'   => $slug,
				'action' => 'reinstall',
				'reason' => 'Plugin integrity verification failed.',
				'count'  => $this->plugin_integrity_change_count( $slug ),
			];
		}

		$recommendations = array_values( $recommendations );
		usort(
			$recommendations,
			static function ( $a, $b ) {
				$rank = [ 'reinstall' => 2, 'review' => 1 ];
				$action_compare = ( $rank[ $b['action'] ] ?? 0 ) <=> ( $rank[ $a['action'] ] ?? 0 );
				if ( 0 !== $action_compare ) {
					return $action_compare;
				}

				return strcmp( $a['slug'], $b['slug'] );
			}
		);

		return $recommendations;
	}

	/**
	 * Render remediation recommendations grouped by reason and priority.
	 */
	private function render_terminal_plugin_recommendations( array $groups ) {
		$recommendations = $this->plugin_recommendations( $groups );
		$has_inactive_plugins = ! empty( $this->inactive_plugins );
		$has_inactive_themes = ! empty( $this->inactive_themes );

		if ( empty( $recommendations ) && ! $has_inactive_plugins && ! $has_inactive_themes ) {
			return;
		}

		$buckets = [
			'integrity' => [],
			'threshold' => [],
			'review'    => [],
		];
		foreach ( $recommendations as $recommendation ) {
			if ( 'Plugin integrity verification failed.' === $recommendation['reason'] ) {
				$buckets['integrity'][] = $recommendation['slug'];
			} elseif ( 'reinstall' === $recommendation['action'] ) {
				$buckets['threshold'][] = $recommendation['slug'];
			} else {
				$buckets['review'][] = $recommendation['slug'];
			}
		}

		\WP_CLI::log( '' );
		\WP_CLI::log( 'Recommendations' );
		\WP_CLI::log( str_repeat( '-', 50 ) );

		if ( ! empty( $buckets['integrity'] ) ) {
			\WP_CLI::log( 'HIGH PRIORITY — Plugin integrity verification failed' );
			foreach ( $buckets['integrity'] as $slug ) {
				\WP_CLI::log( '  ⚠ ' . $slug );
			}
			\WP_CLI::log( '  Replace these plugins with fresh trusted copies, then rescan.' );
			\WP_CLI::log( '' );
		}

		if ( ! empty( $buckets['threshold'] ) ) {
			\WP_CLI::log( 'HIGH PRIORITY — Suspicious findings exceeded the replacement threshold' );
			foreach ( $buckets['threshold'] as $slug ) {
				\WP_CLI::log( '  ⚠ ' . $slug );
			}
			\WP_CLI::log( '  Replace these plugins with fresh trusted copies, then rescan.' );
			\WP_CLI::log( '' );
		}

		if ( ! empty( $buckets['review'] ) ) {
			\WP_CLI::log( 'REVIEW — Suspicious plugin findings require manual review' );
			foreach ( $buckets['review'] as $slug ) {
				\WP_CLI::log( '  ⚠ ' . $slug );
			}
			\WP_CLI::log( '' );
		}

		if ( $has_inactive_plugins || $has_inactive_themes ) {
			\WP_CLI::log( $this->full_scan ? 'CLEANUP — Inactive code' : 'CLEANUP — Inactive code is not scanned' );
			if ( $has_inactive_plugins ) {
				$count = count( $this->inactive_plugins );
				$message = $this->full_scan
					? '  ⚠ %d inactive plugin%s detected — included in full scan; remove %s if not needed.'
					: '  ⚠ %d inactive plugin%s detected — not scanned; remove %s if not needed.';
				\WP_CLI::log( sprintf( $message, $count, 1 === $count ? '' : 's', 1 === $count ? 'it' : 'them' ) );
			}
			if ( $has_inactive_themes ) {
				$count = count( $this->inactive_themes );
				$message = $this->full_scan
					? '  ⚠ %d inactive theme%s detected — included in full scan; remove %s if not needed.'
					: '  ⚠ %d inactive theme%s detected — not scanned; remove %s if not needed.';
				\WP_CLI::log( sprintf( $message, $count, 1 === $count ? '' : 's', 1 === $count ? 'it' : 'them' ) );
			}
		}
	}

	/**
	 * Build Markdown remediation recommendations grouped by reason and priority.
	 */
	private function render_markdown_plugin_recommendations( array $groups ) {
		$recommendations = $this->plugin_recommendations( $groups );
		$has_inactive_plugins = ! empty( $this->inactive_plugins );
		$has_inactive_themes = ! empty( $this->inactive_themes );
		if ( empty( $recommendations ) && ! $has_inactive_plugins && ! $has_inactive_themes ) {
			return [];
		}

		$buckets = [ 'integrity' => [], 'threshold' => [], 'review' => [] ];
		foreach ( $recommendations as $recommendation ) {
			if ( 'Plugin integrity verification failed.' === $recommendation['reason'] ) {
				$buckets['integrity'][] = $recommendation['slug'];
			} elseif ( 'reinstall' === $recommendation['action'] ) {
				$buckets['threshold'][] = $recommendation['slug'];
			} else {
				$buckets['review'][] = $recommendation['slug'];
			}
		}

		$lines = [ '## Recommendations', '' ];
		if ( ! empty( $buckets['integrity'] ) ) {
			$lines[] = '### High priority — Plugin integrity verification failed';
			$lines[] = '';
			foreach ( $buckets['integrity'] as $slug ) {
				$lines[] = '- ⚠ `' . $this->markdown_escape( $slug ) . '`';
			}
			$lines[] = '';
			$lines[] = 'Replace these plugins with fresh trusted copies, then rescan.';
			$lines[] = '';
		}
		if ( ! empty( $buckets['threshold'] ) ) {
			$lines[] = '### High priority — Suspicious findings exceeded the replacement threshold';
			$lines[] = '';
			foreach ( $buckets['threshold'] as $slug ) {
				$lines[] = '- ⚠ `' . $this->markdown_escape( $slug ) . '`';
			}
			$lines[] = '';
			$lines[] = 'Replace these plugins with fresh trusted copies, then rescan.';
			$lines[] = '';
		}
		if ( ! empty( $buckets['review'] ) ) {
			$lines[] = '### Review — Suspicious plugin findings require manual review';
			$lines[] = '';
			foreach ( $buckets['review'] as $slug ) {
				$lines[] = '- ⚠ `' . $this->markdown_escape( $slug ) . '`';
			}
			$lines[] = '';
		}
		if ( $has_inactive_plugins || $has_inactive_themes ) {
			$lines[] = $this->full_scan ? '### Cleanup — Inactive code' : '### Cleanup — Inactive code is not scanned';
			$lines[] = '';
			if ( $has_inactive_plugins ) {
				$count = count( $this->inactive_plugins );
				$lines[] = '- ⚠ ' . $count . ' inactive plugin' . ( 1 === $count ? '' : 's' ) . ' detected — ' . ( $this->full_scan ? 'included in full scan' : 'not scanned' ) . '; remove ' . ( 1 === $count ? 'it' : 'them' ) . ' if not needed.';
			}
			if ( $has_inactive_themes ) {
				$count = count( $this->inactive_themes );
				$lines[] = '- ⚠ ' . $count . ' inactive theme' . ( 1 === $count ? '' : 's' ) . ' detected — ' . ( $this->full_scan ? 'included in full scan' : 'not scanned' ) . '; remove ' . ( 1 === $count ? 'it' : 'them' ) . ' if not needed.';
			}
			$lines[] = '';
		}
		return $lines;
	}

	/**
	 * Render plugin findings in a compact plugin -> issue -> file hierarchy.
	 *
	 * Plugins that already crossed the replacement threshold are intentionally
	 * omitted from the verbose finding list; their remediation is shown once in
	 * the Recommendations block at the end of the Plugins section.
	 */
	private function render_terminal_plugin_findings( array $findings ) {
		$groups = $this->group_plugin_findings( $findings );
		$plugin_count = count( $groups );

		if ( $plugin_count > 0 ) {
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
		} else {
			\WP_CLI::log( 'No reportable static plugin findings.' );
			\WP_CLI::log( '' );
		}

		foreach ( $groups as $group ) {
			if ( 'reinstall' === $group['action'] ) {
				continue;
			}

			\WP_CLI::log( $group['slug'] );
			\WP_CLI::log(
				sprintf(
					'  %d finding%s',
					$group['total'],
					1 === $group['total'] ? '' : 's'
				)
			);
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
	 *
	 * Markdown remains the detailed human-readable export, so it preserves all
	 * grouped paths even for plugins that are ultimately recommended for replace.
	 */
	private function render_markdown_plugin_findings( array $findings ) {
		$lines = [];
		$groups = $this->group_plugin_findings( $findings );
		$lines[] = count( $findings ) . ' threat' . ( 1 === count( $findings ) ? '' : 's' ) . ' found across ' . count( $groups ) . ' plugin' . ( 1 === count( $groups ) ? '' : 's' ) . '.';
		$lines[] = '';

		foreach ( $groups as $group ) {
			$lines[] = '### `' . $this->markdown_escape( $group['slug'] ) . '`';
			$lines[] = '';
			$lines[] = $group['total'] . ' finding' . ( 1 === $group['total'] ? '' : 's' ) . '.';
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
	 * Render checksum failures grouped by plugin.
	 *
	 * Modified plugins are already direct replacement candidates, so the terminal
	 * report keeps this section concise and moves remediation to the end of the
	 * Plugins section. Raw checksum details remain available in JSON/Markdown.
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

		\WP_CLI::log( sprintf( '%d integrity issue%s found across %d plugin%s', count( $findings ), 1 === count( $findings ) ? '' : 's', count( $groups ), 1 === count( $groups ) ? '' : 's' ) );
		\WP_CLI::log( '' );

		foreach ( $groups as $plugin => $plugin_findings ) {
			\WP_CLI::log( $plugin );
			if ( 'modified' === $this->plugin_integrity_status( $plugin ) ) {
				\WP_CLI::log( sprintf( '  %d integrity change%s detected.', count( $plugin_findings ), 1 === count( $plugin_findings ) ? '' : 's' ) );
				\WP_CLI::log( '' );
				continue;
			}

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
	 *
	 * The detailed export keeps every affected path. Recommendations are rendered
	 * once at the end of the Plugins section.
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
			foreach ( $plugin_findings as $finding ) {
				$lines[] = '- **' . strtoupper( $finding['severity'] ) . ' · ' . $finding['confidence'] . '%** — ' . $this->markdown_escape( $finding['description'] );
				$lines[] = '  - `' . $this->markdown_escape( $this->plugin_relative_finding_location( $finding, $plugin ) ) . '`';
			}
			$lines[] = '';
		}

		return $lines;
	}

	/**
	 * Render the concise terminal report.
	 *
	 * Detailed findings are intentionally kept out of the interactive terminal
	 * report and written to the scan log instead. This keeps the console focused
	 * on the final summary and remediation actions without discarding evidence.
	 */
	private function render_terminal_report( array $report, $scan_log_path = null ) {
		\WP_CLI::log( '' );
		\WP_CLI::log( '' );
		\WP_CLI::log( 'Summary' );
		\WP_CLI::log( str_repeat( '-', 50 ) );

		$summary_stages = [
			'Checksums' => [ 'Core checksums' ],
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
		\WP_CLI::log( str_repeat( '-', 50 ) );
		\WP_CLI::success( 'Security scan completed.' );

		$plugin_findings = array_values(
			array_filter(
				$report['findings'],
				static function ( $finding ) {
					return 'Plugins' === ( $finding['section'] ?? '' );
				}
			)
		);
		$this->render_terminal_plugin_recommendations( $this->group_plugin_findings( $plugin_findings ) );

		\WP_CLI::log( '' );
		if ( is_string( $scan_log_path ) && '' !== $scan_log_path ) {
			\WP_CLI::log( 'Detailed findings saved to ' . $scan_log_path );
		} else {
			\WP_CLI::warning( 'Detailed findings log could not be written.' );
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
			'Checksums' => [ 'Core checksums' ],
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

		if ( ! isset( $sections['Plugins'] ) ) {
			foreach ( $this->plugin_integrity as $plugin_data ) {
				if ( 'modified' === ( $plugin_data['status'] ?? '' ) ) {
					$sections['Plugins'] = [];
					break;
				}
			}
		}

		$sections = $this->order_report_sections( $sections );
		foreach ( $sections as $section => $findings ) {
			$lines[] = '## ' . $section;
			$lines[] = '';

			if ( 'Plugins' === $section ) {
				$lines = array_merge( $lines, $this->render_markdown_plugin_findings( $findings ) );
				$lines = array_merge( $lines, $this->render_markdown_plugin_integrity_list() );
				continue;
			}

			if ( 'Uploads' === $section ) {
				$lines[] = count( $findings ) . ' threat' . ( 1 === count( $findings ) ? '' : 's' ) . ' found.';
				$lines[] = '';
				$lines = array_merge( $lines, $this->render_markdown_grouped_findings( $findings ) );
				continue;
			}

			if ( 'Core checksums' === $section ) {
				$lines[] = count( $findings ) . ' integrity issue' . ( 1 === count( $findings ) ? '' : 's' ) . ' found.';
			} else {
				$lines[] = count( $findings ) . ' threat' . ( 1 === count( $findings ) ? '' : 's' ) . ' found.';
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

		$plugin_findings = array_values(
			array_filter(
				$report['findings'],
				static function ( $finding ) {
					return 'Plugins' === ( $finding['section'] ?? '' );
				}
			)
		);
		$lines = array_merge( $lines, $this->render_markdown_plugin_recommendations( $this->group_plugin_findings( $plugin_findings ) ) );

		return implode( PHP_EOL, $lines ) . PHP_EOL;
	}


	/**
	 * Write a complete human-readable scan log, replacing the previous scan log.
	 */
	private function write_scan_log( array $report ) {
		$directory = '' !== $this->launch_directory ? $this->launch_directory : $this->resolve_launch_directory();
		$path = rtrim( $directory, '/\\' ) . DIRECTORY_SEPARATOR . 'security-scan.log';
		$content = $this->render_scan_log( $report );
		if ( false === @file_put_contents( $path, $content, LOCK_EX ) ) {
			return null;
		}
		return $path;
	}

	/**
	 * Resolve the directory from which the WP-CLI process was launched.
	 *
	 * WP-CLI can change the PHP working directory while resolving --path. The
	 * shell-provided PWD value therefore takes precedence when it points to a
	 * real directory, with getcwd() as a portable fallback.
	 */
	private function resolve_launch_directory() {
		$candidates = [];
		$pwd = getenv( 'PWD' );
		if ( is_string( $pwd ) && '' !== trim( $pwd ) ) {
			$candidates[] = $pwd;
		}
		if ( isset( $_SERVER['PWD'] ) && is_string( $_SERVER['PWD'] ) && '' !== trim( $_SERVER['PWD'] ) ) {
			$candidates[] = $_SERVER['PWD'];
		}
		$cwd = getcwd();
		if ( is_string( $cwd ) && '' !== $cwd ) {
			$candidates[] = $cwd;
		}

		foreach ( array_unique( $candidates ) as $candidate ) {
			$real = realpath( $candidate );
			if ( false !== $real && is_dir( $real ) ) {
				return $real;
			}
		}

		return defined( 'ABSPATH' ) ? rtrim( ABSPATH, '/\\' ) : '.';
	}

	/**
	 * Build a detailed plain-text report intended for manual incident review.
	 */
	private function render_scan_log( array $report ) {
		$lines = [];
		$lines[] = str_repeat( '-', 80 );
		$lines[] = 'WORDPRESS SECURITY SCAN';
		$lines[] = str_repeat( '-', 80 );
		$lines[] = sprintf( '%-16s %s', 'Scanned at:', ( $report['scanned_at'] ?? gmdate( 'c' ) ) );
		$this->append_scan_log_major_section_gap( $lines );
		$lines[] = 'SUMMARY';
		$lines[] = str_repeat( '-', 80 );
		$lines[] = 'Severity';
		$lines[] = sprintf( '  %-14s %s', 'CRITICAL', number_format( (int) $report['severity']['critical'] ) );
		$lines[] = sprintf( '  %-14s %s', 'HIGH', number_format( (int) $report['severity']['high'] ) );
		$lines[] = sprintf( '  %-14s %s', 'MEDIUM', number_format( (int) $report['severity']['medium'] ) );
		$lines[] = sprintf( '  %-14s %s', 'LOW', number_format( (int) $report['severity']['low'] ) );
		$lines[] = '';
		$lines[] = 'Scope';
		$lines[] = sprintf( '  %-22s %s', 'Files scanned', number_format( (int) $report['files_scanned'] ) );
		$lines[] = sprintf( '  %-22s %s', 'Database rows scanned', number_format( (int) $report['database_rows'] ) );
		$lines[] = sprintf( '  %-22s %s', 'Administrator users', number_format( (int) $report['administrator_users'] ) );
		$lines[] = sprintf( '  %-22s %s', 'Reportable findings', number_format( (int) $report['total_findings'] ) );
		$this->append_scan_log_major_section_gap( $lines );
		$lines[] = 'FINDINGS';
		$lines[] = str_repeat( '-', 80 );

		$sections = [];
		foreach ( $report['findings'] as $finding ) {
			$sections[ $finding['section'] ][] = $finding;
		}
		if ( ! isset( $sections['Plugins'] ) && ! empty( $this->modified_plugin_slugs() ) ) {
			$sections['Plugins'] = [];
		}
		$sections = $this->order_report_sections( $sections );

		if ( empty( $sections ) ) {
			$lines[] = 'No reportable findings.';
			$lines[] = '';
		}

		foreach ( $sections as $section => $findings ) {
			$count = count( $findings );
			$lines[] = sprintf( '%s (%d finding%s)', strtoupper( $section ), $count, 1 === $count ? '' : 's' );
			$lines[] = str_repeat( '-', 80 );

			if ( 'Plugins' === $section ) {
				$groups = $this->group_plugin_findings( $findings );
				foreach ( $groups as $group ) {
					$lines[] = sprintf( 'Plugin: %s (%d finding%s)', $group['slug'], $group['total'], 1 === $group['total'] ? '' : 's' );
					$issue_number = 1;
					foreach ( $group['issues'] as $issue ) {
						$this->append_scan_log_issue( $lines, $issue, $issue_number, '  ', $group['slug'] );
						$issue_number++;
					}
					$lines[] = '';
				}

				$integrity_groups = $this->group_plugin_integrity_changes_by_problem();
				if ( ! empty( $integrity_groups ) ) {
					$lines[] = 'Plugin integrity changes';
					foreach ( $integrity_groups as $problem => $locations ) {
						$lines[] = '  ' . $problem;
						foreach ( $locations as $location ) {
							$lines[] = '    - ' . $location;
						}
						$lines[] = '';
					}
				}
				continue;
			}

			$issue_number = 1;
			if ( 'Uploads' === $section ) {
				foreach ( $this->group_findings_by_issue( $findings ) as $issue ) {
					$this->append_scan_log_issue( $lines, $issue, $issue_number );
					$issue_number++;
				}
			} elseif ( 'Core checksums' === $section ) {
				foreach ( $this->group_findings_by_problem( $findings ) as $issue ) {
					$this->append_scan_log_issue( $lines, $issue, $issue_number );
					$issue_number++;
				}
			} else {
				foreach ( $findings as $finding ) {
					$issue = [
						'rule'        => (string) ( $finding['rule'] ?? '' ),
						'description' => (string) $finding['description'],
						'severity'    => (string) $finding['severity'],
						'confidence'  => (int) $finding['confidence'],
						'findings'    => [ $finding ],
					];
					$this->append_scan_log_issue( $lines, $issue, $issue_number );
					$issue_number++;
				}
			}
			$lines[] = '';
		}

		$plugin_findings = array_values(
			array_filter(
				$report['findings'],
				static function ( $finding ) {
					return 'Plugins' === ( $finding['section'] ?? '' );
				}
			)
		);
		$recommendations = $this->plugin_recommendations( $this->group_plugin_findings( $plugin_findings ) );
		if ( ! empty( $recommendations ) || ! empty( $this->inactive_plugins ) || ! empty( $this->inactive_themes ) ) {
			$this->append_scan_log_major_section_gap( $lines );
			$lines[] = 'RECOMMENDATIONS';
			$lines[] = str_repeat( '-', 80 );
			foreach ( $recommendations as $recommendation ) {
				$lines[] = sprintf( '[%s] %s', strtoupper( $recommendation['action'] ), $recommendation['slug'] );
				$lines[] = '  Reason: ' . $recommendation['reason'];
				$lines[] = '';
			}
			if ( ! empty( $this->inactive_plugins ) ) {
				$count = count( $this->inactive_plugins );
				$lines[] = '[CLEANUP] Inactive plugins';
				$lines[] = sprintf( '  %d inactive plugin%s detected and %s. Remove %s if not needed.', $count, 1 === $count ? '' : 's', $this->full_scan ? 'included in the full scan' : 'not scanned', 1 === $count ? 'it' : 'them' );
				$lines[] = '';
			}
			if ( ! empty( $this->inactive_themes ) ) {
				$count = count( $this->inactive_themes );
				$lines[] = '[CLEANUP] Inactive themes';
				$lines[] = sprintf( '  %d inactive theme%s detected and %s. Remove %s if not needed.', $count, 1 === $count ? '' : 's', $this->full_scan ? 'included in the full scan' : 'not scanned', 1 === $count ? 'it' : 'them' );
				$lines[] = '';
			}
		}

		return implode( PHP_EOL, $lines ) . PHP_EOL;
	}

	/**
	 * Keep exactly two blank lines between top-level scan-log sections.
	 */
	private function append_scan_log_major_section_gap( array &$lines ) {
		while ( ! empty( $lines ) && '' === end( $lines ) ) {
			array_pop( $lines );
		}

		$lines[] = '';
		$lines[] = '';
	}

	/**
	 * Append one grouped issue to the scan log in a triage-friendly layout.
	 */
	private function append_scan_log_issue( array &$lines, array $issue, $number, $indent = '', $plugin = null ) {
		$lines[] = sprintf(
			'%s[%d] %s | %d%% confidence',
			$indent,
			(int) $number,
			strtoupper( (string) $issue['severity'] ),
			(int) $issue['confidence']
		);
		$lines[] = $indent . '    Problem: ' . (string) $issue['description'];
		$lines[] = $indent . '    Locations:';
		foreach ( $issue['findings'] as $finding ) {
			$location = null === $plugin
				? $this->finding_location( $finding )
				: $this->plugin_relative_finding_location( $finding, $plugin );
			$lines[] = $indent . '      - ' . $location;
		}
		$lines[] = '';
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

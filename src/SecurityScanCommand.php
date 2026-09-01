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
	private const VERSION = '0.2.0';
	private const DB_BATCH_SIZE = 500;
	private const FILE_CHUNK_SIZE = 524288;
	private const FILE_CHUNK_OVERLAP = 8192;
	private const DEEP_PHP_WHOLE_FILE_MAX = 8388608;
	private const DEEP_PHP_CHUNK_SIZE = 2097152;
	private const DEEP_PHP_CHUNK_OVERLAP = 65536;

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
				'plugin verify-checksums --all --strict',
				'Scanning plugin integrity...'
			);

			$output = trim( (string) ( $result->stdout ?? '' ) . "\n" . (string) ( $result->stderr ?? '' ) );

			if ( '' !== $output ) {
				foreach ( preg_split( '/\\R+/', $output ) as $line ) {
					$line = trim( $line );
					if ( '' === $line ) {
						continue;
					}

					if ( false !== stripos( $line, "doesn't verify against checksum" ) || false !== stripos( $line, 'should not exist' ) ) {
						$this->add_finding( $stage, 'high', 92, 'Plugins', 'plugin_checksum_mismatch', $this->strip_wp_cli_prefix( $line ) );
					}
				}
			}

			$this->checksum_stage_finish( $stage, $this->count_stage_findings( $stage ) );
		} catch ( \Throwable $e ) {
			$this->add_finding( $stage, 'low', 45, 'Plugins', 'plugin_checksum_error', 'Plugin checksum verification could not complete: ' . $e->getMessage() );
			$this->checksum_stage_finish( $stage, $this->count_stage_findings( $stage ) );
		}
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

		$this->stage_finish( $stage, $count, $this->count_stage_findings( $stage ) );
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
			} else {
				$this->add_file_finding_once( $seen, $stage, 'critical', 99, $relative, 'php_in_non_php', 'PHP code detected inside a non-PHP file', $php_buffer_start_line );
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
		$suspicious_tokens = [
			'eval(',
			'base64_decode(',
			'gzinflate(',
			'gzuncompress(',
			'str_rot13(',
			'strrev(',
			'str_repeat(',
			'chr(',
			'openssl_decrypt(',
			'php://input',
			'call_user_func(',
			'shell_exec(',
			'passthru(',
			'proc_open(',
			'assert(',
			'$_request',
			'$_cookie',
			'$globals',
		];

		$count = 0;
		$first_offset = null;
		$lower = strtolower( $buffer );
		foreach ( $suspicious_tokens as $token ) {
			$offset = strpos( $lower, $token );
			if ( false !== $offset ) {
				$count++;
				if ( null === $first_offset || $offset < $first_offset ) {
					$first_offset = $offset;
				}
			}
		}

		if ( $count >= 5 ) {
			$line = null === $first_offset ? null : $this->line_from_buffer_offset( $buffer, $buffer_start_line, $first_offset );
			$this->add_file_finding_once( $seen, $stage, 'high', 82, $relative, 'dense_suspicious_php', 'Multiple obfuscation/execution primitives occur in the same code block', $line );
		}

		$long_line_matches = [];
		if ( $count >= 2 && 1 === preg_match( '~[^\r\n]{20000,}~', $buffer, $long_line_matches, PREG_OFFSET_CAPTURE ) ) {
			$line = $this->line_from_buffer_offset( $buffer, $buffer_start_line, $long_line_matches[0][1] );
			$this->add_file_finding_once( $seen, $stage, 'high', 84, $relative, 'long_obfuscated_line', 'Very long PHP line combined with suspicious execution/decoder primitives', $line );
		}
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
	 * Scan administrator accounts and cron persistence data.
	 */
	private function scan_users_and_persistence() {
		$stage = 'Users & persistence';
		$this->stage_start( $stage );
		$count = 0;

		$admins = get_users(
			[
				'role'   => 'administrator',
				'fields' => [ 'ID', 'user_login', 'user_email' ],
			]
		);
		$this->admin_count = count( $admins );
		$count += $this->admin_count;
		$this->stage_tick( $stage, $count, 'items' );

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

		$filtered = array_values(
			array_filter(
				$this->findings,
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

				if ( in_array( $section, [ 'Core checksums', 'Plugin integrity' ], true ) ) {
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

			if ( in_array( $section, [ 'Core checksums', 'Plugin integrity' ], true ) ) {
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

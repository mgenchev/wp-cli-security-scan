<?php
/**
 * WP-CLI Security Scan command.
 *
 * Read-only diagnostics for compromised WordPress sites.
 */

if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
	return;
}

if ( ! class_exists( 'Security_Scan_Database', false ) ) {
	require_once __DIR__ . DIRECTORY_SEPARATOR . 'ScannerDatabase.php';
}

class Security_Scan_Command {
	private const VERSION = '1.1.0';
	private const DB_BATCH_SIZE = 500;
	private const USER_BATCH_SIZE = 100;
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
	private const HTTP_RESPONSE_MAX_BYTES = 16777216;
	private const APPLICATION_PASSWORD_META_KEY = '_application_passwords';
	private const SCAN_LOG_SEPARATOR_WIDTH = 68;

	private const ADMINISTRATIVE_CAPABILITIES = [
		'manage_options',
		'edit_users',
		'promote_users',
		'create_users',
		'delete_users',
		'install_plugins',
		'activate_plugins',
		'update_plugins',
		'delete_plugins',
		'update_core',
		'switch_themes',
	];

	private const BUILTIN_NON_ADMIN_ROLES = [
		'editor',
		'author',
		'contributor',
		'subscriber',
	];

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

	private const UPLOAD_CONTAINER_EXTENSIONS = [
		'jpg', 'jpeg', 'png', 'gif', 'webp', 'avif', 'ico', 'bmp', 'tif', 'tiff', 'pdf',
	];

	private const UPLOAD_CONTAINER_TAIL_MAX_BYTES = 262144;

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
	private $include_node_modules = false;
	private $full_scan = false;
	private $deep_database = false;
	private $background_spinner_process = null;
	private $php_data_flow_analyzer = null;
	private $plugin_integrity = [];
	private $plugin_scan_files = [];
	private $inactive_plugins = [];
	private $active_theme_slugs = [];
	private $inactive_themes = [];
	private $launch_directory = '';
	private $scan_log_path = '';
	private $database = null;
	private $wp_root = '';
	private $content_dir = '';
	private $plugin_dir = '';
	private $mu_plugin_dir = '';
	private $theme_dir = '';
	private $uploads_dir = '';
	private $base_table_prefix = '';
	private $site_table_prefix = '';
	private $site_locale = 'en_US';
	private $active_plugin_files = [];
	private $installed_plugins = [];
	private $current_blog_id = 1;
	private $current_network_id = 1;
	private $current_network_main_blog_id = 1;
	private $plugin_scope_reliable = true;
	private $theme_scope_reliable = true;
	private $runtime_warnings = [];
	private $site_home_host = '';
	private $plugin_sha256_available = null;
	private $verified_plugin_ioc_rules = null;
	private $table_column_cache = [];
	private $finalization_active = false;
	private $finalization_memory_reserve = '';
	private $finalization_shutdown_registered = false;

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
	 * [--deep-database]
	 * : Also scan text-like columns in custom tables for the current site prefix.
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
	 * ## OPTIONS
	 *
	 * [--deep-database]
	 * : Also scan text-like columns in custom tables for the current site prefix.
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
		$this->deep_database = isset( $assoc_args['deep-database'] );
		$this->suppress_wordpress_debug();
		$this->start_time = microtime( true );
		$this->launch_directory = $this->resolve_launch_directory();
		$this->scan_log_path = $this->resolve_scan_log_path();

		if ( $this->interactive ) {
			$this->start_background_spinner( 'Security Scan — initializing isolated scanner...' );
		}

		try {
			$this->initialize_scanner_runtime();
		} finally {
			$this->stop_background_spinner();
			$this->release_finalization_guard();
		}

		if ( $this->interactive ) {
			$this->start_background_spinner( 'Security Scan — preparing rules...' );
		}

		try {
			$this->load_rules();
		} finally {
			$this->stop_background_spinner();
		}

		if ( $this->interactive ) {
			$this->start_background_spinner( 'Security Scan — preparing scan inventory...' );
		}

		try {
			$this->initialize_plugin_integrity_inventory();
			$this->initialize_theme_inventory();
		} finally {
			$this->stop_background_spinner();
		}

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
					$this->scan_directory_stage( 'Uploads', $this->uploads_dir, true );
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
		$this->include_node_modules = false;
		$this->full_scan = false;
		$this->deep_database = false;
		$this->php_data_flow_analyzer = null;
		$this->plugin_integrity = [];
		$this->plugin_scan_files = [];
		$this->inactive_plugins = [];
		$this->active_theme_slugs = [];
		$this->inactive_themes = [];
		$this->launch_directory = '';
		$this->scan_log_path = '';
		$this->database = null;
		$this->wp_root = '';
		$this->content_dir = '';
		$this->plugin_dir = '';
		$this->mu_plugin_dir = '';
		$this->theme_dir = '';
		$this->uploads_dir = '';
		$this->base_table_prefix = '';
		$this->site_table_prefix = '';
		$this->site_locale = 'en_US';
		$this->active_plugin_files = [];
		$this->installed_plugins = [];
		$this->current_blog_id = 1;
		$this->current_network_id = 1;
		$this->current_network_main_blog_id = 1;
		$this->plugin_scope_reliable = true;
		$this->theme_scope_reliable = true;
		$this->runtime_warnings = [];
		$this->site_home_host = '';
		$this->plugin_sha256_available = null;
		$this->verified_plugin_ioc_rules = null;
		$this->table_column_cache = [];
		$this->finalization_active = false;
		$this->finalization_memory_reserve = '';
	}

	/**
	 * Disable WordPress debug mode for the lifetime of this scan process.
	 *
	 * The scanner does not load WordPress. Suppress PHP error display while the
	 * clean local wp-config.php is evaluated and while diagnostic work runs.
	 * Nothing is written back to wp-config.php.
	 */
	private function suppress_wordpress_debug() {
		@ini_set( 'display_errors', '0' );
		@ini_set( 'display_startup_errors', '0' );
		error_reporting( 0 );

	}

	/**
	 * Initialize only the trusted runtime pieces required by the scanner.
	 *
	 * wp-settings.php is deliberately not loaded. This keeps regular plugins,
	 * themes, MU plugins and wp-content drop-ins out of the scanner process.
	 */
	private function initialize_scanner_runtime() {
		$this->wp_root = defined( 'ABSPATH' ) ? rtrim( (string) constant( 'ABSPATH' ), '/\\' ) : '';
		if ( '' === $this->wp_root || ! is_dir( $this->wp_root ) ) {
			\WP_CLI::error( 'Unable to determine the WordPress root directory for isolated scanning.' );
		}

		$this->content_dir = $this->wp_root . DIRECTORY_SEPARATOR . 'wp-content';
		$this->plugin_dir = $this->content_dir . DIRECTORY_SEPARATOR . 'plugins';
		$this->mu_plugin_dir = $this->content_dir . DIRECTORY_SEPARATOR . 'mu-plugins';
		$this->theme_dir = $this->content_dir . DIRECTORY_SEPARATOR . 'themes';
		$this->uploads_dir = $this->content_dir . DIRECTORY_SEPARATOR . 'uploads';

		$table_prefix = $this->evaluate_wp_config_without_loading_wordpress();
		$this->base_table_prefix = $this->validate_table_prefix( $table_prefix );

		$this->content_dir = defined( 'WP_CONTENT_DIR' )
			? rtrim( (string) constant( 'WP_CONTENT_DIR' ), '/\\' )
			: $this->wp_root . DIRECTORY_SEPARATOR . 'wp-content';
		$this->plugin_dir = defined( 'WP_PLUGIN_DIR' )
			? rtrim( (string) constant( 'WP_PLUGIN_DIR' ), '/\\' )
			: $this->content_dir . DIRECTORY_SEPARATOR . 'plugins';
		$this->mu_plugin_dir = defined( 'WPMU_PLUGIN_DIR' )
			? rtrim( (string) constant( 'WPMU_PLUGIN_DIR' ), '/\\' )
			: $this->content_dir . DIRECTORY_SEPARATOR . 'mu-plugins';
		$this->theme_dir = $this->content_dir . DIRECTORY_SEPARATOR . 'themes';

		$this->define_isolated_path_constants();
		$this->initialize_scanner_database();
		$this->resolve_current_site_prefix();
		$this->site_home_host = $this->resolve_site_home_host();
		$this->site_locale = $this->resolve_site_locale();
		$this->active_plugin_files = $this->read_active_plugin_files();
		$this->uploads_dir = $this->resolve_upload_directory();
	}

	/**
	 * Define the standard WordPress content path constants that wp-settings.php
	 * would normally provide after wp-config.php has been evaluated.
	 *
	 * The isolated scanner intentionally never loads wp-settings.php. Defining
	 * these resolved path constants keeps WP-CLI/package code that expects the
	 * standard constants compatible without loading or executing wp-content.
	 * Existing custom constants from wp-config.php are always preserved.
	 */
	private function define_isolated_path_constants() {
		$paths = [
			'WP_CONTENT_DIR'  => $this->content_dir,
			'WP_PLUGIN_DIR'   => $this->plugin_dir,
			'WPMU_PLUGIN_DIR' => $this->mu_plugin_dir,
		];

		foreach ( $paths as $name => $path ) {
			if ( defined( $name ) || '' === trim( (string) $path ) ) {
				continue;
			}

			define( $name, $path );
		}
	}

	/**
	 * Evaluate wp-config.php using WP-CLI's stripped config code.
	 *
	 * WP-CLI removes the wp-settings.php require before returning this code. The
	 * scanner assumes wp-config.php belongs to the clean local installation and
	 * does not treat it as part of the restored suspect wp-content scope.
	 */
	private function evaluate_wp_config_without_loading_wordpress() {
		$table_prefix = null;
		$buffer_level = ob_get_level();
		ob_start();

		try {
			$code = \WP_CLI::get_runner()->get_wp_config_code();
			// WP-CLI itself uses this stripped code for before_wp_load config commands.
			eval( $code );
		} catch ( \Throwable $e ) {
			while ( ob_get_level() > $buffer_level ) {
				ob_end_clean();
			}
			\WP_CLI::error( 'Unable to read wp-config.php for isolated scanning: ' . $e->getMessage() );
		}

		while ( ob_get_level() > $buffer_level ) {
			ob_end_clean();
		}

		return is_string( $table_prefix ) ? $table_prefix : '';
	}

	/**
	 * Validate the table prefix before using it in SQL identifiers.
	 */
	private function validate_table_prefix( $prefix ) {
		$prefix = (string) $prefix;
		if ( '' === $prefix || ! preg_match( '/^[A-Za-z0-9_]+$/', $prefix ) ) {
			\WP_CLI::error( 'Unable to determine a safe WordPress table prefix from wp-config.php.' );
		}
		return $prefix;
	}

	/**
	 * Open a direct database connection without loading db.php or object-cache.php.
	 */
	private function initialize_scanner_database() {
		foreach ( [ 'DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DB_HOST' ] as $constant ) {
			if ( ! defined( $constant ) ) {
				\WP_CLI::error( 'Missing ' . $constant . ' in wp-config.php; isolated database scanning cannot continue.' );
			}
		}

		$charset = defined( 'DB_CHARSET' ) ? (string) constant( 'DB_CHARSET' ) : 'utf8mb4';
		$flags = defined( 'MYSQL_CLIENT_FLAGS' ) ? (int) constant( 'MYSQL_CLIENT_FLAGS' ) : 0;

		try {
			$this->database = new Security_Scan_Database(
				(string) constant( 'DB_NAME' ),
				(string) constant( 'DB_USER' ),
				(string) constant( 'DB_PASSWORD' ),
				(string) constant( 'DB_HOST' ),
				$charset,
				$this->base_table_prefix,
				$flags
			);

			$this->database->set_user_tables(
				defined( 'CUSTOM_USER_TABLE' ) ? (string) constant( 'CUSTOM_USER_TABLE' ) : '',
				defined( 'CUSTOM_USER_META_TABLE' ) ? (string) constant( 'CUSTOM_USER_META_TABLE' ) : ''
			);
		} catch ( \Throwable $e ) {
			\WP_CLI::error( $e->getMessage() );
		}
	}

	/**
	 * Resolve the current site's prefix in multisite without bootstrapping WordPress.
	 */
	private function resolve_current_site_prefix() {
		$this->site_table_prefix = $this->base_table_prefix;
		$this->current_blog_id = 1;
		$this->current_network_id = 1;
		$this->current_network_main_blog_id = 1;

		if ( ! $this->database ) {
			return;
		}

		if ( ! $this->scanner_is_multisite() ) {
			$this->database->set_prefix( $this->site_table_prefix );
			return;
		}

		$blog_id = defined( 'BLOG_ID_CURRENT_SITE' )
			? max( 1, (int) constant( 'BLOG_ID_CURRENT_SITE' ) )
			: ( defined( 'BLOGID_CURRENT_SITE' ) ? max( 1, (int) constant( 'BLOGID_CURRENT_SITE' ) ) : 1 );
		$network_id = defined( 'SITE_ID_CURRENT_SITE' ) ? max( 1, (int) constant( 'SITE_ID_CURRENT_SITE' ) ) : 1;
		$runner = \WP_CLI::get_runner();
		$url = isset( $runner->assoc_args['url'] ) ? trim( (string) $runner->assoc_args['url'] ) : '';
		if ( '' !== $url ) {
			$resolved = $this->resolve_multisite_blog_id_from_url( $url );
			if ( null === $resolved ) {
				\WP_CLI::error(
					'Unable to resolve --url to a multisite blog without loading WordPress. ' .
					'Use the canonical domain/path stored in the WordPress blogs table.'
				);
			}
			$blog_id = $resolved['blog_id'];
			$network_id = $resolved['network_id'];
		} else {
			$context = $this->resolve_multisite_context_for_blog( $blog_id );
			if ( null !== $context ) {
				$network_id = $context['network_id'];
			}
		}

		$this->current_blog_id = $blog_id;
		$this->current_network_id = max( 1, (int) $network_id );
		$this->current_network_main_blog_id = $this->resolve_network_main_blog_id( $this->current_network_id );
		if ( $this->current_network_main_blog_id < 1 ) {
			$this->current_network_main_blog_id = $this->current_blog_id;
		}
		$this->site_table_prefix = 1 === $blog_id
			? $this->base_table_prefix
			: $this->base_table_prefix . $blog_id . '_';
		$this->database->set_prefix( $this->site_table_prefix );
	}

	/**
	 * Mirror WordPress is_multisite() without loading wp-includes/load.php.
	 */
	private function scanner_is_multisite() {
		if ( defined( 'MULTISITE' ) ) {
			return (bool) constant( 'MULTISITE' );
		}

		return defined( 'SUBDOMAIN_INSTALL' ) || defined( 'VHOST' ) || defined( 'SUNRISE' );
	}

	/**
	 * Resolve a multisite blog/network pair from WP-CLI --url using the blogs table only.
	 */
	private function resolve_multisite_blog_id_from_url( $url ) {
		$url = false === strpos( $url, '://' ) ? 'http://' . ltrim( $url, '/' ) : $url;
		$host = strtolower( (string) parse_url( $url, PHP_URL_HOST ) );
		$path = (string) parse_url( $url, PHP_URL_PATH );
		if ( '' === $host ) {
			return null;
		}
		$path = '/' . trim( $path, '/' );
		$path = '/' === $path ? '/' : $path . '/';

		$table = $this->base_table_prefix . 'blogs';
		if ( ! $this->database->table_exists( $table ) ) {
			return null;
		}

		$sql = $this->database->prepare(
			'SELECT blog_id, site_id, path FROM ' . $this->quote_identifier( $table ) . ' WHERE domain = %s ORDER BY LENGTH(path) DESC',
			$host
		);
		$rows = $this->database->get_results( $sql, true );
		foreach ( $rows as $row ) {
			$candidate = isset( $row['path'] ) ? (string) $row['path'] : '/';
			if ( 0 === strpos( $path, $candidate ) ) {
				return [
					'blog_id'    => max( 1, (int) $row['blog_id'] ),
					'network_id' => max( 1, (int) ( $row['site_id'] ?? 1 ) ),
				];
			}
		}

		return null;
	}

	/**
	 * Resolve the network ID for one blog without loading multisite objects.
	 */
	private function resolve_multisite_context_for_blog( $blog_id ) {
		$table = $this->base_table_prefix . 'blogs';
		if ( ! $this->database || ! $this->database->table_exists( $table ) ) {
			return null;
		}

		$sql = $this->database->prepare(
			'SELECT blog_id, site_id FROM ' . $this->quote_identifier( $table ) . ' WHERE blog_id = %d LIMIT 1',
			max( 1, (int) $blog_id )
		);
		$row = $this->database->get_results( $sql, true );
		if ( empty( $row[0] ) ) {
			return null;
		}

		return [
			'blog_id'    => max( 1, (int) ( $row[0]['blog_id'] ?? $blog_id ) ),
			'network_id' => max( 1, (int) ( $row[0]['site_id'] ?? 1 ) ),
		];
	}

	/**
	 * Resolve a network's main site using trusted constants/network metadata only.
	 */
	private function resolve_network_main_blog_id( $network_id ) {
		$network_id = max( 1, (int) $network_id );
		if (
			defined( 'SITE_ID_CURRENT_SITE' )
			&& $network_id === (int) constant( 'SITE_ID_CURRENT_SITE' )
		) {
			if ( defined( 'BLOG_ID_CURRENT_SITE' ) ) {
				return max( 1, (int) constant( 'BLOG_ID_CURRENT_SITE' ) );
			}
			if ( defined( 'BLOGID_CURRENT_SITE' ) ) {
				return max( 1, (int) constant( 'BLOGID_CURRENT_SITE' ) );
			}
		}

		$raw = $this->database ? $this->database->get_network_option_raw( 'main_site', $network_id ) : null;
		if ( null !== $raw ) {
			$decoded = $this->decode_stored_value( $raw );
			if ( is_numeric( $decoded ) && (int) $decoded > 0 ) {
				return (int) $decoded;
			}
		}

		$network_table = $this->base_table_prefix . 'site';
		$blogs_table = $this->base_table_prefix . 'blogs';
		if (
			! $this->database
			|| ! $this->database->table_exists( $network_table )
			|| ! $this->database->table_exists( $blogs_table )
		) {
			return 0;
		}

		$network_sql = $this->database->prepare(
			'SELECT domain, path FROM ' . $this->quote_identifier( $network_table ) . ' WHERE id = %d LIMIT 1',
			$network_id
		);
		$network = $this->database->get_results( $network_sql, true );
		if ( empty( $network[0] ) ) {
			return 0;
		}

		$site_sql = $this->database->prepare(
			'SELECT blog_id FROM ' . $this->quote_identifier( $blogs_table ) . ' WHERE site_id = %d AND domain = %s AND path = %s ORDER BY blog_id ASC LIMIT 1',
			$network_id,
			(string) ( $network[0]['domain'] ?? '' ),
			(string) ( $network[0]['path'] ?? '/' )
		);
		$main_blog_id = $this->database->get_var( $site_sql );
		return is_numeric( $main_blog_id ) && (int) $main_blog_id > 0 ? (int) $main_blog_id : 0;
	}

	/**
	 * Resolve the primary network ID without loading WP_Network.
	 */
	private function resolve_main_network_id() {
		if ( ! $this->scanner_is_multisite() ) {
			return 1;
		}
		if ( defined( 'PRIMARY_NETWORK_ID' ) && (int) constant( 'PRIMARY_NETWORK_ID' ) > 0 ) {
			return (int) constant( 'PRIMARY_NETWORK_ID' );
		}
		if ( 1 === (int) $this->current_network_id ) {
			return 1;
		}

		$table = $this->base_table_prefix . 'site';
		if ( ! $this->database || ! $this->database->table_exists( $table ) ) {
			return 1;
		}
		$id = $this->database->get_var( 'SELECT id FROM ' . $this->quote_identifier( $table ) . ' ORDER BY id ASC LIMIT 1' );
		return is_numeric( $id ) && (int) $id > 0 ? (int) $id : 1;
	}

	/**
	 * Read one site option without loading WordPress option APIs.
	 */
	private function scanner_get_option( $name, $default = null ) {
		if ( ! $this->database ) {
			return $default;
		}

		$raw = $this->database->get_option_raw( $name );
		if ( null === $raw ) {
			return $default;
		}

		return $this->decode_stored_value( $raw );
	}

	/**
	 * Read one network option without loading WordPress site-option APIs.
	 */
	private function scanner_get_network_option( $name, $default = null ) {
		if ( ! $this->database ) {
			return $default;
		}

		$raw = $this->database->get_network_option_raw( $name, max( 1, (int) $this->current_network_id ) );
		if ( null === $raw ) {
			return $default;
		}

		return $this->decode_stored_value( $raw );
	}

	/**
	 * Decode ordinary WordPress option serialization without allowing objects.
	 */
	private function decode_stored_value( $value ) {
		if ( ! is_string( $value ) || '' === $value ) {
			return $value;
		}

		if ( strlen( $value ) > 8388608 ) {
			return $value;
		}

		$trimmed = trim( $value );
		if ( preg_match( '/^(?:a|s|i|d|b|N):/', $trimmed ) || 'N;' === $trimmed ) {
			// Reject object/custom-object/reference tokens before unserializing
			// attacker-controlled database content.
			if ( preg_match( '/(?:^|[;{}])(?:O|C|R|r):\d*:/', $trimmed ) ) {
				return $value;
			}

			$decoded = @unserialize( $trimmed, [ 'allowed_classes' => false, 'max_depth' => 64 ] );
			if ( false !== $decoded || 'b:0;' === $trimmed ) {
				return $decoded;
			}
		}

		return $value;
	}

	/**
	 * Resolve the site's canonical host for HTTP proxy bypass parity.
	 */
	private function resolve_site_home_host() {
		$home = defined( 'WP_HOME' ) ? (string) constant( 'WP_HOME' ) : '';
		if ( '' === trim( $home ) ) {
			$home = $this->scanner_get_option( 'home', '' );
		}
		if ( ! is_string( $home ) || '' === trim( $home ) ) {
			$home = defined( 'WP_SITEURL' ) ? (string) constant( 'WP_SITEURL' ) : '';
		}
		if ( '' === trim( (string) $home ) ) {
			$home = $this->scanner_get_option( 'siteurl', '' );
		}

		if ( ! is_string( $home ) || '' === trim( $home ) ) {
			return '';
		}

		$host = parse_url( $home, PHP_URL_HOST );
		return is_string( $host ) ? strtolower( trim( $host ) ) : '';
	}

	/**
	 * Resolve the locale used for WordPress.org inventory requests.
	 */
	private function resolve_site_locale() {
		$details = $this->read_wordpress_core_version_details();
		$locale = trim( (string) ( $details['wp_local_package'] ?? '' ) );

		if ( defined( 'WPLANG' ) ) {
			$locale = trim( (string) constant( 'WPLANG' ) );
		}

		$site_raw = $this->database ? $this->database->get_option_raw( 'WPLANG' ) : null;
		if ( null !== $site_raw ) {
			$site_locale = $this->decode_stored_value( $site_raw );
			if ( is_string( $site_locale ) ) {
				$locale = trim( $site_locale );
			}
		} elseif ( $this->scanner_is_multisite() ) {
			$network_raw = $this->database ? $this->database->get_network_option_raw( 'WPLANG', $this->current_network_id ) : null;
			if ( null !== $network_raw ) {
				$network_locale = $this->decode_stored_value( $network_raw );
				if ( is_string( $network_locale ) ) {
					$locale = trim( $network_locale );
				}
			}
		}

		return '' !== $locale ? $locale : 'en_US';
	}

	/**
	 * Return active regular plugin main files for the current site/network.
	 */
	private function read_active_plugin_files() {
		$this->plugin_scope_reliable = true;
		$files = [];

		$raw = $this->database ? $this->database->get_option_raw( 'active_plugins' ) : null;
		if ( null === $raw ) {
			$this->plugin_scope_reliable = false;
		} else {
			$active = $this->decode_stored_value( $raw );
			if ( ! is_array( $active ) ) {
				$this->plugin_scope_reliable = false;
			} else {
				foreach ( $active as $file ) {
					if ( ! is_string( $file ) || '' === trim( $file ) ) {
						$this->plugin_scope_reliable = false;
						continue;
					}
					$files[] = $file;
				}
			}
		}

		if ( $this->scanner_is_multisite() ) {
			$network_raw = $this->database ? $this->database->get_network_option_raw( 'active_sitewide_plugins', $this->current_network_id ) : null;
			if ( null !== $network_raw ) {
				$network = $this->decode_stored_value( $network_raw );
				if ( ! is_array( $network ) ) {
					$this->plugin_scope_reliable = false;
				} else {
					foreach ( array_keys( $network ) as $file ) {
						if ( ! is_string( $file ) || '' === trim( $file ) ) {
							$this->plugin_scope_reliable = false;
							continue;
						}
						$files[] = $file;
					}
				}
			}
		}

		$normalized_files = [];
		foreach ( $files as $file ) {
			$normalized = $this->normalize_plugin_main_file( $file );
			if ( '' === $normalized ) {
				$this->plugin_scope_reliable = false;
				continue;
			}
			$normalized_files[] = $normalized;
		}

		if ( ! $this->plugin_scope_reliable ) {
			$this->runtime_warnings[] = 'Plugin activation state could not be read safely; all installed plugins will be scanned.';
		}

		return array_values( array_unique( $normalized_files ) );
	}

	/**
	 * Normalize a plugin main-file value from the restored database.
	 */
	private function normalize_plugin_main_file( $file ) {
		if ( ! is_string( $file ) || '' === trim( $file ) || false !== strpos( $file, "\0" ) ) {
			return '';
		}

		$file = str_replace( '\\', '/', trim( $file ) );
		if ( '/' === substr( $file, 0, 1 ) || preg_match( '/^[A-Za-z]:\//', $file ) ) {
			return '';
		}

		$segments = explode( '/', $file );
		foreach ( $segments as $segment ) {
			if ( '' === $segment || '.' === $segment || '..' === $segment ) {
				return '';
			}
		}

		if ( 'php' !== strtolower( pathinfo( $file, PATHINFO_EXTENSION ) ) ) {
			return '';
		}

		return $file;
	}

	/**
	 * Resolve the uploads directory from the same configuration WordPress uses.
	 */
	private function resolve_upload_directory() {
		$upload_path = $this->scanner_get_option( 'upload_path', '' );
		$upload_path = is_string( $upload_path ) ? trim( $upload_path ) : '';
		if ( '' === $upload_path || 'wp-content/uploads' === $upload_path ) {
			$directory = $this->content_dir . DIRECTORY_SEPARATOR . 'uploads';
		} elseif ( $this->path_is_absolute( $upload_path ) ) {
			$directory = rtrim( $upload_path, '/\\' );
		} else {
			$directory = $this->wp_root . DIRECTORY_SEPARATOR . trim( str_replace( [ '/', '\\' ], DIRECTORY_SEPARATOR, $upload_path ), DIRECTORY_SEPARATOR );
		}

		$is_multisite = $this->scanner_is_multisite();
		$ms_files_rewriting = $is_multisite && (bool) $this->scanner_get_network_option( 'ms_files_rewriting', false );

		if ( defined( 'UPLOADS' ) && ! ( $is_multisite && $ms_files_rewriting ) ) {
			$uploads = ltrim( str_replace( [ '/', '\\' ], DIRECTORY_SEPARATOR, (string) constant( 'UPLOADS' ) ), DIRECTORY_SEPARATOR );
			$directory = $this->wp_root . DIRECTORY_SEPARATOR . $uploads;
		}

		if ( $is_multisite ) {
			$is_main_network = $this->current_network_id === $this->resolve_main_network_id();
			$is_main_site = $this->current_blog_id === $this->current_network_main_blog_id;
			$is_post_mu_main_site = $is_main_network && $is_main_site && defined( 'MULTISITE' );

			if ( ! $is_post_mu_main_site ) {
				if ( ! $ms_files_rewriting ) {
					$segment = defined( 'MULTISITE' )
						? [ 'sites', (string) $this->current_blog_id ]
						: [ (string) $this->current_blog_id ];
					$directory = rtrim( $directory, '/\\' ) . DIRECTORY_SEPARATOR . implode( DIRECTORY_SEPARATOR, $segment );
				} elseif ( defined( 'UPLOADS' ) ) {
					if ( defined( 'BLOGUPLOADDIR' ) && '' !== trim( (string) constant( 'BLOGUPLOADDIR' ) ) ) {
						$directory = rtrim( (string) constant( 'BLOGUPLOADDIR' ), '/\\' );
					} else {
						$uploads = ltrim( str_replace( [ '/', '\\' ], DIRECTORY_SEPARATOR, (string) constant( 'UPLOADS' ) ), DIRECTORY_SEPARATOR );
						$directory = $this->wp_root . DIRECTORY_SEPARATOR . $uploads;
					}
				}
			}
		}

		return rtrim( $directory, '/\\' );
	}

	private function path_is_absolute( $path ) {
		return '/' === substr( $path, 0, 1 ) || '\\' === substr( $path, 0, 1 ) || (bool) preg_match( '/^[A-Za-z]:[\\\\\/]/', $path );
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
	 * Read WordPress core version metadata without including version.php.
	 *
	 * The version file is treated as scan input. Values are parsed from text so a
	 * compromised core file cannot execute code inside the scanner process.
	 */
	private function read_wordpress_core_version_details() {
		$path = $this->wp_root . DIRECTORY_SEPARATOR . 'wp-includes' . DIRECTORY_SEPARATOR . 'version.php';
		if ( ! is_readable( $path ) ) {
			return [];
		}

		$content = (string) @file_get_contents( $path, false, null, 0, 8192 );
		if ( '' === $content ) {
			return [];
		}

		return [
			'wp_version'       => $this->parse_php_scalar_assignment( $content, 'wp_version' ),
			'wp_local_package' => $this->parse_php_scalar_assignment( $content, 'wp_local_package' ),
		];
	}

	/**
	 * Parse one simple scalar assignment from PHP source without executing it.
	 */
	private function parse_php_scalar_assignment( $content, $variable ) {
		$variable = preg_quote( (string) $variable, '/' );
		if ( preg_match( '/\$' . $variable . '\s*=\s*([\'"])(.*?)\1\s*;/s', (string) $content, $matches ) ) {
			return stripcslashes( (string) $matches[2] );
		}
		if ( preg_match( '/\$' . $variable . '\s*=\s*([0-9]+)\s*;/', (string) $content, $matches ) ) {
			return (string) $matches[1];
		}
		return '';
	}

	/**
	 * Normalize one WordPress.org core checksum manifest path.
	 *
	 * Remote manifest data is never allowed to escape the local WordPress root.
	 */
	private function normalize_core_manifest_path( $file ) {
		if ( ! is_string( $file ) || '' === trim( $file ) || false !== strpos( $file, "\0" ) ) {
			return '';
		}

		$file = str_replace( '\\', '/', trim( $file ) );
		if ( '/' === substr( $file, 0, 1 ) || preg_match( '/^[A-Za-z]:\//', $file ) ) {
			return '';
		}

		$segments = explode( '/', $file );
		foreach ( $segments as $segment ) {
			if ( '' === $segment || '.' === $segment || '..' === $segment ) {
				return '';
			}
		}

		return implode( '/', $segments );
	}

	/**
	 * Whether a local path participates in WP-CLI's default unexpected-core-file check.
	 */
	private function core_checksum_path_is_checked( $file ) {
		$file = str_replace( '\\', '/', ltrim( (string) $file, '/' ) );
		return 0 === strpos( $file, 'wp-admin/' )
			|| 0 === strpos( $file, 'wp-includes/' )
			|| 1 === preg_match( '/^wp-(?!config\.php)([^\/]*)$/', $file );
	}

	/**
	 * Discover local core files covered by the default unexpected-file policy.
	 */
	private function discover_core_checksum_files() {
		$files = [];

		foreach ( [ 'wp-admin', 'wp-includes' ] as $directory_name ) {
			$directory = $this->wp_root . DIRECTORY_SEPARATOR . $directory_name;
			if ( ! is_dir( $directory ) ) {
				continue;
			}

			$iterator = new \RecursiveIteratorIterator(
				new \RecursiveDirectoryIterator( $directory, \FilesystemIterator::SKIP_DOTS )
			);
			foreach ( $iterator as $item ) {
				if ( ! $item->isFile() && ! $item->isLink() ) {
					continue;
				}
				$relative = ltrim( substr( $item->getPathname(), strlen( $this->wp_root ) ), '/\\' );
				$relative = str_replace( '\\', '/', $relative );
				if ( $this->core_checksum_path_is_checked( $relative ) ) {
					$files[] = $relative;
				}
			}
		}

		$root = new \DirectoryIterator( $this->wp_root );
		foreach ( $root as $item ) {
			if ( $item->isDot() || ( ! $item->isFile() && ! $item->isLink() ) ) {
				continue;
			}
			$file = (string) $item->getFilename();
			if ( $this->core_checksum_path_is_checked( $file ) ) {
				$files[] = $file;
			}
		}

		$files = array_values( array_unique( $files ) );
		sort( $files, SORT_STRING );
		return $files;
	}

	/**
	 * Fetch the official WordPress core checksum manifest using scanner-owned HTTP.
	 */
	private function fetch_core_checksum_manifest( $version, $locale ) {
		$url = 'https://api.wordpress.org/core/checksums/1.0/?' . http_build_query(
			[
				'version' => (string) $version,
				'locale'  => '' !== trim( (string) $locale ) ? (string) $locale : 'en_US',
			],
			'',
			'&'
		);
		$response = $this->http_request_json( 'GET', $url, null, 30 );
		if ( 200 !== (int) ( $response['code'] ?? 0 ) ) {
			return [ 'checksums' => [], 'error' => (string) ( $response['error'] ?? 'WordPress.org checksum request failed' ) ];
		}

		$json = $response['json'] ?? null;
		if ( ! is_array( $json ) || ! isset( $json['checksums'] ) || ! is_array( $json['checksums'] ) ) {
			return [ 'checksums' => [], 'error' => 'WordPress.org returned an invalid core checksum manifest' ];
		}

		$checksums = [];
		foreach ( $json['checksums'] as $file => $checksum ) {
			$normalized = $this->normalize_core_manifest_path( $file );
			$checksum = strtolower( trim( (string) $checksum ) );
			if ( '' === $normalized || ! preg_match( '/^[a-f0-9]{32}$/', $checksum ) ) {
				return [ 'checksums' => [], 'error' => 'WordPress.org returned an unsafe or malformed core checksum manifest' ];
			}
			$checksums[ $normalized ] = $checksum;
		}

		return [ 'checksums' => $checksums, 'error' => '' ];
	}

	/**
	 * Verify WordPress core checksums without launching another WP-CLI process.
	 */
	private function scan_core_checksums() {
		$stage = 'Core checksums';
		$this->stage_start( $stage );

		try {
			$details = $this->read_wordpress_core_version_details();
			$version = trim( (string) ( $details['wp_version'] ?? '' ) );
			$locale = trim( (string) ( $details['wp_local_package'] ?? '' ) );
			if ( '' === $version ) {
				throw new \RuntimeException( 'Unable to determine the installed WordPress version from wp-includes/version.php.' );
			}
			if ( '' === $locale ) {
				$locale = 'en_US';
			}

			if ( $this->interactive ) {
				$this->start_background_spinner( 'Scanning core checksums...' );
			}
			try {
				$manifest = $this->fetch_core_checksum_manifest( $version, $locale );
			} finally {
				if ( $this->interactive ) {
					$this->stop_background_spinner();
				}
			}
			$checksums = (array) ( $manifest['checksums'] ?? [] );
			if ( empty( $checksums ) ) {
				$error = trim( (string) ( $manifest['error'] ?? '' ) );
				throw new \RuntimeException( '' !== $error ? $error : 'Unable to retrieve WordPress core checksums.' );
			}

			$processed = 0;
			foreach ( $checksums as $file => $checksum ) {
				if ( 0 === strpos( $file, 'wp-content/' ) ) {
					continue;
				}

				$processed++;
				$this->stage_tick( $stage, $processed, 'files' );
				$absolute = $this->wp_root . DIRECTORY_SEPARATOR . str_replace( '/', DIRECTORY_SEPARATOR, $file );
				if ( ! file_exists( $absolute ) && ! is_link( $absolute ) ) {
					$this->add_finding( $stage, 'high', 96, $file, 'core_checksum_missing', 'Core file is missing from the WordPress installation' );
					continue;
				}
				if ( is_link( $absolute ) ) {
					$this->add_finding( $stage, 'high', 96, $file, 'core_checksum_symlink', 'WordPress core file is a symbolic link' );
					continue;
				}
				$actual = @md5_file( $absolute );
				if ( ! is_string( $actual ) || 0 !== strcasecmp( $checksum, $actual ) ) {
					$this->add_finding( $stage, 'high', 96, $file, 'core_checksum_mismatch', 'Core file differs from the official WordPress checksum' );
				}
			}

			$expected = [];
			foreach ( array_keys( $checksums ) as $file ) {
				if ( $this->core_checksum_path_is_checked( $file ) ) {
					$expected[ $file ] = true;
				}
			}

			foreach ( $this->discover_core_checksum_files() as $file ) {
				if ( isset( $expected[ $file ] ) ) {
					continue;
				}
				$this->add_finding( $stage, 'high', 96, $file, 'core_checksum_unexpected', 'Unexpected file found in WordPress core' );
			}

			$this->checksum_stage_finish( $stage, $this->count_stage_findings( $stage ) );
		} catch ( \Throwable $e ) {
			$this->add_finding( $stage, 'high', 90, 'WordPress core', 'core_checksum_failed', 'WordPress core checksum verification could not complete: ' . $e->getMessage() );
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
			? $this->plugin_dir . DIRECTORY_SEPARATOR . $slug
			: $this->plugin_dir;

		if ( $has_directory && is_link( $root ) ) {
			$this->set_plugin_integrity_status( $slug, 'modified' );
			$this->plugin_integrity[ $slug ]['checksum_errors'][] = [
				'file'    => $main_file,
				'message' => 'Plugin directory is a symbolic link',
			];
			return;
		}

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
			$absolute = $file_info->getPathname();
			$relative = ltrim( str_replace( '\\', '/', substr( $absolute, strlen( $root ) ) ), '/' );
			if ( ! $has_directory ) {
				if ( $relative !== basename( $main_file ) ) {
					continue;
				}
			}

			if ( $file_info->isLink() ) {
				$errors[] = [ 'file' => $relative, 'message' => 'Local plugin path is a symbolic link' ];
				continue;
			}

			if ( ! $file_info->isFile() ) {
				continue;
			}

			$current_count = isset( $this->stage_stats['Plugin integrity']['items'] )
				? (int) $this->stage_stats['Plugin integrity']['items'] + 1
				: 1;
			$this->stage_tick( 'Plugin integrity', $current_count, 'files' );

			if ( ! array_key_exists( $relative, $normalized_manifest ) ) {
				$errors[] = [ 'file' => $relative, 'message' => 'Local file is not part of the official plugin package' ];
				continue;
			}

			$hash_sets = $this->normalize_checksum_manifest_entry( $normalized_manifest[ $relative ] );
			$verified = false;

			if ( ! empty( $hash_sets['sha256'] ) && $this->plugin_sha256_is_available() ) {
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
	 * Cache SHA-256 support for the plugin-integrity stage.
	 */
	private function plugin_sha256_is_available() {
		if ( null === $this->plugin_sha256_available ) {
			$this->plugin_sha256_available = in_array( 'sha256', hash_algos(), true );
		}

		return (bool) $this->plugin_sha256_available;
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
		$this->installed_plugins = $this->discover_installed_plugins();
		$this->installed_plugins = $this->include_active_plugins_missing_headers( $this->installed_plugins );
		$active_lookup = array_fill_keys( $this->active_plugin_files, true );

		foreach ( $this->installed_plugins as $file => $data ) {
			$file = str_replace( '\\', '/', (string) $file );
			$slug = $this->plugin_slug_from_main_file( $file );
			if ( '' === $slug ) {
				continue;
			}

			$is_active = ! $this->plugin_scope_reliable || isset( $active_lookup[ $file ] );
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
	 * Keep an active plugin in scan scope even if its plugin header was removed.
	 *
	 * WordPress can still load a PHP file referenced by active_plugins when its
	 * metadata header is damaged or stripped. Treat that state as unverified and
	 * retain the plugin root for static analysis rather than silently skipping it.
	 */
	private function include_active_plugins_missing_headers( array $plugins ) {
		foreach ( $this->active_plugin_files as $file ) {
			$file = $this->normalize_plugin_main_file( $file );
			if ( '' === $file || isset( $plugins[ $file ] ) ) {
				continue;
			}

			$absolute = $this->plugin_dir . DIRECTORY_SEPARATOR . str_replace( '/', DIRECTORY_SEPARATOR, $file );
			if ( ! is_file( $absolute ) ) {
				continue;
			}

			$root_component = false !== strpos( $file, '/' ) ? strstr( $file, '/', true ) : $file;
			$root_path = $this->plugin_dir . DIRECTORY_SEPARATOR . $root_component;
			$data = [
				'Name'      => $this->plugin_slug_from_main_file( $file ),
				'PluginURI' => '',
				'Version'   => '',
				'UpdateURI' => '',
			];

			if ( ! is_link( $root_path ) ) {
				$headers = $this->read_file_headers(
					$absolute,
					[
						'Name'      => 'Plugin Name',
						'PluginURI' => 'Plugin URI',
						'Version'   => 'Version',
						'UpdateURI' => 'Update URI',
					]
				);
				foreach ( $headers as $key => $value ) {
					if ( '' !== (string) $value ) {
						$data[ $key ] = $value;
					}
				}
			}

			$plugins[ $file ] = $data;
		}

		ksort( $plugins, SORT_STRING );
		return $plugins;
	}

	/**
	 * Discover regular plugins by reading plugin headers only; no plugin PHP is executed.
	 */
	private function discover_installed_plugins() {
		if ( ! is_dir( $this->plugin_dir ) ) {
			return [];
		}

		$candidates = [];
		$top = new \DirectoryIterator( $this->plugin_dir );
		foreach ( $top as $item ) {
			if ( $item->isDot() ) {
				continue;
			}

			if ( $item->isFile() && 'php' === strtolower( $item->getExtension() ) ) {
				$candidates[ $item->getFilename() ] = $item->getPathname();
				continue;
			}

			if ( ! $item->isDir() ) {
				continue;
			}

			$directory = new \DirectoryIterator( $item->getPathname() );
			foreach ( $directory as $plugin_file ) {
				if ( $plugin_file->isDot() || ! $plugin_file->isFile() ) {
					continue;
				}
				if ( 'php' !== strtolower( $plugin_file->getExtension() ) ) {
					continue;
				}

				$relative = $item->getFilename() . '/' . $plugin_file->getFilename();
				$candidates[ $relative ] = $plugin_file->getPathname();
			}
		}

		ksort( $candidates, SORT_STRING );
		$plugins = [];
		foreach ( $candidates as $relative => $path ) {
			$data = $this->read_file_headers(
				$path,
				[
					'Name'      => 'Plugin Name',
					'PluginURI' => 'Plugin URI',
					'Version'   => 'Version',
					'UpdateURI' => 'Update URI',
				]
			);
			if ( '' === (string) ( $data['Name'] ?? '' ) ) {
				continue;
			}
			$plugins[ str_replace( '\\', '/', $relative ) ] = $data;
		}

		return $plugins;
	}

	/**
	 * Build active/inactive theme inventory from style.css and database options.
	 */
	private function initialize_theme_inventory() {
		$this->theme_scope_reliable = true;
		$installed = [];

		if ( is_dir( $this->theme_dir ) ) {
			$themes = new \DirectoryIterator( $this->theme_dir );
			foreach ( $themes as $item ) {
				if ( $item->isDot() || ! $item->isDir() ) {
					continue;
				}

				$slug = (string) $item->getFilename();
				$style = $item->getPathname() . DIRECTORY_SEPARATOR . 'style.css';
				if ( ! is_file( $style ) ) {
					continue;
				}

				$data = $this->read_file_headers( $style, [ 'Name' => 'Theme Name' ] );
				$installed[ $slug ] = [
					'slug' => $slug,
					'name' => '' !== (string) ( $data['Name'] ?? '' ) ? (string) $data['Name'] : $slug,
				];
			}
		}

		$stylesheet = $this->read_theme_slug_option( 'stylesheet' );
		$template = $this->read_theme_slug_option( 'template' );

		foreach ( [ $stylesheet, $template ] as $slug ) {
			if ( '' === $slug || ! isset( $installed[ $slug ] ) ) {
				$this->theme_scope_reliable = false;
				continue;
			}
			$this->active_theme_slugs[ $slug ] = true;
		}

		if ( ! $this->theme_scope_reliable ) {
			$this->active_theme_slugs = array_fill_keys( array_keys( $installed ), true );
			$this->runtime_warnings[] = 'Active theme state could not be read safely; all installed themes will be scanned.';
			return;
		}

		foreach ( $installed as $slug => $data ) {
			if ( isset( $this->active_theme_slugs[ $slug ] ) ) {
				continue;
			}
			$this->inactive_themes[] = $data;
		}
	}

	/**
	 * Read an active-theme option without trusting it as a filesystem path.
	 */
	private function read_theme_slug_option( $name ) {
		if ( ! $this->database ) {
			return '';
		}

		$raw = $this->database->get_option_raw( $name );
		if ( null === $raw ) {
			return '';
		}

		$value = $this->decode_stored_value( $raw );
		if ( ! is_string( $value ) ) {
			return '';
		}

		$value = trim( $value );
		if ( '' === $value || '.' === $value || '..' === $value || false !== strpos( $value, '/' ) || false !== strpos( $value, '\\' ) ) {
			return '';
		}

		return $value;
	}

	/**
	 * Read WordPress-style file headers from the first 8 KiB of a file.
	 */
	private function read_file_headers( $path, array $headers ) {
		$data = [];
		foreach ( $headers as $key => $label ) {
			$data[ $key ] = '';
		}

		$handle = @fopen( $path, 'rb' );
		if ( false === $handle ) {
			return $data;
		}
		$content = (string) fread( $handle, 8192 );
		fclose( $handle );
		$content = str_replace( "\r", "\n", $content );

		foreach ( $headers as $key => $label ) {
			$pattern = '/^[ \t\/*#@]*' . preg_quote( $label, '/' ) . ':(.*)$/mi';
			if ( preg_match( $pattern, $content, $matches ) ) {
				$value = trim( preg_replace( '/\s*(?:\*\/|\?>).*/', '', $matches[1] ) );
				$data[ $key ] = $value;
			}
		}

		return $data;
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
			return $this->sanitize_key_value( dirname( $file ) );
		}

		return $this->sanitize_key_value( pathinfo( $file, PATHINFO_FILENAME ) );
	}


	/**
	 * Update a plugin integrity status without downgrading a stronger state.
	 */
	private function set_plugin_integrity_status( $plugin, $status ) {
		$plugin = $this->sanitize_key_value( (string) $plugin );
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
		if ( ! empty( $plugins ) ) {
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
		return array_intersect_key( $this->installed_plugins, $this->plugin_scan_files );
	}


	/**
	 * Apply high-confidence local reputation signals that need no network call.
	 */
	private function apply_local_plugin_reputation_signals() {
		foreach ( $this->plugin_integrity as $slug => &$data ) {
			$update_uri = trim( (string) ( $data['update_uri'] ?? '' ) );
			if ( '' !== $update_uri ) {
				$host = strtolower( (string) parse_url( $update_uri, PHP_URL_HOST ) );
				if ( '' === $host || ! $this->is_wordpress_org_host( $host ) ) {
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
		$payload = [
			'plugins' => $plugins,
			'active'  => $this->active_plugin_files,
		];

		$locales = array_values( array_unique( array_filter( [ $this->site_locale ] ) ) );
		$timeout = max( 5, 3 + (int) ( count( $plugins ) / 10 ) );
		$response = $this->http_request_json(
			'POST',
			'https://api.wordpress.org/plugins/update-check/1.1/',
			[
				'plugins'      => json_encode( $payload ),
				'translations' => json_encode( [] ),
				'locale'       => json_encode( $locales ),
				'all'          => json_encode( true ),
			],
			$timeout
		);

		if ( ! is_array( $response ) || 200 !== (int) ( $response['code'] ?? 0 ) ) {
			return null;
		}

		return is_array( $response['json'] ?? null ) ? $response['json'] : null;
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
			if ( 'external' === ( $this->plugin_integrity[ $slug ]['source'] ?? '' ) ) {
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
	 * Allow outbound scanner HTTP only to the official WordPress.org services
	 * required for plugin reputation and checksum verification.
	 */
	private function scanner_http_url_is_allowed( $url ) {
		$scheme = strtolower( (string) parse_url( (string) $url, PHP_URL_SCHEME ) );
		$host = strtolower( (string) parse_url( (string) $url, PHP_URL_HOST ) );

		if ( 'https' !== $scheme || ! in_array( $host, [ 'api.wordpress.org', 'downloads.wordpress.org' ], true ) ) {
			return false;
		}

		return $this->scanner_http_external_policy_allows( $url );
	}

	/**
	 * Honor trusted WP_HTTP_BLOCK_EXTERNAL/WP_ACCESSIBLE_HOSTS configuration.
	 */
	private function scanner_http_external_policy_allows( $url ) {
		if ( ! defined( 'WP_HTTP_BLOCK_EXTERNAL' ) || ! (bool) constant( 'WP_HTTP_BLOCK_EXTERNAL' ) ) {
			return true;
		}

		$host = strtolower( (string) parse_url( (string) $url, PHP_URL_HOST ) );
		if ( '' === $host ) {
			return false;
		}
		if ( 'localhost' === $host || ( '' !== $this->site_home_host && $host === $this->site_home_host ) ) {
			return true;
		}
		if ( ! defined( 'WP_ACCESSIBLE_HOSTS' ) ) {
			return false;
		}

		return $this->scanner_http_host_matches_list( $host, (string) constant( 'WP_ACCESSIBLE_HOSTS' ) );
	}

	/**
	 * Match the comma-separated hostname/wildcard format used by WordPress HTTP policy.
	 */
	private function scanner_http_host_matches_list( $host, $list ) {
		$host = strtolower( trim( (string) $host ) );
		$patterns = preg_split( '/,\s*/', (string) $list, -1, PREG_SPLIT_NO_EMPTY );
		foreach ( $patterns as $pattern ) {
			$pattern = strtolower( trim( (string) $pattern ) );
			if ( '' === $pattern ) {
				continue;
			}
			if ( false !== strpos( $pattern, '*' ) ) {
				$regex = '/^' . str_replace( '\\*', '.+', preg_quote( $pattern, '/' ) ) . '$/i';
				if ( preg_match( $regex, $host ) ) {
					return true;
				}
			} elseif ( 0 === strcasecmp( $pattern, $host ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Resolve trusted WP_PROXY_* configuration without loading WP_HTTP_Proxy.
	 */
	private function scanner_http_proxy_for_url( $url ) {
		if ( ! defined( 'WP_PROXY_HOST' ) || ! defined( 'WP_PROXY_PORT' ) ) {
			return null;
		}

		$proxy_host = trim( (string) constant( 'WP_PROXY_HOST' ) );
		$proxy_port = (int) constant( 'WP_PROXY_PORT' );
		$request_host = strtolower( (string) parse_url( (string) $url, PHP_URL_HOST ) );
		if ( '' === $proxy_host || $proxy_port < 1 || $proxy_port > 65535 || '' === $request_host ) {
			return null;
		}

		if ( 'localhost' === $request_host || ( '' !== $this->site_home_host && $request_host === $this->site_home_host ) ) {
			return null;
		}

		if ( defined( 'WP_PROXY_BYPASS_HOSTS' ) ) {
			$bypass_hosts = preg_split( '/,\s*/', (string) constant( 'WP_PROXY_BYPASS_HOSTS' ), -1, PREG_SPLIT_NO_EMPTY );
			foreach ( $bypass_hosts as $bypass_host ) {
				$bypass_host = trim( (string) $bypass_host );
				if ( '' === $bypass_host ) {
					continue;
				}

				if ( false !== strpos( $bypass_host, '*' ) ) {
					$pattern = '/^' . str_replace( '\\*', '.+', preg_quote( $bypass_host, '/' ) ) . '$/i';
					if ( preg_match( $pattern, $request_host ) ) {
						return null;
					}
				} elseif ( 0 === strcasecmp( $bypass_host, $request_host ) ) {
					return null;
				}
			}
		}

		$proxy = [
			'host' => $proxy_host,
			'port' => $proxy_port,
			'auth' => '',
		];

		if ( defined( 'WP_PROXY_USERNAME' ) && defined( 'WP_PROXY_PASSWORD' ) ) {
			$proxy['auth'] = (string) constant( 'WP_PROXY_USERNAME' ) . ':' . (string) constant( 'WP_PROXY_PASSWORD' );
		}

		return $proxy;
	}

	/**
	 * Add trusted WordPress proxy settings to a cURL request.
	 */
	private function apply_scanner_curl_proxy_options( array &$options, $url ) {
		$proxy = $this->scanner_http_proxy_for_url( $url );
		if ( null === $proxy ) {
			return;
		}

		$options[ CURLOPT_PROXYTYPE ] = CURLPROXY_HTTP;
		$options[ CURLOPT_PROXY ] = $proxy['host'];
		$options[ CURLOPT_PROXYPORT ] = $proxy['port'];
		if ( '' !== $proxy['auth'] ) {
			$options[ CURLOPT_PROXYAUTH ] = CURLAUTH_ANY;
			$options[ CURLOPT_PROXYUSERPWD ] = $proxy['auth'];
		}
	}

	/**
	 * Create bounded cURL transfer state for scanner-owned JSON requests.
	 */
	private function scanner_curl_response_state() {
		return (object) [
			'too_large' => false,
		];
	}

	/**
	 * Return a lightweight cURL progress callback that aborts oversized downloads.
	 *
	 * Response bytes remain buffered natively by cURL via CURLOPT_RETURNTRANSFER;
	 * PHP only receives numeric transfer progress instead of every body chunk.
	 */
	private function scanner_curl_progress_callback( $state ) {
		return function ( $handle, $download_size, $downloaded, $upload_size, $uploaded ) use ( $state ) {
			if ( $download_size > self::HTTP_RESPONSE_MAX_BYTES || $downloaded > self::HTTP_RESPONSE_MAX_BYTES ) {
				$state->too_large = true;
				return 1;
			}
			return 0;
		};
	}

	/**
	 * Fetch multiple JSON URLs concurrently when cURL multi is available.
	 *
	 * TLS verification is never disabled. A scanner-owned sequential HTTPS
	 * client is used as the compatibility fallback.
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
		$results = [];
		$completed = 0;
		foreach ( $urls as $key => $url ) {
			if ( ! $this->scanner_http_url_is_allowed( $url ) ) {
				$results[ $key ] = [
					'code'  => 0,
					'body'  => '',
					'json'  => null,
					'error' => 'Scanner HTTP request was blocked because the destination is not an approved WordPress.org endpoint',
				];
				$completed++;
				continue;
			}

			$queue[] = [ 'key' => $key, 'url' => $url ];
		}

		$active = [];
		$total = count( $urls );
		$offset = 0;

		$add_next = function () use ( &$queue, &$offset, &$active, $multi ) {
			if ( ! isset( $queue[ $offset ] ) ) {
				return false;
			}

			$item = $queue[ $offset++ ];
			$handle = curl_init();
			$state = $this->scanner_curl_response_state();
			$options = [
				CURLOPT_URL            => $item['url'],
				CURLOPT_FOLLOWLOCATION => false,
				CURLOPT_CONNECTTIMEOUT => 8,
				CURLOPT_TIMEOUT        => 20,
				CURLOPT_SSL_VERIFYPEER => true,
				CURLOPT_SSL_VERIFYHOST => 2,
				CURLOPT_ENCODING          => '',
				CURLOPT_USERAGENT         => 'WP-CLI Security Scan/' . self::VERSION,
				CURLOPT_RETURNTRANSFER    => true,
				CURLOPT_NOPROGRESS        => false,
				CURLOPT_XFERINFOFUNCTION  => $this->scanner_curl_progress_callback( $state ),
			];
			$this->apply_scanner_curl_proxy_options( $options, $item['url'] );
			curl_setopt_array( $handle, $options );
			curl_multi_add_handle( $multi, $handle );
			$handle_id = is_object( $handle ) ? spl_object_id( $handle ) : (int) $handle;
			$active[ $handle_id ] = [ 'handle' => $handle, 'key' => $item['key'], 'state' => $state ];
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

				$state = $item['state'];
				$body = (string) curl_multi_getcontent( $handle );
				if ( strlen( $body ) > self::HTTP_RESPONSE_MAX_BYTES ) {
					$state->too_large = true;
					$body = '';
				}
				$code = (int) curl_getinfo( $handle, CURLINFO_HTTP_CODE );
				$error = $state->too_large
					? 'HTTP response exceeded the scanner size limit'
					: ( CURLE_OK === (int) $info['result'] ? '' : curl_error( $handle ) );
				$results[ $item['key'] ] = [
					'code'  => $code,
					'body'  => $body,
					'json'  => '' !== $body && ! $state->too_large ? json_decode( $body, true ) : null,
					'error' => $error,
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
			$error = (string) ( $results[ $key ]['error'] ?? '' );
			if (
				! isset( $results[ $key ] )
				|| ( 0 === (int) ( $results[ $key ]['code'] ?? 0 ) && '' !== $error && 'HTTP response exceeded the scanner size limit' !== $error )
			) {
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
				$response = $this->http_request_json( 'GET', $url, null, 20 );
			} finally {
				if ( $this->interactive ) {
					$this->stop_background_spinner();
				}
			}

			$results[ $key ] = is_array( $response )
				? $response
				: [ 'code' => 0, 'body' => '', 'json' => null, 'error' => 'HTTP request failed' ];
		}

		return $results;
	}

	/**
	 * Perform a small read-only HTTP request without loading the WordPress HTTP API.
	 *
	 * TLS peer/hostname verification is always enabled. cURL is preferred; the
	 * PHP HTTPS stream wrapper is a compatibility fallback.
	 */
	private function http_request_json( $method, $url, $body = null, $timeout = 20 ) {
		$method = strtoupper( (string) $method );
		if ( ! $this->scanner_http_url_is_allowed( $url ) ) {
			return [ 'code' => 0, 'body' => '', 'json' => null, 'error' => 'Scanner HTTP request was blocked because the destination is not an approved WordPress.org endpoint' ];
		}

		$payload = is_array( $body ) ? http_build_query( $body, '', '&' ) : '';
		$user_agent = 'WP-CLI Security Scan/' . self::VERSION;

		if ( function_exists( 'curl_init' ) ) {
			$handle = curl_init();
			$state = $this->scanner_curl_response_state();
			$options = [
				CURLOPT_URL            => $url,
				CURLOPT_FOLLOWLOCATION => false,
				CURLOPT_CONNECTTIMEOUT => min( 8, max( 1, (int) $timeout ) ),
				CURLOPT_TIMEOUT        => max( 1, (int) $timeout ),
				CURLOPT_SSL_VERIFYPEER => true,
				CURLOPT_SSL_VERIFYHOST => 2,
				CURLOPT_ENCODING          => '',
				CURLOPT_USERAGENT         => $user_agent,
				CURLOPT_RETURNTRANSFER    => true,
				CURLOPT_NOPROGRESS        => false,
				CURLOPT_XFERINFOFUNCTION  => $this->scanner_curl_progress_callback( $state ),
			];
			if ( 'POST' === $method ) {
				$options[ CURLOPT_POST ] = true;
				$options[ CURLOPT_POSTFIELDS ] = $payload;
				$options[ CURLOPT_HTTPHEADER ] = [ 'Content-Type: application/x-www-form-urlencoded' ];
			}
			$this->apply_scanner_curl_proxy_options( $options, $url );
			curl_setopt_array( $handle, $options );
			$result = curl_exec( $handle );
			$code = (int) curl_getinfo( $handle, CURLINFO_HTTP_CODE );
			$response_body = is_string( $result ) ? $result : '';
			if ( strlen( $response_body ) > self::HTTP_RESPONSE_MAX_BYTES ) {
				$state->too_large = true;
				$response_body = '';
			}
			$error = $state->too_large
				? 'HTTP response exceeded the scanner size limit'
				: ( false === $result ? curl_error( $handle ) : '' );
			curl_close( $handle );
			return [
				'code'  => $code,
				'body'  => $response_body,
				'json'  => '' !== $response_body && ! $state->too_large ? json_decode( $response_body, true ) : null,
				'error' => $error,
			];
		}

		if ( null !== $this->scanner_http_proxy_for_url( $url ) ) {
			return [ 'code' => 0, 'body' => '', 'json' => null, 'error' => 'Configured WordPress HTTP proxy requires the cURL PHP extension in isolated scanner mode' ];
		}

		if ( ! (bool) ini_get( 'allow_url_fopen' ) ) {
			return [ 'code' => 0, 'body' => '', 'json' => null, 'error' => 'No HTTPS transport is available' ];
		}

		$headers = [ 'User-Agent: ' . $user_agent ];
		if ( 'POST' === $method ) {
			$headers[] = 'Content-Type: application/x-www-form-urlencoded';
			$headers[] = 'Content-Length: ' . strlen( $payload );
		}
		$context = stream_context_create(
			[
				'http' => [
					'method'        => $method,
					'timeout'       => max( 1, (int) $timeout ),
					'ignore_errors' => true,
					'header'        => implode( "\r\n", $headers ),
					'content'       => 'POST' === $method ? $payload : '',
				],
				'ssl' => [
					'verify_peer'      => true,
					'verify_peer_name' => true,
					'allow_self_signed' => false,
				],
			]
		);
		$response_headers = [];
		$response_body = @file_get_contents( $url, false, $context, 0, self::HTTP_RESPONSE_MAX_BYTES + 1 );
		if ( isset( $http_response_header ) && is_array( $http_response_header ) ) {
			$response_headers = $http_response_header;
		}
		$code = 0;
		if ( isset( $response_headers[0] ) && preg_match( '/\s(\d{3})(?:\s|$)/', $response_headers[0], $matches ) ) {
			$code = (int) $matches[1];
		}
		$response_body = is_string( $response_body ) ? $response_body : '';
		if ( strlen( $response_body ) > self::HTTP_RESPONSE_MAX_BYTES ) {
			return [
				'code'  => $code,
				'body'  => '',
				'json'  => null,
				'error' => 'HTTP response exceeded the scanner size limit',
			];
		}
		return [
			'code'  => $code,
			'body'  => $response_body,
			'json'  => '' !== $response_body ? json_decode( $response_body, true ) : null,
			'error' => false === $response_body ? 'HTTPS stream request failed' : '',
		];
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
				if ( $this->is_scanner_output_path( $current->getPathname() ) ) {
					return false;
				}

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
		$show_database = in_array( 'database', $sections, true );

		if ( $show_plugins ) {
			\WP_CLI::log( ( $this->full_scan || ! $this->plugin_scope_reliable )
				? 'Plugin scope: all installed regular plugins.'
				: 'Plugin scope: active plugins only.' );
		}

		if ( $show_themes ) {
			\WP_CLI::log( ( $this->full_scan || ! $this->theme_scope_reliable )
				? 'Theme scope: all installed themes.'
				: 'Theme scope: active theme and parent theme only, when applicable.' );
		}

		if ( $show_database && $this->deep_database ) {
			\WP_CLI::log( 'Database scope: standard WordPress tables plus current-site custom text tables.' );
		}

		$shown_warning = false;
		foreach ( array_values( array_unique( $this->runtime_warnings ) ) as $warning ) {
			if ( 0 === strpos( $warning, 'Plugin ' ) && ! $show_plugins ) {
				continue;
			}
			if ( 0 === strpos( $warning, 'Active theme ' ) && ! $show_themes ) {
				continue;
			}
			\WP_CLI::warning( $warning );
			$shown_warning = true;
		}

		if ( $show_plugins || $show_themes || ( $show_database && $this->deep_database ) || $shown_warning ) {
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
				? $this->plugin_dir . DIRECTORY_SEPARATOR . $main_file
				: $this->plugin_dir . DIRECTORY_SEPARATOR . $relative_dir;
			$key = $this->normalize_path( $root );
			$is_verified = 'verified' === (string) ( $data['status'] ?? 'unverified' );

			if ( ! isset( $roots[ $key ] ) ) {
				$roots[ $key ] = [
					'path'     => $root,
					'verified' => $is_verified,
				];
			} elseif ( ! $is_verified ) {
				// Multiple plugin headers may share one directory. Only use the
				// fast path when every selected plugin rooted there is verified.
				$roots[ $key ]['verified'] = false;
			}
		}

		foreach ( $roots as $root_data ) {
			$root = $root_data['path'];
			$verified_fast_path = ! empty( $root_data['verified'] );

			if ( is_link( $root ) ) {
				$this->scan_symlink( $stage, $root );
				continue;
			}

			if ( is_file( $root ) ) {
				$count++;
				$this->scanned_files++;
				$this->stage_tick( $stage, $count, 'files' );
				if ( $verified_fast_path ) {
					$this->scan_verified_plugin_file( $stage, $root );
				} else {
					$this->scan_file( $stage, $root, false );
				}
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
				if ( $verified_fast_path ) {
					$this->scan_verified_plugin_file( $stage, $item->getPathname() );
				} else {
					$this->scan_file( $stage, $item->getPathname(), false );
				}
			}
		}

		$this->stage_finish( $stage, $count, $this->count_reportable_plugin_findings() );
	}

	/**
	 * Scan a checksum-verified plugin file only for findings that remain
	 * reportable after checksum trust is applied.
	 *
	 * Verified WordPress.org plugins suppress normal static/semantic heuristics
	 * at report time. Running those expensive analyzers first wastes CPU and I/O.
	 * Keep exact high-confidence IOC coverage in executable PHP/JS files, which
	 * is exactly the file-level evidence still allowed by
	 * is_verified_plugin_risk_finding().
	 */
	private function scan_verified_plugin_file( $stage, $path ) {
		$extension = strtolower( pathinfo( $path, PATHINFO_EXTENSION ) );
		$executable_extensions = array_merge( self::PHP_EXTENSIONS, [ 'js', 'mjs', 'cjs' ] );
		if ( ! in_array( $extension, $executable_extensions, true ) ) {
			return;
		}

		$rules = $this->verified_plugin_ioc_rules();
		if ( empty( $rules ) ) {
			return;
		}

		$handle = @fopen( $path, 'rb' );
		if ( false === $handle ) {
			return;
		}

		$relative = $this->relative_wp_content_path( $path );
		$seen = [];
		$overlap = '';
		$line_at_chunk_start = 1;

		while ( ! feof( $handle ) ) {
			$chunk = fread( $handle, self::FILE_CHUNK_SIZE );
			if ( false === $chunk || '' === $chunk ) {
				break;
			}

			$buffer = $overlap . $chunk;
			$buffer_start_line = max( 1, $line_at_chunk_start - substr_count( $overlap, "\n" ) );
			foreach ( $rules as $rule ) {
				$match_offset = stripos( $buffer, $rule['needle'] );
				if ( false === $match_offset ) {
					continue;
				}

				$this->add_file_rule_once(
					$seen,
					$stage,
					$relative,
					$rule,
					$this->line_from_buffer_offset( $buffer, $buffer_start_line, $match_offset )
				);
			}

			$overlap = substr( $buffer, -self::FILE_CHUNK_OVERLAP );
			$line_at_chunk_start += substr_count( $chunk, "\n" );
			$this->stage_heartbeat( $stage, 'files' );
		}

		fclose( $handle );
	}

	/**
	 * Cache the exact IOC rules that remain reportable for verified plugins.
	 */
	private function verified_plugin_ioc_rules() {
		if ( null !== $this->verified_plugin_ioc_rules ) {
			return $this->verified_plugin_ioc_rules;
		}

		$this->verified_plugin_ioc_rules = array_values(
			array_filter(
				$this->rules['iocs'] ?? [],
				static function ( $rule ) {
					return 0 === strpos( (string) ( $rule['id'] ?? '' ), 'ioc_' )
						&& 'critical' === (string) ( $rule['severity'] ?? '' )
						&& (int) ( $rule['confidence'] ?? 0 ) >= 97
						&& '' !== (string) ( $rule['needle'] ?? '' );
				}
			)
		);

		return $this->verified_plugin_ioc_rules;
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
			$root = $this->theme_dir . DIRECTORY_SEPARATOR . $slug;
			if ( is_link( $root ) ) {
				$this->scan_symlink( $stage, $root );
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

		if ( is_dir( $this->mu_plugin_dir ) ) {
			$iterator = $this->create_scan_iterator( $this->mu_plugin_dir );

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

		foreach ( self::DROPIN_FILES as $filename ) {
			$path = $this->content_dir . DIRECTORY_SEPARATOR . $filename;
			if ( is_link( $path ) ) {
				$this->scan_symlink( $stage, $path );
				continue;
			}
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

		$known_dirs = [
			$this->plugin_dir,
			$this->theme_dir,
			$this->uploads_dir,
			$this->mu_plugin_dir,
		];

		foreach ( $known_dirs as $dir ) {
			$excluded[] = $this->normalize_path( $dir );
		}

		$top = new \DirectoryIterator( $this->content_dir );
		foreach ( $top as $item ) {
			if ( $item->isDot() ) {
				continue;
			}

			$path = $item->getPathname();
			$normalized = $this->normalize_path( $path );

			if ( in_array( $normalized, $excluded, true ) ) {
				continue;
			}

			if ( $this->is_scanner_output_path( $path ) ) {
				continue;
			}

			if ( $item->isLink() ) {
				$this->scan_symlink( $stage, $path );
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

			if ( ! $item->isDir() ) {
				continue;
			}

			if ( ! $this->include_node_modules && 'node_modules' === strtolower( $item->getFilename() ) ) {
				continue;
			}

			$iterator = $this->create_scan_iterator( $path );

			foreach ( $iterator as $child ) {
				if ( $child->isLink() ) {
					$this->scan_symlink( $stage, $child->getPathname() );
					continue;
				}

				if ( ! $child->isFile() ) {
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

		if ( $is_uploads && in_array( $extension, self::UPLOAD_CONTAINER_EXTENSIONS, true ) ) {
			$this->scan_upload_media_container( $handle, $path, $relative, $extension, $seen );
			@rewind( $handle );
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
	 * Validate common upload media/document containers without parsing them through
	 * image/PDF libraries. Signature mismatches are integrity anomalies; trailing
	 * bytes are only reported when they contain a high-confidence script/executable
	 * marker so legitimate metadata/junk does not become a security finding.
	 */
	private function scan_upload_media_container( $handle, $path, $relative, $extension, array &$seen ) {
		$expected = $this->expected_upload_container_type( $extension );
		if ( null === $expected ) {
			return;
		}

		$size = @filesize( $path );
		if ( false === $size || $size <= 0 ) {
			$this->add_file_finding_once( $seen, 'Uploads', 'medium', 82, $relative, 'upload_invalid_media_signature', 'Upload does not have a valid media/document file signature' );
			return;
		}

		@rewind( $handle );
		$head = fread( $handle, 1024 );
		if ( false === $head ) {
			return;
		}

		$detected = $this->detect_upload_container_type( $head );
		if ( $expected !== $detected ) {
			// PHP hidden behind a media extension is already a stronger CRITICAL
			// finding in scan_file_buffer(); avoid a duplicate container finding.
			if ( 'php' === $detected ) {
				return;
			}

			if ( null !== $detected ) {
				$this->add_file_finding_once( $seen, 'Uploads', 'high', 94, $relative, 'upload_media_type_mismatch', 'Upload contents match a different file type than the extension' );
			} else {
				$this->add_file_finding_once( $seen, 'Uploads', 'medium', 82, $relative, 'upload_invalid_media_signature', 'Upload does not have a valid media/document file signature' );
			}
			return;
		}

		$container = $this->resolve_upload_container_end( $handle, $extension, (int) $size );
		if ( isset( $container['invalid'] ) && $container['invalid'] ) {
			$this->add_file_finding_once( $seen, 'Uploads', 'medium', 84, $relative, 'upload_malformed_media_container', 'Upload media/document container appears truncated or malformed' );
			return;
		}

		if ( ! isset( $container['end'] ) || null === $container['end'] || $container['end'] >= $size ) {
			return;
		}

		$trailing_length = min( self::UPLOAD_CONTAINER_TAIL_MAX_BYTES, (int) $size - (int) $container['end'] );
		if ( $trailing_length <= 0 || 0 !== @fseek( $handle, (int) $container['end'], SEEK_SET ) ) {
			return;
		}

		$trailing = fread( $handle, $trailing_length );
		if ( false === $trailing || '' === $trailing ) {
			return;
		}

		$trimmed = ltrim( $trailing, "\x00\x09\x0A\x0D\x20" );
		if ( '' === $trimmed ) {
			return;
		}

		// PHP tags are already handled by uploads_embedded_php at CRITICAL.
		if ( false !== stripos( $trimmed, '<?php' ) || false !== strpos( $trimmed, '<?=' ) ) {
			return;
		}

		if ( 0 === strpos( $trimmed, "\x7fELF" ) || 0 === strpos( $trimmed, 'MZ' ) ) {
			$this->add_file_finding_once( $seen, 'Uploads', 'high', 97, $relative, 'upload_appended_executable', 'Executable payload is appended after the media/document container' );
			return;
		}

		$sample = substr( $trimmed, 0, 32768 );
		$printable = preg_match_all( '/[\x09\x0A\x0D\x20-\x7E]/', $sample, $matches );
		if ( false === $printable || ( $printable / max( 1, strlen( $sample ) ) ) < 0.78 ) {
			return;
		}

		if ( 1 === preg_match( '~(?:<script\b|#!\s*/(?:usr/)?bin/|\b(?:powershell|cmd\.exe)\b|\b(?:eval|assert|base64_decode|shell_exec|passthru|system)\s*\()~i', $sample ) ) {
			$this->add_file_finding_once( $seen, 'Uploads', 'high', 95, $relative, 'upload_appended_script_payload', 'Script-like payload is appended after the media/document container' );
		}
	}

	/**
	 * Map upload extensions to the expected container signature family.
	 */
	private function expected_upload_container_type( $extension ) {
		$map = [
			'jpg'  => 'jpeg',
			'jpeg' => 'jpeg',
			'png'  => 'png',
			'gif'  => 'gif',
			'webp' => 'webp',
			'avif' => 'avif',
			'ico'  => 'ico',
			'bmp'  => 'bmp',
			'tif'  => 'tiff',
			'tiff' => 'tiff',
			'pdf'  => 'pdf',
		];

		return isset( $map[ $extension ] ) ? $map[ $extension ] : null;
	}

	/**
	 * Detect a small set of trusted magic-byte families used for upload validation.
	 */
	private function detect_upload_container_type( $head ) {
		if ( 0 === strpos( $head, "\x89PNG\r\n\x1a\n" ) ) {
			return 'png';
		}
		if ( 0 === strpos( $head, "\xff\xd8\xff" ) ) {
			return 'jpeg';
		}
		if ( 0 === strpos( $head, 'GIF87a' ) || 0 === strpos( $head, 'GIF89a' ) ) {
			return 'gif';
		}
		if ( strlen( $head ) >= 12 && 'RIFF' === substr( $head, 0, 4 ) && 'WEBP' === substr( $head, 8, 4 ) ) {
			return 'webp';
		}
		if ( strlen( $head ) >= 16 && 'ftyp' === substr( $head, 4, 4 ) ) {
			$brands = substr( $head, 8, 56 );
			if ( false !== strpos( $brands, 'avif' ) || false !== strpos( $brands, 'avis' ) ) {
				return 'avif';
			}
		}
		if ( 0 === strpos( $head, "\x00\x00\x01\x00" ) ) {
			return 'ico';
		}
		if ( 0 === strpos( $head, 'BM' ) ) {
			return 'bmp';
		}
		if ( 0 === strpos( $head, "II*\x00" ) || 0 === strpos( $head, "MM\x00*" ) ) {
			return 'tiff';
		}
		if ( false !== strpos( substr( $head, 0, 1024 ), '%PDF-' ) ) {
			return 'pdf';
		}
		if ( false !== stripos( substr( $head, 0, 1024 ), '<?php' ) || false !== strpos( substr( $head, 0, 1024 ), '<?=' ) ) {
			return 'php';
		}
		if ( 0 === strpos( $head, "PK\x03\x04" ) || 0 === strpos( $head, "PK\x05\x06" ) || 0 === strpos( $head, "PK\x07\x08" ) ) {
			return 'zip';
		}
		if ( 0 === strpos( $head, "\x1f\x8b" ) ) {
			return 'gzip';
		}
		if ( 0 === strpos( $head, "Rar!\x1a\x07" ) ) {
			return 'rar';
		}
		if ( 0 === strpos( $head, "7z\xbc\xaf\x27\x1c" ) ) {
			return '7z';
		}
		if ( 0 === strpos( $head, "\x7fELF" ) ) {
			return 'elf';
		}
		if ( 0 === strpos( $head, 'MZ' ) ) {
			return 'pe';
		}

		return null;
	}

	/**
	 * Resolve the logical end of containers where a reliable bounded end marker
	 * is available. Formats without a safe cheap boundary return null.
	 */
	private function resolve_upload_container_end( $handle, $extension, $size ) {
		if ( 'png' === $extension ) {
			return $this->resolve_png_end( $handle, $size );
		}

		if ( 'webp' === $extension ) {
			if ( 0 !== @fseek( $handle, 4, SEEK_SET ) ) {
				return [ 'end' => null, 'invalid' => false ];
			}
			$raw = fread( $handle, 4 );
			if ( false === $raw || 4 !== strlen( $raw ) ) {
				return [ 'end' => null, 'invalid' => true ];
			}
			$unpacked = unpack( 'Vsize', $raw );
			$end = 8 + (int) $unpacked['size'];
			return [ 'end' => $end, 'invalid' => $end < 12 || $end > $size ];
		}

		if ( in_array( $extension, [ 'jpg', 'jpeg' ], true ) ) {
			return $this->resolve_tail_marker_end( $handle, $size, "\xff\xd9", 2 );
		}

		if ( 'pdf' === $extension ) {
			return $this->resolve_tail_marker_end( $handle, $size, '%%EOF', 5 );
		}

		return [ 'end' => null, 'invalid' => false ];
	}

	/**
	 * Parse PNG chunk boundaries without decoding image data.
	 */
	private function resolve_png_end( $handle, $size ) {
		$offset = 8;
		$chunks = 0;
		$has_ihdr = false;
		while ( $offset + 12 <= $size && $chunks < 100000 ) {
			if ( 0 !== @fseek( $handle, $offset, SEEK_SET ) ) {
				return [ 'end' => null, 'invalid' => true ];
			}
			$header = fread( $handle, 8 );
			if ( false === $header || 8 !== strlen( $header ) ) {
				return [ 'end' => null, 'invalid' => true ];
			}
			$length_data = unpack( 'Nlength', substr( $header, 0, 4 ) );
			$length = (int) $length_data['length'];
			$type = substr( $header, 4, 4 );
			$chunk_end = $offset + 12 + $length;
			if ( $chunk_end > $size || $length < 0 ) {
				return [ 'end' => null, 'invalid' => true ];
			}
			if ( 0 === $chunks ) {
				if ( 'IHDR' !== $type || 13 !== $length ) {
					return [ 'end' => null, 'invalid' => true ];
				}
				$has_ihdr = true;
			}
			if ( 'IEND' === $type ) {
				return [ 'end' => $chunk_end, 'invalid' => ! $has_ihdr || 0 !== $length ];
			}
			$offset = $chunk_end;
			$chunks++;
		}

		return [ 'end' => null, 'invalid' => true ];
	}

	/**
	 * Find the last bounded end marker for JPEG/PDF containers.
	 */
	private function resolve_tail_marker_end( $handle, $size, $marker, $marker_length ) {
		$read_length = min( self::UPLOAD_CONTAINER_TAIL_MAX_BYTES, $size );
		$start = $size - $read_length;
		if ( 0 !== @fseek( $handle, $start, SEEK_SET ) ) {
			return [ 'end' => null, 'invalid' => false ];
		}
		$tail = fread( $handle, $read_length );
		if ( false === $tail ) {
			return [ 'end' => null, 'invalid' => false ];
		}
		$position = strrpos( $tail, $marker );
		if ( false === $position ) {
			return [ 'end' => null, 'invalid' => true ];
		}

		return [ 'end' => $start + $position + $marker_length, 'invalid' => false ];
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
			if ( ! $this->is_inert_upload_php_guard_file( $path, $extension ) ) {
				$this->add_file_finding_once( $seen, $stage, 'high', 96, $relative, 'uploads_executable', 'Executable/script file found inside uploads' );
			}
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
	 * Return true for empty/comment-only PHP guard files in uploads.
	 *
	 * WordPress plugins commonly place inert index.php files in writable upload
	 * directories to prevent directory listing. Suppress only the generic upload
	 * executable-location finding when tokenization proves there is no executable
	 * behavior beyond an optional exit/die statement. The normal content scanners
	 * still inspect the file, so IOC/semantic findings remain available.
	 */
	private function is_inert_upload_php_guard_file( $path, $extension ) {
		if ( ! in_array( strtolower( (string) $extension ), [ 'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml' ], true ) ) {
			return false;
		}

		$size = @filesize( $path );
		if ( false === $size || $size > 16384 ) {
			return false;
		}

		$content = @file_get_contents( $path );
		if ( ! is_string( $content ) ) {
			return false;
		}

		$tokens = token_get_all( $content );
		$has_exit = false;
		foreach ( $tokens as $token ) {
			if ( is_array( $token ) ) {
				if ( in_array( $token[0], [ T_OPEN_TAG, T_CLOSE_TAG, T_WHITESPACE, T_COMMENT, T_DOC_COMMENT ], true ) ) {
					continue;
				}
				if ( T_EXIT === $token[0] ) {
					$has_exit = true;
					continue;
				}
				if ( $has_exit && in_array( $token[0], [ T_CONSTANT_ENCAPSED_STRING, T_LNUMBER, T_DNUMBER ], true ) ) {
					continue;
				}
				return false;
			}

			if ( $has_exit && in_array( $token, [ '(', ')', ';' ], true ) ) {
				continue;
			}
			if ( ';' === $token ) {
				continue;
			}
			return false;
		}

		return true;
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

			$this->scan_javascript_sensitive_external_transfer( $stage, $relative, $buffer, $seen, $buffer_start_line );
		}
	}

	/**
	 * Detect direct browser credential/payment skimmers without requiring JS obfuscation.
	 *
	 * A finding requires three independent signals in one bounded neighborhood:
	 * a sensitive browser source, a network API, and a literal HTTP(S) target whose
	 * host is not the current WordPress host. This avoids classifying local AJAX or
	 * ordinary checkout-field handling as exfiltration by itself.
	 */
	private function scan_javascript_sensitive_external_transfer( $stage, $location, $buffer, array &$seen, $buffer_start_line = null ) {
		$rule = 'js_sensitive_external_transfer';
		if ( isset( $seen[ $rule ] ) ) {
			return;
		}

		if ( ! preg_match( '~(?:document\\.cookie|getElementById|querySelector|FormData|\\.get\\s*\\()~i', $buffer ) ) {
			return;
		}
		if ( ! preg_match( '~(?:fetch\\s*\\(|\\.open\\s*\\(|sendBeacon\\s*\\(|new\\s+WebSocket\\s*\\(|\\$\\.(?:post|ajax)\\s*\\()~i', $buffer ) ) {
			return;
		}

		$sink_patterns = [
			'~\\bfetch\\s*\\(\\s*([\\\'\"])(https?://[^\\\'\"]+)\\1~i',
			'~\\bsendBeacon\\s*\\(\\s*([\\\'\"])(https?://[^\\\'\"]+)\\1~i',
			'~\\.open\\s*\\(\\s*([\\\'\"])(?:GET|POST|PUT|PATCH)\\1\\s*,\\s*([\\\'\"])(https?://[^\\\'\"]+)\\2~i',
			'~\\bnew\\s+WebSocket\\s*\\(\\s*([\\\'\"])(https?://[^\\\'\"]+)\\1~i',
			'~\\$\\.post\\s*\\(\\s*([\\\'\"])(https?://[^\\\'\"]+)\\1~i',
			'~\\$\\.ajax\\s*\\(\\s*\\{[\\s\\S]{0,800}?\\burl\\s*:\\s*([\\\'\"])(https?://[^\\\'\"]+)\\1~i',
		];

		foreach ( $sink_patterns as $pattern ) {
			$matches = [];
			if ( ! preg_match_all( $pattern, $buffer, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE ) ) {
				continue;
			}

			foreach ( $matches as $match ) {
				$url = '';
				$url_offset = null;
				for ( $i = count( $match ) - 1; $i >= 1; $i-- ) {
					if ( isset( $match[ $i ][0] ) && is_string( $match[ $i ][0] ) && preg_match( '~^https?://~i', $match[ $i ][0] ) ) {
						$url = $match[ $i ][0];
						$url_offset = $match[ $i ][1];
						break;
					}
				}
				if ( '' === $url || ! $this->javascript_url_is_external( $url ) ) {
					continue;
				}

				$sink_offset = isset( $match[0][1] ) ? (int) $match[0][1] : (int) $url_offset;
				$start = max( 0, $sink_offset - 4096 );
				$window = substr( $buffer, $start, min( 8192, strlen( $buffer ) - $start ) );
				if ( ! $this->javascript_window_has_sensitive_source( $window ) ) {
					continue;
				}

				$seen[ $rule ] = true;
				$line = null;
				if ( null !== $buffer_start_line ) {
					$line = $this->line_from_buffer_offset( $buffer, (int) $buffer_start_line, $sink_offset );
				}
				$this->add_finding( $stage, 'high', 95, $location, $rule, 'Sensitive browser form/session data is sent to an external JavaScript endpoint', $line );
				return;
			}
		}
	}

	/**
	 * Return true when a bounded JS window contains a credential/session/payment source.
	 */
	private function javascript_window_has_sensitive_source( $window ) {
		if ( preg_match( '~\\bdocument\\.cookie\\b~i', $window ) ) {
			return true;
		}

		$sensitive = '(?:password|passwd|passphrase|pwd|card[_-]?(?:number|no)?|credit[_-]?card|cc[_-]?(?:num|number|no)|cc_num|cc_cid|pan|cvv|cvc|card[_-]?security|expiry|expiration|access[_-]?token|auth[_-]?token|bearer|jwt)';
		$patterns = [
			'~(?:getElementById|querySelector|querySelectorAll)\\s*\\(\\s*[\\\'\"][^\\\'\"]{0,180}' . $sensitive . '[^\\\'\"]*[\\\'\"]\\s*\\)[^;\\r\\n]{0,180}\\.value\\b~i',
			'~\\b(?:formData|data|payload)\\s*\\.get\\s*\\(\\s*[\\\'\"]' . $sensitive . '[\\\'\"]\\s*\\)~i',
			'~\\b(?:password|passwd|cardNumber|card_number|cc_num|cvv|cvc|cc_cid|accessToken|authToken)\\s*[:=][^;\\r\\n]{0,240}(?:\\.value\\b|document\\.cookie)~i',
		];
		foreach ( $patterns as $pattern ) {
			if ( preg_match( $pattern, $window ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Compare a literal JS endpoint with the canonical WordPress host.
	 */
	private function javascript_url_is_external( $url ) {
		$host = parse_url( (string) $url, PHP_URL_HOST );
		if ( ! is_string( $host ) || '' === trim( $host ) ) {
			return false;
		}

		$host = strtolower( trim( $host, " .\\t\\r\\n" ) );
		if ( in_array( $host, [ 'localhost', '127.0.0.1', '::1' ], true ) ) {
			return false;
		}

		$site = strtolower( trim( (string) $this->site_home_host, " .\\t\\r\\n" ) );
		if ( '' === $site ) {
			return true;
		}

		$normalize = static function ( $value ) {
			return 0 === strpos( $value, 'www.' ) ? substr( $value, 4 ) : $value;
		};
		return $normalize( $host ) !== $normalize( $site );
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
			'shell_exec(',
			'passthru(',
			'proc_open(',
		];

		$obfuscation_tokens = [
			'base64_decode(',
			'gzinflate(',
			'gzuncompress(',
			'str_rot13(',
			'strrev(',
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

		// Density is only reportable when the independent signals are also close
		// enough to plausibly belong to the same behavior. Large libraries often
		// contain these primitives in unrelated functions hundreds of lines apart.
		if ( $execution_count >= 1 && $obfuscation_count >= 2 && $untrusted_count >= 1 ) {
			$cluster_offset = $this->find_density_signal_cluster(
				$lower,
				$execution_tokens,
				$obfuscation_tokens,
				$untrusted_tokens,
				4096
			);
			if ( null !== $cluster_offset ) {
				$line = $this->line_from_buffer_offset( $buffer, $buffer_start_line, $cluster_offset );
				$this->add_file_finding_once( $seen, $stage, 'high', 88, $relative, 'dense_suspicious_php', 'Execution, obfuscation and untrusted-input primitives occur together', $line );
			}
		}

		$long_line_matches = [];
		if ( $execution_count >= 1 && $obfuscation_count >= 1 && 1 === preg_match( '~[^\r\n]{20000,}~', $buffer, $long_line_matches, PREG_OFFSET_CAPTURE ) ) {
			$line = $this->line_from_buffer_offset( $buffer, $buffer_start_line, $long_line_matches[0][1] );
			$this->add_file_finding_once( $seen, $stage, 'high', 86, $relative, 'long_obfuscated_line', 'Very long PHP line combines obfuscation with an execution primitive', $line );
		}
	}

	/**
	 * Confirm that density signals occur in one bounded neighborhood rather
	 * than merely somewhere in the same large PHP file/chunk.
	 */
	private function find_density_signal_cluster( $buffer, array $execution_tokens, array $obfuscation_tokens, array $untrusted_tokens, $radius ) {
		$length = strlen( $buffer );
		foreach ( $execution_tokens as $execution_token ) {
			$offset = 0;
			while ( false !== ( $execution_offset = strpos( $buffer, $execution_token, $offset ) ) ) {
				$start = max( 0, $execution_offset - $radius );
				$window = substr( $buffer, $start, min( $length - $start, ( 2 * $radius ) + strlen( $execution_token ) ) );
				if ( $this->count_present_tokens( $window, $obfuscation_tokens ) >= 2 && $this->count_present_tokens( $window, $untrusted_tokens ) >= 1 ) {
					return $execution_offset;
				}
				$offset = $execution_offset + max( 1, strlen( $execution_token ) );
			}
		}

		return null;
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

		if ( 0 !== strpos( $this->normalize_path( $target ), $this->normalize_path( $this->content_dir ) . '/' ) ) {
			$this->add_finding( $stage, 'high', 78, $relative, 'external_symlink', 'Symlink points outside wp-content: ' . $target );
		}
	}

	/**
	 * Scan database content tables in batches.
	 */
	private function scan_database() {
		$db = $this->database;
		if ( ! $db ) {
			return;
		}

		$stage = 'Database';
		$this->stage_start( $stage );

		$definitions = [
			[
				'table'   => $db->posts,
				'pk'      => 'ID',
				'fields'  => [ 'post_content', 'post_excerpt' ],
				'context' => [ 'post_title', 'post_type' ],
			],
			[
				'table'   => $db->postmeta,
				'pk'      => 'meta_id',
				'fields'  => [ 'meta_value' ],
				'context' => [ 'post_id', 'meta_key' ],
			],
			[
				'table'   => $db->options,
				'pk'      => 'option_id',
				'fields'  => [ 'option_value' ],
				'context' => [ 'option_name' ],
			],
			[
				'table'   => $db->comments,
				'pk'      => 'comment_ID',
				'fields'  => [ 'comment_content' ],
				'context' => [ 'comment_post_ID', 'comment_author' ],
			],
			[
				'table'   => $db->commentmeta,
				'pk'      => 'meta_id',
				'fields'  => [ 'meta_value' ],
				'context' => [ 'comment_id', 'meta_key' ],
			],
			[
				'table'   => $db->termmeta,
				'pk'      => 'meta_id',
				'fields'  => [ 'meta_value' ],
				'context' => [ 'term_id', 'meta_key' ],
			],
			[
				'table'   => $db->usermeta,
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

		if ( $this->deep_database ) {
			$excluded_tables = array_column( $definitions, 'table' );
			$total_rows += $this->scan_deep_database_tables( $stage, $excluded_tables );
		}

		$this->stage_finish( $stage, $total_rows, $this->count_stage_findings( $stage ), 'rows' );
	}


	/**
	 * Scan text-like columns in custom tables for the current site prefix.
	 *
	 * This is opt-in because plugin tables can be very large. Schema discovery is
	 * read-only, core tables are excluded, and other multisite blogs are not
	 * traversed when scanning the main-site prefix.
	 */
	private function scan_deep_database_tables( $stage, array $excluded_tables ) {
		$total_rows = 0;
		foreach ( $this->discover_deep_database_tables( $excluded_tables ) as $table ) {
			$definition = $this->deep_database_table_definition( $table );
			if ( empty( $definition['fields'] ) ) {
				continue;
			}
			$total_rows += $this->scan_deep_database_table( $stage, $definition );
		}
		return $total_rows;
	}

	/**
	 * Discover custom tables belonging to the current site without crossing into
	 * another blog's numbered multisite prefix.
	 */
	private function discover_deep_database_tables( array $excluded_tables ) {
		$db = $this->database;
		if ( ! $db || '' === $this->site_table_prefix ) {
			return [];
		}

		$excluded = array_fill_keys( array_merge( $excluded_tables, $this->known_wordpress_tables() ), true );
		$pattern = $db->esc_like( $this->site_table_prefix ) . '%';
		$rows = $db->get_results( $db->prepare( 'SHOW TABLES LIKE %s', $pattern ), true );
		$tables = [];
		$other_blog_pattern = '';
		if ( $this->site_table_prefix === $this->base_table_prefix ) {
			$other_blog_pattern = '/^' . preg_quote( $this->base_table_prefix, '/' ) . '\\d+_/';
		}

		foreach ( $rows as $row ) {
			if ( ! is_array( $row ) || empty( $row ) ) {
				continue;
			}
			$table = (string) reset( $row );
			if ( '' === $table || isset( $excluded[ $table ] ) ) {
				continue;
			}
			if ( '' !== $other_blog_pattern && preg_match( $other_blog_pattern, $table ) ) {
				continue;
			}
			$tables[] = $table;
		}

		sort( $tables, SORT_STRING );
		return array_values( array_unique( $tables ) );
	}

	/**
	 * Core/global WordPress tables that deep mode must not rescan as custom data.
	 */
	private function known_wordpress_tables() {
		$site = $this->site_table_prefix;
		$base = $this->base_table_prefix;
		$tables = [];
		foreach ( [ 'posts', 'postmeta', 'terms', 'termmeta', 'term_taxonomy', 'term_relationships', 'comments', 'commentmeta', 'links', 'options' ] as $suffix ) {
			$tables[] = $site . $suffix;
		}
		foreach ( [ 'users', 'usermeta', 'blogs', 'blog_versions', 'registration_log', 'signups', 'site', 'sitemeta', 'sitecategories' ] as $suffix ) {
			$tables[] = $base . $suffix;
		}
		foreach ( [ 'actionscheduler_actions', 'actionscheduler_claims', 'actionscheduler_groups', 'actionscheduler_logs' ] as $suffix ) {
			$tables[] = $site . $suffix;
		}
		if ( $this->database ) {
			$tables[] = $this->database->users;
			$tables[] = $this->database->usermeta;
		}
		return array_values( array_unique( array_filter( $tables ) ) );
	}

	/**
	 * Return cached column metadata for a table during one scan run.
	 */
	private function scanner_table_columns( $table ) {
		$table = (string) $table;
		if ( '' === $table || ! $this->database ) {
			return [];
		}

		if ( array_key_exists( $table, $this->table_column_cache ) ) {
			return $this->table_column_cache[ $table ];
		}

		$this->table_column_cache[ $table ] = $this->database->get_results(
			'SHOW COLUMNS FROM ' . $this->quote_identifier( $table ),
			true
		);

		return $this->table_column_cache[ $table ];
	}

	/**
	 * Build a bounded custom-table scan definition from SHOW COLUMNS metadata.
	 */
	private function deep_database_table_definition( $table ) {
		$db = $this->database;
		if ( ! $db ) {
			return [];
		}

		$columns = $this->scanner_table_columns( $table );
		$text_fields = [];
		$primary_fields = [];
		$primary_types = [];
		foreach ( $columns as $column ) {
			$field = (string) ( $column['Field'] ?? '' );
			$type = strtolower( (string) ( $column['Type'] ?? '' ) );
			if ( '' === $field ) {
				continue;
			}
			if ( 'PRI' === strtoupper( (string) ( $column['Key'] ?? '' ) ) ) {
				$primary_fields[] = $field;
				$primary_types[ $field ] = $type;
			}
			if ( preg_match( '/^(?:var)?char\b|^(?:tiny|medium|long)?text\b|^json\b|^enum\b|^set\b/i', $type ) ) {
				$text_fields[] = $field;
			}
		}

		$pk = 1 === count( $primary_fields ) ? $primary_fields[0] : '';
		$pk_type = '' !== $pk ? ( $primary_types[ $pk ] ?? '' ) : '';
		return [
			'table'      => $table,
			'pk'         => $pk,
			'pk_numeric' => '' !== $pk && (bool) preg_match( '/^(?:tinyint|smallint|mediumint|int|integer|bigint)\b/i', $pk_type ),
			'fields'     => array_values( array_unique( $text_fields ) ),
		];
	}

	/**
	 * Scan one custom table. A simple primary key uses keyset pagination when it
	 * is numeric; other schemas use bounded LIMIT/OFFSET so tables without a
	 * conventional integer ID are still covered in explicit deep mode.
	 */
	private function scan_deep_database_table( $stage, array $definition ) {
		$db = $this->database;
		if ( ! $db ) {
			return 0;
		}

		$table = (string) $definition['table'];
		$pk = (string) ( $definition['pk'] ?? '' );
		$pk_numeric = ! empty( $definition['pk_numeric'] );
		$fields = array_values( array_unique( $definition['fields'] ?? [] ) );
		if ( empty( $fields ) ) {
			return 0;
		}

		$columns = $fields;
		if ( '' !== $pk ) {
			array_unshift( $columns, $pk );
		}
		$select = implode( ', ', array_map( [ $this, 'quote_identifier' ], array_values( array_unique( $columns ) ) ) );
		$offset = 0;
		$last_id = 0;
		$count = 0;

		while ( true ) {
			if ( $pk_numeric ) {
				$sql = sprintf(
					'SELECT %s FROM %s WHERE %s > %%d ORDER BY %s ASC LIMIT %d',
					$select,
					$this->quote_identifier( $table ),
					$this->quote_identifier( $pk ),
					$this->quote_identifier( $pk ),
					self::DB_BATCH_SIZE
				);
				$rows = $db->get_results( $db->prepare( $sql, $last_id ), true );
			} else {
				$sql = sprintf(
					'SELECT %s FROM %s LIMIT %d OFFSET %d',
					$select,
					$this->quote_identifier( $table ),
					self::DB_BATCH_SIZE,
					$offset
				);
				$rows = $db->get_results( $sql, true );
			}

			if ( empty( $rows ) ) {
				break;
			}

			foreach ( $rows as $index => $row ) {
				$count++;
				$this->scanned_db_rows++;
				$location_pk = $pk;
				if ( $pk_numeric ) {
					$last_id = max( $last_id, (int) ( $row[ $pk ] ?? 0 ) );
				} elseif ( '' === $location_pk ) {
					$location_pk = '__rownum';
					$row[ $location_pk ] = $offset + $index + 1;
				}

				foreach ( $fields as $field ) {
					$value = isset( $row[ $field ] ) ? (string) $row[ $field ] : '';
					if ( '' === $value ) {
						continue;
					}
					$this->scan_database_value( $stage, $table, $location_pk, $row, $field, $value, [] );
				}
				$this->stage_tick( $stage, $count, 'rows' );
			}

			if ( ! $pk_numeric ) {
				$offset += count( $rows );
			}
			if ( count( $rows ) < self::DB_BATCH_SIZE ) {
				break;
			}
		}

		return $count;
	}

	/**
	 * Scan one database table with keyset pagination.
	 */
	private function scan_database_table( $stage, array $definition ) {
		$db = $this->database;
		if ( ! $db ) {
			return 0;
		}

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

			$rows = $db->get_results( $db->prepare( $sql, $last_id ), true );
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

		$this->scan_known_persistence_option_name( $stage, $table, $row, $field, $location, $seen );

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
		if ( preg_match( '~(?:<script\b|<iframe\b|\beval\s*\(|\batob\s*\(|fromCharCode|javascript\s*:|location\.|clipboard\.writeText|execCommand\s*\(|powershell(?:\.exe)?|cmd\.exe)~i', $value ) ) {
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

		$this->scan_javascript_sensitive_external_transfer( $stage, $location, $value, $seen, null );
	}

	/**
	 * Detect exact wp_options keys tied to documented WordPress persistence campaigns.
	 *
	 * The match is intentionally limited to the option_name column context rather
	 * than searching these strings globally in source files or documentation.
	 */
	private function scan_known_persistence_option_name( $stage, $table, array $row, $field, $location, array &$seen ) {
		if ( ! $this->database || $table !== $this->database->options || 'option_value' !== $field ) {
			return;
		}

		$option_name = isset( $row['option_name'] ) ? (string) $row['option_name'] : '';
		$known = [
			'_hdra_core' => [
				'severity'   => 'critical',
				'confidence' => 98,
				'rule'       => 'db_known_persistence_option_hdra_core',
				'description'=> 'Known MU-plugin backdoor payload-storage option is present',
			],
			'_pre_user_id' => [
				'severity'   => 'high',
				'confidence' => 97,
				'rule'       => 'db_known_persistence_option_pre_user_id',
				'description'=> 'Known hidden-administrator persistence option is present',
			],
			'API_SN_CLOUDSERVER' => [
				'severity'   => 'high',
				'confidence' => 96,
				'rule'       => 'db_known_persistence_option_cloudserver',
				'description'=> 'Known hidden-plugin command-and-control option is present',
			],
		];

		if ( ! isset( $known[ $option_name ] ) ) {
			return;
		}

		$rule = $known[ $option_name ];
		if ( isset( $seen[ $rule['rule'] ] ) ) {
			return;
		}
		$seen[ $rule['rule'] ] = true;
		$this->add_finding( $stage, $rule['severity'], $rule['confidence'], $location, $rule['rule'], $rule['description'] );
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
		$db = $this->database;
		if ( ! $db ) {
			return;
		}

		$stage = 'Users & persistence';
		$this->stage_start( $stage );

		try {
			$count = 0;
			$admin_count = 0;
			$recent_users = [];
			$role_definitions = $this->read_role_definitions();
			$super_admin_logins = $this->read_multisite_super_admin_logins();
			$recent_cutoff = strtotime( '-' . self::RECENT_USER_MONTHS . ' months', time() );
			$this->scan_role_capability_persistence( $stage, $role_definitions );
			$last_user_id = 0;

			while ( true ) {
				$user_rows = $db->get_results(
					$db->prepare(
						'SELECT ID, user_login, user_email, user_registered FROM ' . $this->quote_identifier( $db->users ) . ' WHERE ID > %d ORDER BY ID ASC LIMIT %d',
						$last_user_id,
						self::USER_BATCH_SIZE
					),
					true
				);

				if ( empty( $user_rows ) ) {
					break;
				}

				$user_ids = [];
				foreach ( $user_rows as $row ) {
					$user_id = (int) ( $row['ID'] ?? 0 );
					if ( $user_id > 0 ) {
						$user_ids[] = $user_id;
						$last_user_id = max( $last_user_id, $user_id );
					}
				}

				if ( empty( $user_ids ) ) {
					break;
				}

				$capability_map = $this->read_user_capability_map_for_ids( $user_ids );
				$application_password_map = $this->read_user_application_password_map_for_ids( $user_ids );

				foreach ( $user_rows as $row ) {
					$user_id = (int) ( $row['ID'] ?? 0 );
					if ( $user_id < 1 ) {
						continue;
					}

					$count++;
					$user_caps = $capability_map[ $user_id ] ?? [];
					$user_state = $this->resolve_user_security_state( $user_caps, $role_definitions );
					$user_login = (string) ( $row['user_login'] ?? '' );
					$is_super_admin = isset( $super_admin_logins[ $user_login ] );
					if ( $is_super_admin ) {
						$user_state['is_privileged'] = true;
					}

					$this->scan_user_direct_capability_persistence( $stage, $row, $user_state, $is_super_admin );
					$this->scan_user_application_password_persistence(
						$stage,
						$row,
						$user_state,
						$application_password_map[ $user_id ] ?? [],
						$recent_cutoff
					);

					if ( in_array( 'administrator', $user_state['roles'], true ) ) {
						$admin_count++;
					}

					$registered = (string) ( $row['user_registered'] ?? '' );
					if ( '' === $registered || '0000-00-00 00:00:00' === $registered ) {
						continue;
					}

					$timestamp = strtotime( $registered . ' UTC' );
					if ( false === $timestamp || $timestamp < $recent_cutoff ) {
						continue;
					}

					$recent_users[] = [
						'id'            => $user_id,
						'login'         => $user_login,
						'email'         => (string) ( $row['user_email'] ?? '' ),
						'registered'    => $registered,
						'timestamp'     => $timestamp,
						'roles'         => $user_state['roles'],
						'is_privileged' => $user_state['is_privileged'],
					];
				}

				$this->stage_tick( $stage, $count, 'items' );
			}

			$this->admin_count = $admin_count;
			usort(
				$recent_users,
				static function ( $a, $b ) {
					return $a['timestamp'] <=> $b['timestamp'];
				}
			);
			$this->scan_recent_and_burst_users( $stage, $recent_users );

			$cron_raw = $db->get_option_raw( 'cron' );
			$cron = null === $cron_raw ? [] : $this->decode_stored_value( $cron_raw );
			if ( is_array( $cron ) ) {
				foreach ( $cron as $timestamp => $hooks ) {
					if ( ! is_array( $hooks ) ) {
						continue;
					}

					foreach ( $hooks as $hook => $events ) {
						$count++;
						$serialized = is_scalar( $events ) ? (string) $events : serialize( $events );
						$location = 'cron hook: ' . $hook;
						$this->scan_persistence_value( $stage, $location, $hook . ' ' . $serialized );
						$this->stage_tick( $stage, $count, 'items' );
					}
				}
			} elseif ( is_string( $cron_raw ) && '' !== $cron_raw ) {
				// If a damaged or intentionally hostile serialized cron value cannot be
				// decoded safely, still inspect its raw bytes for strong persistence IOCs.
				$count++;
				$this->scan_persistence_value( $stage, 'cron option (raw)', $cron_raw );
				$this->stage_tick( $stage, $count, 'items' );
			}

			$this->scan_action_scheduler_persistence( $stage, $count );
			$this->stage_finish( $stage, $count, $this->count_stage_findings( $stage ), 'items' );
		} catch ( \Throwable $e ) {
			$this->clear_spinner();
			\WP_CLI::error( 'Users & persistence scan failed: ' . $e->getMessage() );
		}
	}

	/**
	 * Read current-site user role/capability assignments for one bounded batch.
	 */
	private function read_user_capability_map_for_ids( array $user_ids ) {
		$db = $this->database;
		if ( ! $db || empty( $user_ids ) || ! $db->table_exists( $db->usermeta ) ) {
			return [];
		}

		$user_ids = array_values( array_unique( array_filter( array_map( 'intval', $user_ids ) ) ) );
		if ( empty( $user_ids ) ) {
			return [];
		}

		$meta_key = $this->site_table_prefix . 'capabilities';
		$sql = $db->prepare(
			'SELECT user_id, meta_value FROM ' . $this->quote_identifier( $db->usermeta ) . ' WHERE meta_key = %s AND user_id IN (' . implode( ',', $user_ids ) . ')',
			$meta_key
		);
		$rows = $db->get_results( $sql, true );
		$map = [];

		foreach ( $rows as $row ) {
			$user_id = (int) ( $row['user_id'] ?? 0 );
			$decoded = $this->decode_stored_value( (string) ( $row['meta_value'] ?? '' ) );
			if ( $user_id < 1 || ! is_array( $decoded ) ) {
				continue;
			}

			if ( ! isset( $map[ $user_id ] ) ) {
				$map[ $user_id ] = [];
			}

			foreach ( $decoded as $capability => $enabled ) {
				if ( is_string( $capability ) ) {
					$map[ $user_id ][ $capability ] = $enabled;
				}
			}
		}

		return $map;
	}


	/**
	 * Read application-password metadata for one bounded user batch.
	 *
	 * WordPress stores these records in the `_application_passwords` user meta
	 * key. Values are decoded through the scanner's object-safe bounded decoder;
	 * password hashes are never included in findings or logs.
	 */
	private function read_user_application_password_map_for_ids( array $user_ids ) {
		$db = $this->database;
		if ( ! $db || empty( $user_ids ) || ! $db->table_exists( $db->usermeta ) ) {
			return [];
		}

		$user_ids = array_values( array_unique( array_filter( array_map( 'intval', $user_ids ) ) ) );
		if ( empty( $user_ids ) ) {
			return [];
		}

		$sql = $db->prepare(
			'SELECT user_id, meta_value FROM ' . $this->quote_identifier( $db->usermeta ) . ' WHERE meta_key = %s AND user_id IN (' . implode( ',', $user_ids ) . ')',
			self::APPLICATION_PASSWORD_META_KEY
		);
		$rows = $db->get_results( $sql, true );
		$map = [];

		foreach ( $rows as $row ) {
			$user_id = (int) ( $row['user_id'] ?? 0 );
			$decoded = $this->decode_stored_value( (string) ( $row['meta_value'] ?? '' ) );
			if ( $user_id < 1 || ! is_array( $decoded ) ) {
				continue;
			}
			$map[ $user_id ] = $decoded;
		}

		return $map;
	}

	/**
	 * Flag role definitions that grant core administrative capabilities outside
	 * the normal administrator role.
	 *
	 * Custom roles can legitimately be powerful, so they remain MEDIUM. Changes
	 * to WordPress's built-in non-administrator roles are stronger persistence
	 * evidence because those roles do not normally carry these capabilities.
	 */
	private function scan_role_capability_persistence( $stage, array $role_definitions ) {
		foreach ( $role_definitions as $role => $capabilities ) {
			if ( 'administrator' === $role || ! is_array( $capabilities ) ) {
				continue;
			}

			$granted = [];
			foreach ( self::ADMINISTRATIVE_CAPABILITIES as $capability ) {
				if ( ! empty( $capabilities[ $capability ] ) ) {
					$granted[] = $capability;
				}
			}

			if ( empty( $granted ) ) {
				continue;
			}

			$is_builtin = in_array( $role, self::BUILTIN_NON_ADMIN_ROLES, true );
			$this->add_finding(
				$stage,
				$is_builtin ? 'high' : 'medium',
				$is_builtin ? 92 : 82,
				'role: ' . $this->single_line_log_value( $role ) . ' · capabilities: ' . implode( ', ', $granted ),
				$is_builtin ? 'builtin_role_admin_capabilities' : 'custom_role_admin_capabilities',
				$is_builtin
					? 'Built-in non-administrator role grants administrative capabilities'
					: 'Custom role grants administrative capabilities'
			);
		}
	}

	/**
	 * Flag direct user capability grants that bypass the user's assigned roles.
	 */
	private function scan_user_direct_capability_persistence( $stage, array $row, array $user_state, $is_super_admin ) {
		if ( $is_super_admin || in_array( 'administrator', $user_state['roles'] ?? [], true ) ) {
			return;
		}

		$direct = array_values( array_intersect( $user_state['direct_capabilities'] ?? [], self::ADMINISTRATIVE_CAPABILITIES ) );
		if ( empty( $direct ) ) {
			return;
		}

		sort( $direct, SORT_STRING );
		$user_id = (int) ( $row['ID'] ?? 0 );
		$user_login = $this->single_line_log_value( (string) ( $row['user_login'] ?? '' ) );
		$this->add_finding(
			$stage,
			'medium',
			84,
			sprintf( 'user #%d · %s · direct capabilities: %s', $user_id, $user_login, implode( ', ', $direct ) ),
			'user_direct_admin_capabilities',
			'User has direct administrative capabilities outside assigned roles'
		);
	}

	/**
	 * Flag recently created application passwords on privileged accounts.
	 *
	 * Application passwords are a legitimate WordPress authentication mechanism,
	 * so their presence alone is not suspicious. Recent credentials on a
	 * privileged account are useful incident-response persistence evidence and
	 * are reported for manual review without exposing the stored password hash.
	 */
	private function scan_user_application_password_persistence( $stage, array $row, array $user_state, array $passwords, $recent_cutoff ) {
		if ( empty( $user_state['is_privileged'] ) || empty( $passwords ) ) {
			return;
		}

		foreach ( $passwords as $password ) {
			if ( ! is_array( $password ) ) {
				continue;
			}

			$created = isset( $password['created'] ) ? (int) $password['created'] : 0;
			if ( $created < 1 || $created < $recent_cutoff ) {
				continue;
			}

			$name = $this->single_line_log_value( (string) ( $password['name'] ?? 'unnamed' ) );
			$last_used = isset( $password['last_used'] ) ? (int) $password['last_used'] : 0;
			$last_ip = $this->single_line_log_value( (string) ( $password['last_ip'] ?? '' ) );
			$details = sprintf(
				'user #%d · %s · application password: %s · created %s UTC',
				(int) ( $row['ID'] ?? 0 ),
				$this->single_line_log_value( (string) ( $row['user_login'] ?? '' ) ),
				$name,
				gmdate( 'Y-m-d H:i:s', $created )
			);
			if ( $last_used > 0 ) {
				$details .= ' · last used ' . gmdate( 'Y-m-d H:i:s', $last_used ) . ' UTC';
			}
			if ( '' !== $last_ip ) {
				$details .= ' · last IP: ' . $last_ip;
			}

			$this->add_finding(
				$stage,
				'high',
				90,
				$details,
				'recent_privileged_application_password',
				'Privileged user has a recently created application password'
			);
		}
	}

	/**
	 * Keep attacker-controlled labels from creating extra lines in reports.
	 */
	private function single_line_log_value( $value ) {
		$value = preg_replace( '/[\x00-\x1F\x7F]+/', ' ', (string) $value );
		$value = preg_replace( '/\s+/', ' ', (string) $value );
		return trim( (string) $value );
	}

	/**
	 * Resolve roles and effective capabilities without loading WP_User.
	 */
	private function resolve_user_security_state( array $user_caps, array $role_definitions ) {
		$roles = [];
		$effective_caps = [];
		$direct_caps = [];

		foreach ( $user_caps as $capability => $enabled ) {
			if ( ! $enabled ) {
				continue;
			}

			if ( isset( $role_definitions[ $capability ] ) ) {
				$roles[] = $capability;
				foreach ( $role_definitions[ $capability ] as $role_cap => $role_enabled ) {
					if ( $role_enabled ) {
						$effective_caps[ $role_cap ] = true;
					}
				}
			} else {
				$effective_caps[ $capability ] = true;
				$direct_caps[ $capability ] = true;
			}
		}

		$roles = array_values( array_unique( $roles ) );
		$is_privileged = isset( $effective_caps['edit_others_posts'] ) || isset( $effective_caps['manage_woocommerce'] );
		foreach ( self::ADMINISTRATIVE_CAPABILITIES as $capability ) {
			if ( isset( $effective_caps[ $capability ] ) ) {
				$is_privileged = true;
				break;
			}
		}

		return [
			'roles'               => $roles,
			'direct_capabilities' => array_keys( $direct_caps ),
			'is_privileged'       => $is_privileged || in_array( 'administrator', $roles, true ),
		];
	}

	/**
	 * Read multisite super-administrator logins without loading user APIs.
	 *
	 * Super administrators are privileged even when they do not carry the
	 * current site's administrator role, so burst detection must account for
	 * the network-level site_admins option as WordPress would.
	 */
	private function read_multisite_super_admin_logins() {
		if ( ! $this->scanner_is_multisite() ) {
			return [];
		}

		$site_admins = $this->scanner_get_network_option( 'site_admins', [] );
		if ( ! is_array( $site_admins ) ) {
			return [];
		}

		$logins = [];
		foreach ( $site_admins as $login ) {
			if ( is_string( $login ) && '' !== trim( $login ) ) {
				$logins[ $login ] = true;
			}
		}

		return $logins;
	}

	/**
	 * Read role capabilities from the current site's user_roles option.
	 */
	private function read_role_definitions() {
		$roles = $this->scanner_get_option( $this->site_table_prefix . 'user_roles', [] );
		if ( ! is_array( $roles ) ) {
			return [];
		}

		$result = [];
		foreach ( $roles as $role => $definition ) {
			if ( ! is_array( $definition ) || ! isset( $definition['capabilities'] ) || ! is_array( $definition['capabilities'] ) ) {
				continue;
			}
			$result[ (string) $role ] = $definition['capabilities'];
		}
		return $result;
	}


	/**
	 * Flag recently created users and rapid-registration clusters.
	 *
	 * Burst analysis is intentionally limited to the same recent-user window so
	 * historical imports/migrations do not dominate an incident report.
	 */
	private function scan_recent_and_burst_users( $stage, array $users ) {
		if ( empty( $users ) ) {
			return;
		}

		// The caller already retains only users inside the configured recent window.
		// Avoid filtering and timestamp work a second time before burst analysis.
		$burst_members = $this->find_user_burst_members( $users );

		foreach ( $users as $user ) {
			$location = $this->format_user_location( $user );

			if ( isset( $burst_members[ $user['id'] ] ) ) {
				$burst = $burst_members[ $user['id'] ];
				if ( $burst['privileged'] ) {
					$description = 'Privileged users were created in a rapid-registration cluster';
					$location .= sprintf( ' · cluster: %d privileged accounts within 10 minutes', $burst['count'] );
				} else {
					$description = 'Users were created in a rapid-registration cluster';
					$location .= sprintf( ' · cluster: %d accounts within 10 minutes', $burst['count'] );
				}

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
	 * Inspect active Action Scheduler jobs for the same strong persistence
	 * indicators used for WP-Cron.
	 *
	 * Action Scheduler is widely used by legitimate plugins, so hook names and
	 * arguments are not suspicious by themselves. Only existing IOC/database
	 * persistence rules can create findings here.
	 */
	private function scan_action_scheduler_persistence( $stage, &$count ) {
		$db = $this->database;
		if ( ! $db ) {
			return;
		}

		$table = $this->site_table_prefix . 'actionscheduler_actions';
		if ( ! $db->table_exists( $table ) ) {
			return;
		}

		$column_rows = $this->scanner_table_columns( $table );
		$columns = [];
		foreach ( $column_rows as $column ) {
			$field = (string) ( $column['Field'] ?? '' );
			if ( '' !== $field ) {
				$columns[ $field ] = true;
			}
		}

		foreach ( [ 'action_id', 'hook', 'args' ] as $required ) {
			if ( ! isset( $columns[ $required ] ) ) {
				return;
			}
		}

		$selected = [ 'action_id', 'hook', 'args' ];
		foreach ( [ 'status', 'scheduled_date_gmt', 'extended_args' ] as $optional ) {
			if ( isset( $columns[ $optional ] ) ) {
				$selected[] = $optional;
			}
		}
		$select = implode( ', ', array_map( [ $this, 'quote_identifier' ], $selected ) );
		$last_id = 0;

		while ( true ) {
			$where = $this->quote_identifier( 'action_id' ) . ' > %d';
			if ( isset( $columns['status'] ) ) {
				$where .= " AND " . $this->quote_identifier( 'status' ) . " IN ('pending','in-progress')";
			}
			$sql = sprintf(
				'SELECT %s FROM %s WHERE %s ORDER BY %s ASC LIMIT %d',
				$select,
				$this->quote_identifier( $table ),
				$where,
				$this->quote_identifier( 'action_id' ),
				self::DB_BATCH_SIZE
			);
			$rows = $db->get_results( $db->prepare( $sql, $last_id ), true );
			if ( empty( $rows ) ) {
				break;
			}

			foreach ( $rows as $row ) {
				$action_id = (int) ( $row['action_id'] ?? 0 );
				if ( $action_id < 1 ) {
					continue;
				}
				$last_id = max( $last_id, $action_id );
				$count++;
				$this->scanned_db_rows++;

				$hook = $this->single_line_log_value( (string) ( $row['hook'] ?? '' ) );
				$status = $this->single_line_log_value( (string) ( $row['status'] ?? '' ) );
				$scheduled = $this->single_line_log_value( (string) ( $row['scheduled_date_gmt'] ?? '' ) );
				$location = sprintf( 'Action Scheduler #%d · hook: %s', $action_id, $hook );
				if ( '' !== $status ) {
					$location .= ' · status: ' . $status;
				}
				if ( '' !== $scheduled && '0000-00-00 00:00:00' !== $scheduled ) {
					$location .= ' · scheduled ' . $scheduled . ' UTC';
				}

				$value = (string) ( $row['hook'] ?? '' ) . ' ' . (string) ( $row['args'] ?? '' ) . ' ' . (string) ( $row['extended_args'] ?? '' );
				$this->scan_persistence_value( $stage, $location, $value );
				$this->stage_tick( $stage, $count, 'items' );
			}

			if ( count( $rows ) < self::DB_BATCH_SIZE ) {
				break;
			}
		}
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

		$this->prepare_finalization_guard();
		if ( $this->interactive ) {
			$this->start_background_spinner( 'Security Scan — finalizing report...' );
		}

		try {
			// Apply checksum trust and min-severity in one pass. Building an
			// intermediate reportable-finding array here can briefly duplicate a large
			// finding set at the exact point where heavily compromised sites have the
			// highest memory pressure.
			$filtered = [];
			foreach ( $this->findings as $finding ) {
				if ( ! $this->finding_passes_plugin_integrity_policy( $finding ) ) {
					continue;
				}
				if ( self::SEVERITY_WEIGHT[ $finding['severity'] ] < self::SEVERITY_WEIGHT[ $min_severity ] ) {
					continue;
				}
				$filtered[] = $finding;
			}
			$this->findings = [];
			if ( function_exists( 'gc_collect_cycles' ) ) {
				gc_collect_cycles();
			}

			usort( $filtered, [ $this, 'sort_findings' ] );

			$report = $this->build_report( $filtered );
			$scan_log_path = $this->write_scan_log( $report );
		} catch ( \Throwable $exception ) {
			\WP_CLI::error(
				'Security report finalization failed: ' . $exception->getMessage()
				. ' (' . basename( $exception->getFile() ) . ':' . $exception->getLine() . ')'
			);
		} finally {
			$this->stop_background_spinner();
		}
		$output_file = isset( $assoc_args['output'] ) ? (string) $assoc_args['output'] : '';

		if ( 'json' === $this->format ) {
			$content = json_encode( $report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES );
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
	 * Keep a small memory reserve so fatal report-finalization errors can be
	 * surfaced even when normal PHP error display is disabled.
	 */
	private function prepare_finalization_guard() {
		$this->finalization_active = true;
		$this->finalization_memory_reserve = str_repeat( 'R', 262144 );

		if ( $this->finalization_shutdown_registered ) {
			return;
		}

		$this->finalization_shutdown_registered = true;
		register_shutdown_function(
			function () {
				$this->handle_finalization_shutdown();
			}
		);
	}

	/**
	 * Disable the report-finalization fatal guard after a normal completion.
	 */
	private function release_finalization_guard() {
		$this->finalization_active = false;
		$this->finalization_memory_reserve = '';
	}

	/**
	 * Surface otherwise-hidden fatal errors that occur after the scan stages.
	 *
	 * OS-level SIGKILL/OOM termination cannot be intercepted here, but ordinary
	 * PHP fatal/memory-limit failures will now leave a useful diagnostic.
	 */
	private function handle_finalization_shutdown() {
		if ( ! $this->finalization_active ) {
			return;
		}

		$error = error_get_last();
		if ( ! is_array( $error ) || ! in_array( (int) ( $error['type'] ?? 0 ), [ E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR ], true ) ) {
			return;
		}

		$this->finalization_memory_reserve = '';
		$message = preg_replace( '/[\x00-\x1F\x7F]+/', ' ', (string) ( $error['message'] ?? 'Unknown fatal error' ) );
		$message = trim( preg_replace( '/\s+/', ' ', (string) $message ) );
		@fwrite( STDERR, PHP_EOL . 'Error: Security report finalization terminated: ' . $message . PHP_EOL );
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
			'correlations'      => $this->build_cross_layer_indicator_correlations( $findings ),
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
			if ( $this->finding_passes_plugin_integrity_policy( $finding ) ) {
				$filtered[] = $finding;
			}
		}

		return $filtered;
	}

	/**
	 * Return whether one finding survives the plugin-integrity trust policy.
	 */
	private function finding_passes_plugin_integrity_policy( array $finding ) {
		if ( 'Plugin integrity' === ( $finding['section'] ?? '' ) ) {
			return false;
		}

		if ( 'Plugins' !== ( $finding['section'] ?? '' ) ) {
			return true;
		}

		$plugin = $this->plugin_slug_from_location( $finding['location'] ?? '' );
		$status = $this->plugin_integrity_status( $plugin );

		return 'verified' !== $status || $this->is_verified_plugin_risk_finding( $finding );
	}

	/**
	 * Count plugin findings that will actually be shown after checksum trust.
	 */
	private function count_reportable_plugin_findings() {
		$count = 0;
		foreach ( $this->findings as $finding ) {
			if ( 'Plugins' === ( $finding['section'] ?? '' ) && $this->finding_passes_plugin_integrity_policy( $finding ) ) {
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
	 * Group plugin findings by plugin and then by human-readable problem.
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

			$issue_description = trim( (string) ( $finding['description'] ?? '' ) );
			$issue_key = '' !== $issue_description
				? $issue_description
				: ( ! empty( $finding['rule'] ) ? (string) $finding['rule'] : md5( serialize( $finding ) ) );
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

				if ( ! isset( $groups[ $problem ] ) ) {
					$groups[ $problem ] = [
						'plugins' => [],
						'files'   => [],
					];
				}
				$groups[ $problem ]['plugins'][ $slug ] = true;
				$groups[ $problem ]['files'][ $location ] = true;
			}
		}

		ksort( $groups, SORT_STRING );
		foreach ( $groups as &$group ) {
			$group['plugins'] = array_keys( $group['plugins'] );
			$group['files'] = array_keys( $group['files'] );
			sort( $group['plugins'], SORT_STRING );
			sort( $group['files'], SORT_STRING );
		}
		unset( $group );

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
	 * Correlate exact known indicators that appear in more than one scan layer.
	 *
	 * Correlation is contextual evidence only: it does not create extra findings
	 * or alter severity counters. Restricting this to exact IOC rules keeps the
	 * signal strong and avoids correlating broad heuristics across unrelated code.
	 */
	private function build_cross_layer_indicator_correlations( array $findings ) {
		$groups = [];

		foreach ( $findings as $finding ) {
			$rule = (string) ( $finding['rule'] ?? '' );
			if ( 0 !== strpos( $rule, 'ioc_' ) ) {
				continue;
			}

			$section = (string) ( $finding['section'] ?? '' );
			if ( '' === $section ) {
				continue;
			}

			if ( ! isset( $groups[ $rule ] ) ) {
				$groups[ $rule ] = [
					'rule'        => $rule,
					'description' => (string) ( $finding['description'] ?? 'Known security indicator' ),
					'severity'    => (string) ( $finding['severity'] ?? 'high' ),
					'confidence'  => (int) ( $finding['confidence'] ?? 0 ),
					'sections'    => [],
					'locations'   => [],
				];
			}

			$groups[ $rule ]['sections'][ $section ] = true;
			$location = $this->finding_location( $finding );
			$groups[ $rule ]['locations'][ $section . "\0" . $location ] = [
				'section'  => $section,
				'location' => $location,
			];

			if (
				self::SEVERITY_WEIGHT[ $finding['severity'] ] > self::SEVERITY_WEIGHT[ $groups[ $rule ]['severity'] ]
				|| (
					$finding['severity'] === $groups[ $rule ]['severity']
					&& (int) $finding['confidence'] > (int) $groups[ $rule ]['confidence']
				)
			) {
				$groups[ $rule ]['severity'] = (string) $finding['severity'];
				$groups[ $rule ]['confidence'] = (int) $finding['confidence'];
			}
		}

		$correlations = [];
		foreach ( $groups as $group ) {
			if ( count( $group['sections'] ) < 2 ) {
				continue;
			}

			$group['sections'] = array_keys( $group['sections'] );
			sort( $group['sections'], SORT_STRING );
			$group['locations'] = array_values( $group['locations'] );
			usort(
				$group['locations'],
				static function ( $a, $b ) {
					$section_compare = strcmp( $a['section'], $b['section'] );
					return 0 !== $section_compare ? $section_compare : strcmp( $a['location'], $b['location'] );
				}
			);
			$correlations[] = $group;
		}

		usort(
			$correlations,
			function ( $a, $b ) {
				$severity_compare = self::SEVERITY_WEIGHT[ $b['severity'] ] <=> self::SEVERITY_WEIGHT[ $a['severity'] ];
				if ( 0 !== $severity_compare ) {
					return $severity_compare;
				}
				$confidence_compare = (int) $b['confidence'] <=> (int) $a['confidence'];
				return 0 !== $confidence_compare ? $confidence_compare : strcmp( $a['description'], $b['description'] );
			}
		);

		return $correlations;
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
			$description = trim( (string) ( $finding['description'] ?? '' ) );
			$key = '' !== $description
				? $description
				: ( ! empty( $finding['rule'] ) ? (string) $finding['rule'] : md5( serialize( $finding ) ) );
			if ( ! isset( $groups[ $key ] ) ) {
				$groups[ $key ] = [
					'description' => '' !== $description ? $description : 'Unclassified security finding',
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
	 * Return unique rendered locations for one grouped human-readable problem.
	 */
	private function grouped_issue_locations( array $issue, $plugin = null ) {
		$locations = [];
		foreach ( (array) ( $issue['findings'] ?? [] ) as $finding ) {
			$location = null === $plugin
				? $this->finding_location( $finding )
				: $this->plugin_relative_finding_location( $finding, $plugin );
			$locations[ $location ] = true;
		}

		return array_keys( $locations );
	}

	/**
	 * Render a normal section grouped by problem and preserving all locations.
	 */
	private function render_terminal_grouped_findings( array $findings ) {
		foreach ( $this->group_findings_by_problem( $findings ) as $issue ) {
			$label = strtoupper( $issue['severity'] ) . ' · ' . $issue['confidence'] . '%';
			\WP_CLI::log( sprintf( '%-16s %s', $label, $issue['description'] ) );
			foreach ( $this->grouped_issue_locations( $issue ) as $location ) {
				\WP_CLI::log( str_repeat( ' ', 17 ) . $location );
			}
			\WP_CLI::log( '' );
		}
	}

	/**
	 * Render grouped findings as Markdown while preserving all locations.
	 */
	private function render_markdown_grouped_findings( array $findings ) {
		$lines = [];
		foreach ( $this->group_findings_by_problem( $findings ) as $issue ) {
			$lines[] = sprintf(
				'**%s · %d%% — %s**',
				strtoupper( $issue['severity'] ),
				$issue['confidence'],
				$this->markdown_escape( $issue['description'] )
			);
			$lines[] = '';
			foreach ( $this->grouped_issue_locations( $issue ) as $location ) {
				$lines[] = '- `' . $this->markdown_escape( $location ) . '`';
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
					? 'Plugin files do not match the official package.'
					: 'Multiple high-risk findings were detected.';

				$recommendations[ $slug ] = [
					'slug'   => $slug,
					'action' => 'reinstall',
					'reason' => $reason,
					'count'  => max( (int) $group['total'], $this->plugin_integrity_change_count( $slug ) ),
				];
				continue;
			}

			$reason = 'verified' === $group['integrity']
				? 'High-confidence findings remain despite verified files.'
				: 'Suspicious findings require manual review.';

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
				'reason' => 'Plugin files do not match the official package.',
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
	 * Group plugin recommendations by the user-facing action and reason.
	 *
	 * Internal plugin scores remain per-plugin, but the final remediation report
	 * should present one concise instruction for every equivalent recommendation.
	 */
	private function group_plugin_recommendations( array $recommendations ) {
		$groups = [];
		foreach ( $recommendations as $recommendation ) {
			$action = (string) ( $recommendation['action'] ?? 'review' );
			$reason = trim( (string) ( $recommendation['reason'] ?? '' ) );
			$slug = trim( (string) ( $recommendation['slug'] ?? '' ) );
			if ( '' === $slug || '' === $reason ) {
				continue;
			}

			$key = $action . "\0" . $reason;
			if ( ! isset( $groups[ $key ] ) ) {
				$groups[ $key ] = [
					'action' => $action,
					'reason' => $reason,
					'slugs'  => [],
				];
			}
			$groups[ $key ]['slugs'][ $slug ] = true;
		}

		$groups = array_values( $groups );
		foreach ( $groups as &$group ) {
			$group['slugs'] = array_keys( $group['slugs'] );
			sort( $group['slugs'], SORT_STRING );
		}
		unset( $group );

		usort(
			$groups,
			static function ( $a, $b ) {
				$rank = [ 'reinstall' => 2, 'review' => 1 ];
				$action_compare = ( $rank[ $b['action'] ] ?? 0 ) <=> ( $rank[ $a['action'] ] ?? 0 );
				if ( 0 !== $action_compare ) {
					return $action_compare;
				}
				return strcmp( $a['reason'], $b['reason'] );
			}
		);

		return $groups;
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

		\WP_CLI::log( '' );
		\WP_CLI::log( 'Recommendations' );
		\WP_CLI::log( str_repeat( '-', 50 ) );

		foreach ( $this->group_plugin_recommendations( $recommendations ) as $recommendation_group ) {
			$prefix = 'reinstall' === $recommendation_group['action'] ? 'HIGH PRIORITY' : 'REVIEW';
			\WP_CLI::log( $prefix . ' — ' . rtrim( $recommendation_group['reason'], '.' ) );
			foreach ( $recommendation_group['slugs'] as $slug ) {
				\WP_CLI::log( '  ⚠ ' . $slug );
			}
			if ( 'reinstall' === $recommendation_group['action'] ) {
				\WP_CLI::log( '  Replace these plugins with fresh trusted copies, then rescan.' );
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

		$lines = [ '## Recommendations', '' ];
		foreach ( $this->group_plugin_recommendations( $recommendations ) as $recommendation_group ) {
			$prefix = 'reinstall' === $recommendation_group['action'] ? 'High priority' : 'Review';
			$lines[] = '### ' . $prefix . ' — ' . rtrim( $recommendation_group['reason'], '.' );
			$lines[] = '';
			foreach ( $recommendation_group['slugs'] as $slug ) {
				$lines[] = '- ⚠ `' . $this->markdown_escape( $slug ) . '`';
			}
			$lines[] = '';
			if ( 'reinstall' === $recommendation_group['action'] ) {
				$lines[] = 'Replace these plugins with fresh trusted copies, then rescan.';
				$lines[] = '';
			}
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
	 * Plugins already marked for reinstall are intentionally omitted from the
	 * verbose finding list; their remediation is shown once in
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

		$replacement_plugins = [];
		foreach ( $groups as $group ) {
			if ( 'reinstall' === $group['action'] ) {
				$replacement_plugins[ $group['slug'] ] = true;
			}
		}

		$visible_findings = array_values(
			array_filter(
				$findings,
				function ( $finding ) use ( $replacement_plugins ) {
					$plugin = $this->plugin_slug_from_location( $finding['location'] );
					return null === $plugin || ! isset( $replacement_plugins[ $plugin ] );
				}
			)
		);

		$this->render_terminal_grouped_findings( $visible_findings );
	}

	/**
	 * Render plugin findings for the Markdown report.
	 *
	 * Markdown remains the detailed human-readable export, so it preserves all
	 * grouped paths even for plugins that are ultimately recommended for replace.
	 */
	private function render_markdown_plugin_findings( array $findings ) {
		$lines = [];
		$plugin_slugs = [];
		foreach ( $findings as $finding ) {
			$plugin = $this->plugin_slug_from_location( $finding['location'] );
			if ( null !== $plugin ) {
				$plugin_slugs[ $plugin ] = true;
			}
		}

		$lines[] = count( $findings ) . ' threat' . ( 1 === count( $findings ) ? '' : 's' ) . ' found across ' . count( $plugin_slugs ) . ' plugin' . ( 1 === count( $plugin_slugs ) ? '' : 's' ) . '.';
		$lines[] = '';
		$lines = array_merge( $lines, $this->render_markdown_grouped_findings( $findings ) );

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
		$plugins = [];
		foreach ( $findings as $finding ) {
			$plugin = $this->plugin_slug_from_location( $finding['location'] );
			if ( null !== $plugin ) {
				$plugins[ $plugin ] = true;
			}
		}

		\WP_CLI::log( sprintf( '%d integrity issue%s found across %d plugin%s', count( $findings ), 1 === count( $findings ) ? '' : 's', count( $plugins ), 1 === count( $plugins ) ? '' : 's' ) );
		\WP_CLI::log( '' );
		$this->render_terminal_grouped_findings( $findings );
	}

	/**
	 * Render plugin checksum failures for Markdown.
	 *
	 * The detailed export keeps every affected path. Recommendations are rendered
	 * once at the end of the Plugins section.
	 */
	private function render_markdown_plugin_integrity_findings( array $findings ) {
		$lines = [];
		$lines[] = count( $findings ) . ' integrity issue' . ( 1 === count( $findings ) ? '' : 's' ) . ' found.';
		$lines[] = '';
		$lines = array_merge( $lines, $this->render_markdown_grouped_findings( $findings ) );
		return $lines;
	}

	/**
	 * Render the concise terminal report.
	 *
	 * Detailed findings are intentionally kept out of the interactive terminal
	 * report and written to the scan log instead. Recommendations also remain in
	 * the scan log, keeping the console focused on the final summary only.
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

			$lines = array_merge( $lines, $this->render_markdown_grouped_findings( $findings ) );
		}

		if ( ! empty( $report['correlations'] ) ) {
			$lines[] = '## Correlated indicators';
			$lines[] = '';
			foreach ( $report['correlations'] as $correlation ) {
				$lines[] = sprintf(
					'### %s — %d%% confidence',
					strtoupper( (string) $correlation['severity'] ),
					(int) $correlation['confidence']
				);
				$lines[] = '';
				$lines[] = '- Indicator: ' . $this->markdown_escape( (string) $correlation['description'] );
				$lines[] = '- Seen in: ' . $this->markdown_escape( implode( ', ', $correlation['sections'] ) );
				$lines[] = '- Locations:';
				foreach ( $correlation['locations'] as $location ) {
					$lines[] = '  - [' . $this->markdown_escape( $location['section'] ) . '] `' . $this->markdown_escape( $location['location'] ) . '`';
				}
				$lines[] = '';
			}
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
		$path = '' !== $this->scan_log_path ? $this->scan_log_path : $this->resolve_scan_log_path();
		$content = $this->render_scan_log( $report );
		if ( false === @file_put_contents( $path, $content, LOCK_EX ) ) {
			return null;
		}
		return $path;
	}

	/**
	 * Resolve the exact scanner-owned log path for this run.
	 */
	private function resolve_scan_log_path() {
		$directory = '' !== $this->launch_directory ? $this->launch_directory : $this->resolve_launch_directory();
		return rtrim( $directory, '/\\' ) . DIRECTORY_SEPARATOR . 'security-scan.log';
	}

	/**
	 * Whether a filesystem path is owned by the scanner itself.
	 *
	 * Only the exact log path selected for the current run is excluded. A file
	 * with the same basename elsewhere in wp-content remains in scan scope.
	 */
	private function is_scanner_output_path( $path ) {
		if ( '' === $this->scan_log_path ) {
			return false;
		}

		$expected = rtrim( $this->normalize_path( $this->scan_log_path ), '/' );
		$current = rtrim( $this->normalize_path( $path ), '/' );

		return '' !== $expected && $expected === $current;
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

		return defined( 'ABSPATH' ) ? rtrim( (string) constant( 'ABSPATH' ), '/\\' ) : '.';
	}

	/**
	 * Render the scan timestamp in the local timezone of the machine running WP-CLI.
	 *
	 * The scanner intentionally ignores the WordPress site's timezone here. It
	 * prefers explicit machine/process timezone signals and falls back to UTC when
	 * the host timezone cannot be determined without executing external commands.
	 */
	private function resolve_scan_log_timestamp( $timestamp ) {
		try {
			$instant = new \DateTimeImmutable( (string) $timestamp, new \DateTimeZone( 'UTC' ) );
		} catch ( \Exception $exception ) {
			$instant = new \DateTimeImmutable( 'now', new \DateTimeZone( 'UTC' ) );
		}

		return $instant->setTimezone( $this->resolve_machine_timezone() )->format( 'c' );
	}

	/**
	 * Resolve the machine/CLI timezone without shelling out or loading WordPress.
	 */
	private function resolve_machine_timezone() {
		$candidates = [];

		$environment_timezone = getenv( 'TZ' );
		if ( is_string( $environment_timezone ) && '' !== trim( $environment_timezone ) ) {
			$candidates[] = ltrim( trim( $environment_timezone ), ':' );
		}

		if ( is_readable( '/etc/timezone' ) ) {
			$system_timezone = trim( (string) @file_get_contents( '/etc/timezone' ) );
			if ( '' !== $system_timezone ) {
				$candidates[] = $system_timezone;
			}
		}

		$localtime_link = @readlink( '/etc/localtime' );
		if ( is_string( $localtime_link ) && '' !== $localtime_link ) {
			$marker = '/zoneinfo/';
			$position = strpos( str_replace( '\\', '/', $localtime_link ), $marker );
			if ( false !== $position ) {
				$candidates[] = substr( str_replace( '\\', '/', $localtime_link ), $position + strlen( $marker ) );
			}
		}

		$php_timezone = trim( (string) ini_get( 'date.timezone' ) );
		if ( '' !== $php_timezone ) {
			$candidates[] = $php_timezone;
		}

		foreach ( array_unique( $candidates ) as $candidate ) {
			if ( '' === $candidate ) {
				continue;
			}
			try {
				return new \DateTimeZone( $candidate );
			} catch ( \Exception $exception ) {
				// Try the next machine-local timezone signal.
			}
		}

		return new \DateTimeZone( 'UTC' );
	}

	/**
	 * Build a stable display list for inactive plugins/themes in cleanup guidance.
	 */
	private function inactive_code_display_list( array $items ) {
		$labels = [];
		foreach ( $items as $item ) {
			$slug = trim( (string) ( $item['slug'] ?? '' ) );
			$name = trim( (string) ( $item['name'] ?? '' ) );
			if ( '' === $slug && '' === $name ) {
				continue;
			}

			$label = '' !== $name ? $name : $slug;
			if ( '' !== $slug && $slug !== $label ) {
				$label .= ' (' . $slug . ')';
			}
			$labels[ $label ] = true;
		}

		$labels = array_keys( $labels );
		sort( $labels, SORT_NATURAL | SORT_FLAG_CASE );
		return $labels;
	}

	/**
	 * Build a detailed plain-text report intended for manual incident review.
	 */
	private function render_scan_log( array $report ) {
		$lines = [];
		$lines[] = 'WORDPRESS SECURITY SCAN:      ' . $this->resolve_scan_log_timestamp( $report['scanned_at'] ?? gmdate( 'c' ) );
		$lines[] = str_repeat( '-', self::SCAN_LOG_SEPARATOR_WIDTH );
		$this->append_scan_log_major_section_gap( $lines );
		$lines[] = 'FINDINGS';
		$lines[] = str_repeat( '-', self::SCAN_LOG_SEPARATOR_WIDTH );

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
			$lines[] = str_repeat( '-', self::SCAN_LOG_SEPARATOR_WIDTH );

			if ( 'Plugins' === $section ) {
				$issue_number = 1;
				foreach ( $this->group_findings_by_problem( $findings ) as $issue ) {
					$this->append_scan_log_issue( $lines, $issue, $issue_number );
					$issue_number++;
				}

				$integrity_groups = $this->group_plugin_integrity_changes_by_problem();
				foreach ( $integrity_groups as $problem => $integrity_group ) {
					$lines[] = '[CRITICAL] Plugin integrity changes';
					$lines[] = '    Plugins: ' . implode( ', ', $integrity_group['plugins'] );
					$lines[] = '    Problem: ' . $problem;
					$lines[] = '    Files:';
					foreach ( $integrity_group['files'] as $location ) {
						$lines[] = '      - ' . $location;
					}
					$lines[] = '';
				}
				continue;
			}

			$issue_number = 1;
			foreach ( $this->group_findings_by_problem( $findings ) as $issue ) {
				if ( 'Users & persistence' === $section ) {
					$this->append_scan_log_users_issue( $lines, $issue, $issue_number );
				} else {
					$this->append_scan_log_issue( $lines, $issue, $issue_number );
				}
				$issue_number++;
			}

			$lines[] = '';
		}

		if ( ! empty( $report['correlations'] ) ) {
			$this->append_scan_log_major_section_gap( $lines );
			$lines[] = 'CORRELATED INDICATORS';
			$lines[] = str_repeat( '-', self::SCAN_LOG_SEPARATOR_WIDTH );
			$correlation_number = 1;
			foreach ( $report['correlations'] as $correlation ) {
				$lines[] = sprintf(
					'[%d] %s | %d%% confidence',
					$correlation_number,
					strtoupper( (string) $correlation['severity'] ),
					(int) $correlation['confidence']
				);
				$lines[] = '    Indicator: ' . (string) $correlation['description'];
				$lines[] = '    Seen in: ' . implode( ', ', $correlation['sections'] );
				$lines[] = '    Locations:';
				foreach ( $correlation['locations'] as $location ) {
					$lines[] = '      - [' . $location['section'] . '] ' . $location['location'];
				}
				$lines[] = '';
				$correlation_number++;
			}
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
			$lines[] = str_repeat( '-', self::SCAN_LOG_SEPARATOR_WIDTH );
			foreach ( $this->group_plugin_recommendations( $recommendations ) as $recommendation_group ) {
				$lines[] = sprintf( '[%s] %s', strtoupper( $recommendation_group['action'] ), $recommendation_group['reason'] );
				$lines[] = '    Plugins:';
				foreach ( $recommendation_group['slugs'] as $slug ) {
					$lines[] = '      - ' . $slug;
				}
				$lines[] = '';
			}
			if ( ! empty( $this->inactive_plugins ) ) {
				$lines[] = '[CLEANUP] Inactive plugins';
				$lines[] = '    Status: ' . ( $this->full_scan ? 'Included in the full scan.' : 'Not scanned.' );
				$lines[] = '    Action: Remove if not needed.';
				$lines[] = '    Plugins:';
				foreach ( $this->inactive_code_display_list( $this->inactive_plugins ) as $plugin ) {
					$lines[] = '      - ' . $plugin;
				}
				$lines[] = '';
			}
			if ( ! empty( $this->inactive_themes ) ) {
				$lines[] = '[CLEANUP] Inactive themes';
				$lines[] = '    Status: ' . ( $this->full_scan ? 'Included in the full scan.' : 'Not scanned.' );
				$lines[] = '    Action: Remove if not needed.';
				$lines[] = '    Themes:';
				foreach ( $this->inactive_code_display_list( $this->inactive_themes ) as $theme ) {
					$lines[] = '      - ' . $theme;
				}
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
	 * Append one Users & persistence issue with structured user rows when possible.
	 */
	private function append_scan_log_users_issue( array &$lines, array $issue, $number ) {
		$locations = $this->grouped_issue_locations( $issue );
		$parsed = [];
		$type = null;

		foreach ( $locations as $location ) {
			$row = $this->parse_scan_log_user_location( $location );
			if ( null === $row || ( null !== $type && $type !== $row['type'] ) ) {
				$this->append_scan_log_issue( $lines, $issue, $number );
				return;
			}
			$type = $row['type'];
			$parsed[] = $row['values'];
		}

		if ( empty( $parsed ) ) {
			$this->append_scan_log_issue( $lines, $issue, $number );
			return;
		}

		$lines[] = sprintf(
			'[%d] %s | %d%% confidence',
			(int) $number,
			strtoupper( (string) $issue['severity'] ),
			(int) $issue['confidence']
		);
		$lines[] = '    Problem: ' . (string) $issue['description'];
		$lines[] = '    Users:';

		if ( 'account' === $type ) {
			$this->append_scan_log_columns(
				$lines,
				[ 'ID', 'Login', 'Email', 'Roles', 'Registered', 'Context' ],
				$parsed
			);
		} elseif ( 'direct_capabilities' === $type ) {
			$this->append_scan_log_columns(
				$lines,
				[ 'ID', 'Login', 'Direct capabilities' ],
				$parsed
			);
		} else {
			$this->append_scan_log_columns(
				$lines,
				[ 'ID', 'Login', 'Application password', 'Created', 'Last used', 'Last IP' ],
				$parsed
			);
		}

		$lines[] = '';
	}

	/**
	 * Parse known user finding locations into stable report columns.
	 */
	private function parse_scan_log_user_location( $location ) {
		$location = (string) $location;

		if ( preg_match( '/^user #(\d+) · (.*?) · (.*?) · roles?: (.*?) · registered (.*?) UTC(?: · cluster: (.*))?$/', $location, $matches ) ) {
			return [
				'type'   => 'account',
				'values' => [
					'#' . $matches[1],
					$matches[2],
					$matches[3],
					$matches[4],
					$matches[5] . ' UTC',
					isset( $matches[6] ) && '' !== $matches[6] ? $matches[6] : '-',
				],
			];
		}

		if ( preg_match( '/^user #(\d+) · (.*?) · direct capabilities: (.*)$/', $location, $matches ) ) {
			return [
				'type'   => 'direct_capabilities',
				'values' => [ '#' . $matches[1], $matches[2], $matches[3] ],
			];
		}

		if ( preg_match( '/^user #(\d+) · (.*?) · application password: (.*?) · created (.*?) UTC(?: · last used (.*?) UTC)?(?: · last IP: (.*))?$/', $location, $matches ) ) {
			return [
				'type'   => 'application_password',
				'values' => [
					'#' . $matches[1],
					$matches[2],
					$matches[3],
					$matches[4] . ' UTC',
					isset( $matches[5] ) && '' !== $matches[5] ? $matches[5] . ' UTC' : '-',
					isset( $matches[6] ) && '' !== $matches[6] ? $matches[6] : '-',
				],
			];
		}

		return null;
	}

	/**
	 * Append an aligned plain-text table without truncating forensic values.
	 */
	private function append_scan_log_columns( array &$lines, array $headers, array $rows, $indent = '      ' ) {
		$widths = array_map( 'strlen', $headers );
		foreach ( $rows as $row ) {
			foreach ( $headers as $index => $_header ) {
				$value = isset( $row[ $index ] ) ? (string) $row[ $index ] : '';
				$widths[ $index ] = max( $widths[ $index ], strlen( $value ) );
			}
		}

		$render = static function ( array $values ) use ( $headers, $widths ) {
			$parts = [];
			$last = count( $headers ) - 1;
			foreach ( $headers as $index => $_header ) {
				$value = isset( $values[ $index ] ) ? (string) $values[ $index ] : '';
				$parts[] = $index === $last ? $value : str_pad( $value, $widths[ $index ] );
			}
			return implode( '  ', $parts );
		};

		$lines[] = $indent . $render( $headers );
		$lines[] = $indent . $render( array_map( static function ( $width ) { return str_repeat( '-', $width ); }, $widths ) );
		foreach ( $rows as $row ) {
			$lines[] = $indent . $render( $row );
		}
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
		foreach ( $this->grouped_issue_locations( $issue, $plugin ) as $location ) {
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
		if ( ! is_dir( $directory ) && ! @mkdir( $directory, 0777, true ) && ! is_dir( $directory ) ) {
			\WP_CLI::error( 'Unable to create export directory: ' . $directory );
		}

		if ( false === file_put_contents( $output_file, $content ) ) {
			\WP_CLI::error( 'Unable to write report: ' . $output_file );
		}

		\WP_CLI::success( 'Report written to ' . $output_file );
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
		return $this->database ? $this->database->table_exists( $table ) : false;
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
		$base = rtrim( $this->normalize_path( $this->content_dir ), '/' ) . '/';
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
		return str_replace( '\\', '/', (string) $path );
	}

	/**
	 * WordPress-compatible key sanitization without loading formatting.php.
	 */
	private function sanitize_key_value( $key ) {
		$key = strtolower( (string) $key );
		return preg_replace( '/[^a-z0-9_\-]/', '', $key );
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

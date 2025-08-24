<?php
/**
 * The file that defines the core plugin class
 *
 * A class definition that includes attributes and functions used across both the
 * public-facing side of the site and the admin area.
 *
 * @link       https://github.com/luozongbao
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes
 */

/**
 * The core plugin class.
 *
 * This is used to define internationalization, admin-specific hooks, and
 * public-facing site hooks.
 *
 * Also maintains the unique identifier of this plugin as well as the current
 * version of the plugin.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes
 * @author     luozongbao <luo.zongbao@outlook.com>
 */
class WP_Breach {

	/**
	 * The loader that's responsible for maintaining and registering all hooks that power
	 * the plugin.
	 *
	 * @since    1.0.0
	 * @access   protected
	 * @var      WP_Breach_Loader    $loader    Maintains and registers all hooks for the plugin.
	 */
	protected $loader;

	/**
	 * The unique identifier of this plugin.
	 *
	 * @since    1.0.0
	 * @access   protected
	 * @var      string    $plugin_name    The string used to uniquely identify this plugin.
	 */
	protected $plugin_name;

	/**
	 * The current version of the plugin.
	 *
	 * @since    1.0.0
	 * @access   protected
	 * @var      string    $version    The current version of the plugin.
	 */
	protected $version;

	/**
	 * Define the core functionality of the plugin.
	 *
	 * Set the plugin name and the plugin version that can be used throughout the plugin.
	 * Load the dependencies, define the locale, and set the hooks for the admin area and
	 * the public-facing side of the site.
	 *
	 * @since    1.0.0
	 */
	public function __construct() {
		if ( defined( 'WP_BREACH_VERSION' ) ) {
			$this->version = WP_BREACH_VERSION;
		} else {
			$this->version = '1.0.0';
		}
		$this->plugin_name = 'wp-breach';

		$this->load_dependencies();
		$this->set_locale();
		$this->define_admin_hooks();
		$this->define_public_hooks();
		$this->define_database_hooks();
	}

	/**
	 * Load the required dependencies for this plugin.
	 *
	 * Include the following files that make up the plugin:
	 *
	 * - WP_Breach_Loader. Orchestrates the hooks of the plugin.
	 * - WP_Breach_i18n. Defines internationalization functionality.
	 * - WP_Breach_Admin. Defines all hooks for the admin area.
	 * - WP_Breach_Public. Defines all hooks for the public side of the site.
	 *
	 * Create an instance of the loader which will be used to register the hooks
	 * with WordPress.
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function load_dependencies() {

		/**
		 * The class responsible for orchestrating the actions and filters of the
		 * core plugin.
		 */
		require_once WP_BREACH_PLUGIN_DIR . 'includes/class-wp-breach-loader.php';

		/**
		 * The class responsible for defining internationalization functionality
		 * of the plugin.
		 */
		require_once WP_BREACH_PLUGIN_DIR . 'includes/class-wp-breach-i18n.php';

		/**
		 * The class responsible for defining all actions that occur in the admin area.
		 */
		require_once WP_BREACH_PLUGIN_DIR . 'admin/class-wp-breach-admin.php';

		/**
		 * The class responsible for defining all actions that occur in the public-facing
		 * side of the site.
		 */
		require_once WP_BREACH_PLUGIN_DIR . 'public/class-wp-breach-public.php';

		/**
		 * The class responsible for database operations.
		 */
		require_once WP_BREACH_PLUGIN_DIR . 'includes/class-wp-breach-database.php';

		/**
		 * Load scanner classes
		 */
		$this->load_scanner_classes();

		/**
		 * Load user management system (Issue #010)
		 */
		$this->load_user_management_classes();

		$this->loader = new WP_Breach_Loader();
	}

	/**
	 * Define the locale for this plugin for internationalization.
	 *
	 * Uses the WP_Breach_i18n class in order to set the domain and to register the hook
	 * with WordPress.
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function set_locale() {
		$plugin_i18n = new WP_Breach_i18n();

		$this->loader->add_action( 'plugins_loaded', $plugin_i18n, 'load_plugin_textdomain' );
	}

	/**
	 * Register all of the hooks related to the admin area functionality
	 * of the plugin.
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function define_admin_hooks() {
		$plugin_admin = new WP_Breach_Admin( $this->get_plugin_name(), $this->get_version() );

		$this->loader->add_action( 'admin_enqueue_scripts', $plugin_admin, 'enqueue_styles' );
		$this->loader->add_action( 'admin_enqueue_scripts', $plugin_admin, 'enqueue_scripts' );

		// Add menu
		$this->loader->add_action( 'admin_menu', $plugin_admin, 'add_admin_menu' );
		
		// Add admin notices
		$this->loader->add_action( 'admin_notices', $plugin_admin, 'add_admin_notices' );
		
		// Add dashboard widgets
		$this->loader->add_action( 'wp_dashboard_setup', $plugin_admin, 'add_dashboard_widgets' );
		
		// Add admin bar menu
		$this->loader->add_action( 'admin_bar_menu', $plugin_admin, 'add_admin_bar_menu', 100 );
		
		// AJAX handlers
		$this->loader->add_action( 'wp_ajax_wp_breach_quick_scan', $plugin_admin, 'handle_ajax_requests' );
		$this->loader->add_action( 'wp_ajax_wp_breach_get_scan_status', $plugin_admin, 'handle_ajax_requests' );
		$this->loader->add_action( 'wp_ajax_wp_breach_dismiss_vulnerability', $plugin_admin, 'handle_ajax_requests' );

		// Load user management admin hooks
		$this->define_user_management_hooks();
	}

	/**
	 * Register all of the hooks related to the public-facing functionality
	 * of the plugin.
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function define_public_hooks() {
		$plugin_public = new WP_Breach_Public( $this->get_plugin_name(), $this->get_version() );

		$this->loader->add_action( 'wp_enqueue_scripts', $plugin_public, 'enqueue_styles' );
		$this->loader->add_action( 'wp_enqueue_scripts', $plugin_public, 'enqueue_scripts' );
		
		// Add security headers
		$this->loader->add_action( 'init', $plugin_public, 'add_security_headers' );
		
		// Monitor frontend activity
		$this->loader->add_action( 'init', $plugin_public, 'monitor_frontend_activity' );
		
		// Add shortcodes
		$this->loader->add_action( 'init', $plugin_public, 'add_shortcodes' );
		
		// AJAX handlers for public
		$this->loader->add_action( 'wp_ajax_wp_breach_report_security_issue', $plugin_public, 'handle_public_ajax' );
		$this->loader->add_action( 'wp_ajax_nopriv_wp_breach_report_security_issue', $plugin_public, 'handle_public_ajax' );
	}

	/**
	 * Register all database-related hooks.
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function define_database_hooks() {
		// Check for database updates
		$this->loader->add_action( 'init', $this, 'check_database_version' );
	}

	/**
	 * Plugin activation handler.
	 *
	 * @since    1.0.0
	 */
	public function activate_plugin() {
		$database = new WP_Breach_Database();
		$database->create_tables();
		
		// Initialize default settings
		$settings_model = $database->get_settings_model();
		$settings_model->initialize_default_settings();
		
		// Set database version
		$database->update_migration_version( $database->get_db_version() );
		
		// Create default scheduled events
		if ( ! wp_next_scheduled( 'wp_breach_daily_scan' ) ) {
			wp_schedule_event( time(), 'daily', 'wp_breach_daily_scan' );
		}
		
		if ( ! wp_next_scheduled( 'wp_breach_cleanup' ) ) {
			wp_schedule_event( time(), 'weekly', 'wp_breach_cleanup' );
		}
	}

	/**
	 * Plugin deactivation handler.
	 *
	 * @since    1.0.0
	 */
	public function deactivate_plugin() {
		// Clear scheduled events
		wp_clear_scheduled_hook( 'wp_breach_daily_scan' );
		wp_clear_scheduled_hook( 'wp_breach_cleanup' );
	}

	/**
	 * Check database version and run migrations if needed.
	 *
	 * @since    1.0.0
	 */
	public function check_database_version() {
		$database = new WP_Breach_Database();
		$current_version = $database->get_migration_version();
		$required_version = $database->get_db_version();
		
		if ( version_compare( $current_version, $required_version, '<' ) ) {
			// Run database migrations
			$database->create_tables();
			
			// Run specific migrations
			$this->run_database_migrations( $current_version, $required_version );
			
			$database->update_migration_version( $required_version );
		}
	}

	/**
	 * Run database migrations based on version.
	 *
	 * @since    1.0.0
	 * @param    string   $from_version    The current version.
	 * @param    string   $to_version      The target version.
	 */
	private function run_database_migrations( $from_version, $to_version ) {
		// Migration from 1.0.0 to 1.0.1 - Add false_positive column
		if ( version_compare( $from_version, '1.0.1', '<' ) && version_compare( $to_version, '1.0.1', '>=' ) ) {
			$migration_file = WP_BREACH_PLUGIN_DIR . 'includes/database/migrations/add-false-positive-column.php';
			if ( file_exists( $migration_file ) ) {
				$result = include $migration_file;
				if ( is_array( $result ) && ! $result['success'] ) {
					error_log( 'WP-Breach Migration Failed: ' . $result['message'] );
				}
			}
		}

		// Migration for Issue #010 - User Management and Permissions System
		$migration_010_status = get_option( 'wp_breach_migration_010_status', 'pending' );
		if ( $migration_010_status !== 'completed' ) {
			$migration_file = WP_BREACH_PLUGIN_DIR . 'includes/migrations/class-wp-breach-migration-010-user-management.php';
			if ( file_exists( $migration_file ) ) {
				require_once $migration_file;
				$migration = new WP_Breach_Migration_010_User_Management();
				$result = $migration->up();
				if ( ! $result ) {
					error_log( 'WP-Breach Migration 010 Failed: User Management System migration failed' );
				} else {
					error_log( 'WP-Breach Migration 010 Completed: User Management System migration successful' );
				}
			}
		}
	}

	/**
	 * Get database instance.
	 *
	 * @since    1.0.0
	 * @return   WP_Breach_Database    The database instance.
	 */
	public function get_database() {
		static $database = null;
		
		if ( $database === null ) {
			$database = new WP_Breach_Database();
		}
		
		return $database;
	}

	/**
	 * Load user management classes and dependencies
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function load_user_management_classes() {
		// Load permissions manager
		require_once WP_BREACH_PLUGIN_DIR . 'includes/permissions/class-wp-breach-permissions-manager.php';
		
		// Load audit logger
		require_once WP_BREACH_PLUGIN_DIR . 'includes/permissions/class-wp-breach-audit-logger.php';
		
		// Load capability checker
		require_once WP_BREACH_PLUGIN_DIR . 'includes/permissions/class-wp-breach-capability-checker.php';
		
		// Load user management admin
		require_once WP_BREACH_PLUGIN_DIR . 'admin/class-wp-breach-user-management-admin.php';
	}

	/**
	 * Define user management and permissions system hooks
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function define_user_management_hooks() {
		// Initialize permissions manager
		$permissions_manager = new WP_Breach_Permissions_Manager();
		$this->loader->add_action( 'init', $permissions_manager, 'init' );
		
		// Initialize audit logger
		$audit_logger = new WP_Breach_Audit_Logger();
		$this->loader->add_action( 'init', $audit_logger, 'init' );
		
		// Initialize capability checker
		$capability_checker = new WP_Breach_Capability_Checker();
		$this->loader->add_action( 'init', $capability_checker, 'init' );
		
		// Initialize user management admin
		$user_management_admin = new WP_Breach_User_Management_Admin( $this->get_plugin_name(), $this->get_version() );
		$this->loader->add_action( 'admin_menu', $user_management_admin, 'add_menu_pages' );
		$this->loader->add_action( 'admin_enqueue_scripts', $user_management_admin, 'enqueue_scripts' );
		$this->loader->add_action( 'admin_enqueue_scripts', $user_management_admin, 'enqueue_styles' );
		
		// User management AJAX handlers
		$this->loader->add_action( 'wp_ajax_wp_breach_get_users', $user_management_admin, 'handle_ajax_get_users' );
		$this->loader->add_action( 'wp_ajax_wp_breach_assign_role', $user_management_admin, 'handle_ajax_assign_role' );
		$this->loader->add_action( 'wp_ajax_wp_breach_remove_role', $user_management_admin, 'handle_ajax_remove_role' );
		$this->loader->add_action( 'wp_ajax_wp_breach_toggle_user_status', $user_management_admin, 'handle_ajax_toggle_user_status' );
		$this->loader->add_action( 'wp_ajax_wp_breach_bulk_user_action', $user_management_admin, 'handle_ajax_bulk_user_action' );
		$this->loader->add_action( 'wp_ajax_wp_breach_get_audit_logs', $user_management_admin, 'handle_ajax_get_audit_logs' );
		$this->loader->add_action( 'wp_ajax_wp_breach_export_audit_logs', $user_management_admin, 'handle_ajax_export_audit_logs' );
		$this->loader->add_action( 'wp_ajax_wp_breach_create_delegation', $user_management_admin, 'handle_ajax_create_delegation' );
		$this->loader->add_action( 'wp_ajax_wp_breach_revoke_delegation', $user_management_admin, 'handle_ajax_revoke_delegation' );
		$this->loader->add_action( 'wp_ajax_wp_breach_get_delegations', $user_management_admin, 'handle_ajax_get_delegations' );
		$this->loader->add_action( 'wp_ajax_wp_breach_save_user_management_settings', $user_management_admin, 'handle_ajax_save_settings' );
	}

	/**
	 * Run the loader to execute all of the hooks with WordPress.
	 *
	 * @since    1.0.0
	 */
	public function run() {
		$this->loader->run();
	}

	/**
	 * Load scanner classes and dependencies
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function load_scanner_classes() {
		// Load scanner interface
		require_once WP_BREACH_PLUGIN_DIR . 'includes/scanners/interface-wp-breach-scanner.php';
		
		// Load scanner utilities
		require_once WP_BREACH_PLUGIN_DIR . 'includes/scanners/class-wp-breach-scanner-progress.php';
		require_once WP_BREACH_PLUGIN_DIR . 'includes/scanners/class-wp-breach-scanner-factory.php';
		
		// Load main scanner
		require_once WP_BREACH_PLUGIN_DIR . 'includes/scanners/class-wp-breach-scanner.php';
		
		// Load individual scanners
		require_once WP_BREACH_PLUGIN_DIR . 'includes/scanners/class-wp-breach-core-scanner.php';
		require_once WP_BREACH_PLUGIN_DIR . 'includes/scanners/class-wp-breach-plugin-scanner.php';
		
		// Load detectors
		require_once WP_BREACH_PLUGIN_DIR . 'includes/scanners/detectors/class-wp-breach-sql-injection-detector.php';
		require_once WP_BREACH_PLUGIN_DIR . 'includes/scanners/detectors/class-wp-breach-xss-detector.php';
	}

	/**
	 * The name of the plugin used to uniquely identify it within the context of
	 * WordPress and to define internationalization functionality.
	 *
	 * @since     1.0.0
	 * @return    string    The name of the plugin.
	 */
	public function get_plugin_name() {
		return $this->plugin_name;
	}

	/**
	 * The reference to the class that orchestrates the hooks with the plugin.
	 *
	 * @since     1.0.0
	 * @return    WP_Breach_Loader    Orchestrates the hooks of the plugin.
	 */
	public function get_loader() {
		return $this->loader;
	}

	/**
	 * Retrieve the version number of the plugin.
	 *
	 * @since     1.0.0
	 * @return    string    The version number of the plugin.
	 */
	public function get_version() {
		return $this->version;
	}
}

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
		// Initialize database on plugin activation
		register_activation_hook( WP_BREACH_PLUGIN_FILE, array( $this, 'activate_plugin' ) );
		
		// Clean up database on plugin deactivation
		register_deactivation_hook( WP_BREACH_PLUGIN_FILE, array( $this, 'deactivate_plugin' ) );
		
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
			$database->update_migration_version( $required_version );
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
	 * Run the loader to execute all of the hooks with WordPress.
	 *
	 * @since    1.0.0
	 */
	public function run() {
		$this->loader->run();
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

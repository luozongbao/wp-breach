<?php
/**
 * Fired during plugin activation
 *
 * @link       https://github.com/luozongbao
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes
 */

/**
 * Fired during plugin activation.
 *
 * This class defines all code necessary to run during the plugin's activation.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes
 * @author     luozongbao <luo.zongbao@outlook.com>
 */
class WP_Breach_Activator {

	/**
	 * Short Description. (use period)
	 *
	 * Long Description.
	 *
	 * @since    1.0.0
	 */
	public static function activate() {
		// Start output buffering to prevent any unexpected output
		ob_start();
		
		try {
			// Check WordPress version
			if ( ! self::check_wordpress_version() ) {
				ob_end_clean();
				deactivate_plugins( WP_BREACH_PLUGIN_BASENAME );
				wp_die(
					esc_html__( 'WP-Breach requires WordPress 5.0 or higher. Please upgrade WordPress before activating this plugin.', 'wp-breach' ),
					esc_html__( 'Plugin Activation Error', 'wp-breach' ),
					array( 'back_link' => true )
				);
			}

			// Check PHP version
			if ( ! self::check_php_version() ) {
				ob_end_clean();
				deactivate_plugins( WP_BREACH_PLUGIN_BASENAME );
				wp_die(
					esc_html__( 'WP-Breach requires PHP 7.4 or higher. Please upgrade PHP before activating this plugin.', 'wp-breach' ),
					esc_html__( 'Plugin Activation Error', 'wp-breach' ),
					array( 'back_link' => true )
				);
			}

			// Set default options
			self::set_default_options();

			// Initialize database
			self::initialize_database();

			// Create necessary capabilities
			self::create_capabilities();

			// Schedule initial scan if needed
			self::schedule_initial_setup();

			// Log activation
			self::log_activation();
			
		} catch ( Exception $e ) {
			// Log error but don't output it
			error_log( 'WP-Breach: Activation failed: ' . $e->getMessage() );
		}
		
		// Clean and discard any output
		ob_end_clean();
	}

	/**
	 * Check if WordPress version meets minimum requirements
	 *
	 * @since    1.0.0
	 * @return   bool
	 */
	private static function check_wordpress_version() {
		global $wp_version;
		return version_compare( $wp_version, '5.0', '>=' );
	}

	/**
	 * Check if PHP version meets minimum requirements
	 *
	 * @since    1.0.0
	 * @return   bool
	 */
	private static function check_php_version() {
		return version_compare( PHP_VERSION, '7.4', '>=' );
	}

	/**
	 * Set default plugin options
	 *
	 * @since    1.0.0
	 */
	private static function set_default_options() {
		$default_options = array(
			'wp_breach_version'          => WP_BREACH_VERSION,
			'wp_breach_first_activation' => current_time( 'timestamp' ),
			'wp_breach_security_level'   => 'standard',
			'wp_breach_debug_mode'       => false,
			'wp_breach_data_retention'   => 90, // days
		);

		foreach ( $default_options as $option_name => $option_value ) {
			if ( ! get_option( $option_name ) ) {
				add_option( $option_name, $option_value );
			}
		}
	}

	/**
	 * Create custom capabilities for the plugin
	 *
	 * @since    1.0.0
	 */
	private static function create_capabilities() {
		// Get administrator role
		$admin_role = get_role( 'administrator' );

		if ( $admin_role ) {
			// Add basic capabilities to administrator
			$admin_role->add_cap( 'wp_breach_run_scans' );
			$admin_role->add_cap( 'wp_breach_view_vulnerabilities' );
			$admin_role->add_cap( 'wp_breach_apply_fixes' );
			$admin_role->add_cap( 'wp_breach_manage_settings' );
			$admin_role->add_cap( 'wp_breach_view_reports' );
			$admin_role->add_cap( 'wp_breach_manage_users' );
		}
	}

	/**
	 * Schedule initial setup tasks
	 *
	 * @since    1.0.0
	 */
	private static function schedule_initial_setup() {
		// Schedule first scan for 5 minutes after activation
		if ( ! wp_next_scheduled( 'wp_breach_initial_scan' ) ) {
			wp_schedule_single_event( time() + 300, 'wp_breach_initial_scan' );
		}
	}

	/**
	 * Initialize database tables and settings
	 *
	 * @since    1.0.0
	 */
	private static function initialize_database() {
		// Start output buffering to prevent unexpected output during activation
		ob_start();
		
		try {
			// Load database class
			require_once WP_BREACH_PLUGIN_DIR . 'includes/class-wp-breach-database.php';
			
			$database = new WP_Breach_Database();
			
			// Create database tables (only if they don't exist)
			$database->create_tables();
			
			// Skip settings initialization during activation to prevent output
			// Settings will be initialized on first admin page load
			
			// Set database version
			$database->update_migration_version( $database->get_db_version() );
			
			// Create default scheduled events
			if ( ! wp_next_scheduled( 'wp_breach_daily_scan' ) ) {
				wp_schedule_event( time(), 'daily', 'wp_breach_daily_scan' );
			}
			
			if ( ! wp_next_scheduled( 'wp_breach_cleanup' ) ) {
				wp_schedule_event( time(), 'weekly', 'wp_breach_cleanup' );
			}
			
		} catch ( Exception $e ) {
			// Log any errors but don't output them
			error_log( 'WP-Breach: Database initialization failed: ' . $e->getMessage() );
		}
		
		// Clean and discard any output that was generated
		ob_end_clean();
	}

	/**
	 * Log plugin activation
	 *
	 * @since    1.0.0
	 */
	private static function log_activation() {
		if ( function_exists( 'error_log' ) ) {
			error_log( 'WP-Breach Plugin Activated - Version: ' . WP_BREACH_VERSION . ' - Time: ' . current_time( 'mysql' ) );
		}

		// Store activation log in database for future reference
		$activation_log = array(
			'version'    => WP_BREACH_VERSION,
			'time'       => current_time( 'mysql' ),
			'user_id'    => get_current_user_id(),
			'user_login' => wp_get_current_user()->user_login,
			'ip_address' => self::get_user_ip(),
		);

		update_option( 'wp_breach_last_activation', $activation_log );
	}

	/**
	 * Get user IP address
	 *
	 * @since    1.0.0
	 * @return   string
	 */
	private static function get_user_ip() {
		if ( ! empty( $_SERVER['HTTP_CLIENT_IP'] ) ) {
			$ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CLIENT_IP'] ) );
		} elseif ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			$ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) );
		} else {
			$ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ?? '' ) );
		}

		return $ip;
	}
}

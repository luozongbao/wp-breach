<?php

/**
 * Fired when the plugin is uninstalled.
 *
 * When populating this file, consider the following flow
 * of control:
 *
 * - This method should be static
 * - Check if the $_REQUEST content actually is the plugin name
 * - Run an admin referrer check to make sure it goes through authentication
 * - Verify the output of $_GET makes sense
 * - Repeat with other user roles. Best directly by using the links/query string parameters.
 * - Repeat things for multisite. Once for a single site in the network, once sitewide.
 *
 * This file may be updated more in future version of the WP-Breach Plugin; however, this is a good place
 * to put uninstall functionality.
 *
 * @link       https://github.com/luozongbao
 * @since      1.0.0
 *
 * @package    WP_Breach
 */

// If uninstall not called from WordPress, then exit.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

/**
 * WP-Breach Plugin Uninstaller
 *
 * Removes all plugin data including database tables, options, and files
 * when the plugin is deleted (not just deactivated).
 *
 * @since    1.0.0
 */
class WP_Breach_Uninstaller {

	/**
	 * Run the uninstall process
	 *
	 * @since    1.0.0
	 */
	public static function uninstall() {
		// Load plugin constants if not already loaded
		if ( ! defined( 'WP_BREACH_PLUGIN_DIR' ) ) {
			define( 'WP_BREACH_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
		}

		// Check user permissions
		if ( ! current_user_can( 'activate_plugins' ) ) {
			return;
		}

		// Check if we're on the correct plugin
		$plugin = isset( $_REQUEST['plugin'] ) ? $_REQUEST['plugin'] : '';
		if ( $plugin !== 'wp-breach/wp-breach.php' ) {
			return;
		}

		// Verify nonce for security
		check_admin_referer( 'bulk-plugins' );

		// Load database class
		self::load_database_class();

		// Remove all database tables
		self::remove_database_tables();

		// Remove all plugin options
		self::remove_plugin_options();

		// Remove scheduled events
		self::remove_scheduled_events();

		// Remove user meta data
		self::remove_user_meta();

		// Remove transients
		self::remove_transients();

		// Remove uploaded files and directories
		self::remove_uploaded_files();

		// Log uninstall completion
		error_log( 'WP-Breach: Plugin uninstalled successfully - ' . current_time( 'mysql' ) );
	}

	/**
	 * Load database class for table removal
	 *
	 * @since    1.0.0
	 */
	private static function load_database_class() {
		$database_file = WP_BREACH_PLUGIN_DIR . 'includes/class-wp-breach-database.php';
		if ( file_exists( $database_file ) ) {
			require_once $database_file;
		}
	}

	/**
	 * Remove all WP-Breach database tables
	 *
	 * @since    1.0.0
	 */
	private static function remove_database_tables() {
		global $wpdb;

		// Try to use the database class first
		if ( class_exists( 'WP_Breach_Database' ) ) {
			try {
				$database = new WP_Breach_Database();
				$database->drop_tables();
				return;
			} catch ( Exception $e ) {
				error_log( 'WP-Breach Uninstall: Database class failed, using manual removal: ' . $e->getMessage() );
			}
		}

		// Manual table removal as fallback
		$tables = array(
			$wpdb->prefix . 'breach_scans',
			$wpdb->prefix . 'breach_vulnerabilities',
			$wpdb->prefix . 'breach_fixes',
			$wpdb->prefix . 'breach_settings',
			$wpdb->prefix . 'breach_schedules',
			$wpdb->prefix . 'breach_alerts',
			$wpdb->prefix . 'breach_monitoring',
			$wpdb->prefix . 'breach_vulnerability_db',
			$wpdb->prefix . 'breach_scan_logs',
			$wpdb->prefix . 'breach_reports',
			$wpdb->prefix . 'breach_user_preferences',
		);

		foreach ( $tables as $table ) {
			$wpdb->query( "DROP TABLE IF EXISTS `{$table}`" );
		}
	}

	/**
	 * Remove all plugin options
	 *
	 * @since    1.0.0
	 */
	private static function remove_plugin_options() {
		// Core plugin options
		delete_option( 'wp_breach_db_version' );
		delete_option( 'wp_breach_version' );
		delete_option( 'wp_breach_settings' );
		delete_option( 'wp_breach_scan_settings' );
		delete_option( 'wp_breach_notification_settings' );
		delete_option( 'wp_breach_advanced_settings' );
		delete_option( 'wp_breach_license_key' );
		delete_option( 'wp_breach_license_status' );
		delete_option( 'wp_breach_last_scan' );
		delete_option( 'wp_breach_scan_statistics' );
		delete_option( 'wp_breach_installation_date' );
		delete_option( 'wp_breach_data_retention' );

		// Remove any options that start with 'wp_breach_'
		global $wpdb;
		$wpdb->query( 
			$wpdb->prepare(
				"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s",
				'wp_breach_%'
			)
		);

		// Remove from multisite if applicable
		if ( is_multisite() ) {
			delete_site_option( 'wp_breach_network_settings' );
			delete_site_option( 'wp_breach_network_license' );
			
			$wpdb->query(
				$wpdb->prepare(
					"DELETE FROM {$wpdb->sitemeta} WHERE meta_key LIKE %s",
					'wp_breach_%'
				)
			);
		}
	}

	/**
	 * Remove scheduled events
	 *
	 * @since    1.0.0
	 */
	private static function remove_scheduled_events() {
		// Remove scheduled scans
		wp_clear_scheduled_hook( 'wp_breach_daily_scan' );
		wp_clear_scheduled_hook( 'wp_breach_weekly_scan' );
		wp_clear_scheduled_hook( 'wp_breach_monthly_scan' );
		
		// Remove cleanup events
		wp_clear_scheduled_hook( 'wp_breach_cleanup' );
		wp_clear_scheduled_hook( 'wp_breach_data_cleanup' );
		
		// Remove monitoring events
		wp_clear_scheduled_hook( 'wp_breach_monitoring_check' );
		wp_clear_scheduled_hook( 'wp_breach_integrity_check' );
		
		// Remove notification events
		wp_clear_scheduled_hook( 'wp_breach_send_notifications' );
		wp_clear_scheduled_hook( 'wp_breach_digest_email' );

		// Remove any other wp_breach_ scheduled events
		global $wpdb;
		$events = $wpdb->get_results(
			"SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE '_cron%'"
		);

		foreach ( $events as $event ) {
			$cron_data = get_option( $event->option_name );
			if ( is_array( $cron_data ) ) {
				foreach ( $cron_data as $timestamp => $cron_array ) {
					if ( is_array( $cron_array ) ) {
						foreach ( $cron_array as $hook => $details ) {
							if ( strpos( $hook, 'wp_breach_' ) === 0 ) {
								wp_clear_scheduled_hook( $hook );
							}
						}
					}
				}
			}
		}
	}

	/**
	 * Remove user meta data
	 *
	 * @since    1.0.0
	 */
	private static function remove_user_meta() {
		global $wpdb;

		// Remove user preferences and settings
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE %s",
				'wp_breach_%'
			)
		);

		// Specific user meta keys
		delete_metadata( 'user', 0, 'wp_breach_user_preferences', '', true );
		delete_metadata( 'user', 0, 'wp_breach_last_login', '', true );
		delete_metadata( 'user', 0, 'wp_breach_notification_settings', '', true );
		delete_metadata( 'user', 0, 'wp_breach_dashboard_widgets', '', true );
	}

	/**
	 * Remove transients and cached data
	 *
	 * @since    1.0.0
	 */
	private static function remove_transients() {
		global $wpdb;

		// Remove transients
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
				'_transient_wp_breach_%',
				'_transient_timeout_wp_breach_%'
			)
		);

		// Remove site transients (multisite)
		if ( is_multisite() ) {
			$wpdb->query(
				$wpdb->prepare(
					"DELETE FROM {$wpdb->sitemeta} WHERE meta_key LIKE %s OR meta_key LIKE %s",
					'_site_transient_wp_breach_%',
					'_site_transient_timeout_wp_breach_%'
				)
			);
		}

		// Clear object cache
		wp_cache_flush();
	}

	/**
	 * Remove uploaded files and directories
	 *
	 * @since    1.0.0
	 */
	private static function remove_uploaded_files() {
		$upload_dir = wp_upload_dir();
		$wp_breach_dir = $upload_dir['basedir'] . '/wp-breach-backups/';

		// Remove backup directory
		if ( is_dir( $wp_breach_dir ) ) {
			self::delete_directory( $wp_breach_dir );
		}

		// Remove any wp-breach files in uploads
		$wp_breach_files = glob( $upload_dir['basedir'] . '/wp-breach-*' );
		foreach ( $wp_breach_files as $file ) {
			if ( is_file( $file ) ) {
				unlink( $file );
			} elseif ( is_dir( $file ) ) {
				self::delete_directory( $file );
			}
		}
	}

	/**
	 * Recursively delete a directory
	 *
	 * @since    1.0.0
	 * @param    string   $dir    Directory path to delete
	 * @return   bool             Success status
	 */
	private static function delete_directory( $dir ) {
		if ( ! is_dir( $dir ) ) {
			return false;
		}

		$files = array_diff( scandir( $dir ), array( '.', '..' ) );
		
		foreach ( $files as $file ) {
			$path = $dir . DIRECTORY_SEPARATOR . $file;
			if ( is_dir( $path ) ) {
				self::delete_directory( $path );
			} else {
				unlink( $path );
			}
		}

		return rmdir( $dir );
	}

	/**
	 * Perform final cleanup and verification
	 *
	 * @since    1.0.0
	 */
	private static function final_cleanup() {
		global $wpdb;

		// Verify all tables are removed
		$remaining_tables = $wpdb->get_results(
			"SHOW TABLES LIKE '{$wpdb->prefix}breach_%'"
		);

		if ( ! empty( $remaining_tables ) ) {
			error_log( 'WP-Breach Uninstall Warning: Some tables may not have been removed completely' );
		}

		// Verify all options are removed
		$remaining_options = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE %s",
				'wp_breach_%'
			)
		);

		if ( $remaining_options > 0 ) {
			error_log( "WP-Breach Uninstall Warning: {$remaining_options} options may not have been removed completely" );
		}

		// Final cache clear
		wp_cache_flush();
	}
}

// Run the uninstall process
WP_Breach_Uninstaller::uninstall();

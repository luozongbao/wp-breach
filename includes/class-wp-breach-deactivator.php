<?php
/**
 * Fired during plugin deactivation
 *
 * @link       https://github.com/luozongbao
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes
 */

/**
 * Fired during plugin deactivation.
 *
 * This class defines all code necessary to run during the plugin's deactivation.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes
 * @author     luozongbao <luo.zongbao@outlook.com>
 */
class WP_Breach_Deactivator {

	/**
	 * Short Description. (use period)
	 *
	 * Long Description.
	 *
	 * @since    1.0.0
	 */
	public static function deactivate() {
		// Clear scheduled events
		self::clear_scheduled_events();

		// Clean up temporary data
		self::cleanup_temporary_data();

		// Log deactivation
		self::log_deactivation();

		// Send notification if enabled
		self::send_deactivation_notification();
	}

	/**
	 * Clear all scheduled events
	 *
	 * @since    1.0.0
	 */
	private static function clear_scheduled_events() {
		// Clear all WP-Breach scheduled events
		$scheduled_hooks = array(
			'wp_breach_daily_scan',
			'wp_breach_weekly_report',
			'wp_breach_monthly_cleanup',
			'wp_breach_initial_scan',
			'wp_breach_vulnerability_check',
			'wp_breach_auto_fix_check',
		);

		foreach ( $scheduled_hooks as $hook ) {
			$timestamp = wp_next_scheduled( $hook );
			if ( $timestamp ) {
				wp_unschedule_event( $timestamp, $hook );
			}
		}

		// Clear any custom recurring schedules
		wp_clear_scheduled_hook( 'wp_breach_daily_scan' );
		wp_clear_scheduled_hook( 'wp_breach_weekly_report' );
		wp_clear_scheduled_hook( 'wp_breach_monthly_cleanup' );
	}

	/**
	 * Clean up temporary data
	 *
	 * @since    1.0.0
	 */
	private static function cleanup_temporary_data() {
		// Clean up temporary scan files
		$upload_dir = wp_upload_dir();
		$temp_dir = $upload_dir['basedir'] . '/wp-breach-temp/';

		if ( is_dir( $temp_dir ) ) {
			self::delete_directory( $temp_dir );
		}

		// Clean up transients
		self::cleanup_transients();

		// Clean up temporary options
		self::cleanup_temporary_options();
	}

	/**
	 * Recursively delete a directory
	 *
	 * @since    1.0.0
	 * @param    string $dir Directory path to delete
	 */
	private static function delete_directory( $dir ) {
		if ( ! is_dir( $dir ) ) {
			return;
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

		rmdir( $dir );
	}

	/**
	 * Clean up plugin transients
	 *
	 * @since    1.0.0
	 */
	private static function cleanup_transients() {
		global $wpdb;

		// Delete all transients with wp_breach prefix
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->options} 
				WHERE option_name LIKE %s 
				OR option_name LIKE %s",
				'_transient_wp_breach_%',
				'_transient_timeout_wp_breach_%'
			)
		);
	}

	/**
	 * Clean up temporary options
	 *
	 * @since    1.0.0
	 */
	private static function cleanup_temporary_options() {
		$temp_options = array(
			'wp_breach_scan_in_progress',
			'wp_breach_temp_scan_data',
			'wp_breach_last_scan_log',
			'wp_breach_processing_queue',
		);

		foreach ( $temp_options as $option ) {
			delete_option( $option );
		}
	}

	/**
	 * Log plugin deactivation
	 *
	 * @since    1.0.0
	 */
	private static function log_deactivation() {
		if ( function_exists( 'error_log' ) ) {
			error_log( 'WP-Breach Plugin Deactivated - Version: ' . WP_BREACH_VERSION . ' - Time: ' . current_time( 'mysql' ) );
		}

		// Store deactivation log in database
		$deactivation_log = array(
			'version'    => WP_BREACH_VERSION,
			'time'       => current_time( 'mysql' ),
			'user_id'    => get_current_user_id(),
			'user_login' => wp_get_current_user()->user_login,
			'ip_address' => self::get_user_ip(),
			'reason'     => self::get_deactivation_reason(),
		);

		update_option( 'wp_breach_last_deactivation', $deactivation_log );

		// Add to deactivation history
		$history = get_option( 'wp_breach_deactivation_history', array() );
		$history[] = $deactivation_log;

		// Keep only last 10 deactivation records
		if ( count( $history ) > 10 ) {
			$history = array_slice( $history, -10 );
		}

		update_option( 'wp_breach_deactivation_history', $history );
	}

	/**
	 * Send deactivation notification if enabled
	 *
	 * @since    1.0.0
	 */
	private static function send_deactivation_notification() {
		$notification_enabled = get_option( 'wp_breach_deactivation_notification', false );

		if ( ! $notification_enabled ) {
			return;
		}

		$admin_email = get_option( 'admin_email' );
		$site_name = get_bloginfo( 'name' );
		$site_url = get_site_url();

		$subject = sprintf(
			/* translators: %s: Site name */
			__( 'WP-Breach Security Plugin Deactivated on %s', 'wp-breach' ),
			$site_name
		);

		$message = sprintf(
			/* translators: %1$s: Site name, %2$s: Site URL, %3$s: Current time, %4$s: User login */
			__(
				'The WP-Breach security plugin has been deactivated on %1$s (%2$s).

Deactivation Details:
- Time: %3$s
- User: %4$s
- Version: %5$s

Please ensure your website security is maintained through alternative measures.

If this deactivation was unexpected, please check your website for any security issues.',
				'wp-breach'
			),
			$site_name,
			$site_url,
			current_time( 'mysql' ),
			wp_get_current_user()->user_login,
			WP_BREACH_VERSION
		);

		wp_mail( $admin_email, $subject, $message );
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

	/**
	 * Get deactivation reason from user input or context
	 *
	 * @since    1.0.0
	 * @return   string
	 */
	private static function get_deactivation_reason() {
		// This could be enhanced with a deactivation survey
		// For now, just return a generic reason
		return 'Manual deactivation by user';
	}
}

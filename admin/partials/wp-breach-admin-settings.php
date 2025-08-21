<?php
/**
 * Provide a admin area view for plugin settings
 *
 * This file is used to markup the settings page of the plugin.
 *
 * @link       https://github.com/luozongbao
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/admin/partials
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
	die;
}

// Get the database instance
$database = ( new WP_Breach() )->get_database();
$settings_model = $database->get_settings_model();

// Get current settings
$settings = $settings_model->get_all_settings();

// Handle form submission
if ( isset( $_POST['wp_breach_save_settings'] ) && wp_verify_nonce( $_POST['wp_breach_settings_nonce'], 'wp_breach_save_settings' ) ) {
	// Process settings update
	$updated_settings = array();
	
	// Scan settings
	$updated_settings['scan_frequency'] = sanitize_text_field( $_POST['scan_frequency'] ?? 'weekly' );
	$updated_settings['auto_scan_enabled'] = isset( $_POST['auto_scan_enabled'] ) ? 1 : 0;
	$updated_settings['scan_types'] = isset( $_POST['scan_types'] ) ? array_map( 'sanitize_text_field', $_POST['scan_types'] ) : array();
	$updated_settings['max_scan_duration'] = intval( $_POST['max_scan_duration'] ?? 300 );
	
	// Notification settings
	$updated_settings['email_notifications'] = isset( $_POST['email_notifications'] ) ? 1 : 0;
	$updated_settings['notification_email'] = sanitize_email( $_POST['notification_email'] ?? get_option( 'admin_email' ) );
	$updated_settings['critical_alerts'] = isset( $_POST['critical_alerts'] ) ? 1 : 0;
	$updated_settings['weekly_reports'] = isset( $_POST['weekly_reports'] ) ? 1 : 0;
	
	// Security settings
	$updated_settings['auto_fix_enabled'] = isset( $_POST['auto_fix_enabled'] ) ? 1 : 0;
	$updated_settings['quarantine_files'] = isset( $_POST['quarantine_files'] ) ? 1 : 0;
	$updated_settings['block_suspicious_requests'] = isset( $_POST['block_suspicious_requests'] ) ? 1 : 0;
	$updated_settings['security_headers'] = isset( $_POST['security_headers'] ) ? 1 : 0;
	
	// Advanced settings
	$updated_settings['debug_mode'] = isset( $_POST['debug_mode'] ) ? 1 : 0;
	$updated_settings['log_retention_days'] = intval( $_POST['log_retention_days'] ?? 30 );
	$updated_settings['api_rate_limit'] = intval( $_POST['api_rate_limit'] ?? 100 );
	
	// Update settings
	foreach ( $updated_settings as $key => $value ) {
		$settings_model->update_setting( $key, $value );
	}
	
	// Show success message
	echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Settings saved successfully!', 'wp-breach' ) . '</p></div>';
	
	// Refresh settings
	$settings = $settings_model->get_all_settings();
}

?>

<div class="wrap wp-breach-settings">
	<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>
	
	<form method="post" action="">
		<?php wp_nonce_field( 'wp_breach_save_settings', 'wp_breach_settings_nonce' ); ?>
		
		<div class="wp-breach-settings-tabs">
			<nav class="nav-tab-wrapper">
				<a href="#scan-settings" class="nav-tab nav-tab-active"><?php esc_html_e( 'Scan Settings', 'wp-breach' ); ?></a>
				<a href="#notifications" class="nav-tab"><?php esc_html_e( 'Notifications', 'wp-breach' ); ?></a>
				<a href="#security" class="nav-tab"><?php esc_html_e( 'Security', 'wp-breach' ); ?></a>
				<a href="#advanced" class="nav-tab"><?php esc_html_e( 'Advanced', 'wp-breach' ); ?></a>
			</nav>
		</div>

		<!-- Scan Settings Tab -->
		<div id="scan-settings" class="wp-breach-tab-content wp-breach-tab-active">
			<table class="form-table">
				<tr>
					<th scope="row">
						<label for="auto_scan_enabled"><?php esc_html_e( 'Automatic Scanning', 'wp-breach' ); ?></label>
					</th>
					<td>
						<label>
							<input type="checkbox" id="auto_scan_enabled" name="auto_scan_enabled" value="1" <?php checked( $settings['auto_scan_enabled'] ?? 0, 1 ); ?>>
							<?php esc_html_e( 'Enable automatic security scans', 'wp-breach' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'Automatically run security scans based on the schedule below.', 'wp-breach' ); ?></p>
					</td>
				</tr>
				
				<tr>
					<th scope="row">
						<label for="scan_frequency"><?php esc_html_e( 'Scan Frequency', 'wp-breach' ); ?></label>
					</th>
					<td>
						<select id="scan_frequency" name="scan_frequency">
							<option value="hourly" <?php selected( $settings['scan_frequency'] ?? 'weekly', 'hourly' ); ?>><?php esc_html_e( 'Hourly', 'wp-breach' ); ?></option>
							<option value="twicedaily" <?php selected( $settings['scan_frequency'] ?? 'weekly', 'twicedaily' ); ?>><?php esc_html_e( 'Twice Daily', 'wp-breach' ); ?></option>
							<option value="daily" <?php selected( $settings['scan_frequency'] ?? 'weekly', 'daily' ); ?>><?php esc_html_e( 'Daily', 'wp-breach' ); ?></option>
							<option value="weekly" <?php selected( $settings['scan_frequency'] ?? 'weekly', 'weekly' ); ?>><?php esc_html_e( 'Weekly', 'wp-breach' ); ?></option>
							<option value="monthly" <?php selected( $settings['scan_frequency'] ?? 'weekly', 'monthly' ); ?>><?php esc_html_e( 'Monthly', 'wp-breach' ); ?></option>
						</select>
						<p class="description"><?php esc_html_e( 'How often automatic scans should be performed.', 'wp-breach' ); ?></p>
					</td>
				</tr>
				
				<tr>
					<th scope="row">
						<label><?php esc_html_e( 'Scan Types', 'wp-breach' ); ?></label>
					</th>
					<td>
						<fieldset>
							<?php
							$scan_types = array(
								'core' => __( 'WordPress Core Files', 'wp-breach' ),
								'plugins' => __( 'Plugin Files', 'wp-breach' ),
								'themes' => __( 'Theme Files', 'wp-breach' ),
								'uploads' => __( 'Upload Directory', 'wp-breach' ),
								'database' => __( 'Database Security', 'wp-breach' ),
								'configuration' => __( 'Configuration Settings', 'wp-breach' ),
							);
							$selected_types = $settings['scan_types'] ?? array_keys( $scan_types );
							
							foreach ( $scan_types as $type => $label ) :
							?>
								<label>
									<input type="checkbox" name="scan_types[]" value="<?php echo esc_attr( $type ); ?>" <?php checked( in_array( $type, $selected_types ) ); ?>>
									<?php echo esc_html( $label ); ?>
								</label><br>
							<?php endforeach; ?>
						</fieldset>
						<p class="description"><?php esc_html_e( 'Select which areas of your website should be scanned.', 'wp-breach' ); ?></p>
					</td>
				</tr>
				
				<tr>
					<th scope="row">
						<label for="max_scan_duration"><?php esc_html_e( 'Maximum Scan Duration', 'wp-breach' ); ?></label>
					</th>
					<td>
						<input type="number" id="max_scan_duration" name="max_scan_duration" value="<?php echo esc_attr( $settings['max_scan_duration'] ?? 300 ); ?>" min="60" max="3600" step="60">
						<span><?php esc_html_e( 'seconds', 'wp-breach' ); ?></span>
						<p class="description"><?php esc_html_e( 'Maximum time in seconds that a scan should run before timing out.', 'wp-breach' ); ?></p>
					</td>
				</tr>
			</table>
		</div>

		<!-- Notifications Tab -->
		<div id="notifications" class="wp-breach-tab-content">
			<table class="form-table">
				<tr>
					<th scope="row">
						<label for="email_notifications"><?php esc_html_e( 'Email Notifications', 'wp-breach' ); ?></label>
					</th>
					<td>
						<label>
							<input type="checkbox" id="email_notifications" name="email_notifications" value="1" <?php checked( $settings['email_notifications'] ?? 1, 1 ); ?>>
							<?php esc_html_e( 'Send email notifications for security alerts', 'wp-breach' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'Enable email notifications when vulnerabilities are detected.', 'wp-breach' ); ?></p>
					</td>
				</tr>
				
				<tr>
					<th scope="row">
						<label for="notification_email"><?php esc_html_e( 'Notification Email', 'wp-breach' ); ?></label>
					</th>
					<td>
						<input type="email" id="notification_email" name="notification_email" value="<?php echo esc_attr( $settings['notification_email'] ?? get_option( 'admin_email' ) ); ?>" class="regular-text">
						<p class="description"><?php esc_html_e( 'Email address to receive security notifications.', 'wp-breach' ); ?></p>
					</td>
				</tr>
				
				<tr>
					<th scope="row">
						<label for="critical_alerts"><?php esc_html_e( 'Critical Alerts', 'wp-breach' ); ?></label>
					</th>
					<td>
						<label>
							<input type="checkbox" id="critical_alerts" name="critical_alerts" value="1" <?php checked( $settings['critical_alerts'] ?? 1, 1 ); ?>>
							<?php esc_html_e( 'Send immediate alerts for critical vulnerabilities', 'wp-breach' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'Receive immediate notifications for critical security issues.', 'wp-breach' ); ?></p>
					</td>
				</tr>
				
				<tr>
					<th scope="row">
						<label for="weekly_reports"><?php esc_html_e( 'Weekly Reports', 'wp-breach' ); ?></label>
					</th>
					<td>
						<label>
							<input type="checkbox" id="weekly_reports" name="weekly_reports" value="1" <?php checked( $settings['weekly_reports'] ?? 0, 1 ); ?>>
							<?php esc_html_e( 'Send weekly security summary reports', 'wp-breach' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'Receive weekly summaries of security scans and status.', 'wp-breach' ); ?></p>
					</td>
				</tr>
			</table>
		</div>

		<!-- Security Tab -->
		<div id="security" class="wp-breach-tab-content">
			<table class="form-table">
				<tr>
					<th scope="row">
						<label for="auto_fix_enabled"><?php esc_html_e( 'Automatic Fixes', 'wp-breach' ); ?></label>
					</th>
					<td>
						<label>
							<input type="checkbox" id="auto_fix_enabled" name="auto_fix_enabled" value="1" <?php checked( $settings['auto_fix_enabled'] ?? 0, 1 ); ?>>
							<?php esc_html_e( 'Automatically apply safe security fixes', 'wp-breach' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'Allow the plugin to automatically fix certain low-risk security issues.', 'wp-breach' ); ?></p>
					</td>
				</tr>
				
				<tr>
					<th scope="row">
						<label for="quarantine_files"><?php esc_html_e( 'File Quarantine', 'wp-breach' ); ?></label>
					</th>
					<td>
						<label>
							<input type="checkbox" id="quarantine_files" name="quarantine_files" value="1" <?php checked( $settings['quarantine_files'] ?? 1, 1 ); ?>>
							<?php esc_html_e( 'Quarantine suspicious files', 'wp-breach' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'Move potentially malicious files to a quarantine folder.', 'wp-breach' ); ?></p>
					</td>
				</tr>
				
				<tr>
					<th scope="row">
						<label for="block_suspicious_requests"><?php esc_html_e( 'Request Blocking', 'wp-breach' ); ?></label>
					</th>
					<td>
						<label>
							<input type="checkbox" id="block_suspicious_requests" name="block_suspicious_requests" value="1" <?php checked( $settings['block_suspicious_requests'] ?? 0, 1 ); ?>>
							<?php esc_html_e( 'Block suspicious HTTP requests', 'wp-breach' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'Automatically block requests that match known attack patterns.', 'wp-breach' ); ?></p>
					</td>
				</tr>
				
				<tr>
					<th scope="row">
						<label for="security_headers"><?php esc_html_e( 'Security Headers', 'wp-breach' ); ?></label>
					</th>
					<td>
						<label>
							<input type="checkbox" id="security_headers" name="security_headers" value="1" <?php checked( $settings['security_headers'] ?? 1, 1 ); ?>>
							<?php esc_html_e( 'Add security headers to HTTP responses', 'wp-breach' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'Add headers like X-Frame-Options, X-XSS-Protection, etc.', 'wp-breach' ); ?></p>
					</td>
				</tr>
			</table>
		</div>

		<!-- Advanced Tab -->
		<div id="advanced" class="wp-breach-tab-content">
			<table class="form-table">
				<tr>
					<th scope="row">
						<label for="debug_mode"><?php esc_html_e( 'Debug Mode', 'wp-breach' ); ?></label>
					</th>
					<td>
						<label>
							<input type="checkbox" id="debug_mode" name="debug_mode" value="1" <?php checked( $settings['debug_mode'] ?? 0, 1 ); ?>>
							<?php esc_html_e( 'Enable debug logging', 'wp-breach' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'Log detailed information for troubleshooting. Only enable when necessary.', 'wp-breach' ); ?></p>
					</td>
				</tr>
				
				<tr>
					<th scope="row">
						<label for="log_retention_days"><?php esc_html_e( 'Log Retention', 'wp-breach' ); ?></label>
					</th>
					<td>
						<input type="number" id="log_retention_days" name="log_retention_days" value="<?php echo esc_attr( $settings['log_retention_days'] ?? 30 ); ?>" min="1" max="365">
						<span><?php esc_html_e( 'days', 'wp-breach' ); ?></span>
						<p class="description"><?php esc_html_e( 'How long to keep scan logs and reports.', 'wp-breach' ); ?></p>
					</td>
				</tr>
				
				<tr>
					<th scope="row">
						<label for="api_rate_limit"><?php esc_html_e( 'API Rate Limit', 'wp-breach' ); ?></label>
					</th>
					<td>
						<input type="number" id="api_rate_limit" name="api_rate_limit" value="<?php echo esc_attr( $settings['api_rate_limit'] ?? 100 ); ?>" min="10" max="1000">
						<span><?php esc_html_e( 'requests per hour', 'wp-breach' ); ?></span>
						<p class="description"><?php esc_html_e( 'Maximum number of API requests to external vulnerability databases per hour.', 'wp-breach' ); ?></p>
					</td>
				</tr>
			</table>
		</div>

		<!-- Submit Button -->
		<p class="submit">
			<input type="submit" name="wp_breach_save_settings" class="button-primary" value="<?php esc_attr_e( 'Save Changes', 'wp-breach' ); ?>">
		</p>
	</form>

	<!-- System Information -->
	<div class="wp-breach-system-info">
		<h2><?php esc_html_e( 'System Information', 'wp-breach' ); ?></h2>
		<div class="wp-breach-info-grid">
			<div class="wp-breach-info-item">
				<strong><?php esc_html_e( 'Plugin Version:', 'wp-breach' ); ?></strong>
				<?php echo esc_html( WP_BREACH_VERSION ); ?>
			</div>
			<div class="wp-breach-info-item">
				<strong><?php esc_html_e( 'WordPress Version:', 'wp-breach' ); ?></strong>
				<?php echo esc_html( get_bloginfo( 'version' ) ); ?>
			</div>
			<div class="wp-breach-info-item">
				<strong><?php esc_html_e( 'PHP Version:', 'wp-breach' ); ?></strong>
				<?php echo esc_html( PHP_VERSION ); ?>
			</div>
			<div class="wp-breach-info-item">
				<strong><?php esc_html_e( 'Database Version:', 'wp-breach' ); ?></strong>
				<?php echo esc_html( $database->get_migration_version() ); ?>
			</div>
			<div class="wp-breach-info-item">
				<strong><?php esc_html_e( 'Last Scan:', 'wp-breach' ); ?></strong>
				<?php
				$scan_model = $database->get_scan_model();
				$last_scan = $scan_model->get_latest_completed_scan();
				if ( $last_scan ) {
					echo esc_html( human_time_diff( strtotime( $last_scan['completed_at'] ), current_time( 'timestamp' ) ) . ' ago' );
				} else {
					esc_html_e( 'Never', 'wp-breach' );
				}
				?>
			</div>
			<div class="wp-breach-info-item">
				<strong><?php esc_html_e( 'Next Scheduled Scan:', 'wp-breach' ); ?></strong>
				<?php
				$next_scan = wp_next_scheduled( 'wp_breach_scheduled_scan' );
				if ( $next_scan ) {
					echo esc_html( human_time_diff( current_time( 'timestamp' ), $next_scan ) . ' from now' );
				} else {
					esc_html_e( 'Not scheduled', 'wp-breach' );
				}
				?>
			</div>
		</div>
	</div>

	<!-- Tools Section -->
	<div class="wp-breach-tools">
		<h2><?php esc_html_e( 'Tools', 'wp-breach' ); ?></h2>
		<div class="wp-breach-tool-buttons">
			<a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin.php?page=wp-breach-settings&action=clear_logs' ), 'wp_breach_clear_logs' ) ); ?>" class="button" onclick="return confirm('<?php esc_attr_e( 'Are you sure you want to clear all logs?', 'wp-breach' ); ?>');">
				<?php esc_html_e( 'Clear Logs', 'wp-breach' ); ?>
			</a>
			<a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin.php?page=wp-breach-settings&action=reset_settings' ), 'wp_breach_reset_settings' ) ); ?>" class="button" onclick="return confirm('<?php esc_attr_e( 'Are you sure you want to reset all settings to defaults?', 'wp-breach' ); ?>');">
				<?php esc_html_e( 'Reset Settings', 'wp-breach' ); ?>
			</a>
			<a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin.php?page=wp-breach-settings&action=rebuild_database' ), 'wp_breach_rebuild_database' ) ); ?>" class="button" onclick="return confirm('<?php esc_attr_e( 'Are you sure you want to rebuild the database tables?', 'wp-breach' ); ?>');">
				<?php esc_html_e( 'Rebuild Database', 'wp-breach' ); ?>
			</a>
		</div>
	</div>
</div>

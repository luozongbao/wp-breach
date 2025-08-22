<?php
/**
 * Provide a admin area view for security alerts
 *
 * This file is used to markup the alerts page of the plugin.
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
$vulnerability_model = $database->get_vulnerability_model();

// Get alerts and notifications
$critical_alerts = $vulnerability_model->get_vulnerabilities_by_severity( 'critical', 10 );
$recent_alerts = $vulnerability_model->get_recent_vulnerabilities( 20 );

// Get alert statistics
$total_alerts = count( $recent_alerts );
$unread_alerts = count( array_filter( $recent_alerts, function( $alert ) {
	return ! $alert['is_read'];
} ) );

?>

<div class="wrap wp-breach-alerts">
	<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>
	
	<!-- Alert Summary -->
	<div class="wp-breach-alert-summary">
		<div class="wp-breach-summary-card wp-breach-card-critical">
			<div class="wp-breach-card-icon">
				<span class="dashicons dashicons-warning"></span>
			</div>
			<div class="wp-breach-card-content">
				<h3><?php echo esc_html( count( $critical_alerts ) ); ?></h3>
				<p><?php esc_html_e( 'Critical Alerts', 'wp-breach' ); ?></p>
			</div>
		</div>
		
		<div class="wp-breach-summary-card">
			<div class="wp-breach-card-icon">
				<span class="dashicons dashicons-bell"></span>
			</div>
			<div class="wp-breach-card-content">
				<h3><?php echo esc_html( $unread_alerts ); ?></h3>
				<p><?php esc_html_e( 'Unread Alerts', 'wp-breach' ); ?></p>
			</div>
		</div>
		
		<div class="wp-breach-summary-card">
			<div class="wp-breach-card-icon">
				<span class="dashicons dashicons-list-view"></span>
			</div>
			<div class="wp-breach-card-content">
				<h3><?php echo esc_html( $total_alerts ); ?></h3>
				<p><?php esc_html_e( 'Total Alerts', 'wp-breach' ); ?></p>
			</div>
		</div>
	</div>

	<!-- Alert Actions -->
	<div class="wp-breach-alert-actions">
		<div class="wp-breach-action-buttons">
			<button id="wp-breach-mark-all-read" class="button button-primary" <?php echo $unread_alerts === 0 ? 'disabled' : ''; ?>>
				<span class="dashicons dashicons-yes-alt"></span>
				<?php esc_html_e( 'Mark All as Read', 'wp-breach' ); ?>
			</button>
			
			<button id="wp-breach-clear-resolved" class="button button-secondary">
				<span class="dashicons dashicons-trash"></span>
				<?php esc_html_e( 'Clear Resolved Alerts', 'wp-breach' ); ?>
			</button>
			
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-breach-settings#notifications' ) ); ?>" class="button button-secondary">
				<span class="dashicons dashicons-admin-generic"></span>
				<?php esc_html_e( 'Alert Settings', 'wp-breach' ); ?>
			</a>
		</div>
	</div>

	<!-- Critical Alerts Section -->
	<?php if ( ! empty( $critical_alerts ) ) : ?>
		<div class="wp-breach-critical-alerts">
			<h2><?php esc_html_e( 'Critical Security Alerts', 'wp-breach' ); ?></h2>
			
			<div class="wp-breach-alert-list wp-breach-critical-alert-list">
				<?php foreach ( $critical_alerts as $alert ) : ?>
					<div class="wp-breach-alert-item wp-breach-alert-critical <?php echo ! $alert['is_read'] ? 'wp-breach-alert-unread' : ''; ?>">
						<div class="wp-breach-alert-icon">
							<span class="dashicons dashicons-warning"></span>
						</div>
						<div class="wp-breach-alert-content">
							<div class="wp-breach-alert-header">
								<h4><?php echo esc_html( $alert['title'] ); ?></h4>
								<span class="wp-breach-alert-time">
									<?php echo esc_html( human_time_diff( strtotime( $alert['detected_at'] ), current_time( 'timestamp' ) ) . ' ago' ); ?>
								</span>
							</div>
							<div class="wp-breach-alert-description">
								<p><?php echo esc_html( $alert['description'] ); ?></p>
							</div>
							<div class="wp-breach-alert-meta">
								<span class="wp-breach-severity wp-breach-severity-critical">
									<?php esc_html_e( 'Critical', 'wp-breach' ); ?>
								</span>
								<span class="wp-breach-alert-type">
									<?php echo esc_html( str_replace( '_', ' ', ucwords( $alert['type'], '_' ) ) ); ?>
								</span>
								<?php if ( ! empty( $alert['file_path'] ) ) : ?>
									<span class="wp-breach-alert-location">
										<?php echo esc_html( basename( $alert['file_path'] ) ); ?>
									</span>
								<?php endif; ?>
							</div>
						</div>
						<div class="wp-breach-alert-actions">
							<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-breach-vulnerabilities&vulnerability_id=' . $alert['id'] ) ); ?>" class="button button-small button-primary">
								<?php esc_html_e( 'View Details', 'wp-breach' ); ?>
							</a>
							<button class="button button-small wp-breach-mark-read" data-alert-id="<?php echo esc_attr( $alert['id'] ); ?>">
								<?php esc_html_e( 'Mark Read', 'wp-breach' ); ?>
							</button>
						</div>
					</div>
				<?php endforeach; ?>
			</div>
		</div>
	<?php endif; ?>

	<!-- All Alerts Section -->
	<div class="wp-breach-all-alerts">
		<h2><?php esc_html_e( 'Recent Security Alerts', 'wp-breach' ); ?></h2>
		
		<!-- Alert Filters -->
		<div class="wp-breach-alert-filters">
			<div class="wp-breach-filter-buttons">
				<button class="wp-breach-filter-btn wp-breach-filter-active" data-filter="all">
					<?php esc_html_e( 'All', 'wp-breach' ); ?>
				</button>
				<button class="wp-breach-filter-btn" data-filter="unread">
					<?php esc_html_e( 'Unread', 'wp-breach' ); ?>
				</button>
				<button class="wp-breach-filter-btn" data-filter="critical">
					<?php esc_html_e( 'Critical', 'wp-breach' ); ?>
				</button>
				<button class="wp-breach-filter-btn" data-filter="high">
					<?php esc_html_e( 'High', 'wp-breach' ); ?>
				</button>
			</div>
		</div>
		
		<?php if ( ! empty( $recent_alerts ) ) : ?>
			<div class="wp-breach-alert-list">
				<?php foreach ( $recent_alerts as $alert ) : ?>
					<div class="wp-breach-alert-item wp-breach-alert-<?php echo esc_attr( $alert['severity'] ); ?> <?php echo ! $alert['is_read'] ? 'wp-breach-alert-unread' : ''; ?>" 
						data-alert-id="<?php echo esc_attr( $alert['id'] ); ?>"
						data-severity="<?php echo esc_attr( $alert['severity'] ); ?>"
						data-read="<?php echo $alert['is_read'] ? 'true' : 'false'; ?>">
						
						<div class="wp-breach-alert-icon">
							<?php
							$icon = 'info';
							switch ( $alert['severity'] ) {
								case 'critical':
									$icon = 'warning';
									break;
								case 'high':
									$icon = 'flag';
									break;
								case 'medium':
									$icon = 'info';
									break;
								case 'low':
									$icon = 'admin-generic';
									break;
							}
							?>
							<span class="dashicons dashicons-<?php echo esc_attr( $icon ); ?>"></span>
						</div>
						
						<div class="wp-breach-alert-content">
							<div class="wp-breach-alert-header">
								<h4><?php echo esc_html( $alert['title'] ); ?></h4>
								<span class="wp-breach-alert-time">
									<?php echo esc_html( human_time_diff( strtotime( $alert['detected_at'] ), current_time( 'timestamp' ) ) . ' ago' ); ?>
								</span>
							</div>
							<div class="wp-breach-alert-description">
								<p><?php echo esc_html( wp_trim_words( $alert['description'], 20 ) ); ?></p>
							</div>
							<div class="wp-breach-alert-meta">
								<span class="wp-breach-severity wp-breach-severity-<?php echo esc_attr( $alert['severity'] ); ?>">
									<?php echo esc_html( ucfirst( $alert['severity'] ) ); ?>
								</span>
								<span class="wp-breach-alert-type">
									<?php echo esc_html( str_replace( '_', ' ', ucwords( $alert['type'], '_' ) ) ); ?>
								</span>
								<?php if ( ! empty( $alert['file_path'] ) ) : ?>
									<span class="wp-breach-alert-location">
										<span class="dashicons dashicons-media-code"></span>
										<?php echo esc_html( basename( $alert['file_path'] ) ); ?>
									</span>
								<?php endif; ?>
								<span class="wp-breach-alert-status">
									<?php echo esc_html( str_replace( '_', ' ', ucwords( $alert['status'], '_' ) ) ); ?>
								</span>
							</div>
						</div>
						
						<div class="wp-breach-alert-actions">
							<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-breach-vulnerabilities&vulnerability_id=' . $alert['id'] ) ); ?>" class="button button-small">
								<?php esc_html_e( 'View', 'wp-breach' ); ?>
							</a>
							
							<?php if ( ! $alert['is_read'] ) : ?>
								<button class="button button-small wp-breach-mark-read" data-alert-id="<?php echo esc_attr( $alert['id'] ); ?>">
									<?php esc_html_e( 'Mark Read', 'wp-breach' ); ?>
								</button>
							<?php endif; ?>
							
							<?php if ( $alert['status'] === 'active' ) : ?>
								<button class="button button-small wp-breach-dismiss-alert" data-alert-id="<?php echo esc_attr( $alert['id'] ); ?>">
									<?php esc_html_e( 'Dismiss', 'wp-breach' ); ?>
								</button>
							<?php endif; ?>
						</div>
					</div>
				<?php endforeach; ?>
			</div>
		<?php else : ?>
			<div class="wp-breach-no-alerts">
				<div class="wp-breach-no-data">
					<span class="dashicons dashicons-yes-alt"></span>
					<h3><?php esc_html_e( 'No Security Alerts', 'wp-breach' ); ?></h3>
					<p><?php esc_html_e( 'Great! No security alerts have been detected recently.', 'wp-breach' ); ?></p>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-breach' ) ); ?>" class="button button-primary">
						<?php esc_html_e( 'Run Security Scan', 'wp-breach' ); ?>
					</a>
				</div>
			</div>
		<?php endif; ?>
	</div>

	<!-- Alert Configuration -->
	<div class="wp-breach-alert-config">
		<h2><?php esc_html_e( 'Alert Configuration', 'wp-breach' ); ?></h2>
		
		<form method="post" action="">
			<?php wp_nonce_field( 'wp_breach_alert_config', 'wp_breach_alert_nonce' ); ?>
			
			<table class="form-table">
				<tr>
					<th scope="row">
						<label for="desktop_notifications"><?php esc_html_e( 'Desktop Notifications', 'wp-breach' ); ?></label>
					</th>
					<td>
						<label>
							<input type="checkbox" id="desktop_notifications" name="desktop_notifications" value="1">
							<?php esc_html_e( 'Show browser notifications for critical alerts', 'wp-breach' ); ?>
						</label>
					</td>
				</tr>
				
				<tr>
					<th scope="row">
						<label for="email_alerts"><?php esc_html_e( 'Email Alerts', 'wp-breach' ); ?></label>
					</th>
					<td>
						<label>
							<input type="checkbox" id="email_alerts" name="email_alerts" value="1" checked>
							<?php esc_html_e( 'Send email notifications for security alerts', 'wp-breach' ); ?>
						</label>
					</td>
				</tr>
				
				<tr>
					<th scope="row">
						<label for="alert_threshold"><?php esc_html_e( 'Alert Threshold', 'wp-breach' ); ?></label>
					</th>
					<td>
						<select id="alert_threshold" name="alert_threshold">
							<option value="all"><?php esc_html_e( 'All Vulnerabilities', 'wp-breach' ); ?></option>
							<option value="medium_plus" selected><?php esc_html_e( 'Medium Severity and Above', 'wp-breach' ); ?></option>
							<option value="high_plus"><?php esc_html_e( 'High Severity and Above', 'wp-breach' ); ?></option>
							<option value="critical_only"><?php esc_html_e( 'Critical Only', 'wp-breach' ); ?></option>
						</select>
						<p class="description"><?php esc_html_e( 'Minimum severity level for generating alerts.', 'wp-breach' ); ?></p>
					</td>
				</tr>
				
				<tr>
					<th scope="row">
						<label for="alert_frequency"><?php esc_html_e( 'Alert Frequency', 'wp-breach' ); ?></label>
					</th>
					<td>
						<select id="alert_frequency" name="alert_frequency">
							<option value="immediate" selected><?php esc_html_e( 'Immediate', 'wp-breach' ); ?></option>
							<option value="hourly"><?php esc_html_e( 'Hourly Digest', 'wp-breach' ); ?></option>
							<option value="daily"><?php esc_html_e( 'Daily Digest', 'wp-breach' ); ?></option>
						</select>
						<p class="description"><?php esc_html_e( 'How often to send alert notifications.', 'wp-breach' ); ?></p>
					</td>
				</tr>
			</table>
			
			<p class="submit">
				<input type="submit" name="wp_breach_save_alert_config" class="button-primary" value="<?php esc_attr_e( 'Save Alert Configuration', 'wp-breach' ); ?>">
			</p>
		</form>
	</div>

	<!-- Alert Statistics -->
	<div class="wp-breach-alert-stats">
		<h2><?php esc_html_e( 'Alert Statistics', 'wp-breach' ); ?></h2>
		
		<div class="wp-breach-stats-grid">
			<?php
			$alert_stats = $vulnerability_model->get_alert_statistics();
			?>
			
			<div class="wp-breach-stat-item">
				<h4><?php esc_html_e( 'Alerts Today', 'wp-breach' ); ?></h4>
				<span class="wp-breach-stat-number"><?php echo esc_html( $alert_stats['today'] ?? 0 ); ?></span>
			</div>
			
			<div class="wp-breach-stat-item">
				<h4><?php esc_html_e( 'Alerts This Week', 'wp-breach' ); ?></h4>
				<span class="wp-breach-stat-number"><?php echo esc_html( $alert_stats['week'] ?? 0 ); ?></span>
			</div>
			
			<div class="wp-breach-stat-item">
				<h4><?php esc_html_e( 'Average Response Time', 'wp-breach' ); ?></h4>
				<span class="wp-breach-stat-number">
					<?php
					if ( isset( $alert_stats['avg_response_time'] ) && $alert_stats['avg_response_time'] > 0 ) {
						echo esc_html( human_time_diff( 0, $alert_stats['avg_response_time'] ) );
					} else {
						echo '—';
					}
					?>
				</span>
			</div>
			
			<div class="wp-breach-stat-item">
				<h4><?php esc_html_e( 'Resolution Rate', 'wp-breach' ); ?></h4>
				<span class="wp-breach-stat-number">
					<?php
					$resolution_rate = $alert_stats['resolution_rate'] ?? 0;
					echo esc_html( round( $resolution_rate, 1 ) . '%' );
					?>
				</span>
			</div>
		</div>
	</div>
</div>

<!-- Alert Details Modal -->
<div id="wp-breach-alert-modal" class="wp-breach-modal" style="display: none;">
	<div class="wp-breach-modal-content">
		<div class="wp-breach-modal-header">
			<h2><?php esc_html_e( 'Alert Details', 'wp-breach' ); ?></h2>
			<button class="wp-breach-modal-close">&times;</button>
		</div>
		<div class="wp-breach-modal-body">
			<!-- Content will be loaded via AJAX -->
		</div>
		<div class="wp-breach-modal-footer">
			<button class="button button-secondary wp-breach-modal-close"><?php esc_html_e( 'Close', 'wp-breach' ); ?></button>
		</div>
	</div>
</div>

<?php
/**
 * Provide a admin area view for the plugin
 *
 * This file is used to markup the admin-facing aspects of the plugin.
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
$scan_model = $database->get_scan_model();
$vulnerability_model = $database->get_vulnerability_model();

// Get recent scans and vulnerabilities
$recent_scans = $scan_model->get_recent_scans( 5 );
$critical_vulnerabilities = $vulnerability_model->get_vulnerabilities_by_severity( 'critical', 5 );
$high_vulnerabilities = $vulnerability_model->get_vulnerabilities_by_severity( 'high', 5 );

// Get statistics
$total_scans = $scan_model->get_scan_count();
$total_vulnerabilities = $vulnerability_model->get_vulnerability_count();
$resolved_vulnerabilities = $vulnerability_model->get_resolved_count();
$pending_vulnerabilities = $total_vulnerabilities - $resolved_vulnerabilities;

// Get current scan status
$current_scan = $scan_model->get_current_scan();
$scan_progress = $current_scan ? $scan_model->get_scan_progress( $current_scan['id'] ) : null;

?>

<div class="wrap wp-breach-dashboard">
	<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>
	
	<!-- Dashboard Overview Cards -->
	<div class="wp-breach-overview-cards">
		<div class="wp-breach-card wp-breach-card-scans">
			<div class="wp-breach-card-icon">
				<span class="dashicons dashicons-search"></span>
			</div>
			<div class="wp-breach-card-content">
				<h3><?php echo number_format( $total_scans ); ?></h3>
				<p><?php esc_html_e( 'Total Scans', 'wp-breach' ); ?></p>
			</div>
		</div>
		
		<div class="wp-breach-card wp-breach-card-vulnerabilities">
			<div class="wp-breach-card-icon">
				<span class="dashicons dashicons-warning"></span>
			</div>
			<div class="wp-breach-card-content">
				<h3><?php echo number_format( $total_vulnerabilities ); ?></h3>
				<p><?php esc_html_e( 'Vulnerabilities Found', 'wp-breach' ); ?></p>
			</div>
		</div>
		
		<div class="wp-breach-card wp-breach-card-resolved">
			<div class="wp-breach-card-icon">
				<span class="dashicons dashicons-yes-alt"></span>
			</div>
			<div class="wp-breach-card-content">
				<h3><?php echo number_format( $resolved_vulnerabilities ); ?></h3>
				<p><?php esc_html_e( 'Resolved Issues', 'wp-breach' ); ?></p>
			</div>
		</div>
		
		<div class="wp-breach-card wp-breach-card-pending">
			<div class="wp-breach-card-icon">
				<span class="dashicons dashicons-clock"></span>
			</div>
			<div class="wp-breach-card-content">
				<h3><?php echo number_format( $pending_vulnerabilities ); ?></h3>
				<p><?php esc_html_e( 'Pending Actions', 'wp-breach' ); ?></p>
			</div>
		</div>
	</div>

	<!-- Quick Actions -->
	<div class="wp-breach-quick-actions">
		<h2><?php esc_html_e( 'Quick Actions', 'wp-breach' ); ?></h2>
		<div class="wp-breach-action-buttons">
			<button id="wp-breach-quick-scan" class="button button-primary" <?php echo $current_scan ? 'disabled' : ''; ?>>
				<span class="dashicons dashicons-search"></span>
				<?php esc_html_e( 'Start Quick Scan', 'wp-breach' ); ?>
			</button>
			
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-breach-vulnerabilities' ) ); ?>" class="button button-secondary">
				<span class="dashicons dashicons-list-view"></span>
				<?php esc_html_e( 'View All Vulnerabilities', 'wp-breach' ); ?>
			</a>
			
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-breach-reports' ) ); ?>" class="button button-secondary">
				<span class="dashicons dashicons-chart-area"></span>
				<?php esc_html_e( 'Generate Report', 'wp-breach' ); ?>
			</a>
			
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-breach-settings' ) ); ?>" class="button button-secondary">
				<span class="dashicons dashicons-admin-generic"></span>
				<?php esc_html_e( 'Settings', 'wp-breach' ); ?>
			</a>
		</div>
	</div>

	<!-- Current Scan Progress -->
	<?php if ( $current_scan && $scan_progress ) : ?>
	<div class="wp-breach-scan-progress">
		<h2><?php esc_html_e( 'Current Scan Progress', 'wp-breach' ); ?></h2>
		<div class="wp-breach-progress-container">
			<div class="wp-breach-progress-bar">
				<div class="wp-breach-progress-fill" style="width: <?php echo esc_attr( $scan_progress['percentage'] ); ?>%;"></div>
			</div>
			<div class="wp-breach-progress-info">
				<span class="wp-breach-progress-percentage"><?php echo esc_html( $scan_progress['percentage'] ); ?>%</span>
				<span class="wp-breach-progress-status"><?php echo esc_html( $scan_progress['current_step'] ); ?></span>
			</div>
		</div>
		<div class="wp-breach-progress-details">
			<p><?php echo esc_html( sprintf( __( 'Scanning: %s', 'wp-breach' ), $scan_progress['current_item'] ) ); ?></p>
			<p><?php echo esc_html( sprintf( __( 'Progress: %d of %d items completed', 'wp-breach' ), $scan_progress['completed_items'], $scan_progress['total_items'] ) ); ?></p>
		</div>
	</div>
	<?php endif; ?>

	<!-- Main Dashboard Content -->
	<div class="wp-breach-dashboard-content">
		<!-- Critical Vulnerabilities -->
		<div class="wp-breach-dashboard-section wp-breach-critical-vulnerabilities">
			<h2><?php esc_html_e( 'Critical Vulnerabilities', 'wp-breach' ); ?></h2>
			<?php if ( ! empty( $critical_vulnerabilities ) ) : ?>
				<div class="wp-breach-vulnerability-list">
					<?php foreach ( $critical_vulnerabilities as $vulnerability ) : ?>
						<div class="wp-breach-vulnerability-item wp-breach-severity-critical">
							<div class="wp-breach-vulnerability-info">
								<h4><?php echo esc_html( $vulnerability['title'] ); ?></h4>
								<p><?php echo esc_html( $vulnerability['description'] ); ?></p>
								<div class="wp-breach-vulnerability-meta">
									<span class="wp-breach-severity wp-breach-severity-<?php echo esc_attr( $vulnerability['severity'] ); ?>">
										<?php echo esc_html( ucfirst( $vulnerability['severity'] ) ); ?>
									</span>
									<span class="wp-breach-vulnerability-type">
										<?php echo esc_html( $vulnerability['type'] ); ?>
									</span>
									<span class="wp-breach-vulnerability-date">
										<?php echo esc_html( human_time_diff( strtotime( $vulnerability['detected_at'] ), current_time( 'timestamp' ) ) . ' ago' ); ?>
									</span>
								</div>
							</div>
							<div class="wp-breach-vulnerability-actions">
								<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-breach-vulnerabilities&vulnerability_id=' . $vulnerability['id'] ) ); ?>" class="button button-small">
									<?php esc_html_e( 'View Details', 'wp-breach' ); ?>
								</a>
								<?php if ( $vulnerability['status'] !== 'resolved' ) : ?>
									<button class="button button-small wp-breach-dismiss-vulnerability" data-vulnerability-id="<?php echo esc_attr( $vulnerability['id'] ); ?>">
										<?php esc_html_e( 'Dismiss', 'wp-breach' ); ?>
									</button>
								<?php endif; ?>
							</div>
						</div>
					<?php endforeach; ?>
				</div>
				<div class="wp-breach-section-footer">
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-breach-vulnerabilities&severity=critical' ) ); ?>" class="button button-secondary">
						<?php esc_html_e( 'View All Critical Issues', 'wp-breach' ); ?>
					</a>
				</div>
			<?php else : ?>
				<div class="wp-breach-no-data">
					<span class="dashicons dashicons-yes-alt"></span>
					<p><?php esc_html_e( 'No critical vulnerabilities found. Great job!', 'wp-breach' ); ?></p>
				</div>
			<?php endif; ?>
		</div>

		<!-- High Priority Vulnerabilities -->
		<div class="wp-breach-dashboard-section wp-breach-high-vulnerabilities">
			<h2><?php esc_html_e( 'High Priority Issues', 'wp-breach' ); ?></h2>
			<?php if ( ! empty( $high_vulnerabilities ) ) : ?>
				<div class="wp-breach-vulnerability-list">
					<?php foreach ( $high_vulnerabilities as $vulnerability ) : ?>
						<div class="wp-breach-vulnerability-item wp-breach-severity-high">
							<div class="wp-breach-vulnerability-info">
								<h4><?php echo esc_html( $vulnerability['title'] ); ?></h4>
								<p><?php echo esc_html( wp_trim_words( $vulnerability['description'], 20 ) ); ?></p>
								<div class="wp-breach-vulnerability-meta">
									<span class="wp-breach-severity wp-breach-severity-<?php echo esc_attr( $vulnerability['severity'] ); ?>">
										<?php echo esc_html( ucfirst( $vulnerability['severity'] ) ); ?>
									</span>
									<span class="wp-breach-vulnerability-type">
										<?php echo esc_html( $vulnerability['type'] ); ?>
									</span>
									<span class="wp-breach-vulnerability-date">
										<?php echo esc_html( human_time_diff( strtotime( $vulnerability['detected_at'] ), current_time( 'timestamp' ) ) . ' ago' ); ?>
									</span>
								</div>
							</div>
							<div class="wp-breach-vulnerability-actions">
								<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-breach-vulnerabilities&vulnerability_id=' . $vulnerability['id'] ) ); ?>" class="button button-small">
									<?php esc_html_e( 'View Details', 'wp-breach' ); ?>
								</a>
							</div>
						</div>
					<?php endforeach; ?>
				</div>
				<div class="wp-breach-section-footer">
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-breach-vulnerabilities&severity=high' ) ); ?>" class="button button-secondary">
						<?php esc_html_e( 'View All High Priority Issues', 'wp-breach' ); ?>
					</a>
				</div>
			<?php else : ?>
				<div class="wp-breach-no-data">
					<span class="dashicons dashicons-yes-alt"></span>
					<p><?php esc_html_e( 'No high priority issues found.', 'wp-breach' ); ?></p>
				</div>
			<?php endif; ?>
		</div>

		<!-- Recent Scans -->
		<div class="wp-breach-dashboard-section wp-breach-recent-scans">
			<h2><?php esc_html_e( 'Recent Scans', 'wp-breach' ); ?></h2>
			<?php if ( ! empty( $recent_scans ) ) : ?>
				<div class="wp-breach-scan-list">
					<?php foreach ( $recent_scans as $scan ) : ?>
						<div class="wp-breach-scan-item">
							<div class="wp-breach-scan-info">
								<h4><?php echo esc_html( $scan['scan_type'] ); ?> Scan</h4>
								<div class="wp-breach-scan-meta">
									<span class="wp-breach-scan-status wp-breach-status-<?php echo esc_attr( $scan['status'] ); ?>">
										<?php echo esc_html( ucfirst( $scan['status'] ) ); ?>
									</span>
									<span class="wp-breach-scan-date">
										<?php echo esc_html( human_time_diff( strtotime( $scan['created_at'] ), current_time( 'timestamp' ) ) . ' ago' ); ?>
									</span>
									<?php if ( $scan['status'] === 'completed' ) : ?>
										<span class="wp-breach-scan-duration">
											<?php echo esc_html( sprintf( __( 'Duration: %s', 'wp-breach' ), human_time_diff( strtotime( $scan['created_at'] ), strtotime( $scan['completed_at'] ) ) ) ); ?>
										</span>
									<?php endif; ?>
								</div>
							</div>
							<div class="wp-breach-scan-results">
								<?php if ( $scan['status'] === 'completed' ) : ?>
									<span class="wp-breach-scan-findings">
										<?php echo esc_html( sprintf( _n( '%d finding', '%d findings', $scan['findings_count'], 'wp-breach' ), $scan['findings_count'] ) ); ?>
									</span>
								<?php endif; ?>
							</div>
						</div>
					<?php endforeach; ?>
				</div>
				<div class="wp-breach-section-footer">
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-breach-monitoring' ) ); ?>" class="button button-secondary">
						<?php esc_html_e( 'View All Scans', 'wp-breach' ); ?>
					</a>
				</div>
			<?php else : ?>
				<div class="wp-breach-no-data">
					<span class="dashicons dashicons-search"></span>
					<p><?php esc_html_e( 'No scans have been performed yet.', 'wp-breach' ); ?></p>
					<button id="wp-breach-first-scan" class="button button-primary">
						<?php esc_html_e( 'Run Your First Scan', 'wp-breach' ); ?>
					</button>
				</div>
			<?php endif; ?>
		</div>

		<!-- Security Score Chart -->
		<div class="wp-breach-dashboard-section wp-breach-security-chart">
			<h2><?php esc_html_e( 'Security Score Trend', 'wp-breach' ); ?></h2>
			<div class="wp-breach-chart-container">
				<canvas id="wp-breach-security-chart" width="400" height="200"></canvas>
			</div>
			<div class="wp-breach-chart-legend">
				<div class="wp-breach-legend-item">
					<span class="wp-breach-legend-color wp-breach-color-primary"></span>
					<span><?php esc_html_e( 'Security Score', 'wp-breach' ); ?></span>
				</div>
				<div class="wp-breach-legend-item">
					<span class="wp-breach-legend-color wp-breach-color-secondary"></span>
					<span><?php esc_html_e( 'Vulnerabilities', 'wp-breach' ); ?></span>
				</div>
			</div>
		</div>
	</div>

	<!-- Dashboard Footer -->
	<div class="wp-breach-dashboard-footer">
		<div class="wp-breach-footer-info">
			<p><?php esc_html_e( 'Last security check:', 'wp-breach' ); ?> 
				<?php
				$last_scan = $scan_model->get_latest_completed_scan();
				if ( $last_scan ) {
					echo esc_html( human_time_diff( strtotime( $last_scan['completed_at'] ), current_time( 'timestamp' ) ) . ' ago' );
				} else {
					esc_html_e( 'Never', 'wp-breach' );
				}
				?>
			</p>
		</div>
		<div class="wp-breach-footer-actions">
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-breach-settings' ) ); ?>">
				<?php esc_html_e( 'Configure Scanning', 'wp-breach' ); ?>
			</a>
			<span class="separator">|</span>
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-breach-reports' ) ); ?>">
				<?php esc_html_e( 'Export Report', 'wp-breach' ); ?>
			</a>
		</div>
	</div>
</div>

<!-- Loading overlay for AJAX operations -->
<div id="wp-breach-loading-overlay" class="wp-breach-loading-overlay" style="display: none;">
	<div class="wp-breach-loading-content">
		<div class="wp-breach-spinner"></div>
		<p><?php esc_html_e( 'Processing...', 'wp-breach' ); ?></p>
	</div>
</div>

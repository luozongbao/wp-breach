<?php
/**
 * Provide a admin area view for security reports
 *
 * This file is used to markup the reports page of the plugin.
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

// Get report data
$total_scans = $scan_model->get_scan_count();
$total_vulnerabilities = $vulnerability_model->get_vulnerability_count();
$resolved_vulnerabilities = $vulnerability_model->get_resolved_count();
$critical_vulnerabilities = $vulnerability_model->get_vulnerability_count( array( 'severity' => 'critical', 'status' => 'active' ) );

// Get recent scans for timeline
$recent_scans = $scan_model->get_recent_scans( 10 );

// Get vulnerability trends (last 30 days)
$vulnerability_trends = $vulnerability_model->get_vulnerability_trends( 30 );

// Get scan statistics
$scan_stats = $scan_model->get_scan_statistics();

?>

<div class="wrap wp-breach-reports">
	<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>
	
	<!-- Report Summary Cards -->
	<div class="wp-breach-report-summary">
		<div class="wp-breach-summary-card">
			<div class="wp-breach-card-icon">
				<span class="dashicons dashicons-chart-line"></span>
			</div>
			<div class="wp-breach-card-content">
				<h3><?php echo number_format( $total_scans ); ?></h3>
				<p><?php esc_html_e( 'Total Scans Performed', 'wp-breach' ); ?></p>
			</div>
		</div>
		
		<div class="wp-breach-summary-card">
			<div class="wp-breach-card-icon">
				<span class="dashicons dashicons-warning"></span>
			</div>
			<div class="wp-breach-card-content">
				<h3><?php echo number_format( $total_vulnerabilities ); ?></h3>
				<p><?php esc_html_e( 'Vulnerabilities Detected', 'wp-breach' ); ?></p>
			</div>
		</div>
		
		<div class="wp-breach-summary-card">
			<div class="wp-breach-card-icon">
				<span class="dashicons dashicons-yes-alt"></span>
			</div>
			<div class="wp-breach-card-content">
				<h3><?php echo number_format( $resolved_vulnerabilities ); ?></h3>
				<p><?php esc_html_e( 'Issues Resolved', 'wp-breach' ); ?></p>
			</div>
		</div>
		
		<div class="wp-breach-summary-card wp-breach-card-critical">
			<div class="wp-breach-card-icon">
				<span class="dashicons dashicons-shield-alt"></span>
			</div>
			<div class="wp-breach-card-content">
				<h3><?php echo number_format( $critical_vulnerabilities ); ?></h3>
				<p><?php esc_html_e( 'Critical Issues Active', 'wp-breach' ); ?></p>
			</div>
		</div>
	</div>

	<!-- Report Actions -->
	<div class="wp-breach-report-actions">
		<h2><?php esc_html_e( 'Generate Reports', 'wp-breach' ); ?></h2>
		<div class="wp-breach-action-buttons">
			<button id="wp-breach-generate-summary" class="button button-primary">
				<span class="dashicons dashicons-chart-area"></span>
				<?php esc_html_e( 'Security Summary Report', 'wp-breach' ); ?>
			</button>
			
			<button id="wp-breach-generate-detailed" class="button button-secondary">
				<span class="dashicons dashicons-list-view"></span>
				<?php esc_html_e( 'Detailed Vulnerability Report', 'wp-breach' ); ?>
			</button>
			
			<button id="wp-breach-generate-compliance" class="button button-secondary">
				<span class="dashicons dashicons-admin-generic"></span>
				<?php esc_html_e( 'Compliance Report', 'wp-breach' ); ?>
			</button>
			
			<button id="wp-breach-generate-executive" class="button button-secondary">
				<span class="dashicons dashicons-businessman"></span>
				<?php esc_html_e( 'Executive Summary', 'wp-breach' ); ?>
			</button>
		</div>
	</div>

	<!-- Charts and Analytics -->
	<div class="wp-breach-analytics">
		<div class="wp-breach-analytics-section">
			<h2><?php esc_html_e( 'Security Trends', 'wp-breach' ); ?></h2>
			<div class="wp-breach-chart-container">
				<canvas id="wp-breach-trends-chart" width="600" height="300"></canvas>
			</div>
		</div>
		
		<div class="wp-breach-analytics-section">
			<h2><?php esc_html_e( 'Vulnerability Distribution', 'wp-breach' ); ?></h2>
			<div class="wp-breach-chart-container">
				<canvas id="wp-breach-distribution-chart" width="400" height="400"></canvas>
			</div>
		</div>
	</div>

	<!-- Scan History Timeline -->
	<div class="wp-breach-scan-timeline">
		<h2><?php esc_html_e( 'Scan History', 'wp-breach' ); ?></h2>
		<?php if ( ! empty( $recent_scans ) ) : ?>
			<div class="wp-breach-timeline">
				<?php foreach ( $recent_scans as $scan ) : ?>
					<div class="wp-breach-timeline-item">
						<div class="wp-breach-timeline-marker wp-breach-marker-<?php echo esc_attr( $scan['status'] ); ?>">
							<span class="dashicons dashicons-<?php echo $scan['status'] === 'completed' ? 'yes-alt' : ( $scan['status'] === 'failed' ? 'dismiss' : 'clock' ); ?>"></span>
						</div>
						<div class="wp-breach-timeline-content">
							<div class="wp-breach-timeline-header">
								<h4><?php echo esc_html( ucfirst( $scan['scan_type'] ) ); ?> Scan</h4>
								<span class="wp-breach-timeline-date">
									<?php echo esc_html( human_time_diff( strtotime( $scan['created_at'] ), current_time( 'timestamp' ) ) . ' ago' ); ?>
								</span>
							</div>
							<div class="wp-breach-timeline-details">
								<p><strong><?php esc_html_e( 'Status:', 'wp-breach' ); ?></strong> 
									<span class="wp-breach-status wp-breach-status-<?php echo esc_attr( $scan['status'] ); ?>">
										<?php echo esc_html( ucfirst( $scan['status'] ) ); ?>
									</span>
								</p>
								<?php if ( $scan['status'] === 'completed' ) : ?>
									<p><strong><?php esc_html_e( 'Findings:', 'wp-breach' ); ?></strong> 
										<?php echo esc_html( sprintf( _n( '%d vulnerability found', '%d vulnerabilities found', $scan['findings_count'], 'wp-breach' ), $scan['findings_count'] ) ); ?>
									</p>
									<p><strong><?php esc_html_e( 'Duration:', 'wp-breach' ); ?></strong> 
										<?php echo esc_html( human_time_diff( strtotime( $scan['created_at'] ), strtotime( $scan['completed_at'] ) ) ); ?>
									</p>
								<?php endif; ?>
								<?php if ( ! empty( $scan['error_message'] ) ) : ?>
									<p><strong><?php esc_html_e( 'Error:', 'wp-breach' ); ?></strong> 
										<?php echo esc_html( $scan['error_message'] ); ?>
									</p>
								<?php endif; ?>
							</div>
						</div>
					</div>
				<?php endforeach; ?>
			</div>
		<?php else : ?>
			<div class="wp-breach-no-data">
				<span class="dashicons dashicons-search"></span>
				<p><?php esc_html_e( 'No scan history available.', 'wp-breach' ); ?></p>
			</div>
		<?php endif; ?>
	</div>

	<!-- Vulnerability Breakdown -->
	<div class="wp-breach-vulnerability-breakdown">
		<h2><?php esc_html_e( 'Vulnerability Analysis', 'wp-breach' ); ?></h2>
		
		<div class="wp-breach-breakdown-grid">
			<!-- By Severity -->
			<div class="wp-breach-breakdown-section">
				<h3><?php esc_html_e( 'By Severity', 'wp-breach' ); ?></h3>
				<div class="wp-breach-breakdown-list">
					<?php
					$severity_counts = $vulnerability_model->get_vulnerability_counts_by_severity();
					$severities = array( 'critical', 'high', 'medium', 'low' );
					foreach ( $severities as $severity ) :
						$count = $severity_counts[ $severity ] ?? 0;
					?>
						<div class="wp-breach-breakdown-item">
							<span class="wp-breach-severity wp-breach-severity-<?php echo esc_attr( $severity ); ?>">
								<?php echo esc_html( ucfirst( $severity ) ); ?>
							</span>
							<span class="wp-breach-breakdown-count"><?php echo esc_html( $count ); ?></span>
						</div>
					<?php endforeach; ?>
				</div>
			</div>
			
			<!-- By Type -->
			<div class="wp-breach-breakdown-section">
				<h3><?php esc_html_e( 'By Type', 'wp-breach' ); ?></h3>
				<div class="wp-breach-breakdown-list">
					<?php
					$type_counts = $vulnerability_model->get_vulnerability_counts_by_type();
					foreach ( $type_counts as $type => $count ) :
					?>
						<div class="wp-breach-breakdown-item">
							<span class="wp-breach-type">
								<?php echo esc_html( str_replace( '_', ' ', ucwords( $type, '_' ) ) ); ?>
							</span>
							<span class="wp-breach-breakdown-count"><?php echo esc_html( $count ); ?></span>
						</div>
					<?php endforeach; ?>
				</div>
			</div>
			
			<!-- By Status -->
			<div class="wp-breach-breakdown-section">
				<h3><?php esc_html_e( 'By Status', 'wp-breach' ); ?></h3>
				<div class="wp-breach-breakdown-list">
					<?php
					$status_counts = $vulnerability_model->get_vulnerability_counts_by_status();
					foreach ( $status_counts as $status => $count ) :
					?>
						<div class="wp-breach-breakdown-item">
							<span class="wp-breach-status wp-breach-status-<?php echo esc_attr( $status ); ?>">
								<?php echo esc_html( str_replace( '_', ' ', ucwords( $status, '_' ) ) ); ?>
							</span>
							<span class="wp-breach-breakdown-count"><?php echo esc_html( $count ); ?></span>
						</div>
					<?php endforeach; ?>
				</div>
			</div>
		</div>
	</div>

	<!-- Security Score History -->
	<div class="wp-breach-security-score">
		<h2><?php esc_html_e( 'Security Score History', 'wp-breach' ); ?></h2>
		<div class="wp-breach-score-chart">
			<canvas id="wp-breach-score-history" width="800" height="300"></canvas>
		</div>
		<div class="wp-breach-score-info">
			<p><?php esc_html_e( 'Security score is calculated based on the number and severity of active vulnerabilities.', 'wp-breach' ); ?></p>
			<div class="wp-breach-score-legend">
				<div class="wp-breach-score-range wp-breach-score-excellent">
					<span class="wp-breach-score-label"><?php esc_html_e( 'Excellent', 'wp-breach' ); ?></span>
					<span class="wp-breach-score-values">90-100</span>
				</div>
				<div class="wp-breach-score-range wp-breach-score-good">
					<span class="wp-breach-score-label"><?php esc_html_e( 'Good', 'wp-breach' ); ?></span>
					<span class="wp-breach-score-values">70-89</span>
				</div>
				<div class="wp-breach-score-range wp-breach-score-fair">
					<span class="wp-breach-score-label"><?php esc_html_e( 'Fair', 'wp-breach' ); ?></span>
					<span class="wp-breach-score-values">50-69</span>
				</div>
				<div class="wp-breach-score-range wp-breach-score-poor">
					<span class="wp-breach-score-label"><?php esc_html_e( 'Poor', 'wp-breach' ); ?></span>
					<span class="wp-breach-score-values">0-49</span>
				</div>
			</div>
		</div>
	</div>

	<!-- Export Options -->
	<div class="wp-breach-export-section">
		<h2><?php esc_html_e( 'Export Options', 'wp-breach' ); ?></h2>
		<form method="post" action="" class="wp-breach-export-form">
			<?php wp_nonce_field( 'wp_breach_export_report', 'wp_breach_export_nonce' ); ?>
			
			<div class="wp-breach-export-options">
				<div class="wp-breach-export-group">
					<h4><?php esc_html_e( 'Report Type', 'wp-breach' ); ?></h4>
					<label>
						<input type="radio" name="report_type" value="summary" checked>
						<?php esc_html_e( 'Executive Summary', 'wp-breach' ); ?>
					</label>
					<label>
						<input type="radio" name="report_type" value="detailed">
						<?php esc_html_e( 'Detailed Report', 'wp-breach' ); ?>
					</label>
					<label>
						<input type="radio" name="report_type" value="compliance">
						<?php esc_html_e( 'Compliance Report', 'wp-breach' ); ?>
					</label>
				</div>
				
				<div class="wp-breach-export-group">
					<h4><?php esc_html_e( 'Export Format', 'wp-breach' ); ?></h4>
					<label>
						<input type="radio" name="export_format" value="pdf" checked>
						<?php esc_html_e( 'PDF Document', 'wp-breach' ); ?>
					</label>
					<label>
						<input type="radio" name="export_format" value="csv">
						<?php esc_html_e( 'CSV Spreadsheet', 'wp-breach' ); ?>
					</label>
					<label>
						<input type="radio" name="export_format" value="json">
						<?php esc_html_e( 'JSON Data', 'wp-breach' ); ?>
					</label>
				</div>
				
				<div class="wp-breach-export-group">
					<h4><?php esc_html_e( 'Date Range', 'wp-breach' ); ?></h4>
					<label>
						<input type="radio" name="date_range" value="last_week" checked>
						<?php esc_html_e( 'Last 7 days', 'wp-breach' ); ?>
					</label>
					<label>
						<input type="radio" name="date_range" value="last_month">
						<?php esc_html_e( 'Last 30 days', 'wp-breach' ); ?>
					</label>
					<label>
						<input type="radio" name="date_range" value="last_quarter">
						<?php esc_html_e( 'Last 3 months', 'wp-breach' ); ?>
					</label>
					<label>
						<input type="radio" name="date_range" value="custom">
						<?php esc_html_e( 'Custom range', 'wp-breach' ); ?>
					</label>
					<div class="wp-breach-custom-range" style="display: none;">
						<input type="date" name="start_date" placeholder="<?php esc_attr_e( 'Start date', 'wp-breach' ); ?>">
						<input type="date" name="end_date" placeholder="<?php esc_attr_e( 'End date', 'wp-breach' ); ?>">
					</div>
				</div>
			</div>
			
			<div class="wp-breach-export-actions">
				<button type="submit" name="wp_breach_export_report" class="button button-primary">
					<span class="dashicons dashicons-download"></span>
					<?php esc_html_e( 'Generate & Download Report', 'wp-breach' ); ?>
				</button>
			</div>
		</form>
	</div>

	<!-- Scheduled Reports -->
	<div class="wp-breach-scheduled-reports">
		<h2><?php esc_html_e( 'Scheduled Reports', 'wp-breach' ); ?></h2>
		<div class="wp-breach-schedule-options">
			<form method="post" action="">
				<?php wp_nonce_field( 'wp_breach_schedule_report', 'wp_breach_schedule_nonce' ); ?>
				
				<table class="form-table">
					<tr>
						<th scope="row">
							<label for="schedule_enabled"><?php esc_html_e( 'Enable Scheduled Reports', 'wp-breach' ); ?></label>
						</th>
						<td>
							<label>
								<input type="checkbox" id="schedule_enabled" name="schedule_enabled" value="1">
								<?php esc_html_e( 'Send automated security reports', 'wp-breach' ); ?>
							</label>
						</td>
					</tr>
					
					<tr>
						<th scope="row">
							<label for="schedule_frequency"><?php esc_html_e( 'Frequency', 'wp-breach' ); ?></label>
						</th>
						<td>
							<select id="schedule_frequency" name="schedule_frequency">
								<option value="weekly"><?php esc_html_e( 'Weekly', 'wp-breach' ); ?></option>
								<option value="monthly"><?php esc_html_e( 'Monthly', 'wp-breach' ); ?></option>
								<option value="quarterly"><?php esc_html_e( 'Quarterly', 'wp-breach' ); ?></option>
							</select>
						</td>
					</tr>
					
					<tr>
						<th scope="row">
							<label for="report_recipients"><?php esc_html_e( 'Recipients', 'wp-breach' ); ?></label>
						</th>
						<td>
							<textarea id="report_recipients" name="report_recipients" rows="3" class="large-text" placeholder="<?php esc_attr_e( 'Enter email addresses, one per line', 'wp-breach' ); ?>"></textarea>
						</td>
					</tr>
				</table>
				
				<p class="submit">
					<input type="submit" name="wp_breach_save_schedule" class="button-primary" value="<?php esc_attr_e( 'Save Schedule', 'wp-breach' ); ?>">
				</p>
			</form>
		</div>
	</div>
</div>

<!-- Chart data for JavaScript -->
<script type="application/json" id="wp-breach-chart-data">
<?php
echo wp_json_encode( array(
	'trends' => $vulnerability_trends,
	'distribution' => $vulnerability_model->get_vulnerability_distribution(),
	'score_history' => $scan_model->get_security_score_history( 30 ),
) );
?>
</script>

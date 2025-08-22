<?php
/**
 * Provide a admin area view for monitoring scans
 *
 * This file is used to markup the monitoring page of the plugin.
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

// Handle pagination
$current_page = isset( $_GET['paged'] ) ? max( 1, intval( $_GET['paged'] ) ) : 1;
$per_page = 20;
$status_filter = isset( $_GET['status'] ) ? sanitize_text_field( $_GET['status'] ) : '';
$type_filter = isset( $_GET['type'] ) ? sanitize_text_field( $_GET['type'] ) : '';

// Build filters
$filters = array();
if ( $status_filter ) {
	$filters['status'] = $status_filter;
}
if ( $type_filter ) {
	$filters['scan_type'] = $type_filter;
}

// Get scans
$offset = ( $current_page - 1 ) * $per_page;
$scans = $scan_model->get_scans( $filters, $per_page, $offset );
$total_scans = $scan_model->get_scan_count( $filters );
$total_pages = ceil( $total_scans / $per_page );

// Get current scan
$current_scan = $scan_model->get_current_scan();

?>

<div class="wrap wp-breach-monitoring">
	<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>
	
	<!-- Current Scan Status -->
	<?php if ( $current_scan ) : ?>
		<div class="wp-breach-current-scan">
			<h2><?php esc_html_e( 'Current Scan in Progress', 'wp-breach' ); ?></h2>
			<div id="wp-breach-scan-progress" class="wp-breach-progress-container">
				<!-- Progress will be updated via AJAX -->
			</div>
		</div>
	<?php endif; ?>

	<!-- Scan Controls -->
	<div class="wp-breach-scan-controls">
		<h2><?php esc_html_e( 'Scan Controls', 'wp-breach' ); ?></h2>
		<div class="wp-breach-control-buttons">
			<button id="wp-breach-start-scan" class="button button-primary" <?php echo $current_scan ? 'disabled' : ''; ?>>
				<span class="dashicons dashicons-search"></span>
				<?php esc_html_e( 'Start New Scan', 'wp-breach' ); ?>
			</button>
			
			<?php if ( $current_scan ) : ?>
				<button id="wp-breach-pause-scan" class="button button-secondary">
					<span class="dashicons dashicons-controls-pause"></span>
					<?php esc_html_e( 'Pause Scan', 'wp-breach' ); ?>
				</button>
				
				<button id="wp-breach-stop-scan" class="button button-secondary">
					<span class="dashicons dashicons-controls-stop"></span>
					<?php esc_html_e( 'Stop Scan', 'wp-breach' ); ?>
				</button>
			<?php endif; ?>
		</div>
	</div>

	<!-- Scan History Filters -->
	<div class="wp-breach-filters">
		<form method="get" action="">
			<input type="hidden" name="page" value="wp-breach-monitoring">
			
			<div class="wp-breach-filter-row">
				<div class="wp-breach-filter-group">
					<label for="status-filter"><?php esc_html_e( 'Status:', 'wp-breach' ); ?></label>
					<select name="status" id="status-filter">
						<option value=""><?php esc_html_e( 'All Statuses', 'wp-breach' ); ?></option>
						<option value="pending" <?php selected( $status_filter, 'pending' ); ?>><?php esc_html_e( 'Pending', 'wp-breach' ); ?></option>
						<option value="running" <?php selected( $status_filter, 'running' ); ?>><?php esc_html_e( 'Running', 'wp-breach' ); ?></option>
						<option value="completed" <?php selected( $status_filter, 'completed' ); ?>><?php esc_html_e( 'Completed', 'wp-breach' ); ?></option>
						<option value="failed" <?php selected( $status_filter, 'failed' ); ?>><?php esc_html_e( 'Failed', 'wp-breach' ); ?></option>
						<option value="cancelled" <?php selected( $status_filter, 'cancelled' ); ?>><?php esc_html_e( 'Cancelled', 'wp-breach' ); ?></option>
					</select>
				</div>
				
				<div class="wp-breach-filter-group">
					<label for="type-filter"><?php esc_html_e( 'Type:', 'wp-breach' ); ?></label>
					<select name="type" id="type-filter">
						<option value=""><?php esc_html_e( 'All Types', 'wp-breach' ); ?></option>
						<option value="quick" <?php selected( $type_filter, 'quick' ); ?>><?php esc_html_e( 'Quick Scan', 'wp-breach' ); ?></option>
						<option value="full" <?php selected( $type_filter, 'full' ); ?>><?php esc_html_e( 'Full Scan', 'wp-breach' ); ?></option>
						<option value="scheduled" <?php selected( $type_filter, 'scheduled' ); ?>><?php esc_html_e( 'Scheduled Scan', 'wp-breach' ); ?></option>
						<option value="manual" <?php selected( $type_filter, 'manual' ); ?>><?php esc_html_e( 'Manual Scan', 'wp-breach' ); ?></option>
					</select>
				</div>
				
				<div class="wp-breach-filter-actions">
					<button type="submit" class="button"><?php esc_html_e( 'Filter', 'wp-breach' ); ?></button>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-breach-monitoring' ) ); ?>" class="button"><?php esc_html_e( 'Clear', 'wp-breach' ); ?></a>
				</div>
			</div>
		</form>
	</div>

	<!-- Scan History Table -->
	<div class="wp-breach-scan-history">
		<h2><?php esc_html_e( 'Scan History', 'wp-breach' ); ?></h2>
		
		<?php if ( ! empty( $scans ) ) : ?>
			<table class="wp-list-table widefat fixed striped">
				<thead>
					<tr>
						<th class="manage-column column-scan-id"><?php esc_html_e( 'Scan ID', 'wp-breach' ); ?></th>
						<th class="manage-column column-type"><?php esc_html_e( 'Type', 'wp-breach' ); ?></th>
						<th class="manage-column column-status"><?php esc_html_e( 'Status', 'wp-breach' ); ?></th>
						<th class="manage-column column-started"><?php esc_html_e( 'Started', 'wp-breach' ); ?></th>
						<th class="manage-column column-duration"><?php esc_html_e( 'Duration', 'wp-breach' ); ?></th>
						<th class="manage-column column-findings"><?php esc_html_e( 'Findings', 'wp-breach' ); ?></th>
						<th class="manage-column column-actions"><?php esc_html_e( 'Actions', 'wp-breach' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $scans as $scan ) : ?>
						<tr class="wp-breach-scan-row">
							<td class="column-scan-id">
								<strong>#<?php echo esc_html( $scan['id'] ); ?></strong>
							</td>
							<td class="column-type">
								<?php echo esc_html( ucfirst( $scan['scan_type'] ) ); ?>
							</td>
							<td class="column-status">
								<span class="wp-breach-status wp-breach-status-<?php echo esc_attr( $scan['status'] ); ?>">
									<?php echo esc_html( ucfirst( $scan['status'] ) ); ?>
								</span>
							</td>
							<td class="column-started">
								<?php echo esc_html( human_time_diff( strtotime( $scan['created_at'] ), current_time( 'timestamp' ) ) . ' ago' ); ?>
								<br>
								<small><?php echo esc_html( date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), strtotime( $scan['created_at'] ) ) ); ?></small>
							</td>
							<td class="column-duration">
								<?php
								if ( $scan['status'] === 'completed' && $scan['completed_at'] ) {
									echo esc_html( human_time_diff( strtotime( $scan['created_at'] ), strtotime( $scan['completed_at'] ) ) );
								} elseif ( $scan['status'] === 'running' ) {
									echo esc_html( human_time_diff( strtotime( $scan['created_at'] ), current_time( 'timestamp' ) ) );
								} else {
									echo '—';
								}
								?>
							</td>
							<td class="column-findings">
								<?php if ( $scan['status'] === 'completed' ) : ?>
									<strong><?php echo esc_html( $scan['findings_count'] ?? 0 ); ?></strong>
									<?php esc_html_e( 'findings', 'wp-breach' ); ?>
								<?php else : ?>
									—
								<?php endif; ?>
							</td>
							<td class="column-actions">
								<div class="wp-breach-scan-actions">
									<?php if ( $scan['status'] === 'completed' ) : ?>
										<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-breach-monitoring&action=view&scan_id=' . $scan['id'] ) ); ?>" class="button button-small">
											<?php esc_html_e( 'View Results', 'wp-breach' ); ?>
										</a>
									<?php endif; ?>
									
									<?php if ( $scan['status'] === 'running' ) : ?>
										<button class="button button-small wp-breach-cancel-scan" data-scan-id="<?php echo esc_attr( $scan['id'] ); ?>">
											<?php esc_html_e( 'Cancel', 'wp-breach' ); ?>
										</button>
									<?php endif; ?>
									
									<?php if ( in_array( $scan['status'], array( 'completed', 'failed', 'cancelled' ) ) ) : ?>
										<button class="button button-small wp-breach-delete-scan" data-scan-id="<?php echo esc_attr( $scan['id'] ); ?>">
											<?php esc_html_e( 'Delete', 'wp-breach' ); ?>
										</button>
									<?php endif; ?>
								</div>
							</td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>

			<!-- Pagination -->
			<?php if ( $total_pages > 1 ) : ?>
				<div class="wp-breach-pagination">
					<?php
					$pagination_args = array(
						'base' => add_query_arg( 'paged', '%#%' ),
						'format' => '',
						'prev_text' => __( '&laquo; Previous', 'wp-breach' ),
						'next_text' => __( 'Next &raquo;', 'wp-breach' ),
						'total' => $total_pages,
						'current' => $current_page,
					);
					echo wp_kses_post( paginate_links( $pagination_args ) );
					?>
				</div>
			<?php endif; ?>

		<?php else : ?>
			<div class="wp-breach-no-scans">
				<div class="wp-breach-no-data">
					<span class="dashicons dashicons-search"></span>
					<h3><?php esc_html_e( 'No scans found', 'wp-breach' ); ?></h3>
					<?php if ( $status_filter || $type_filter ) : ?>
						<p><?php esc_html_e( 'No scans match your current filters.', 'wp-breach' ); ?></p>
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-breach-monitoring' ) ); ?>" class="button">
							<?php esc_html_e( 'Clear Filters', 'wp-breach' ); ?>
						</a>
					<?php else : ?>
						<p><?php esc_html_e( 'No security scans have been performed yet.', 'wp-breach' ); ?></p>
						<button id="wp-breach-first-scan" class="button button-primary">
							<?php esc_html_e( 'Run Your First Scan', 'wp-breach' ); ?>
						</button>
					<?php endif; ?>
				</div>
			</div>
		<?php endif; ?>
	</div>

	<!-- Scan Statistics -->
	<div class="wp-breach-scan-stats">
		<h2><?php esc_html_e( 'Scan Statistics', 'wp-breach' ); ?></h2>
		
		<?php
		$scan_stats = $scan_model->get_scan_statistics();
		?>
		
		<div class="wp-breach-stats-grid">
			<div class="wp-breach-stat-item">
				<h4><?php esc_html_e( 'Total Scans', 'wp-breach' ); ?></h4>
				<span class="wp-breach-stat-number"><?php echo esc_html( $scan_stats['total'] ?? 0 ); ?></span>
			</div>
			
			<div class="wp-breach-stat-item">
				<h4><?php esc_html_e( 'Completed', 'wp-breach' ); ?></h4>
				<span class="wp-breach-stat-number"><?php echo esc_html( $scan_stats['completed'] ?? 0 ); ?></span>
			</div>
			
			<div class="wp-breach-stat-item">
				<h4><?php esc_html_e( 'Failed', 'wp-breach' ); ?></h4>
				<span class="wp-breach-stat-number"><?php echo esc_html( $scan_stats['failed'] ?? 0 ); ?></span>
			</div>
			
			<div class="wp-breach-stat-item">
				<h4><?php esc_html_e( 'Average Duration', 'wp-breach' ); ?></h4>
				<span class="wp-breach-stat-number">
					<?php
					if ( isset( $scan_stats['avg_duration'] ) && $scan_stats['avg_duration'] > 0 ) {
						echo esc_html( human_time_diff( 0, $scan_stats['avg_duration'] ) );
					} else {
						echo '—';
					}
					?>
				</span>
			</div>
		</div>
	</div>

	<!-- System Status -->
	<div class="wp-breach-system-status">
		<h2><?php esc_html_e( 'System Status', 'wp-breach' ); ?></h2>
		
		<div class="wp-breach-status-grid">
			<div class="wp-breach-status-item">
				<span class="wp-breach-status-label"><?php esc_html_e( 'Scanner Engine:', 'wp-breach' ); ?></span>
				<span class="wp-breach-status-value wp-breach-status-active">
					<?php esc_html_e( 'Active', 'wp-breach' ); ?>
				</span>
			</div>
			
			<div class="wp-breach-status-item">
				<span class="wp-breach-status-label"><?php esc_html_e( 'Database Connection:', 'wp-breach' ); ?></span>
				<span class="wp-breach-status-value wp-breach-status-active">
					<?php esc_html_e( 'Connected', 'wp-breach' ); ?>
				</span>
			</div>
			
			<div class="wp-breach-status-item">
				<span class="wp-breach-status-label"><?php esc_html_e( 'Scheduled Scans:', 'wp-breach' ); ?></span>
				<span class="wp-breach-status-value">
					<?php
					$next_scan = wp_next_scheduled( 'wp_breach_scheduled_scan' );
					if ( $next_scan ) {
						echo '<span class="wp-breach-status-active">' . esc_html__( 'Enabled', 'wp-breach' ) . '</span>';
						echo '<br><small>' . esc_html( sprintf( __( 'Next: %s', 'wp-breach' ), human_time_diff( current_time( 'timestamp' ), $next_scan ) . ' from now' ) ) . '</small>';
					} else {
						echo '<span class="wp-breach-status-inactive">' . esc_html__( 'Disabled', 'wp-breach' ) . '</span>';
					}
					?>
				</span>
			</div>
			
			<div class="wp-breach-status-item">
				<span class="wp-breach-status-label"><?php esc_html_e( 'Memory Usage:', 'wp-breach' ); ?></span>
				<span class="wp-breach-status-value">
					<?php
					$memory_usage = memory_get_usage( true );
					$memory_limit = wp_convert_hr_to_bytes( ini_get( 'memory_limit' ) );
					$memory_percent = round( ( $memory_usage / $memory_limit ) * 100 );
					
					echo esc_html( size_format( $memory_usage ) . ' / ' . size_format( $memory_limit ) );
					echo '<br><small>' . esc_html( sprintf( __( '%d%% used', 'wp-breach' ), $memory_percent ) ) . '</small>';
					?>
				</span>
			</div>
		</div>
	</div>
</div>

<!-- Scan Progress Modal -->
<div id="wp-breach-scan-modal" class="wp-breach-modal" style="display: none;">
	<div class="wp-breach-modal-content">
		<div class="wp-breach-modal-header">
			<h2><?php esc_html_e( 'Scan Progress', 'wp-breach' ); ?></h2>
		</div>
		<div class="wp-breach-modal-body">
			<div id="wp-breach-scan-progress-detail">
				<!-- Progress details will be loaded here -->
			</div>
		</div>
		<div class="wp-breach-modal-footer">
			<button class="button button-secondary wp-breach-modal-close"><?php esc_html_e( 'Close', 'wp-breach' ); ?></button>
		</div>
	</div>
</div>

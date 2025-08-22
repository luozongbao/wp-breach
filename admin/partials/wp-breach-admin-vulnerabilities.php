<?php
/**
 * Provide a admin area view for vulnerabilities management
 *
 * This file is used to markup the vulnerabilities page of the plugin.
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

// Handle filters and pagination
$current_page = isset( $_GET['paged'] ) ? max( 1, intval( $_GET['paged'] ) ) : 1;
$per_page = 20;
$severity_filter = isset( $_GET['severity'] ) ? sanitize_text_field( $_GET['severity'] ) : '';
$status_filter = isset( $_GET['status'] ) ? sanitize_text_field( $_GET['status'] ) : '';
$type_filter = isset( $_GET['type'] ) ? sanitize_text_field( $_GET['type'] ) : '';
$search_query = isset( $_GET['s'] ) ? sanitize_text_field( $_GET['s'] ) : '';

// Build filters array
$filters = array();
if ( $severity_filter ) {
	$filters['severity'] = $severity_filter;
}
if ( $status_filter ) {
	$filters['status'] = $status_filter;
}
if ( $type_filter ) {
	$filters['type'] = $type_filter;
}
if ( $search_query ) {
	$filters['search'] = $search_query;
}

// Get vulnerabilities
$offset = ( $current_page - 1 ) * $per_page;
$vulnerabilities = $vulnerability_model->get_vulnerabilities( $filters, $per_page, $offset );
$total_vulnerabilities = $vulnerability_model->get_vulnerability_count( $filters );
$total_pages = ceil( $total_vulnerabilities / $per_page );

// Get summary statistics
$severity_counts = $vulnerability_model->get_vulnerability_counts_by_severity();
$status_counts = $vulnerability_model->get_vulnerability_counts_by_status();

?>

<div class="wrap wp-breach-vulnerabilities">
	<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>
	
	<!-- Vulnerability Statistics -->
	<div class="wp-breach-vulnerability-stats">
		<div class="wp-breach-stat-card">
			<h3><?php echo esc_html( $severity_counts['critical'] ?? 0 ); ?></h3>
			<p class="wp-breach-stat-critical"><?php esc_html_e( 'Critical', 'wp-breach' ); ?></p>
		</div>
		<div class="wp-breach-stat-card">
			<h3><?php echo esc_html( $severity_counts['high'] ?? 0 ); ?></h3>
			<p class="wp-breach-stat-high"><?php esc_html_e( 'High', 'wp-breach' ); ?></p>
		</div>
		<div class="wp-breach-stat-card">
			<h3><?php echo esc_html( $severity_counts['medium'] ?? 0 ); ?></h3>
			<p class="wp-breach-stat-medium"><?php esc_html_e( 'Medium', 'wp-breach' ); ?></p>
		</div>
		<div class="wp-breach-stat-card">
			<h3><?php echo esc_html( $severity_counts['low'] ?? 0 ); ?></h3>
			<p class="wp-breach-stat-low"><?php esc_html_e( 'Low', 'wp-breach' ); ?></p>
		</div>
		<div class="wp-breach-stat-card">
			<h3><?php echo esc_html( $status_counts['resolved'] ?? 0 ); ?></h3>
			<p class="wp-breach-stat-resolved"><?php esc_html_e( 'Resolved', 'wp-breach' ); ?></p>
		</div>
	</div>

	<!-- Filters and Search -->
	<div class="wp-breach-filters">
		<form method="get" action="">
			<input type="hidden" name="page" value="wp-breach-vulnerabilities">
			
			<div class="wp-breach-filter-row">
				<div class="wp-breach-filter-group">
					<label for="severity-filter"><?php esc_html_e( 'Severity:', 'wp-breach' ); ?></label>
					<select name="severity" id="severity-filter">
						<option value=""><?php esc_html_e( 'All Severities', 'wp-breach' ); ?></option>
						<option value="critical" <?php selected( $severity_filter, 'critical' ); ?>><?php esc_html_e( 'Critical', 'wp-breach' ); ?></option>
						<option value="high" <?php selected( $severity_filter, 'high' ); ?>><?php esc_html_e( 'High', 'wp-breach' ); ?></option>
						<option value="medium" <?php selected( $severity_filter, 'medium' ); ?>><?php esc_html_e( 'Medium', 'wp-breach' ); ?></option>
						<option value="low" <?php selected( $severity_filter, 'low' ); ?>><?php esc_html_e( 'Low', 'wp-breach' ); ?></option>
					</select>
				</div>
				
				<div class="wp-breach-filter-group">
					<label for="status-filter"><?php esc_html_e( 'Status:', 'wp-breach' ); ?></label>
					<select name="status" id="status-filter">
						<option value=""><?php esc_html_e( 'All Statuses', 'wp-breach' ); ?></option>
						<option value="active" <?php selected( $status_filter, 'active' ); ?>><?php esc_html_e( 'Active', 'wp-breach' ); ?></option>
						<option value="resolved" <?php selected( $status_filter, 'resolved' ); ?>><?php esc_html_e( 'Resolved', 'wp-breach' ); ?></option>
						<option value="dismissed" <?php selected( $status_filter, 'dismissed' ); ?>><?php esc_html_e( 'Dismissed', 'wp-breach' ); ?></option>
						<option value="false_positive" <?php selected( $status_filter, 'false_positive' ); ?>><?php esc_html_e( 'False Positive', 'wp-breach' ); ?></option>
					</select>
				</div>
				
				<div class="wp-breach-filter-group">
					<label for="type-filter"><?php esc_html_e( 'Type:', 'wp-breach' ); ?></label>
					<select name="type" id="type-filter">
						<option value=""><?php esc_html_e( 'All Types', 'wp-breach' ); ?></option>
						<option value="sql_injection" <?php selected( $type_filter, 'sql_injection' ); ?>><?php esc_html_e( 'SQL Injection', 'wp-breach' ); ?></option>
						<option value="xss" <?php selected( $type_filter, 'xss' ); ?>><?php esc_html_e( 'Cross-Site Scripting', 'wp-breach' ); ?></option>
						<option value="file_inclusion" <?php selected( $type_filter, 'file_inclusion' ); ?>><?php esc_html_e( 'File Inclusion', 'wp-breach' ); ?></option>
						<option value="authentication" <?php selected( $type_filter, 'authentication' ); ?>><?php esc_html_e( 'Authentication', 'wp-breach' ); ?></option>
						<option value="authorization" <?php selected( $type_filter, 'authorization' ); ?>><?php esc_html_e( 'Authorization', 'wp-breach' ); ?></option>
						<option value="configuration" <?php selected( $type_filter, 'configuration' ); ?>><?php esc_html_e( 'Configuration', 'wp-breach' ); ?></option>
						<option value="information_disclosure" <?php selected( $type_filter, 'information_disclosure' ); ?>><?php esc_html_e( 'Information Disclosure', 'wp-breach' ); ?></option>
					</select>
				</div>
				
				<div class="wp-breach-filter-group wp-breach-search-group">
					<label for="vulnerability-search"><?php esc_html_e( 'Search:', 'wp-breach' ); ?></label>
					<input type="search" name="s" id="vulnerability-search" value="<?php echo esc_attr( $search_query ); ?>" placeholder="<?php esc_attr_e( 'Search vulnerabilities...', 'wp-breach' ); ?>">
				</div>
				
				<div class="wp-breach-filter-actions">
					<button type="submit" class="button"><?php esc_html_e( 'Filter', 'wp-breach' ); ?></button>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-breach-vulnerabilities' ) ); ?>" class="button"><?php esc_html_e( 'Clear', 'wp-breach' ); ?></a>
				</div>
			</div>
		</form>
	</div>

	<!-- Bulk Actions -->
	<div class="wp-breach-bulk-actions">
		<form method="post" action="">
			<?php wp_nonce_field( 'wp_breach_bulk_action', 'wp_breach_bulk_nonce' ); ?>
			<div class="alignleft actions">
				<select name="bulk_action">
					<option value=""><?php esc_html_e( 'Bulk Actions', 'wp-breach' ); ?></option>
					<option value="mark_resolved"><?php esc_html_e( 'Mark as Resolved', 'wp-breach' ); ?></option>
					<option value="mark_dismissed"><?php esc_html_e( 'Mark as Dismissed', 'wp-breach' ); ?></option>
					<option value="mark_false_positive"><?php esc_html_e( 'Mark as False Positive', 'wp-breach' ); ?></option>
					<option value="delete"><?php esc_html_e( 'Delete', 'wp-breach' ); ?></option>
				</select>
				<button type="submit" class="button action"><?php esc_html_e( 'Apply', 'wp-breach' ); ?></button>
			</div>
		</form>
	</div>

	<!-- Vulnerabilities Table -->
	<div class="wp-breach-vulnerabilities-table">
		<?php if ( ! empty( $vulnerabilities ) ) : ?>
			<table class="wp-list-table widefat fixed striped">
				<thead>
					<tr>
						<td class="manage-column column-cb check-column">
							<input type="checkbox" id="select-all-vulnerabilities">
						</td>
						<th class="manage-column column-title"><?php esc_html_e( 'Vulnerability', 'wp-breach' ); ?></th>
						<th class="manage-column column-severity"><?php esc_html_e( 'Severity', 'wp-breach' ); ?></th>
						<th class="manage-column column-type"><?php esc_html_e( 'Type', 'wp-breach' ); ?></th>
						<th class="manage-column column-status"><?php esc_html_e( 'Status', 'wp-breach' ); ?></th>
						<th class="manage-column column-detected"><?php esc_html_e( 'Detected', 'wp-breach' ); ?></th>
						<th class="manage-column column-actions"><?php esc_html_e( 'Actions', 'wp-breach' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $vulnerabilities as $vulnerability ) : ?>
						<tr class="wp-breach-vulnerability-row" data-vulnerability-id="<?php echo esc_attr( $vulnerability['id'] ); ?>">
							<th class="check-column">
								<input type="checkbox" name="vulnerability_ids[]" value="<?php echo esc_attr( $vulnerability['id'] ); ?>">
							</th>
							<td class="column-title">
								<strong>
									<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-breach-vulnerabilities&action=view&vulnerability_id=' . $vulnerability['id'] ) ); ?>">
										<?php echo esc_html( $vulnerability['title'] ); ?>
									</a>
								</strong>
								<div class="wp-breach-vulnerability-description">
									<?php echo esc_html( wp_trim_words( $vulnerability['description'], 15 ) ); ?>
								</div>
								<?php if ( ! empty( $vulnerability['file_path'] ) ) : ?>
									<div class="wp-breach-vulnerability-location">
										<span class="dashicons dashicons-media-code"></span>
										<?php echo esc_html( $vulnerability['file_path'] ); ?>
										<?php if ( ! empty( $vulnerability['line_number'] ) ) : ?>
											:<?php echo esc_html( $vulnerability['line_number'] ); ?>
										<?php endif; ?>
									</div>
								<?php endif; ?>
							</td>
							<td class="column-severity">
								<span class="wp-breach-severity wp-breach-severity-<?php echo esc_attr( $vulnerability['severity'] ); ?>">
									<?php echo esc_html( ucfirst( $vulnerability['severity'] ) ); ?>
								</span>
							</td>
							<td class="column-type">
								<?php echo esc_html( str_replace( '_', ' ', ucwords( $vulnerability['type'], '_' ) ) ); ?>
							</td>
							<td class="column-status">
								<span class="wp-breach-status wp-breach-status-<?php echo esc_attr( $vulnerability['status'] ); ?>">
									<?php echo esc_html( str_replace( '_', ' ', ucwords( $vulnerability['status'], '_' ) ) ); ?>
								</span>
							</td>
							<td class="column-detected">
								<?php echo esc_html( human_time_diff( strtotime( $vulnerability['detected_at'] ), current_time( 'timestamp' ) ) . ' ago' ); ?>
							</td>
							<td class="column-actions">
								<div class="wp-breach-vulnerability-actions">
									<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-breach-vulnerabilities&action=view&vulnerability_id=' . $vulnerability['id'] ) ); ?>" class="button button-small">
										<?php esc_html_e( 'View', 'wp-breach' ); ?>
									</a>
									<?php if ( $vulnerability['status'] === 'active' ) : ?>
										<button class="button button-small wp-breach-resolve-vulnerability" data-vulnerability-id="<?php echo esc_attr( $vulnerability['id'] ); ?>">
											<?php esc_html_e( 'Resolve', 'wp-breach' ); ?>
										</button>
										<button class="button button-small wp-breach-dismiss-vulnerability" data-vulnerability-id="<?php echo esc_attr( $vulnerability['id'] ); ?>">
											<?php esc_html_e( 'Dismiss', 'wp-breach' ); ?>
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
			<div class="wp-breach-no-vulnerabilities">
				<div class="wp-breach-no-data">
					<span class="dashicons dashicons-shield-alt"></span>
					<h3><?php esc_html_e( 'No vulnerabilities found', 'wp-breach' ); ?></h3>
					<?php if ( $search_query || $severity_filter || $status_filter || $type_filter ) : ?>
						<p><?php esc_html_e( 'No vulnerabilities match your current filters.', 'wp-breach' ); ?></p>
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-breach-vulnerabilities' ) ); ?>" class="button">
							<?php esc_html_e( 'Clear Filters', 'wp-breach' ); ?>
						</a>
					<?php else : ?>
						<p><?php esc_html_e( 'Great! No security vulnerabilities have been detected on your website.', 'wp-breach' ); ?></p>
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-breach' ) ); ?>" class="button button-primary">
							<?php esc_html_e( 'Run New Scan', 'wp-breach' ); ?>
						</a>
					<?php endif; ?>
				</div>
			</div>
		<?php endif; ?>
	</div>

	<!-- Export Options -->
	<div class="wp-breach-export-options">
		<h3><?php esc_html_e( 'Export Options', 'wp-breach' ); ?></h3>
		<div class="wp-breach-export-buttons">
			<a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin.php?page=wp-breach-vulnerabilities&action=export&format=csv' ), 'wp_breach_export' ) ); ?>" class="button">
				<span class="dashicons dashicons-media-spreadsheet"></span>
				<?php esc_html_e( 'Export to CSV', 'wp-breach' ); ?>
			</a>
			<a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin.php?page=wp-breach-vulnerabilities&action=export&format=pdf' ), 'wp_breach_export' ) ); ?>" class="button">
				<span class="dashicons dashicons-media-document"></span>
				<?php esc_html_e( 'Export to PDF', 'wp-breach' ); ?>
			</a>
			<a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin.php?page=wp-breach-vulnerabilities&action=export&format=json' ), 'wp_breach_export' ) ); ?>" class="button">
				<span class="dashicons dashicons-media-code"></span>
				<?php esc_html_e( 'Export to JSON', 'wp-breach' ); ?>
			</a>
		</div>
	</div>
</div>

<!-- Vulnerability Details Modal -->
<div id="wp-breach-vulnerability-modal" class="wp-breach-modal" style="display: none;">
	<div class="wp-breach-modal-content">
		<div class="wp-breach-modal-header">
			<h2><?php esc_html_e( 'Vulnerability Details', 'wp-breach' ); ?></h2>
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

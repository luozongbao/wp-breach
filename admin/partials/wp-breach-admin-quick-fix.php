<?php
/**
 * Provide a admin area view for quick fixes
 *
 * This file is used to markup the quick fix page of the plugin.
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
$fix_model = $database->get_fix_model();

// Get fixable vulnerabilities
$fixable_vulnerabilities = $vulnerability_model->get_fixable_vulnerabilities();
$applied_fixes = $fix_model->get_applied_fixes();

?>

<div class="wrap wp-breach-quick-fix">
	<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>
	
	<!-- Quick Fix Summary -->
	<div class="wp-breach-fix-summary">
		<div class="wp-breach-summary-card">
			<h3><?php echo esc_html( count( $fixable_vulnerabilities ) ); ?></h3>
			<p><?php esc_html_e( 'Issues Can Be Auto-Fixed', 'wp-breach' ); ?></p>
		</div>
		
		<div class="wp-breach-summary-card">
			<h3><?php echo esc_html( count( $applied_fixes ) ); ?></h3>
			<p><?php esc_html_e( 'Fixes Applied', 'wp-breach' ); ?></p>
		</div>
	</div>

	<!-- Bulk Fix Actions -->
	<div class="wp-breach-bulk-fix">
		<h2><?php esc_html_e( 'Bulk Fix Actions', 'wp-breach' ); ?></h2>
		<div class="wp-breach-bulk-actions">
			<button id="wp-breach-fix-all-safe" class="button button-primary" <?php echo empty( $fixable_vulnerabilities ) ? 'disabled' : ''; ?>>
				<span class="dashicons dashicons-yes-alt"></span>
				<?php esc_html_e( 'Apply All Safe Fixes', 'wp-breach' ); ?>
			</button>
			
			<button id="wp-breach-fix-critical" class="button button-secondary">
				<span class="dashicons dashicons-warning"></span>
				<?php esc_html_e( 'Fix Critical Issues Only', 'wp-breach' ); ?>
			</button>
			
			<button id="wp-breach-backup-before-fix" class="button button-secondary">
				<span class="dashicons dashicons-backup"></span>
				<?php esc_html_e( 'Create Backup & Fix', 'wp-breach' ); ?>
			</button>
		</div>
	</div>

	<!-- Fixable Vulnerabilities -->
	<?php if ( ! empty( $fixable_vulnerabilities ) ) : ?>
		<div class="wp-breach-fixable-vulnerabilities">
			<h2><?php esc_html_e( 'Fixable Vulnerabilities', 'wp-breach' ); ?></h2>
			
			<form id="wp-breach-fix-form" method="post">
				<?php wp_nonce_field( 'wp_breach_apply_fixes', 'wp_breach_fix_nonce' ); ?>
				
				<table class="wp-list-table widefat fixed striped">
					<thead>
						<tr>
							<td class="manage-column column-cb check-column">
								<input type="checkbox" id="select-all-fixes">
							</td>
							<th class="manage-column column-vulnerability"><?php esc_html_e( 'Vulnerability', 'wp-breach' ); ?></th>
							<th class="manage-column column-severity"><?php esc_html_e( 'Severity', 'wp-breach' ); ?></th>
							<th class="manage-column column-fix-type"><?php esc_html_e( 'Fix Type', 'wp-breach' ); ?></th>
							<th class="manage-column column-risk"><?php esc_html_e( 'Fix Risk', 'wp-breach' ); ?></th>
							<th class="manage-column column-actions"><?php esc_html_e( 'Actions', 'wp-breach' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $fixable_vulnerabilities as $vulnerability ) : ?>
							<tr class="wp-breach-fix-row">
								<th class="check-column">
									<input type="checkbox" name="fix_ids[]" value="<?php echo esc_attr( $vulnerability['id'] ); ?>">
								</th>
								<td class="column-vulnerability">
									<strong><?php echo esc_html( $vulnerability['title'] ); ?></strong>
									<div class="wp-breach-vulnerability-description">
										<?php echo esc_html( wp_trim_words( $vulnerability['description'], 15 ) ); ?>
									</div>
									<?php if ( ! empty( $vulnerability['file_path'] ) ) : ?>
										<div class="wp-breach-vulnerability-location">
											<span class="dashicons dashicons-media-code"></span>
											<?php echo esc_html( $vulnerability['file_path'] ); ?>
										</div>
									<?php endif; ?>
								</td>
								<td class="column-severity">
									<span class="wp-breach-severity wp-breach-severity-<?php echo esc_attr( $vulnerability['severity'] ); ?>">
										<?php echo esc_html( ucfirst( $vulnerability['severity'] ) ); ?>
									</span>
								</td>
								<td class="column-fix-type">
									<?php
									$fix_type = $vulnerability['fix_type'] ?? 'manual';
									$fix_labels = array(
										'automatic' => __( 'Automatic', 'wp-breach' ),
										'configuration' => __( 'Configuration', 'wp-breach' ),
										'file_permission' => __( 'File Permissions', 'wp-breach' ),
										'code_update' => __( 'Code Update', 'wp-breach' ),
										'plugin_update' => __( 'Plugin Update', 'wp-breach' ),
										'manual' => __( 'Manual', 'wp-breach' ),
									);
									echo esc_html( $fix_labels[ $fix_type ] ?? $fix_type );
									?>
								</td>
								<td class="column-risk">
									<?php
									$risk_level = $vulnerability['fix_risk'] ?? 'medium';
									$risk_classes = array(
										'low' => 'wp-breach-risk-low',
										'medium' => 'wp-breach-risk-medium',
										'high' => 'wp-breach-risk-high',
									);
									$risk_labels = array(
										'low' => __( 'Low Risk', 'wp-breach' ),
										'medium' => __( 'Medium Risk', 'wp-breach' ),
										'high' => __( 'High Risk', 'wp-breach' ),
									);
									?>
									<span class="wp-breach-fix-risk <?php echo esc_attr( $risk_classes[ $risk_level ] ?? '' ); ?>">
										<?php echo esc_html( $risk_labels[ $risk_level ] ?? $risk_level ); ?>
									</span>
								</td>
								<td class="column-actions">
									<div class="wp-breach-fix-actions">
										<button class="button button-small wp-breach-apply-fix" 
											data-vulnerability-id="<?php echo esc_attr( $vulnerability['id'] ); ?>"
											data-fix-type="<?php echo esc_attr( $fix_type ); ?>">
											<?php esc_html_e( 'Apply Fix', 'wp-breach' ); ?>
										</button>
										
										<button class="button button-small wp-breach-view-fix-details" 
											data-vulnerability-id="<?php echo esc_attr( $vulnerability['id'] ); ?>">
											<?php esc_html_e( 'Details', 'wp-breach' ); ?>
										</button>
									</div>
								</td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
				
				<div class="wp-breach-fix-selected-actions">
					<button type="submit" name="apply_selected_fixes" class="button button-primary">
						<?php esc_html_e( 'Apply Selected Fixes', 'wp-breach' ); ?>
					</button>
				</div>
			</form>
		</div>
	<?php else : ?>
		<div class="wp-breach-no-fixes">
			<div class="wp-breach-no-data">
				<span class="dashicons dashicons-yes-alt"></span>
				<h3><?php esc_html_e( 'No Automatic Fixes Available', 'wp-breach' ); ?></h3>
				<p><?php esc_html_e( 'All current vulnerabilities require manual intervention.', 'wp-breach' ); ?></p>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-breach-vulnerabilities' ) ); ?>" class="button button-primary">
					<?php esc_html_e( 'View All Vulnerabilities', 'wp-breach' ); ?>
				</a>
			</div>
		</div>
	<?php endif; ?>

	<!-- Applied Fixes History -->
	<?php if ( ! empty( $applied_fixes ) ) : ?>
		<div class="wp-breach-applied-fixes">
			<h2><?php esc_html_e( 'Recently Applied Fixes', 'wp-breach' ); ?></h2>
			
			<table class="wp-list-table widefat fixed striped">
				<thead>
					<tr>
						<th class="manage-column column-vulnerability"><?php esc_html_e( 'Vulnerability', 'wp-breach' ); ?></th>
						<th class="manage-column column-fix-type"><?php esc_html_e( 'Fix Applied', 'wp-breach' ); ?></th>
						<th class="manage-column column-applied-date"><?php esc_html_e( 'Applied', 'wp-breach' ); ?></th>
						<th class="manage-column column-status"><?php esc_html_e( 'Status', 'wp-breach' ); ?></th>
						<th class="manage-column column-actions"><?php esc_html_e( 'Actions', 'wp-breach' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( array_slice( $applied_fixes, 0, 10 ) as $fix ) : ?>
						<tr class="wp-breach-applied-fix-row">
							<td class="column-vulnerability">
								<strong><?php echo esc_html( $fix['vulnerability_title'] ); ?></strong>
								<div class="wp-breach-fix-description">
									<?php echo esc_html( $fix['fix_description'] ); ?>
								</div>
							</td>
							<td class="column-fix-type">
								<?php echo esc_html( $fix['fix_type'] ); ?>
							</td>
							<td class="column-applied-date">
								<?php echo esc_html( human_time_diff( strtotime( $fix['applied_at'] ), current_time( 'timestamp' ) ) . ' ago' ); ?>
							</td>
							<td class="column-status">
								<span class="wp-breach-fix-status wp-breach-status-<?php echo esc_attr( $fix['status'] ); ?>">
									<?php echo esc_html( ucfirst( $fix['status'] ) ); ?>
								</span>
							</td>
							<td class="column-actions">
								<div class="wp-breach-fix-actions">
									<?php if ( $fix['status'] === 'success' && $fix['can_rollback'] ) : ?>
										<button class="button button-small wp-breach-rollback-fix" 
											data-fix-id="<?php echo esc_attr( $fix['id'] ); ?>">
											<?php esc_html_e( 'Rollback', 'wp-breach' ); ?>
										</button>
									<?php endif; ?>
									
									<button class="button button-small wp-breach-view-fix-log" 
										data-fix-id="<?php echo esc_attr( $fix['id'] ); ?>">
										<?php esc_html_e( 'View Log', 'wp-breach' ); ?>
									</button>
								</div>
							</td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
			
			<div class="wp-breach-fix-history-footer">
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-breach-quick-fix&view=history' ) ); ?>" class="button">
					<?php esc_html_e( 'View Full Fix History', 'wp-breach' ); ?>
				</a>
			</div>
		</div>
	<?php endif; ?>

	<!-- Fix Guidelines -->
	<div class="wp-breach-fix-guidelines">
		<h2><?php esc_html_e( 'Fix Guidelines', 'wp-breach' ); ?></h2>
		
		<div class="wp-breach-guidelines-grid">
			<div class="wp-breach-guideline-item">
				<div class="wp-breach-guideline-icon wp-breach-icon-backup">
					<span class="dashicons dashicons-backup"></span>
				</div>
				<div class="wp-breach-guideline-content">
					<h4><?php esc_html_e( 'Always Backup First', 'wp-breach' ); ?></h4>
					<p><?php esc_html_e( 'Create a full backup before applying any fixes to ensure you can restore if needed.', 'wp-breach' ); ?></p>
				</div>
			</div>
			
			<div class="wp-breach-guideline-item">
				<div class="wp-breach-guideline-icon wp-breach-icon-test">
					<span class="dashicons dashicons-admin-tools"></span>
				</div>
				<div class="wp-breach-guideline-content">
					<h4><?php esc_html_e( 'Test on Staging', 'wp-breach' ); ?></h4>
					<p><?php esc_html_e( 'Apply fixes to a staging environment first to verify they work correctly.', 'wp-breach' ); ?></p>
				</div>
			</div>
			
			<div class="wp-breach-guideline-item">
				<div class="wp-breach-guideline-icon wp-breach-icon-monitor">
					<span class="dashicons dashicons-visibility"></span>
				</div>
				<div class="wp-breach-guideline-content">
					<h4><?php esc_html_e( 'Monitor After Fixes', 'wp-breach' ); ?></h4>
					<p><?php esc_html_e( 'Watch your site closely after applying fixes to ensure everything works normally.', 'wp-breach' ); ?></p>
				</div>
			</div>
		</div>
	</div>
</div>

<!-- Fix Details Modal -->
<div id="wp-breach-fix-details-modal" class="wp-breach-modal" style="display: none;">
	<div class="wp-breach-modal-content">
		<div class="wp-breach-modal-header">
			<h2><?php esc_html_e( 'Fix Details', 'wp-breach' ); ?></h2>
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

<!-- Fix Progress Modal -->
<div id="wp-breach-fix-progress-modal" class="wp-breach-modal" style="display: none;">
	<div class="wp-breach-modal-content">
		<div class="wp-breach-modal-header">
			<h2><?php esc_html_e( 'Applying Fix', 'wp-breach' ); ?></h2>
		</div>
		<div class="wp-breach-modal-body">
			<div class="wp-breach-fix-progress">
				<div class="wp-breach-progress-bar">
					<div class="wp-breach-progress-fill"></div>
				</div>
				<div class="wp-breach-progress-message">
					<p><?php esc_html_e( 'Preparing to apply fix...', 'wp-breach' ); ?></p>
				</div>
			</div>
		</div>
	</div>
</div>

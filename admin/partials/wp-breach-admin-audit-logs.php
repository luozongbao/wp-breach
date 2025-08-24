<?php
/**
 * Provide an admin area view for audit logs.
 *
 * This file is used to markup the audit logs interface.
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

$audit_stats = $this->permissions_manager->get_audit_log(array('limit' => 1000));
?>

<div class="wrap">
	<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>
	
	<div class="wp-breach-audit-dashboard">
		<div class="wp-breach-stats">
			<div class="wp-breach-stat-card">
				<div class="wp-breach-stat-number" id="total-entries">-</div>
				<div class="wp-breach-stat-label"><?php _e('Total Entries', 'wp-breach'); ?></div>
			</div>
			<div class="wp-breach-stat-card">
				<div class="wp-breach-stat-number" id="high-severity">-</div>
				<div class="wp-breach-stat-label"><?php _e('High Severity', 'wp-breach'); ?></div>
			</div>
			<div class="wp-breach-stat-card">
				<div class="wp-breach-stat-number" id="failed-logins">-</div>
				<div class="wp-breach-stat-label"><?php _e('Failed Logins', 'wp-breach'); ?></div>
			</div>
			<div class="wp-breach-stat-card">
				<div class="wp-breach-stat-number" id="unique-users">-</div>
				<div class="wp-breach-stat-label"><?php _e('Active Users', 'wp-breach'); ?></div>
			</div>
		</div>
		
		<div class="wp-breach-audit-filters">
			<div class="wp-breach-filter-row">
				<div class="wp-breach-filter-group">
					<label for="audit-user-filter"><?php _e('User:', 'wp-breach'); ?></label>
					<select id="audit-user-filter">
						<option value=""><?php _e('All Users', 'wp-breach'); ?></option>
						<!-- Users will be populated via JavaScript -->
					</select>
				</div>
				
				<div class="wp-breach-filter-group">
					<label for="audit-action-filter"><?php _e('Action:', 'wp-breach'); ?></label>
					<select id="audit-action-filter">
						<option value=""><?php _e('All Actions', 'wp-breach'); ?></option>
						<option value="user_login"><?php _e('User Login', 'wp-breach'); ?></option>
						<option value="user_logout"><?php _e('User Logout', 'wp-breach'); ?></option>
						<option value="login_failed"><?php _e('Login Failed', 'wp-breach'); ?></option>
						<option value="role_assigned"><?php _e('Role Assigned', 'wp-breach'); ?></option>
						<option value="role_removed"><?php _e('Role Removed', 'wp-breach'); ?></option>
						<option value="capability_added"><?php _e('Capability Added', 'wp-breach'); ?></option>
						<option value="capability_removed"><?php _e('Capability Removed', 'wp-breach'); ?></option>
						<option value="permission_delegated"><?php _e('Permission Delegated', 'wp-breach'); ?></option>
						<option value="delegation_revoked"><?php _e('Delegation Revoked', 'wp-breach'); ?></option>
						<option value="access_granted"><?php _e('Access Granted', 'wp-breach'); ?></option>
						<option value="access_denied"><?php _e('Access Denied', 'wp-breach'); ?></option>
					</select>
				</div>
				
				<div class="wp-breach-filter-group">
					<label for="audit-severity-filter"><?php _e('Severity:', 'wp-breach'); ?></label>
					<select id="audit-severity-filter">
						<option value=""><?php _e('All Severities', 'wp-breach'); ?></option>
						<option value="low"><?php _e('Low', 'wp-breach'); ?></option>
						<option value="medium"><?php _e('Medium', 'wp-breach'); ?></option>
						<option value="high"><?php _e('High', 'wp-breach'); ?></option>
					</select>
				</div>
			</div>
			
			<div class="wp-breach-filter-row">
				<div class="wp-breach-filter-group">
					<label for="audit-start-date"><?php _e('Start Date:', 'wp-breach'); ?></label>
					<input type="date" id="audit-start-date" value="<?php echo date('Y-m-d', strtotime('-7 days')); ?>">
				</div>
				
				<div class="wp-breach-filter-group">
					<label for="audit-end-date"><?php _e('End Date:', 'wp-breach'); ?></label>
					<input type="date" id="audit-end-date" value="<?php echo date('Y-m-d'); ?>">
				</div>
				
				<div class="wp-breach-filter-group">
					<button type="button" id="apply-audit-filters" class="wp-breach-btn">
						<?php _e('Apply Filters', 'wp-breach'); ?>
					</button>
					<button type="button" id="reset-audit-filters" class="wp-breach-btn secondary">
						<?php _e('Reset', 'wp-breach'); ?>
					</button>
				</div>
			</div>
		</div>
		
		<div class="wp-breach-audit-actions">
			<button type="button" id="export-audit-csv" class="wp-breach-btn secondary">
				<?php _e('Export CSV', 'wp-breach'); ?>
			</button>
			<button type="button" id="export-audit-json" class="wp-breach-btn secondary">
				<?php _e('Export JSON', 'wp-breach'); ?>
			</button>
			<button type="button" id="refresh-audit-logs" class="wp-breach-btn">
				<?php _e('Refresh', 'wp-breach'); ?>
			</button>
		</div>
		
		<div class="wp-breach-audit-table-container">
			<table class="wp-list-table widefat fixed striped" id="audit-logs-table">
				<thead>
					<tr>
						<th scope="col" class="manage-column column-timestamp">
							<a href="#" data-sort="timestamp">
								<?php _e('Timestamp', 'wp-breach'); ?>
								<span class="sorting-indicator"></span>
							</a>
						</th>
						<th scope="col" class="manage-column column-user">
							<a href="#" data-sort="user_id">
								<?php _e('User', 'wp-breach'); ?>
								<span class="sorting-indicator"></span>
							</a>
						</th>
						<th scope="col" class="manage-column column-action">
							<a href="#" data-sort="action">
								<?php _e('Action', 'wp-breach'); ?>
								<span class="sorting-indicator"></span>
							</a>
						</th>
						<th scope="col" class="manage-column column-severity">
							<a href="#" data-sort="severity">
								<?php _e('Severity', 'wp-breach'); ?>
								<span class="sorting-indicator"></span>
							</a>
						</th>
						<th scope="col" class="manage-column column-ip">
							<?php _e('IP Address', 'wp-breach'); ?>
						</th>
						<th scope="col" class="manage-column column-details">
							<?php _e('Details', 'wp-breach'); ?>
						</th>
					</tr>
				</thead>
				<tbody id="audit-logs-tbody">
					<tr>
						<td colspan="6" class="wp-breach-loading">
							<?php _e('Loading audit logs...', 'wp-breach'); ?>
						</td>
					</tr>
				</tbody>
			</table>
		</div>
		
		<div class="wp-breach-pagination">
			<div class="wp-breach-pagination-info">
				<span id="pagination-info"><?php _e('Showing 0 of 0 entries', 'wp-breach'); ?></span>
			</div>
			<div class="wp-breach-pagination-controls">
				<button type="button" id="prev-page" class="wp-breach-btn secondary" disabled>
					<?php _e('Previous', 'wp-breach'); ?>
				</button>
				<span id="page-info">1 / 1</span>
				<button type="button" id="next-page" class="wp-breach-btn secondary" disabled>
					<?php _e('Next', 'wp-breach'); ?>
				</button>
			</div>
		</div>
	</div>
</div>

<!-- Audit Log Details Modal -->
<div id="audit-details-modal" class="wp-breach-modal" style="display: none;">
	<div class="wp-breach-modal-content">
		<div class="wp-breach-modal-header">
			<h2><?php _e('Audit Log Details', 'wp-breach'); ?></h2>
			<button type="button" class="wp-breach-modal-close">&times;</button>
		</div>
		<div class="wp-breach-modal-body">
			<div id="audit-details-content"></div>
		</div>
		<div class="wp-breach-modal-footer">
			<button type="button" class="wp-breach-btn secondary" onclick="closeAuditModal()">
				<?php _e('Close', 'wp-breach'); ?>
			</button>
		</div>
	</div>
</div>

<style>
.wp-breach-audit-dashboard {
	margin-top: 20px;
}

.wp-breach-stats {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
	gap: 15px;
	margin-bottom: 20px;
}

.wp-breach-stat-card {
	background: #fff;
	border: 1px solid #c3c4c7;
	border-radius: 4px;
	padding: 15px;
	text-align: center;
}

.wp-breach-stat-number {
	font-size: 24px;
	font-weight: bold;
	color: #0073aa;
}

.wp-breach-stat-label {
	font-size: 12px;
	color: #646970;
	text-transform: uppercase;
	margin-top: 5px;
}

.wp-breach-audit-filters {
	background: #fff;
	border: 1px solid #c3c4c7;
	border-radius: 4px;
	padding: 20px;
	margin-bottom: 20px;
}

.wp-breach-filter-row {
	display: flex;
	gap: 20px;
	margin-bottom: 15px;
	align-items: end;
}

.wp-breach-filter-row:last-child {
	margin-bottom: 0;
}

.wp-breach-filter-group {
	display: flex;
	flex-direction: column;
	min-width: 150px;
}

.wp-breach-filter-group label {
	font-weight: 600;
	margin-bottom: 5px;
	font-size: 13px;
}

.wp-breach-filter-group select,
.wp-breach-filter-group input {
	padding: 6px 8px;
	border: 1px solid #8c8f94;
	border-radius: 3px;
}

.wp-breach-audit-actions {
	display: flex;
	gap: 10px;
	margin-bottom: 20px;
}

.wp-breach-audit-table-container {
	background: #fff;
	border: 1px solid #c3c4c7;
	border-radius: 4px;
	overflow-x: auto;
}

#audit-logs-table {
	margin: 0;
}

#audit-logs-table th {
	background: #f6f7f7;
	border-bottom: 1px solid #c3c4c7;
}

#audit-logs-table th a {
	text-decoration: none;
	color: #2c3338;
	display: flex;
	align-items: center;
	justify-content: space-between;
}

.sorting-indicator {
	width: 0;
	height: 0;
	margin-left: 8px;
	border: 4px solid transparent;
}

.sorting-indicator.asc {
	border-bottom: 8px solid #2c3338;
}

.sorting-indicator.desc {
	border-top: 8px solid #2c3338;
}

.wp-breach-severity-badge {
	padding: 3px 8px;
	border-radius: 3px;
	font-size: 11px;
	font-weight: bold;
	text-transform: uppercase;
}

.wp-breach-severity-badge.low {
	background: #00a32a;
	color: white;
}

.wp-breach-severity-badge.medium {
	background: #d54e21;
	color: white;
}

.wp-breach-severity-badge.high {
	background: #d63638;
	color: white;
}

.wp-breach-action-badge {
	padding: 3px 8px;
	border-radius: 3px;
	font-size: 11px;
	background: #f0f0f1;
	color: #2c3338;
}

.wp-breach-pagination {
	display: flex;
	justify-content: space-between;
	align-items: center;
	margin-top: 20px;
	padding: 15px 0;
}

.wp-breach-pagination-controls {
	display: flex;
	align-items: center;
	gap: 15px;
}

#page-info {
	font-weight: 600;
	color: #2c3338;
}

.wp-breach-modal {
	display: none;
	position: fixed;
	z-index: 100000;
	left: 0;
	top: 0;
	width: 100%;
	height: 100%;
	background-color: rgba(0,0,0,0.5);
}

.wp-breach-modal-content {
	background-color: #fff;
	margin: 5% auto;
	border: 1px solid #c3c4c7;
	border-radius: 4px;
	width: 80%;
	max-width: 600px;
	max-height: 80%;
	overflow-y: auto;
}

.wp-breach-modal-header {
	padding: 15px 20px;
	border-bottom: 1px solid #c3c4c7;
	display: flex;
	justify-content: space-between;
	align-items: center;
}

.wp-breach-modal-header h2 {
	margin: 0;
}

.wp-breach-modal-close {
	background: none;
	border: none;
	font-size: 24px;
	cursor: pointer;
	color: #646970;
}

.wp-breach-modal-close:hover {
	color: #d63638;
}

.wp-breach-modal-body {
	padding: 20px;
}

.wp-breach-modal-footer {
	padding: 15px 20px;
	border-top: 1px solid #c3c4c7;
	text-align: right;
}

.wp-breach-detail-row {
	display: flex;
	margin-bottom: 10px;
	border-bottom: 1px solid #f0f0f1;
	padding-bottom: 8px;
}

.wp-breach-detail-label {
	font-weight: 600;
	width: 150px;
	color: #2c3338;
}

.wp-breach-detail-value {
	flex: 1;
	color: #646970;
}

.wp-breach-loading {
	text-align: center;
	padding: 40px;
	font-style: italic;
	color: #646970;
}

.wp-breach-btn {
	padding: 8px 16px;
	border: 1px solid #0073aa;
	background: #0073aa;
	color: white;
	text-decoration: none;
	border-radius: 3px;
	cursor: pointer;
	font-size: 13px;
	transition: all 0.2s;
	display: inline-block;
}

.wp-breach-btn:hover {
	background: #005a87;
	border-color: #005a87;
	color: white;
}

.wp-breach-btn.secondary {
	background: white;
	color: #0073aa;
}

.wp-breach-btn.secondary:hover {
	background: #f6f7f7;
	color: #005a87;
}

.wp-breach-btn:disabled {
	background: #f6f7f7;
	border-color: #dcdcde;
	color: #a7aaad;
	cursor: not-allowed;
}

@media (max-width: 768px) {
	.wp-breach-filter-row {
		flex-direction: column;
		align-items: stretch;
	}
	
	.wp-breach-filter-group {
		min-width: auto;
	}
	
	.wp-breach-pagination {
		flex-direction: column;
		gap: 15px;
	}
}
</style>

<script>
jQuery(document).ready(function($) {
	let currentPage = 1;
	let currentSort = { column: 'timestamp', order: 'desc' };
	
	// Initialize
	loadAuditStats();
	loadAuditLogs();
	
	// Event handlers
	$('#apply-audit-filters').on('click', function() {
		currentPage = 1;
		loadAuditLogs();
	});
	
	$('#reset-audit-filters').on('click', function() {
		$('#audit-user-filter').val('');
		$('#audit-action-filter').val('');
		$('#audit-severity-filter').val('');
		$('#audit-start-date').val('<?php echo date('Y-m-d', strtotime('-7 days')); ?>');
		$('#audit-end-date').val('<?php echo date('Y-m-d'); ?>');
		currentPage = 1;
		loadAuditLogs();
	});
	
	$('#refresh-audit-logs').on('click', function() {
		loadAuditStats();
		loadAuditLogs();
	});
	
	$('#prev-page').on('click', function() {
		if (currentPage > 1) {
			currentPage--;
			loadAuditLogs();
		}
	});
	
	$('#next-page').on('click', function() {
		currentPage++;
		loadAuditLogs();
	});
	
	// Sorting
	$('#audit-logs-table th a[data-sort]').on('click', function(e) {
		e.preventDefault();
		const column = $(this).data('sort');
		
		if (currentSort.column === column) {
			currentSort.order = currentSort.order === 'asc' ? 'desc' : 'asc';
		} else {
			currentSort.column = column;
			currentSort.order = 'desc';
		}
		
		updateSortingIndicators();
		currentPage = 1;
		loadAuditLogs();
	});
	
	// Export functions
	$('#export-audit-csv').on('click', function() {
		exportAuditLogs('csv');
	});
	
	$('#export-audit-json').on('click', function() {
		exportAuditLogs('json');
	});
	
	// Modal handlers
	$('.wp-breach-modal-close').on('click', closeAuditModal);
	$('#audit-details-modal').on('click', function(e) {
		if (e.target === this) {
			closeAuditModal();
		}
	});
	
	function loadAuditStats() {
		$.ajax({
			url: wpBreachUserManagement.ajax_url,
			type: 'POST',
			data: {
				action: 'wp_breach_get_audit_stats',
				nonce: wpBreachUserManagement.nonce,
				start_date: $('#audit-start-date').val(),
				end_date: $('#audit-end-date').val()
			},
			success: function(response) {
				if (response.success) {
					const stats = response.data;
					$('#total-entries').text(stats.total_entries || 0);
					$('#high-severity').text(stats.by_severity?.high || 0);
					$('#failed-logins').text(stats.failed_logins || 0);
					$('#unique-users').text(stats.unique_users || 0);
				}
			}
		});
	}
	
	function loadAuditLogs() {
		const filters = {
			user_id: $('#audit-user-filter').val(),
			action: $('#audit-action-filter').val(),
			severity: $('#audit-severity-filter').val(),
			start_date: $('#audit-start-date').val(),
			end_date: $('#audit-end-date').val()
		};
		
		$('#audit-logs-tbody').html('<tr><td colspan="6" class="wp-breach-loading">Loading...</td></tr>');
		
		$.ajax({
			url: wpBreachUserManagement.ajax_url,
			type: 'POST',
			data: {
				action: 'wp_breach_get_audit_logs',
				nonce: wpBreachUserManagement.nonce,
				page: currentPage,
				per_page: 20,
				filters: filters,
				sort: currentSort
			},
			success: function(response) {
				if (response.success) {
					renderAuditLogs(response.data.logs);
					updatePagination(response.data);
				} else {
					$('#audit-logs-tbody').html('<tr><td colspan="6">Error loading logs</td></tr>');
				}
			},
			error: function() {
				$('#audit-logs-tbody').html('<tr><td colspan="6">Error loading logs</td></tr>');
			}
		});
	}
	
	function renderAuditLogs(logs) {
		if (!logs || logs.length === 0) {
			$('#audit-logs-tbody').html('<tr><td colspan="6">No audit logs found</td></tr>');
			return;
		}
		
		let html = '';
		logs.forEach(function(log) {
			const user = log.user_login || `User ID: ${log.user_id}`;
			const timestamp = new Date(log.timestamp).toLocaleString();
			const severityClass = log.severity || 'low';
			const details = log.details ? JSON.stringify(log.details).substring(0, 100) + '...' : '';
			
			html += `
				<tr>
					<td>${timestamp}</td>
					<td>${user}</td>
					<td><span class="wp-breach-action-badge">${log.action}</span></td>
					<td><span class="wp-breach-severity-badge ${severityClass}">${log.severity}</span></td>
					<td>${log.ip_address}</td>
					<td>
						<button type="button" class="wp-breach-btn secondary" onclick="viewAuditDetails(${log.id})">
							View Details
						</button>
					</td>
				</tr>
			`;
		});
		
		$('#audit-logs-tbody').html(html);
	}
	
	function updatePagination(data) {
		const totalPages = Math.ceil(data.total / data.per_page);
		
		$('#pagination-info').text(`Showing ${((currentPage - 1) * data.per_page) + 1}-${Math.min(currentPage * data.per_page, data.total)} of ${data.total} entries`);
		$('#page-info').text(`${currentPage} / ${totalPages}`);
		
		$('#prev-page').prop('disabled', currentPage <= 1);
		$('#next-page').prop('disabled', currentPage >= totalPages);
	}
	
	function updateSortingIndicators() {
		$('.sorting-indicator').removeClass('asc desc');
		$(`#audit-logs-table th a[data-sort="${currentSort.column}"] .sorting-indicator`).addClass(currentSort.order);
	}
	
	function exportAuditLogs(format) {
		const filters = {
			user_id: $('#audit-user-filter').val(),
			action: $('#audit-action-filter').val(),
			severity: $('#audit-severity-filter').val(),
			start_date: $('#audit-start-date').val(),
			end_date: $('#audit-end-date').val()
		};
		
		window.location.href = ajaxurl + '?' + $.param({
			action: 'wp_breach_export_audit_logs',
			nonce: wpBreachUserManagement.nonce,
			format: format,
			...filters
		});
	}
	
	window.viewAuditDetails = function(logId) {
		// Load and display detailed audit log information
		$.ajax({
			url: wpBreachUserManagement.ajax_url,
			type: 'POST',
			data: {
				action: 'wp_breach_get_audit_log_details',
				nonce: wpBreachUserManagement.nonce,
				log_id: logId
			},
			success: function(response) {
				if (response.success) {
					showAuditDetails(response.data);
				}
			}
		});
	};
	
	function showAuditDetails(log) {
		let html = '';
		
		const fields = {
			'ID': log.id,
			'Timestamp': new Date(log.timestamp).toLocaleString(),
			'User': log.user_login || `User ID: ${log.user_id}`,
			'Action': log.action,
			'Severity': log.severity,
			'IP Address': log.ip_address,
			'User Agent': log.user_agent
		};
		
		Object.entries(fields).forEach(([label, value]) => {
			html += `
				<div class="wp-breach-detail-row">
					<div class="wp-breach-detail-label">${label}:</div>
					<div class="wp-breach-detail-value">${value || 'N/A'}</div>
				</div>
			`;
		});
		
		if (log.details) {
			html += `
				<div class="wp-breach-detail-row">
					<div class="wp-breach-detail-label">Details:</div>
					<div class="wp-breach-detail-value"><pre>${JSON.stringify(log.details, null, 2)}</pre></div>
				</div>
			`;
		}
		
		$('#audit-details-content').html(html);
		$('#audit-details-modal').show();
	}
	
	window.closeAuditModal = function() {
		$('#audit-details-modal').hide();
	};
});
</script>

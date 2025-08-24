<?php
/**
 * Provide an admin area view for user management.
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

$custom_roles = $this->permissions_manager->get_custom_roles();
$custom_capabilities = $this->permissions_manager->get_custom_capabilities();
?>

<div class="wrap">
	<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>

	<nav class="nav-tab-wrapper">
		<a href="?page=wp-breach-users&tab=users" class="nav-tab <?php echo $active_tab === 'users' ? 'nav-tab-active' : ''; ?>">
			<?php _e( 'Users & Roles', 'wp-breach' ); ?>
		</a>
		<a href="?page=wp-breach-users&tab=roles" class="nav-tab <?php echo $active_tab === 'roles' ? 'nav-tab-active' : ''; ?>">
			<?php _e( 'Role Management', 'wp-breach' ); ?>
		</a>
		<a href="?page=wp-breach-users&tab=capabilities" class="nav-tab <?php echo $active_tab === 'capabilities' ? 'nav-tab-active' : ''; ?>">
			<?php _e( 'Capabilities', 'wp-breach' ); ?>
		</a>
		<a href="?page=wp-breach-users&tab=delegations" class="nav-tab <?php echo $active_tab === 'delegations' ? 'nav-tab-active' : ''; ?>">
			<?php _e( 'Delegations', 'wp-breach' ); ?>
		</a>
		<a href="?page=wp-breach-users&tab=settings" class="nav-tab <?php echo $active_tab === 'settings' ? 'nav-tab-active' : ''; ?>">
			<?php _e( 'Settings', 'wp-breach' ); ?>
		</a>
	</nav>

	<div class="tab-content">
		<?php if ( $active_tab === 'users' ) : ?>
			<?php $this->render_users_tab(); ?>
		<?php elseif ( $active_tab === 'roles' ) : ?>
			<?php $this->render_roles_tab(); ?>
		<?php elseif ( $active_tab === 'capabilities' ) : ?>
			<?php $this->render_capabilities_tab(); ?>
		<?php elseif ( $active_tab === 'delegations' ) : ?>
			<?php $this->render_delegations_tab(); ?>
		<?php elseif ( $active_tab === 'settings' ) : ?>
			<?php $this->render_settings_tab(); ?>
		<?php endif; ?>
	</div>
</div>

<style>
.wp-breach-user-management {
	margin-top: 20px;
}

.wp-breach-user-card {
	background: #fff;
	border: 1px solid #c3c4c7;
	border-radius: 4px;
	margin: 10px 0;
	padding: 15px;
	box-shadow: 0 1px 1px rgba(0,0,0,.04);
}

.wp-breach-user-header {
	display: flex;
	justify-content: space-between;
	align-items: center;
	margin-bottom: 10px;
}

.wp-breach-user-info h3 {
	margin: 0;
	font-size: 16px;
}

.wp-breach-user-email {
	color: #646970;
	font-size: 13px;
}

.wp-breach-roles {
	margin: 10px 0;
}

.wp-breach-role-badge {
	display: inline-block;
	background: #0073aa;
	color: white;
	padding: 3px 8px;
	border-radius: 3px;
	font-size: 11px;
	margin-right: 5px;
}

.wp-breach-role-badge.security-administrator {
	background: #d63638;
}

.wp-breach-role-badge.security-manager {
	background: #d54e21;
}

.wp-breach-role-badge.security-analyst {
	background: #0073aa;
}

.wp-breach-role-badge.security-viewer {
	background: #00a32a;
}

.wp-breach-capabilities {
	margin: 10px 0;
	font-size: 13px;
	color: #646970;
}

.wp-breach-user-actions {
	display: flex;
	gap: 10px;
}

.wp-breach-btn {
	padding: 6px 12px;
	border: 1px solid #0073aa;
	background: #0073aa;
	color: white;
	text-decoration: none;
	border-radius: 3px;
	cursor: pointer;
	font-size: 13px;
	transition: all 0.2s;
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

.wp-breach-btn.danger {
	background: #d63638;
	border-color: #d63638;
}

.wp-breach-btn.danger:hover {
	background: #b32d2e;
	border-color: #b32d2e;
}

.wp-breach-form-grid {
	display: grid;
	grid-template-columns: 1fr 1fr;
	gap: 20px;
	margin-top: 20px;
}

.wp-breach-form-section {
	background: #fff;
	border: 1px solid #c3c4c7;
	border-radius: 4px;
	padding: 20px;
}

.wp-breach-form-section h3 {
	margin-top: 0;
	border-bottom: 1px solid #e1e1e1;
	padding-bottom: 10px;
}

.wp-breach-search-box {
	margin-bottom: 20px;
}

.wp-breach-search-box input {
	width: 300px;
	margin-right: 10px;
}

.wp-breach-filters {
	display: flex;
	gap: 15px;
	margin-bottom: 20px;
}

.wp-breach-filters select {
	min-width: 150px;
}

.wp-breach-pagination {
	text-align: center;
	margin-top: 20px;
}

.wp-breach-loading {
	text-align: center;
	padding: 20px;
	font-style: italic;
	color: #646970;
}

.wp-breach-capability-list {
	max-height: 200px;
	overflow-y: auto;
	border: 1px solid #ddd;
	padding: 10px;
	background: #f9f9f9;
}

.wp-breach-capability-item {
	display: flex;
	justify-content: space-between;
	align-items: center;
	padding: 5px 0;
	border-bottom: 1px solid #eee;
}

.wp-breach-capability-item:last-child {
	border-bottom: none;
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

@media (max-width: 768px) {
	.wp-breach-form-grid {
		grid-template-columns: 1fr;
	}
	
	.wp-breach-filters {
		flex-direction: column;
	}
	
	.wp-breach-user-header {
		flex-direction: column;
		align-items: flex-start;
	}
	
	.wp-breach-user-actions {
		margin-top: 10px;
		width: 100%;
	}
}
</style>

<script>
jQuery(document).ready(function($) {
	// User search functionality
	$('#wp-breach-user-search').on('keyup', function() {
		var searchTerm = $(this).val();
		// Implement search logic
	});
	
	// Role assignment
	$('.wp-breach-assign-role').on('click', function(e) {
		e.preventDefault();
		var userId = $(this).data('user-id');
		var role = $(this).data('role');
		
		if (confirm(wpBreachUserManagement.strings.confirm_assign_role)) {
			assignRole(userId, role);
		}
	});
	
	// Role removal
	$('.wp-breach-remove-role').on('click', function(e) {
		e.preventDefault();
		var userId = $(this).data('user-id');
		var role = $(this).data('role');
		
		if (confirm(wpBreachUserManagement.strings.confirm_remove_role)) {
			removeRole(userId, role);
		}
	});
	
	function assignRole(userId, role) {
		$.ajax({
			url: wpBreachUserManagement.ajax_url,
			type: 'POST',
			data: {
				action: 'wp_breach_assign_role',
				nonce: wpBreachUserManagement.nonce,
				user_id: userId,
				role: role
			},
			success: function(response) {
				if (response.success) {
					location.reload();
				} else {
					alert(response.data || wpBreachUserManagement.strings.error_occurred);
				}
			},
			error: function() {
				alert(wpBreachUserManagement.strings.error_occurred);
			}
		});
	}
	
	function removeRole(userId, role) {
		$.ajax({
			url: wpBreachUserManagement.ajax_url,
			type: 'POST',
			data: {
				action: 'wp_breach_remove_role',
				nonce: wpBreachUserManagement.nonce,
				user_id: userId,
				role: role
			},
			success: function(response) {
				if (response.success) {
					location.reload();
				} else {
					alert(response.data || wpBreachUserManagement.strings.error_occurred);
				}
			},
			error: function() {
				alert(wpBreachUserManagement.strings.error_occurred);
			}
		});
	}
});
</script>

<?php
// Add methods to render each tab
if ( ! function_exists( 'render_users_tab' ) ) {
	function render_users_tab() {
		global $wp_breach_user_management_admin;
		$users = $wp_breach_user_management_admin->get_users_for_management();
		$custom_roles = $wp_breach_user_management_admin->permissions_manager->get_custom_roles();
		?>
		<div class="wp-breach-user-management">
			<div class="wp-breach-stats">
				<div class="wp-breach-stat-card">
					<div class="wp-breach-stat-number"><?php echo count($users); ?></div>
					<div class="wp-breach-stat-label"><?php _e('Total Users', 'wp-breach'); ?></div>
				</div>
				<div class="wp-breach-stat-card">
					<div class="wp-breach-stat-number"><?php echo count(array_filter($users, function($u) { return !empty($u['security_roles']); })); ?></div>
					<div class="wp-breach-stat-label"><?php _e('Security Users', 'wp-breach'); ?></div>
				</div>
				<div class="wp-breach-stat-card">
					<div class="wp-breach-stat-number"><?php echo count($custom_roles); ?></div>
					<div class="wp-breach-stat-label"><?php _e('Security Roles', 'wp-breach'); ?></div>
				</div>
			</div>
			
			<div class="wp-breach-search-box">
				<input type="text" id="wp-breach-user-search" placeholder="<?php _e('Search users...', 'wp-breach'); ?>">
				<button type="button" class="button"><?php _e('Search', 'wp-breach'); ?></button>
			</div>
			
			<div class="wp-breach-filters">
				<select id="wp-breach-role-filter">
					<option value=""><?php _e('All Roles', 'wp-breach'); ?></option>
					<?php foreach ($custom_roles as $role_slug => $role_data) : ?>
						<option value="<?php echo esc_attr($role_slug); ?>"><?php echo esc_html($role_data['name']); ?></option>
					<?php endforeach; ?>
				</select>
			</div>
			
			<div id="wp-breach-users-list">
				<?php foreach ($users as $user) : ?>
					<div class="wp-breach-user-card" data-user-id="<?php echo $user['ID']; ?>">
						<div class="wp-breach-user-header">
							<div class="wp-breach-user-info">
								<h3><?php echo esc_html($user['display_name']); ?> (<?php echo esc_html($user['login']); ?>)</h3>
								<div class="wp-breach-user-email"><?php echo esc_html($user['email']); ?></div>
							</div>
							<div class="wp-breach-user-actions">
								<button type="button" class="wp-breach-btn secondary" onclick="editUser(<?php echo $user['ID']; ?>)">
									<?php _e('Edit', 'wp-breach'); ?>
								</button>
								<button type="button" class="wp-breach-btn" onclick="viewUserDetails(<?php echo $user['ID']; ?>)">
									<?php _e('View Details', 'wp-breach'); ?>
								</button>
							</div>
						</div>
						
						<div class="wp-breach-roles">
							<strong><?php _e('Security Roles:', 'wp-breach'); ?></strong>
							<?php if (!empty($user['security_roles'])) : ?>
								<?php foreach ($user['security_roles'] as $role) : ?>
									<span class="wp-breach-role-badge <?php echo esc_attr($role); ?>">
										<?php echo esc_html($custom_roles[$role]['name']); ?>
									</span>
								<?php endforeach; ?>
							<?php else : ?>
								<span class="wp-breach-role-badge"><?php _e('None', 'wp-breach'); ?></span>
							<?php endif; ?>
						</div>
						
						<div class="wp-breach-capabilities">
							<strong><?php _e('Capabilities:', 'wp-breach'); ?></strong>
							<?php echo count($user['capabilities']); ?> <?php _e('active capabilities', 'wp-breach'); ?>
						</div>
						
						<?php if (!empty($user['delegations'])) : ?>
							<div class="wp-breach-delegations">
								<strong><?php _e('Active Delegations:', 'wp-breach'); ?></strong>
								<?php echo count($user['delegations']); ?> <?php _e('delegations', 'wp-breach'); ?>
							</div>
						<?php endif; ?>
					</div>
				<?php endforeach; ?>
			</div>
		</div>
		<?php
	}
}

if ( ! function_exists( 'render_roles_tab' ) ) {
	function render_roles_tab() {
		global $wp_breach_user_management_admin;
		$custom_roles = $wp_breach_user_management_admin->permissions_manager->get_custom_roles();
		?>
		<div class="wp-breach-form-grid">
			<?php foreach ($custom_roles as $role_slug => $role_data) : ?>
				<div class="wp-breach-form-section">
					<h3><?php echo esc_html($role_data['name']); ?></h3>
					<p><?php echo esc_html($role_data['description']); ?></p>
					
					<div class="wp-breach-capability-list">
						<?php foreach ($role_data['capabilities'] as $capability) : ?>
							<div class="wp-breach-capability-item">
								<span><?php echo esc_html($capability); ?></span>
							</div>
						<?php endforeach; ?>
					</div>
					
					<p><strong><?php _e('Users with this role:', 'wp-breach'); ?></strong>
					<?php 
					$role_users = $wp_breach_user_management_admin->permissions_manager->get_users_by_role($role_slug);
					echo count($role_users);
					?>
					</p>
				</div>
			<?php endforeach; ?>
		</div>
		<?php
	}
}

if ( ! function_exists( 'render_capabilities_tab' ) ) {
	function render_capabilities_tab() {
		global $wp_breach_user_management_admin;
		$custom_capabilities = $wp_breach_user_management_admin->permissions_manager->get_custom_capabilities();
		?>
		<div class="wp-breach-form-section">
			<h3><?php _e('WP-Breach Capabilities', 'wp-breach'); ?></h3>
			<p><?php _e('These are the granular permissions available in the WP-Breach security system.', 'wp-breach'); ?></p>
			
			<div class="wp-breach-capability-list">
				<?php foreach ($custom_capabilities as $capability => $description) : ?>
					<div class="wp-breach-capability-item">
						<span><strong><?php echo esc_html($capability); ?></strong></span>
						<span><?php echo esc_html($description); ?></span>
					</div>
				<?php endforeach; ?>
			</div>
		</div>
		<?php
	}
}

if ( ! function_exists( 'render_delegations_tab' ) ) {
	function render_delegations_tab() {
		?>
		<div class="wp-breach-form-section">
			<h3><?php _e('Permission Delegations', 'wp-breach'); ?></h3>
			<p><?php _e('Manage temporary permission delegations to other users.', 'wp-breach'); ?></p>
			
			<button type="button" class="wp-breach-btn" onclick="openDelegationModal()">
				<?php _e('Create New Delegation', 'wp-breach'); ?>
			</button>
			
			<div id="wp-breach-delegations-list">
				<!-- Delegations will be loaded via AJAX -->
			</div>
		</div>
		<?php
	}
}

if ( ! function_exists( 'render_settings_tab' ) ) {
	function render_settings_tab() {
		?>
		<form method="post" action="options.php">
			<?php
			settings_fields('wp_breach_user_management');
			do_settings_sections('wp_breach_user_management');
			submit_button();
			?>
		</form>
		<?php
	}
}

// Make functions available in scope
$this->render_users_tab = 'render_users_tab';
$this->render_roles_tab = 'render_roles_tab';
$this->render_capabilities_tab = 'render_capabilities_tab';
$this->render_delegations_tab = 'render_delegations_tab';
$this->render_settings_tab = 'render_settings_tab';
?>

/**
 * WP-Breach User Management JavaScript
 *
 * This file contains all JavaScript functionality for the user management
 * and permissions interface.
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/admin/js
 * @since      1.0.0
 */

(function($) {
	'use strict';

	/**
	 * User Management Class
	 */
	class WPBreachUserManagement {
		constructor() {
			this.currentPage = 1;
			this.usersPerPage = 20;
			this.currentFilters = {};
			this.selectedUsers = [];
			
			this.init();
		}

		init() {
			this.bindEvents();
			this.loadUsers();
			this.initModals();
		}

		bindEvents() {
			// Search functionality
			$(document).on('keyup', '#wp-breach-user-search', $.debounce(300, (e) => {
				this.currentFilters.search = $(e.target).val();
				this.currentPage = 1;
				this.loadUsers();
			}));

			// Filter changes
			$(document).on('change', '#wp-breach-role-filter', (e) => {
				this.currentFilters.role = $(e.target).val();
				this.currentPage = 1;
				this.loadUsers();
			});

			// User actions
			$(document).on('click', '.wp-breach-assign-role', this.handleAssignRole.bind(this));
			$(document).on('click', '.wp-breach-remove-role', this.handleRemoveRole.bind(this));
			$(document).on('click', '.wp-breach-add-capability', this.handleAddCapability.bind(this));
			$(document).on('click', '.wp-breach-remove-capability', this.handleRemoveCapability.bind(this));

			// Bulk actions
			$(document).on('change', '.wp-breach-user-checkbox', this.handleUserSelection.bind(this));
			$(document).on('click', '#wp-breach-select-all', this.handleSelectAll.bind(this));
			$(document).on('click', '#wp-breach-bulk-action', this.handleBulkAction.bind(this));

			// Pagination
			$(document).on('click', '.wp-breach-pagination a', this.handlePagination.bind(this));

			// Delegation
			$(document).on('click', '.wp-breach-delegate-permission', this.openDelegationModal.bind(this));
			$(document).on('click', '.wp-breach-revoke-delegation', this.handleRevokeDelegation.bind(this));

			// Modal events
			$(document).on('click', '.wp-breach-modal-close', this.closeModal.bind(this));
			$(document).on('click', '.wp-breach-modal', (e) => {
				if (e.target === e.currentTarget) {
					this.closeModal();
				}
			});
		}

		loadUsers() {
			$('#wp-breach-users-list').html('<div class="wp-breach-loading">Loading users...</div>');

			$.ajax({
				url: wpBreachUserManagement.ajax_url,
				type: 'POST',
				data: {
					action: 'wp_breach_get_users',
					nonce: wpBreachUserManagement.nonce,
					page: this.currentPage,
					per_page: this.usersPerPage,
					filters: this.currentFilters
				},
				success: (response) => {
					if (response.success) {
						this.renderUsers(response.data.users);
						this.updatePagination(response.data.pagination);
						this.updateStats(response.data.stats);
					} else {
						this.showError(response.data);
					}
				},
				error: () => {
					this.showError('Failed to load users');
				}
			});
		}

		renderUsers(users) {
			if (!users || users.length === 0) {
				$('#wp-breach-users-list').html('<div class="wp-breach-no-users">No users found</div>');
				return;
			}

			let html = '';
			users.forEach(user => {
				html += this.renderUserCard(user);
			});

			$('#wp-breach-users-list').html(html);
		}

		renderUserCard(user) {
			const securityRoles = user.security_roles || [];
			const capabilities = user.capabilities || [];
			const delegations = user.delegations || [];

			let rolesHtml = '';
			if (securityRoles.length > 0) {
				securityRoles.forEach(role => {
					rolesHtml += `<span class="wp-breach-role-badge ${role}">${this.getRoleName(role)}</span>`;
				});
			} else {
				rolesHtml = '<span class="wp-breach-role-badge">None</span>';
			}

			let actionsHtml = `
				<button type="button" class="wp-breach-btn secondary" onclick="window.wpBreachUserMgmt.editUser(${user.ID})">
					Edit
				</button>
				<button type="button" class="wp-breach-btn" onclick="window.wpBreachUserMgmt.viewUserDetails(${user.ID})">
					View Details
				</button>
			`;

			if (delegations.length > 0) {
				actionsHtml += `
					<button type="button" class="wp-breach-btn" onclick="window.wpBreachUserMgmt.manageDelegations(${user.ID})">
						Delegations (${delegations.length})
					</button>
				`;
			}

			return `
				<div class="wp-breach-user-card" data-user-id="${user.ID}">
					<div class="wp-breach-user-header">
						<div class="wp-breach-user-checkbox-container">
							<input type="checkbox" class="wp-breach-user-checkbox" value="${user.ID}">
						</div>
						<div class="wp-breach-user-info">
							<h3>${user.display_name} (${user.login})</h3>
							<div class="wp-breach-user-email">${user.email}</div>
							${user.last_login ? `<div class="wp-breach-user-last-login">Last login: ${new Date(user.last_login).toLocaleString()}</div>` : ''}
						</div>
						<div class="wp-breach-user-actions">
							${actionsHtml}
						</div>
					</div>
					
					<div class="wp-breach-roles">
						<strong>Security Roles:</strong>
						${rolesHtml}
					</div>
					
					<div class="wp-breach-capabilities">
						<strong>Capabilities:</strong>
						${capabilities.length} active capabilities
					</div>
				</div>
			`;
		}

		getRoleName(roleSlug) {
			const roleNames = {
				'security_administrator': 'Security Administrator',
				'security_manager': 'Security Manager',
				'security_analyst': 'Security Analyst',
				'security_viewer': 'Security Viewer'
			};
			return roleNames[roleSlug] || roleSlug;
		}

		handleAssignRole(e) {
			e.preventDefault();
			const userId = $(e.target).data('user-id');
			const role = $(e.target).data('role');

			if (!confirm(wpBreachUserManagement.strings.confirm_assign_role)) {
				return;
			}

			this.assignRole(userId, role);
		}

		handleRemoveRole(e) {
			e.preventDefault();
			const userId = $(e.target).data('user-id');
			const role = $(e.target).data('role');

			if (!confirm(wpBreachUserManagement.strings.confirm_remove_role)) {
				return;
			}

			this.removeRole(userId, role);
		}

		handleAddCapability(e) {
			e.preventDefault();
			const userId = $(e.target).data('user-id');
			const capability = $(e.target).data('capability');

			if (!confirm(wpBreachUserManagement.strings.confirm_add_capability)) {
				return;
			}

			this.addCapability(userId, capability);
		}

		handleRemoveCapability(e) {
			e.preventDefault();
			const userId = $(e.target).data('user-id');
			const capability = $(e.target).data('capability');

			if (!confirm(wpBreachUserManagement.strings.confirm_remove_capability)) {
				return;
			}

			this.removeCapability(userId, capability);
		}

		assignRole(userId, role) {
			$.ajax({
				url: wpBreachUserManagement.ajax_url,
				type: 'POST',
				data: {
					action: 'wp_breach_assign_role',
					nonce: wpBreachUserManagement.nonce,
					user_id: userId,
					role: role
				},
				success: (response) => {
					if (response.success) {
						this.showSuccess(response.data.message);
						this.loadUsers();
					} else {
						this.showError(response.data);
					}
				},
				error: () => {
					this.showError('Failed to assign role');
				}
			});
		}

		removeRole(userId, role) {
			$.ajax({
				url: wpBreachUserManagement.ajax_url,
				type: 'POST',
				data: {
					action: 'wp_breach_remove_role',
					nonce: wpBreachUserManagement.nonce,
					user_id: userId,
					role: role
				},
				success: (response) => {
					if (response.success) {
						this.showSuccess(response.data.message);
						this.loadUsers();
					} else {
						this.showError(response.data);
					}
				},
				error: () => {
					this.showError('Failed to remove role');
				}
			});
		}

		addCapability(userId, capability) {
			$.ajax({
				url: wpBreachUserManagement.ajax_url,
				type: 'POST',
				data: {
					action: 'wp_breach_add_capability',
					nonce: wpBreachUserManagement.nonce,
					user_id: userId,
					capability: capability
				},
				success: (response) => {
					if (response.success) {
						this.showSuccess(response.data.message);
						this.loadUsers();
					} else {
						this.showError(response.data);
					}
				},
				error: () => {
					this.showError('Failed to add capability');
				}
			});
		}

		removeCapability(userId, capability) {
			$.ajax({
				url: wpBreachUserManagement.ajax_url,
				type: 'POST',
				data: {
					action: 'wp_breach_remove_capability',
					nonce: wpBreachUserManagement.nonce,
					user_id: userId,
					capability: capability
				},
				success: (response) => {
					if (response.success) {
						this.showSuccess(response.data.message);
						this.loadUsers();
					} else {
						this.showError(response.data);
					}
				},
				error: () => {
					this.showError('Failed to remove capability');
				}
			});
		}

		handleUserSelection(e) {
			const userId = parseInt($(e.target).val());
			const isChecked = $(e.target).is(':checked');

			if (isChecked) {
				if (!this.selectedUsers.includes(userId)) {
					this.selectedUsers.push(userId);
				}
			} else {
				this.selectedUsers = this.selectedUsers.filter(id => id !== userId);
			}

			this.updateBulkActions();
		}

		handleSelectAll(e) {
			const isChecked = $(e.target).is(':checked');
			
			$('.wp-breach-user-checkbox').prop('checked', isChecked);
			
			if (isChecked) {
				this.selectedUsers = $('.wp-breach-user-checkbox').map(function() {
					return parseInt($(this).val());
				}).get();
			} else {
				this.selectedUsers = [];
			}

			this.updateBulkActions();
		}

		updateBulkActions() {
			const hasSelection = this.selectedUsers.length > 0;
			$('#wp-breach-bulk-actions').toggle(hasSelection);
			$('#wp-breach-selection-count').text(this.selectedUsers.length);
		}

		handleBulkAction() {
			const action = $('#wp-breach-bulk-action-select').val();
			if (!action || this.selectedUsers.length === 0) {
				return;
			}

			if (!confirm(`Are you sure you want to perform this action on ${this.selectedUsers.length} users?`)) {
				return;
			}

			this.performBulkAction(action, this.selectedUsers);
		}

		performBulkAction(action, userIds) {
			$.ajax({
				url: wpBreachUserManagement.ajax_url,
				type: 'POST',
				data: {
					action: 'wp_breach_bulk_action',
					nonce: wpBreachUserManagement.nonce,
					bulk_action: action,
					user_ids: userIds
				},
				success: (response) => {
					if (response.success) {
						this.showSuccess(response.data.message);
						this.loadUsers();
						this.selectedUsers = [];
						this.updateBulkActions();
					} else {
						this.showError(response.data);
					}
				},
				error: () => {
					this.showError('Failed to perform bulk action');
				}
			});
		}

		openDelegationModal(e) {
			const userId = $(e.target).data('user-id');
			this.showDelegationModal(userId);
		}

		showDelegationModal(userId) {
			// Load delegation modal content
			$.ajax({
				url: wpBreachUserManagement.ajax_url,
				type: 'POST',
				data: {
					action: 'wp_breach_get_delegation_modal',
					nonce: wpBreachUserManagement.nonce,
					user_id: userId
				},
				success: (response) => {
					if (response.success) {
						$('#delegation-modal-content').html(response.data.html);
						$('#delegation-modal').show();
					}
				}
			});
		}

		handleRevokeDelegation(e) {
			e.preventDefault();
			const delegationId = $(e.target).data('delegation-id');

			if (!confirm('Are you sure you want to revoke this delegation?')) {
				return;
			}

			this.revokeDelegation(delegationId);
		}

		revokeDelegation(delegationId) {
			$.ajax({
				url: wpBreachUserManagement.ajax_url,
				type: 'POST',
				data: {
					action: 'wp_breach_revoke_delegation',
					nonce: wpBreachUserManagement.nonce,
					delegation_id: delegationId
				},
				success: (response) => {
					if (response.success) {
						this.showSuccess(response.data.message);
						this.loadUsers();
					} else {
						this.showError(response.data);
					}
				},
				error: () => {
					this.showError('Failed to revoke delegation');
				}
			});
		}

		editUser(userId) {
			// Open user edit modal
			this.loadUserEditModal(userId);
		}

		loadUserEditModal(userId) {
			$.ajax({
				url: wpBreachUserManagement.ajax_url,
				type: 'POST',
				data: {
					action: 'wp_breach_get_user_edit_modal',
					nonce: wpBreachUserManagement.nonce,
					user_id: userId
				},
				success: (response) => {
					if (response.success) {
						$('#user-edit-modal-content').html(response.data.html);
						$('#user-edit-modal').show();
					}
				}
			});
		}

		viewUserDetails(userId) {
			// Open user details modal
			this.loadUserDetailsModal(userId);
		}

		loadUserDetailsModal(userId) {
			$.ajax({
				url: wpBreachUserManagement.ajax_url,
				type: 'POST',
				data: {
					action: 'wp_breach_get_user_details',
					nonce: wpBreachUserManagement.nonce,
					user_id: userId
				},
				success: (response) => {
					if (response.success) {
						$('#user-details-modal-content').html(response.data.html);
						$('#user-details-modal').show();
					}
				}
			});
		}

		manageDelegations(userId) {
			// Open delegations management modal
			this.loadDelegationsModal(userId);
		}

		loadDelegationsModal(userId) {
			$.ajax({
				url: wpBreachUserManagement.ajax_url,
				type: 'POST',
				data: {
					action: 'wp_breach_get_user_delegations',
					nonce: wpBreachUserManagement.nonce,
					user_id: userId
				},
				success: (response) => {
					if (response.success) {
						$('#delegations-modal-content').html(response.data.html);
						$('#delegations-modal').show();
					}
				}
			});
		}

		handlePagination(e) {
			e.preventDefault();
			const page = parseInt($(e.target).data('page'));
			if (page && page !== this.currentPage) {
				this.currentPage = page;
				this.loadUsers();
			}
		}

		updatePagination(pagination) {
			if (!pagination) return;

			let html = '';
			const totalPages = Math.ceil(pagination.total / this.usersPerPage);

			// Previous button
			if (this.currentPage > 1) {
				html += `<a href="#" class="wp-breach-pagination-link" data-page="${this.currentPage - 1}">Previous</a>`;
			}

			// Page numbers
			for (let i = Math.max(1, this.currentPage - 2); i <= Math.min(totalPages, this.currentPage + 2); i++) {
				if (i === this.currentPage) {
					html += `<span class="wp-breach-pagination-current">${i}</span>`;
				} else {
					html += `<a href="#" class="wp-breach-pagination-link" data-page="${i}">${i}</a>`;
				}
			}

			// Next button
			if (this.currentPage < totalPages) {
				html += `<a href="#" class="wp-breach-pagination-link" data-page="${this.currentPage + 1}">Next</a>`;
			}

			$('#wp-breach-pagination').html(html);
		}

		updateStats(stats) {
			if (!stats) return;

			$('#total-users-stat').text(stats.total_users || 0);
			$('#security-users-stat').text(stats.security_users || 0);
			$('#active-delegations-stat').text(stats.active_delegations || 0);
		}

		initModals() {
			// Initialize modal HTML if not present
			if ($('#user-edit-modal').length === 0) {
				$('body').append(`
					<div id="user-edit-modal" class="wp-breach-modal" style="display: none;">
						<div class="wp-breach-modal-content">
							<div class="wp-breach-modal-header">
								<h2>Edit User Permissions</h2>
								<button type="button" class="wp-breach-modal-close">&times;</button>
							</div>
							<div class="wp-breach-modal-body">
								<div id="user-edit-modal-content"></div>
							</div>
						</div>
					</div>
				`);
			}

			if ($('#user-details-modal').length === 0) {
				$('body').append(`
					<div id="user-details-modal" class="wp-breach-modal" style="display: none;">
						<div class="wp-breach-modal-content">
							<div class="wp-breach-modal-header">
								<h2>User Details</h2>
								<button type="button" class="wp-breach-modal-close">&times;</button>
							</div>
							<div class="wp-breach-modal-body">
								<div id="user-details-modal-content"></div>
							</div>
						</div>
					</div>
				`);
			}

			if ($('#delegations-modal').length === 0) {
				$('body').append(`
					<div id="delegations-modal" class="wp-breach-modal" style="display: none;">
						<div class="wp-breach-modal-content">
							<div class="wp-breach-modal-header">
								<h2>Manage Delegations</h2>
								<button type="button" class="wp-breach-modal-close">&times;</button>
							</div>
							<div class="wp-breach-modal-body">
								<div id="delegations-modal-content"></div>
							</div>
						</div>
					</div>
				`);
			}
		}

		closeModal() {
			$('.wp-breach-modal').hide();
		}

		showSuccess(message) {
			this.showNotice(message, 'success');
		}

		showError(message) {
			this.showNotice(message, 'error');
		}

		showNotice(message, type = 'info') {
			const noticeClass = type === 'error' ? 'notice-error' : 'notice-success';
			const notice = $(`
				<div class="notice ${noticeClass} is-dismissible">
					<p>${message}</p>
					<button type="button" class="notice-dismiss">
						<span class="screen-reader-text">Dismiss this notice.</span>
					</button>
				</div>
			`);

			$('.wrap h1').after(notice);

			// Auto-dismiss after 5 seconds
			setTimeout(() => {
				notice.fadeOut(() => notice.remove());
			}, 5000);

			// Handle manual dismiss
			notice.on('click', '.notice-dismiss', function() {
				notice.fadeOut(() => notice.remove());
			});
		}
	}

	/**
	 * Debounce function
	 */
	$.debounce = function(delay, fn) {
		let timeoutId;
		return function(...args) {
			clearTimeout(timeoutId);
			timeoutId = setTimeout(() => fn.apply(this, args), delay);
		};
	};

	// Initialize when document is ready
	$(document).ready(function() {
		window.wpBreachUserMgmt = new WPBreachUserManagement();
	});

})(jQuery);

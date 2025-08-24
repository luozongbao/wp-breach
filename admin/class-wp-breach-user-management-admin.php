<?php
/**
 * The admin-specific functionality for user management and permissions.
 *
 * This class defines all code necessary to run user management and permissions
 * in the admin area.
 *
 * @link       https://github.com/luozongbao
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/admin
 */

/**
 * The admin-specific functionality of the plugin.
 *
 * Defines the plugin name, version, and hooks for managing user permissions
 * and roles in the admin area.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/admin
 * @author     luozongbao <luo.zongbao@outlook.com>
 */
class WP_Breach_User_Management_Admin {

	/**
	 * The ID of this plugin.
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      string    $plugin_name    The ID of this plugin.
	 */
	private $plugin_name;

	/**
	 * The version of this plugin.
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      string    $version    The current version of this plugin.
	 */
	private $version;

	/**
	 * Permissions manager instance
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      WP_Breach_Permissions_Manager    $permissions_manager    Permissions manager instance.
	 */
	private $permissions_manager;

	/**
	 * Capability checker instance
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      WP_Breach_Capability_Checker    $capability_checker    Capability checker instance.
	 */
	private $capability_checker;

	/**
	 * Initialize the class and set its properties.
	 *
	 * @since    1.0.0
	 * @param    string    $plugin_name       The name of this plugin.
	 * @param    string    $version           The version of this plugin.
	 */
	public function __construct( $plugin_name, $version ) {
		$this->plugin_name = $plugin_name;
		$this->version = $version;

		$this->load_dependencies();
		$this->init_hooks();
	}

	/**
	 * Load the required dependencies for the admin area.
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function load_dependencies() {
		require_once WP_BREACH_PLUGIN_DIR . 'includes/class-wp-breach-permissions-manager.php';
		require_once WP_BREACH_PLUGIN_DIR . 'includes/class-wp-breach-capability-checker.php';

		$this->permissions_manager = new WP_Breach_Permissions_Manager();
		$this->capability_checker = new WP_Breach_Capability_Checker();
	}

	/**
	 * Initialize WordPress hooks
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function init_hooks() {
		add_action( 'admin_menu', array( $this, 'add_admin_menu' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'wp_ajax_wp_breach_assign_role', array( $this, 'ajax_assign_role' ) );
		add_action( 'wp_ajax_wp_breach_remove_role', array( $this, 'ajax_remove_role' ) );
		add_action( 'wp_ajax_wp_breach_add_capability', array( $this, 'ajax_add_capability' ) );
		add_action( 'wp_ajax_wp_breach_remove_capability', array( $this, 'ajax_remove_capability' ) );
		add_action( 'wp_ajax_wp_breach_get_audit_logs', array( $this, 'ajax_get_audit_logs' ) );
		add_action( 'wp_ajax_wp_breach_delegate_permissions', array( $this, 'ajax_delegate_permissions' ) );
		add_action( 'wp_ajax_wp_breach_revoke_delegation', array( $this, 'ajax_revoke_delegation' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_scripts' ) );
		add_filter( 'manage_users_columns', array( $this, 'add_user_columns' ) );
		add_action( 'manage_users_custom_column', array( $this, 'render_user_column' ), 10, 3 );
	}

	/**
	 * Add admin menu for user management
	 *
	 * @since    1.0.0
	 */
	public function add_admin_menu() {
		// Check if user can manage WP-Breach users
		if ( ! $this->capability_checker->current_user_can( 'user.manage' ) ) {
			return;
		}

		add_submenu_page(
			'wp-breach',
			__( 'User Management', 'wp-breach' ),
			__( 'Users & Permissions', 'wp-breach' ),
			'wp_breach_manage_users',
			'wp-breach-users',
			array( $this, 'display_user_management_page' )
		);

		add_submenu_page(
			'wp-breach',
			__( 'Permission Audit', 'wp-breach' ),
			__( 'Audit Logs', 'wp-breach' ),
			'wp_breach_view_audit_logs',
			'wp-breach-audit',
			array( $this, 'display_audit_page' )
		);
	}

	/**
	 * Register settings for user management
	 *
	 * @since    1.0.0
	 */
	public function register_settings() {
		register_setting(
			'wp_breach_user_management',
			'wp_breach_user_management_settings',
			array( $this, 'validate_settings' )
		);

		add_settings_section(
			'wp_breach_user_management_general',
			__( 'General Settings', 'wp-breach' ),
			array( $this, 'settings_section_callback' ),
			'wp_breach_user_management'
		);

		add_settings_field(
			'auto_assign_role',
			__( 'Auto-assign Role', 'wp-breach' ),
			array( $this, 'auto_assign_role_callback' ),
			'wp_breach_user_management',
			'wp_breach_user_management_general'
		);

		add_settings_field(
			'permission_inheritance',
			__( 'Permission Inheritance', 'wp-breach' ),
			array( $this, 'permission_inheritance_callback' ),
			'wp_breach_user_management',
			'wp_breach_user_management_general'
		);

		add_settings_field(
			'audit_retention',
			__( 'Audit Log Retention (days)', 'wp-breach' ),
			array( $this, 'audit_retention_callback' ),
			'wp_breach_user_management',
			'wp_breach_user_management_general'
		);
	}

	/**
	 * Display user management page
	 *
	 * @since    1.0.0
	 */
	public function display_user_management_page() {
		// Check permissions
		if ( ! $this->capability_checker->current_user_can( 'user.manage' ) ) {
			wp_die( __( 'You do not have sufficient permissions to access this page.', 'wp-breach' ) );
		}

		$active_tab = isset( $_GET['tab'] ) ? sanitize_text_field( $_GET['tab'] ) : 'users';

		include WP_BREACH_PLUGIN_DIR . 'admin/partials/wp-breach-admin-user-management.php';
	}

	/**
	 * Display audit page
	 *
	 * @since    1.0.0
	 */
	public function display_audit_page() {
		// Check permissions
		if ( ! $this->capability_checker->current_user_can( 'audit.view' ) ) {
			wp_die( __( 'You do not have sufficient permissions to access this page.', 'wp-breach' ) );
		}

		include WP_BREACH_PLUGIN_DIR . 'admin/partials/wp-breach-admin-audit-logs.php';
	}

	/**
	 * Enqueue admin scripts and styles
	 *
	 * @since    1.0.0
	 * @param    string    $hook    The current admin page hook.
	 */
	public function enqueue_scripts( $hook ) {
		if ( strpos( $hook, 'wp-breach' ) === false ) {
			return;
		}

		wp_enqueue_script(
			$this->plugin_name . '-user-management',
			WP_BREACH_PLUGIN_URL . 'admin/js/wp-breach-user-management.js',
			array( 'jquery', 'wp-util' ),
			$this->version,
			false
		);

		wp_enqueue_style(
			$this->plugin_name . '-user-management',
			WP_BREACH_PLUGIN_URL . 'admin/css/wp-breach-user-management.css',
			array(),
			$this->version,
			'all'
		);

		wp_localize_script(
			$this->plugin_name . '-user-management',
			'wpBreachUserManagement',
			array(
				'ajax_url' => admin_url( 'admin-ajax.php' ),
				'nonce' => wp_create_nonce( 'wp_breach_user_management' ),
				'strings' => array(
					'confirm_assign_role' => __( 'Are you sure you want to assign this role?', 'wp-breach' ),
					'confirm_remove_role' => __( 'Are you sure you want to remove this role?', 'wp-breach' ),
					'confirm_add_capability' => __( 'Are you sure you want to add this capability?', 'wp-breach' ),
					'confirm_remove_capability' => __( 'Are you sure you want to remove this capability?', 'wp-breach' ),
					'error_occurred' => __( 'An error occurred. Please try again.', 'wp-breach' ),
					'success' => __( 'Operation completed successfully.', 'wp-breach' )
				)
			)
		);
	}

	/**
	 * Add custom columns to users table
	 *
	 * @since    1.0.0
	 * @param    array    $columns    Existing columns.
	 * @return   array               Modified columns.
	 */
	public function add_user_columns( $columns ) {
		if ( $this->capability_checker->current_user_can( 'user.view' ) ) {
			$columns['wp_breach_role'] = __( 'WP-Breach Role', 'wp-breach' );
			$columns['wp_breach_capabilities'] = __( 'Security Capabilities', 'wp-breach' );
		}
		return $columns;
	}

	/**
	 * Render custom user columns
	 *
	 * @since    1.0.0
	 * @param    string    $value        The column value.
	 * @param    string    $column_name  The column name.
	 * @param    int       $user_id      The user ID.
	 * @return   string                  The column content.
	 */
	public function render_user_column( $value, $column_name, $user_id ) {
		if ( $column_name === 'wp_breach_role' ) {
			$user = get_user_by( 'id', $user_id );
			$security_roles = array_intersect( $user->roles, array_keys( $this->permissions_manager->get_custom_roles() ) );
			
			if ( ! empty( $security_roles ) ) {
				$role_names = array();
				foreach ( $security_roles as $role ) {
					$roles = $this->permissions_manager->get_custom_roles();
					$role_names[] = $roles[ $role ]['name'];
				}
				return implode( ', ', $role_names );
			}
			return __( 'None', 'wp-breach' );
		}

		if ( $column_name === 'wp_breach_capabilities' ) {
			$capabilities = $this->permissions_manager->get_user_capabilities( $user_id );
			return count( $capabilities ) . ' ' . __( 'capabilities', 'wp-breach' );
		}

		return $value;
	}

	/**
	 * AJAX handler for assigning role
	 *
	 * @since    1.0.0
	 */
	public function ajax_assign_role() {
		check_ajax_referer( 'wp_breach_user_management', 'nonce' );

		if ( ! $this->capability_checker->current_user_can( 'user.manage' ) ) {
			wp_send_json_error( __( 'Insufficient permissions.', 'wp-breach' ) );
		}

		$user_id = intval( $_POST['user_id'] );
		$role = sanitize_text_field( $_POST['role'] );

		// Validate hierarchy
		if ( ! $this->permissions_manager->validate_permission_hierarchy( 'assign_role', $user_id ) ) {
			wp_send_json_error( __( 'Cannot assign role due to permission hierarchy.', 'wp-breach' ) );
		}

		$success = $this->permissions_manager->assign_role( $user_id, $role );

		if ( $success ) {
			wp_send_json_success( array(
				'message' => __( 'Role assigned successfully.', 'wp-breach' )
			) );
		} else {
			wp_send_json_error( __( 'Failed to assign role.', 'wp-breach' ) );
		}
	}

	/**
	 * AJAX handler for removing role
	 *
	 * @since    1.0.0
	 */
	public function ajax_remove_role() {
		check_ajax_referer( 'wp_breach_user_management', 'nonce' );

		if ( ! $this->capability_checker->current_user_can( 'user.manage' ) ) {
			wp_send_json_error( __( 'Insufficient permissions.', 'wp-breach' ) );
		}

		$user_id = intval( $_POST['user_id'] );
		$role = sanitize_text_field( $_POST['role'] );

		// Validate hierarchy
		if ( ! $this->permissions_manager->validate_permission_hierarchy( 'remove_role', $user_id ) ) {
			wp_send_json_error( __( 'Cannot remove role due to permission hierarchy.', 'wp-breach' ) );
		}

		$success = $this->permissions_manager->remove_role( $user_id, $role );

		if ( $success ) {
			wp_send_json_success( array(
				'message' => __( 'Role removed successfully.', 'wp-breach' )
			) );
		} else {
			wp_send_json_error( __( 'Failed to remove role.', 'wp-breach' ) );
		}
	}

	/**
	 * AJAX handler for adding capability
	 *
	 * @since    1.0.0
	 */
	public function ajax_add_capability() {
		check_ajax_referer( 'wp_breach_user_management', 'nonce' );

		if ( ! $this->capability_checker->current_user_can( 'user.manage.permissions' ) ) {
			wp_send_json_error( __( 'Insufficient permissions.', 'wp-breach' ) );
		}

		$user_id = intval( $_POST['user_id'] );
		$capability = sanitize_text_field( $_POST['capability'] );

		// Validate hierarchy
		if ( ! $this->permissions_manager->validate_permission_hierarchy( 'add_capability', $user_id ) ) {
			wp_send_json_error( __( 'Cannot add capability due to permission hierarchy.', 'wp-breach' ) );
		}

		$success = $this->permissions_manager->add_user_capability( $user_id, $capability );

		if ( $success ) {
			wp_send_json_success( array(
				'message' => __( 'Capability added successfully.', 'wp-breach' )
			) );
		} else {
			wp_send_json_error( __( 'Failed to add capability.', 'wp-breach' ) );
		}
	}

	/**
	 * AJAX handler for removing capability
	 *
	 * @since    1.0.0
	 */
	public function ajax_remove_capability() {
		check_ajax_referer( 'wp_breach_user_management', 'nonce' );

		if ( ! $this->capability_checker->current_user_can( 'user.manage.permissions' ) ) {
			wp_send_json_error( __( 'Insufficient permissions.', 'wp-breach' ) );
		}

		$user_id = intval( $_POST['user_id'] );
		$capability = sanitize_text_field( $_POST['capability'] );

		// Validate hierarchy
		if ( ! $this->permissions_manager->validate_permission_hierarchy( 'remove_capability', $user_id ) ) {
			wp_send_json_error( __( 'Cannot remove capability due to permission hierarchy.', 'wp-breach' ) );
		}

		$success = $this->permissions_manager->remove_user_capability( $user_id, $capability );

		if ( $success ) {
			wp_send_json_success( array(
				'message' => __( 'Capability removed successfully.', 'wp-breach' )
			) );
		} else {
			wp_send_json_error( __( 'Failed to remove capability.', 'wp-breach' ) );
		}
	}

	/**
	 * AJAX handler for getting audit logs
	 *
	 * @since    1.0.0
	 */
	public function ajax_get_audit_logs() {
		check_ajax_referer( 'wp_breach_user_management', 'nonce' );

		if ( ! $this->capability_checker->current_user_can( 'audit.view' ) ) {
			wp_send_json_error( __( 'Insufficient permissions.', 'wp-breach' ) );
		}

		$page = intval( $_POST['page'] ?? 1 );
		$per_page = intval( $_POST['per_page'] ?? 20 );
		$filters = $_POST['filters'] ?? array();

		$args = array(
			'limit' => $per_page,
			'offset' => ( $page - 1 ) * $per_page
		);

		if ( ! empty( $filters['user_id'] ) ) {
			$args['user_id'] = intval( $filters['user_id'] );
		}

		if ( ! empty( $filters['action'] ) ) {
			$args['action'] = sanitize_text_field( $filters['action'] );
		}

		if ( ! empty( $filters['severity'] ) ) {
			$args['severity'] = sanitize_text_field( $filters['severity'] );
		}

		if ( ! empty( $filters['start_date'] ) ) {
			$args['start_date'] = sanitize_text_field( $filters['start_date'] );
		}

		if ( ! empty( $filters['end_date'] ) ) {
			$args['end_date'] = sanitize_text_field( $filters['end_date'] );
		}

		$logs = $this->permissions_manager->get_audit_log( $args );

		wp_send_json_success( array(
			'logs' => $logs,
			'page' => $page,
			'per_page' => $per_page
		) );
	}

	/**
	 * AJAX handler for delegating permissions
	 *
	 * @since    1.0.0
	 */
	public function ajax_delegate_permissions() {
		check_ajax_referer( 'wp_breach_user_management', 'nonce' );

		if ( ! $this->capability_checker->current_user_can( 'user.manage.permissions' ) ) {
			wp_send_json_error( __( 'Insufficient permissions.', 'wp-breach' ) );
		}

		$delegated_to = intval( $_POST['delegated_to'] );
		$resource = sanitize_text_field( $_POST['resource'] );
		$operation = sanitize_text_field( $_POST['operation'] );
		$start_date = sanitize_text_field( $_POST['start_date'] );
		$end_date = sanitize_text_field( $_POST['end_date'] );
		$object_id = ! empty( $_POST['object_id'] ) ? intval( $_POST['object_id'] ) : null;

		$success = $this->capability_checker->delegate_permissions(
			get_current_user_id(),
			$delegated_to,
			$resource,
			$operation,
			$start_date,
			$end_date,
			$object_id
		);

		if ( $success ) {
			wp_send_json_success( array(
				'message' => __( 'Permissions delegated successfully.', 'wp-breach' )
			) );
		} else {
			wp_send_json_error( __( 'Failed to delegate permissions.', 'wp-breach' ) );
		}
	}

	/**
	 * AJAX handler for revoking delegation
	 *
	 * @since    1.0.0
	 */
	public function ajax_revoke_delegation() {
		check_ajax_referer( 'wp_breach_user_management', 'nonce' );

		if ( ! $this->capability_checker->current_user_can( 'user.manage.permissions' ) ) {
			wp_send_json_error( __( 'Insufficient permissions.', 'wp-breach' ) );
		}

		$delegation_id = intval( $_POST['delegation_id'] );

		$success = $this->capability_checker->revoke_delegation( $delegation_id, get_current_user_id() );

		if ( $success ) {
			wp_send_json_success( array(
				'message' => __( 'Delegation revoked successfully.', 'wp-breach' )
			) );
		} else {
			wp_send_json_error( __( 'Failed to revoke delegation.', 'wp-breach' ) );
		}
	}

	/**
	 * Settings section callback
	 *
	 * @since    1.0.0
	 */
	public function settings_section_callback() {
		echo '<p>' . __( 'Configure user management and permission settings.', 'wp-breach' ) . '</p>';
	}

	/**
	 * Auto-assign role callback
	 *
	 * @since    1.0.0
	 */
	public function auto_assign_role_callback() {
		$options = get_option( 'wp_breach_user_management_settings', array() );
		$value = $options['auto_assign_role'] ?? 'none';
		$roles = $this->permissions_manager->get_custom_roles();

		echo '<select name="wp_breach_user_management_settings[auto_assign_role]">';
		echo '<option value="none"' . selected( $value, 'none', false ) . '>' . __( 'None', 'wp-breach' ) . '</option>';
		
		foreach ( $roles as $role_slug => $role_data ) {
			echo '<option value="' . esc_attr( $role_slug ) . '"' . selected( $value, $role_slug, false ) . '>' . esc_html( $role_data['name'] ) . '</option>';
		}
		
		echo '</select>';
		echo '<p class="description">' . __( 'Automatically assign this role to new users.', 'wp-breach' ) . '</p>';
	}

	/**
	 * Permission inheritance callback
	 *
	 * @since    1.0.0
	 */
	public function permission_inheritance_callback() {
		$options = get_option( 'wp_breach_user_management_settings', array() );
		$value = $options['permission_inheritance'] ?? 'disabled';

		echo '<input type="checkbox" name="wp_breach_user_management_settings[permission_inheritance]" value="enabled"' . checked( $value, 'enabled', false ) . ' />';
		echo '<label>' . __( 'Enable permission inheritance in multisite networks', 'wp-breach' ) . '</label>';
		echo '<p class="description">' . __( 'Allow users to inherit permissions from parent sites.', 'wp-breach' ) . '</p>';
	}

	/**
	 * Audit retention callback
	 *
	 * @since    1.0.0
	 */
	public function audit_retention_callback() {
		$options = get_option( 'wp_breach_user_management_settings', array() );
		$value = $options['audit_retention'] ?? 90;

		echo '<input type="number" name="wp_breach_user_management_settings[audit_retention]" value="' . esc_attr( $value ) . '" min="30" max="365" />';
		echo '<p class="description">' . __( 'Number of days to retain audit logs (30-365 days).', 'wp-breach' ) . '</p>';
	}

	/**
	 * Validate settings
	 *
	 * @since    1.0.0
	 * @param    array    $input    The input settings.
	 * @return   array             The validated settings.
	 */
	public function validate_settings( $input ) {
		$validated = array();

		if ( isset( $input['auto_assign_role'] ) ) {
			$roles = array_keys( $this->permissions_manager->get_custom_roles() );
			$roles[] = 'none';
			
			if ( in_array( $input['auto_assign_role'], $roles ) ) {
				$validated['auto_assign_role'] = $input['auto_assign_role'];
			}
		}

		if ( isset( $input['permission_inheritance'] ) ) {
			$validated['permission_inheritance'] = $input['permission_inheritance'] === 'enabled' ? 'enabled' : 'disabled';
		}

		if ( isset( $input['audit_retention'] ) ) {
			$retention = intval( $input['audit_retention'] );
			$validated['audit_retention'] = max( 30, min( 365, $retention ) );
		}

		return $validated;
	}

	/**
	 * Get users for management interface
	 *
	 * @since    1.0.0
	 * @param    array    $args    Query arguments.
	 * @return   array            Array of users with security role information.
	 */
	public function get_users_for_management( $args = array() ) {
		$defaults = array(
			'number' => 20,
			'offset' => 0,
			'search' => '',
			'role__in' => array(),
			'meta_query' => array()
		);

		$args = wp_parse_args( $args, $defaults );

		$users = get_users( $args );
		$formatted_users = array();

		foreach ( $users as $user ) {
			$security_roles = array_intersect( $user->roles, array_keys( $this->permissions_manager->get_custom_roles() ) );
			$capabilities = $this->permissions_manager->get_user_capabilities( $user->ID );
			$delegations = $this->capability_checker->get_user_delegations( $user->ID );

			$formatted_users[] = array(
				'ID' => $user->ID,
				'login' => $user->user_login,
				'email' => $user->user_email,
				'display_name' => $user->display_name,
				'roles' => $user->roles,
				'security_roles' => $security_roles,
				'capabilities' => $capabilities,
				'delegations' => $delegations,
				'last_login' => get_user_meta( $user->ID, 'wp_breach_last_login', true )
			);
		}

		return $formatted_users;
	}
}

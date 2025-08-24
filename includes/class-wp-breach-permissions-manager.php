<?php
/**
 * The permissions manager for WP-Breach.
 *
 * This class defines all code necessary to manage user permissions and roles
 * for the WP-Breach security plugin.
 *
 * @link       https://github.com/luozongbao
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes
 */

/**
 * The permissions manager class.
 *
 * This class manages user roles, capabilities, and permissions for the WP-Breach plugin.
 * It provides a comprehensive role-based access control (RBAC) system.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes
 * @author     luozongbao <luo.zongbao@outlook.com>
 */
class WP_Breach_Permissions_Manager {

	/**
	 * Custom role definitions for WP-Breach
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      array    $roles    Array of custom roles and their capabilities.
	 */
	private $roles;

	/**
	 * Custom capability definitions for WP-Breach
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      array    $capabilities    Array of custom capabilities.
	 */
	private $capabilities;

	/**
	 * Audit logger instance
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      WP_Breach_Audit_Logger    $audit_logger    Audit logger instance.
	 */
	private $audit_logger;

	/**
	 * Initialize the permissions manager.
	 *
	 * @since    1.0.0
	 */
	public function __construct() {
		$this->define_roles();
		$this->define_capabilities();
		$this->init_audit_logger();
		$this->init_hooks();
	}

	/**
	 * Define custom roles for WP-Breach
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function define_roles() {
		$this->roles = array(
			'security_administrator' => array(
				'name' => __( 'Security Administrator', 'wp-breach' ),
				'description' => __( 'Full access to all security features and system configuration', 'wp-breach' ),
				'capabilities' => array(
					// Core WordPress capabilities
					'read',
					// Scanning capabilities
					'wp_breach_manage_scans',
					'wp_breach_run_scans',
					'wp_breach_schedule_scans',
					'wp_breach_view_scan_results',
					'wp_breach_delete_scan_results',
					// Vulnerability management
					'wp_breach_manage_vulnerabilities',
					'wp_breach_view_vulnerabilities',
					'wp_breach_apply_fixes',
					'wp_breach_manage_fixes',
					'wp_breach_approve_fixes',
					// Reporting capabilities
					'wp_breach_generate_reports',
					'wp_breach_view_reports',
					'wp_breach_export_reports',
					'wp_breach_schedule_reports',
					// Configuration and settings
					'wp_breach_manage_settings',
					'wp_breach_manage_users',
					'wp_breach_manage_permissions',
					'wp_breach_view_audit_logs',
					// Monitoring capabilities
					'wp_breach_view_monitoring',
					'wp_breach_manage_monitoring',
					'wp_breach_manage_alerts',
					// System capabilities
					'wp_breach_system_config',
					'wp_breach_plugin_management'
				)
			),
			'security_manager' => array(
				'name' => __( 'Security Manager', 'wp-breach' ),
				'description' => __( 'Manage security operations with limited system configuration access', 'wp-breach' ),
				'capabilities' => array(
					'read',
					// Scanning capabilities
					'wp_breach_manage_scans',
					'wp_breach_run_scans',
					'wp_breach_schedule_scans',
					'wp_breach_view_scan_results',
					// Vulnerability management
					'wp_breach_manage_vulnerabilities',
					'wp_breach_view_vulnerabilities',
					'wp_breach_apply_fixes',
					'wp_breach_manage_fixes',
					// Reporting capabilities
					'wp_breach_generate_reports',
					'wp_breach_view_reports',
					'wp_breach_export_reports',
					'wp_breach_schedule_reports',
					// Limited configuration
					'wp_breach_manage_settings',
					'wp_breach_view_audit_logs',
					// Monitoring capabilities
					'wp_breach_view_monitoring',
					'wp_breach_manage_monitoring',
					'wp_breach_manage_alerts'
				)
			),
			'security_analyst' => array(
				'name' => __( 'Security Analyst', 'wp-breach' ),
				'description' => __( 'Run scans and analyze security data with limited management access', 'wp-breach' ),
				'capabilities' => array(
					'read',
					// Scanning capabilities
					'wp_breach_run_scans',
					'wp_breach_view_scan_results',
					// Vulnerability management
					'wp_breach_view_vulnerabilities',
					'wp_breach_apply_fixes',
					// Reporting capabilities
					'wp_breach_generate_reports',
					'wp_breach_view_reports',
					'wp_breach_export_reports',
					// Monitoring capabilities
					'wp_breach_view_monitoring'
				)
			),
			'security_viewer' => array(
				'name' => __( 'Security Viewer', 'wp-breach' ),
				'description' => __( 'Read-only access to security information and reports', 'wp-breach' ),
				'capabilities' => array(
					'read',
					// View-only capabilities
					'wp_breach_view_scan_results',
					'wp_breach_view_vulnerabilities',
					'wp_breach_view_reports',
					'wp_breach_view_monitoring'
				)
			)
		);
	}

	/**
	 * Define custom capabilities for WP-Breach
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function define_capabilities() {
		$this->capabilities = array(
			// Scanning capabilities
			'wp_breach_manage_scans' => __( 'Manage Scans', 'wp-breach' ),
			'wp_breach_run_scans' => __( 'Run Scans', 'wp-breach' ),
			'wp_breach_schedule_scans' => __( 'Schedule Scans', 'wp-breach' ),
			'wp_breach_view_scan_results' => __( 'View Scan Results', 'wp-breach' ),
			'wp_breach_delete_scan_results' => __( 'Delete Scan Results', 'wp-breach' ),
			
			// Vulnerability management
			'wp_breach_manage_vulnerabilities' => __( 'Manage Vulnerabilities', 'wp-breach' ),
			'wp_breach_view_vulnerabilities' => __( 'View Vulnerabilities', 'wp-breach' ),
			'wp_breach_apply_fixes' => __( 'Apply Fixes', 'wp-breach' ),
			'wp_breach_manage_fixes' => __( 'Manage Fixes', 'wp-breach' ),
			'wp_breach_approve_fixes' => __( 'Approve Fixes', 'wp-breach' ),
			
			// Reporting capabilities
			'wp_breach_generate_reports' => __( 'Generate Reports', 'wp-breach' ),
			'wp_breach_view_reports' => __( 'View Reports', 'wp-breach' ),
			'wp_breach_export_reports' => __( 'Export Reports', 'wp-breach' ),
			'wp_breach_schedule_reports' => __( 'Schedule Reports', 'wp-breach' ),
			
			// Configuration and settings
			'wp_breach_manage_settings' => __( 'Manage Settings', 'wp-breach' ),
			'wp_breach_manage_users' => __( 'Manage Users', 'wp-breach' ),
			'wp_breach_manage_permissions' => __( 'Manage Permissions', 'wp-breach' ),
			'wp_breach_view_audit_logs' => __( 'View Audit Logs', 'wp-breach' ),
			
			// Monitoring capabilities
			'wp_breach_view_monitoring' => __( 'View Monitoring', 'wp-breach' ),
			'wp_breach_manage_monitoring' => __( 'Manage Monitoring', 'wp-breach' ),
			'wp_breach_manage_alerts' => __( 'Manage Alerts', 'wp-breach' ),
			
			// System capabilities
			'wp_breach_system_config' => __( 'System Configuration', 'wp-breach' ),
			'wp_breach_plugin_management' => __( 'Plugin Management', 'wp-breach' )
		);
	}

	/**
	 * Initialize audit logger
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function init_audit_logger() {
		require_once WP_BREACH_PLUGIN_DIR . 'includes/class-wp-breach-audit-logger.php';
		$this->audit_logger = new WP_Breach_Audit_Logger();
	}

	/**
	 * Initialize WordPress hooks
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function init_hooks() {
		add_action( 'init', array( $this, 'register_roles_and_capabilities' ) );
		add_action( 'user_register', array( $this, 'log_user_creation' ) );
		add_action( 'set_user_role', array( $this, 'log_role_change' ), 10, 3 );
		add_action( 'add_user_to_blog', array( $this, 'log_user_added_to_site' ), 10, 3 );
		add_action( 'remove_user_from_blog', array( $this, 'log_user_removed_from_site' ), 10, 2 );
	}

	/**
	 * Register custom roles and capabilities with WordPress
	 *
	 * @since    1.0.0
	 */
	public function register_roles_and_capabilities() {
		// Add custom roles
		foreach ( $this->roles as $role_slug => $role_data ) {
			if ( ! get_role( $role_slug ) ) {
				add_role( $role_slug, $role_data['name'], $role_data['capabilities'] );
			}
		}

		// Add custom capabilities to administrator role
		$admin_role = get_role( 'administrator' );
		if ( $admin_role ) {
			foreach ( array_keys( $this->capabilities ) as $capability ) {
				$admin_role->add_cap( $capability );
			}
		}
	}

	/**
	 * Remove custom roles and capabilities
	 *
	 * @since    1.0.0
	 */
	public function remove_roles_and_capabilities() {
		// Remove custom roles
		foreach ( array_keys( $this->roles ) as $role_slug ) {
			remove_role( $role_slug );
		}

		// Remove custom capabilities from all roles
		$wp_roles = wp_roles();
		foreach ( $wp_roles->roles as $role_slug => $role_data ) {
			$role = get_role( $role_slug );
			if ( $role ) {
				foreach ( array_keys( $this->capabilities ) as $capability ) {
					$role->remove_cap( $capability );
				}
			}
		}
	}

	/**
	 * Check if current user has specific WP-Breach capability
	 *
	 * @since    1.0.0
	 * @param    string    $capability    The capability to check.
	 * @return   boolean                  True if user has capability, false otherwise.
	 */
	public function current_user_can( $capability ) {
		return current_user_can( $capability );
	}

	/**
	 * Check if user has specific WP-Breach capability
	 *
	 * @since    1.0.0
	 * @param    int       $user_id       The user ID to check.
	 * @param    string    $capability    The capability to check.
	 * @return   boolean                  True if user has capability, false otherwise.
	 */
	public function user_can( $user_id, $capability ) {
		return user_can( $user_id, $capability );
	}

	/**
	 * Get all custom roles
	 *
	 * @since    1.0.0
	 * @return   array    Array of custom roles.
	 */
	public function get_custom_roles() {
		return $this->roles;
	}

	/**
	 * Get all custom capabilities
	 *
	 * @since    1.0.0
	 * @return   array    Array of custom capabilities.
	 */
	public function get_custom_capabilities() {
		return $this->capabilities;
	}

	/**
	 * Get users by WP-Breach role
	 *
	 * @since    1.0.0
	 * @param    string    $role    The role to filter by.
	 * @return   array             Array of WP_User objects.
	 */
	public function get_users_by_role( $role ) {
		return get_users( array( 'role' => $role ) );
	}

	/**
	 * Get user's WP-Breach capabilities
	 *
	 * @since    1.0.0
	 * @param    int    $user_id    The user ID.
	 * @return   array              Array of capabilities.
	 */
	public function get_user_capabilities( $user_id ) {
		$user = get_user_by( 'id', $user_id );
		if ( ! $user ) {
			return array();
		}

		$user_capabilities = array();
		foreach ( array_keys( $this->capabilities ) as $capability ) {
			if ( user_can( $user_id, $capability ) ) {
				$user_capabilities[] = $capability;
			}
		}

		return $user_capabilities;
	}

	/**
	 * Assign role to user
	 *
	 * @since    1.0.0
	 * @param    int       $user_id    The user ID.
	 * @param    string    $role       The role to assign.
	 * @return   boolean               True on success, false on failure.
	 */
	public function assign_role( $user_id, $role ) {
		$user = get_user_by( 'id', $user_id );
		if ( ! $user ) {
			return false;
		}

		if ( ! array_key_exists( $role, $this->roles ) ) {
			return false;
		}

		$user->set_role( $role );
		
		// Log the role assignment
		$this->audit_logger->log_permission_change(
			$user_id,
			'role_assigned',
			array(
				'role' => $role,
				'assigned_by' => get_current_user_id()
			)
		);

		return true;
	}

	/**
	 * Remove role from user
	 *
	 * @since    1.0.0
	 * @param    int       $user_id    The user ID.
	 * @param    string    $role       The role to remove.
	 * @return   boolean               True on success, false on failure.
	 */
	public function remove_role( $user_id, $role ) {
		$user = get_user_by( 'id', $user_id );
		if ( ! $user ) {
			return false;
		}

		$user->remove_role( $role );
		
		// Log the role removal
		$this->audit_logger->log_permission_change(
			$user_id,
			'role_removed',
			array(
				'role' => $role,
				'removed_by' => get_current_user_id()
			)
		);

		return true;
	}

	/**
	 * Add capability to user
	 *
	 * @since    1.0.0
	 * @param    int       $user_id       The user ID.
	 * @param    string    $capability    The capability to add.
	 * @return   boolean                  True on success, false on failure.
	 */
	public function add_user_capability( $user_id, $capability ) {
		$user = get_user_by( 'id', $user_id );
		if ( ! $user ) {
			return false;
		}

		if ( ! array_key_exists( $capability, $this->capabilities ) ) {
			return false;
		}

		$user->add_cap( $capability );
		
		// Log the capability addition
		$this->audit_logger->log_permission_change(
			$user_id,
			'capability_added',
			array(
				'capability' => $capability,
				'added_by' => get_current_user_id()
			)
		);

		return true;
	}

	/**
	 * Remove capability from user
	 *
	 * @since    1.0.0
	 * @param    int       $user_id       The user ID.
	 * @param    string    $capability    The capability to remove.
	 * @return   boolean                  True on success, false on failure.
	 */
	public function remove_user_capability( $user_id, $capability ) {
		$user = get_user_by( 'id', $user_id );
		if ( ! $user ) {
			return false;
		}

		$user->remove_cap( $capability );
		
		// Log the capability removal
		$this->audit_logger->log_permission_change(
			$user_id,
			'capability_removed',
			array(
				'capability' => $capability,
				'removed_by' => get_current_user_id()
			)
		);

		return true;
	}

	/**
	 * Get permission audit log
	 *
	 * @since    1.0.0
	 * @param    array    $args    Query arguments.
	 * @return   array            Array of audit log entries.
	 */
	public function get_audit_log( $args = array() ) {
		return $this->audit_logger->get_permission_logs( $args );
	}

	/**
	 * Log user creation
	 *
	 * @since    1.0.0
	 * @param    int    $user_id    The newly created user ID.
	 */
	public function log_user_creation( $user_id ) {
		$this->audit_logger->log_permission_change(
			$user_id,
			'user_created',
			array(
				'created_by' => get_current_user_id()
			)
		);
	}

	/**
	 * Log role change
	 *
	 * @since    1.0.0
	 * @param    int       $user_id     The user ID.
	 * @param    string    $role        The new role.
	 * @param    array     $old_roles   The old roles.
	 */
	public function log_role_change( $user_id, $role, $old_roles ) {
		$this->audit_logger->log_permission_change(
			$user_id,
			'role_changed',
			array(
				'new_role' => $role,
				'old_roles' => $old_roles,
				'changed_by' => get_current_user_id()
			)
		);
	}

	/**
	 * Log user added to site
	 *
	 * @since    1.0.0
	 * @param    int       $user_id    The user ID.
	 * @param    string    $role       The role assigned.
	 * @param    int       $blog_id    The blog ID.
	 */
	public function log_user_added_to_site( $user_id, $role, $blog_id ) {
		$this->audit_logger->log_permission_change(
			$user_id,
			'user_added_to_site',
			array(
				'role' => $role,
				'blog_id' => $blog_id,
				'added_by' => get_current_user_id()
			)
		);
	}

	/**
	 * Log user removed from site
	 *
	 * @since    1.0.0
	 * @param    int    $user_id    The user ID.
	 * @param    int    $blog_id    The blog ID.
	 */
	public function log_user_removed_from_site( $user_id, $blog_id ) {
		$this->audit_logger->log_permission_change(
			$user_id,
			'user_removed_from_site',
			array(
				'blog_id' => $blog_id,
				'removed_by' => get_current_user_id()
			)
		);
	}

	/**
	 * Validate permission hierarchy
	 *
	 * @since    1.0.0
	 * @param    string    $action       The action being performed.
	 * @param    int       $target_user  The target user ID.
	 * @return   boolean                 True if action is allowed, false otherwise.
	 */
	public function validate_permission_hierarchy( $action, $target_user = null ) {
		$current_user_id = get_current_user_id();
		
		// Super admin can do anything
		if ( is_super_admin( $current_user_id ) ) {
			return true;
		}

		// Check if current user has required capability for the action
		$required_capability = $this->get_required_capability_for_action( $action );
		if ( ! $this->current_user_can( $required_capability ) ) {
			return false;
		}

		// If modifying another user, check hierarchy
		if ( $target_user && $target_user !== $current_user_id ) {
			return $this->check_user_hierarchy( $current_user_id, $target_user );
		}

		return true;
	}

	/**
	 * Get required capability for action
	 *
	 * @since    1.0.0
	 * @param    string    $action    The action.
	 * @return   string              The required capability.
	 */
	private function get_required_capability_for_action( $action ) {
		$capability_map = array(
			'manage_users' => 'wp_breach_manage_users',
			'manage_permissions' => 'wp_breach_manage_permissions',
			'assign_role' => 'wp_breach_manage_users',
			'remove_role' => 'wp_breach_manage_users',
			'add_capability' => 'wp_breach_manage_permissions',
			'remove_capability' => 'wp_breach_manage_permissions'
		);

		return isset( $capability_map[ $action ] ) ? $capability_map[ $action ] : 'manage_options';
	}

	/**
	 * Check user hierarchy
	 *
	 * @since    1.0.0
	 * @param    int    $current_user    The current user ID.
	 * @param    int    $target_user     The target user ID.
	 * @return   boolean                True if current user can modify target user.
	 */
	private function check_user_hierarchy( $current_user, $target_user ) {
		// Get role hierarchy weights
		$role_weights = array(
			'security_administrator' => 4,
			'security_manager' => 3,
			'security_analyst' => 2,
			'security_viewer' => 1
		);

		$current_user_obj = get_user_by( 'id', $current_user );
		$target_user_obj = get_user_by( 'id', $target_user );

		if ( ! $current_user_obj || ! $target_user_obj ) {
			return false;
		}

		// Get highest role weight for each user
		$current_weight = 0;
		$target_weight = 0;

		foreach ( $current_user_obj->roles as $role ) {
			if ( isset( $role_weights[ $role ] ) && $role_weights[ $role ] > $current_weight ) {
				$current_weight = $role_weights[ $role ];
			}
		}

		foreach ( $target_user_obj->roles as $role ) {
			if ( isset( $role_weights[ $role ] ) && $role_weights[ $role ] > $target_weight ) {
				$target_weight = $role_weights[ $role ];
			}
		}

		// Current user must have higher or equal weight
		return $current_weight >= $target_weight;
	}
}

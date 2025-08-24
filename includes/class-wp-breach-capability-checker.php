<?php
/**
 * The capability checker for WP-Breach.
 *
 * This class provides granular capability checking and permission validation
 * for all WP-Breach functionality.
 *
 * @link       https://github.com/luozongbao
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes
 */

/**
 * The capability checker class.
 *
 * This class handles granular permission checking for WP-Breach features,
 * providing context-aware capability validation and access control.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes
 * @author     luozongbao <luo.zongbao@outlook.com>
 */
class WP_Breach_Capability_Checker {

	/**
	 * Permissions manager instance
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      WP_Breach_Permissions_Manager    $permissions_manager    Permissions manager instance.
	 */
	private $permissions_manager;

	/**
	 * Audit logger instance
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      WP_Breach_Audit_Logger    $audit_logger    Audit logger instance.
	 */
	private $audit_logger;

	/**
	 * Capability contexts for granular checking
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      array    $capability_contexts    Array of capability contexts.
	 */
	private $capability_contexts;

	/**
	 * Initialize the capability checker.
	 *
	 * @since    1.0.0
	 */
	public function __construct() {
		require_once WP_BREACH_PLUGIN_DIR . 'includes/class-wp-breach-permissions-manager.php';
		require_once WP_BREACH_PLUGIN_DIR . 'includes/class-wp-breach-audit-logger.php';
		
		$this->permissions_manager = new WP_Breach_Permissions_Manager();
		$this->audit_logger = new WP_Breach_Audit_Logger();
		
		$this->define_capability_contexts();
		$this->init_hooks();
	}

	/**
	 * Define capability contexts for granular checking
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function define_capability_contexts() {
		$this->capability_contexts = array(
			'scan' => array(
				'run' => array(
					'capability' => 'wp_breach_run_scans',
					'contexts' => array(
						'manual' => 'wp_breach_run_scans',
						'scheduled' => 'wp_breach_schedule_scans',
						'bulk' => 'wp_breach_manage_scans'
					)
				),
				'manage' => array(
					'capability' => 'wp_breach_manage_scans',
					'contexts' => array(
						'create' => 'wp_breach_manage_scans',
						'update' => 'wp_breach_manage_scans',
						'delete' => 'wp_breach_manage_scans',
						'schedule' => 'wp_breach_schedule_scans'
					)
				),
				'view' => array(
					'capability' => 'wp_breach_view_scan_results',
					'contexts' => array(
						'own' => 'wp_breach_view_scan_results',
						'all' => 'wp_breach_manage_scans'
					)
				)
			),
			'vulnerability' => array(
				'view' => array(
					'capability' => 'wp_breach_view_vulnerabilities',
					'contexts' => array(
						'summary' => 'wp_breach_view_vulnerabilities',
						'detailed' => 'wp_breach_view_vulnerabilities',
						'all_sites' => 'wp_breach_manage_vulnerabilities'
					)
				),
				'manage' => array(
					'capability' => 'wp_breach_manage_vulnerabilities',
					'contexts' => array(
						'ignore' => 'wp_breach_manage_vulnerabilities',
						'prioritize' => 'wp_breach_manage_vulnerabilities',
						'assign' => 'wp_breach_manage_vulnerabilities'
					)
				),
				'fix' => array(
					'capability' => 'wp_breach_apply_fixes',
					'contexts' => array(
						'apply' => 'wp_breach_apply_fixes',
						'approve' => 'wp_breach_approve_fixes',
						'manage' => 'wp_breach_manage_fixes'
					)
				)
			),
			'report' => array(
				'view' => array(
					'capability' => 'wp_breach_view_reports',
					'contexts' => array(
						'own' => 'wp_breach_view_reports',
						'all' => 'wp_breach_generate_reports'
					)
				),
				'generate' => array(
					'capability' => 'wp_breach_generate_reports',
					'contexts' => array(
						'standard' => 'wp_breach_generate_reports',
						'custom' => 'wp_breach_generate_reports',
						'scheduled' => 'wp_breach_schedule_reports'
					)
				),
				'export' => array(
					'capability' => 'wp_breach_export_reports',
					'contexts' => array(
						'pdf' => 'wp_breach_export_reports',
						'csv' => 'wp_breach_export_reports',
						'json' => 'wp_breach_export_reports'
					)
				)
			),
			'monitoring' => array(
				'view' => array(
					'capability' => 'wp_breach_view_monitoring',
					'contexts' => array(
						'dashboard' => 'wp_breach_view_monitoring',
						'realtime' => 'wp_breach_view_monitoring',
						'historical' => 'wp_breach_view_monitoring'
					)
				),
				'manage' => array(
					'capability' => 'wp_breach_manage_monitoring',
					'contexts' => array(
						'alerts' => 'wp_breach_manage_alerts',
						'notifications' => 'wp_breach_manage_alerts',
						'thresholds' => 'wp_breach_manage_monitoring'
					)
				)
			),
			'settings' => array(
				'view' => array(
					'capability' => 'wp_breach_manage_settings',
					'contexts' => array(
						'basic' => 'wp_breach_manage_settings',
						'advanced' => 'wp_breach_system_config'
					)
				),
				'manage' => array(
					'capability' => 'wp_breach_manage_settings',
					'contexts' => array(
						'basic' => 'wp_breach_manage_settings',
						'advanced' => 'wp_breach_system_config',
						'plugin' => 'wp_breach_plugin_management'
					)
				)
			),
			'user' => array(
				'view' => array(
					'capability' => 'wp_breach_manage_users',
					'contexts' => array(
						'list' => 'wp_breach_manage_users',
						'profile' => 'wp_breach_manage_users'
					)
				),
				'manage' => array(
					'capability' => 'wp_breach_manage_users',
					'contexts' => array(
						'create' => 'wp_breach_manage_users',
						'edit' => 'wp_breach_manage_users',
						'delete' => 'wp_breach_manage_users',
						'permissions' => 'wp_breach_manage_permissions'
					)
				)
			),
			'audit' => array(
				'view' => array(
					'capability' => 'wp_breach_view_audit_logs',
					'contexts' => array(
						'own' => 'wp_breach_view_audit_logs',
						'all' => 'wp_breach_view_audit_logs'
					)
				),
				'export' => array(
					'capability' => 'wp_breach_view_audit_logs',
					'contexts' => array(
						'csv' => 'wp_breach_view_audit_logs',
						'json' => 'wp_breach_view_audit_logs'
					)
				)
			)
		);
	}

	/**
	 * Initialize WordPress hooks
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function init_hooks() {
		add_filter( 'user_has_cap', array( $this, 'filter_user_capabilities' ), 10, 4 );
		add_action( 'wp_breach_check_capability', array( $this, 'log_capability_check' ), 10, 4 );
	}

	/**
	 * Check if current user can perform action
	 *
	 * @since    1.0.0
	 * @param    string    $action     The action to check.
	 * @param    string    $context    The context of the action.
	 * @param    mixed     $object_id  The object ID (optional).
	 * @return   boolean               True if user can perform action, false otherwise.
	 */
	public function current_user_can( $action, $context = 'default', $object_id = null ) {
		$user_id = get_current_user_id();
		return $this->user_can( $user_id, $action, $context, $object_id );
	}

	/**
	 * Check if user can perform action
	 *
	 * @since    1.0.0
	 * @param    int       $user_id    The user ID to check.
	 * @param    string    $action     The action to check.
	 * @param    string    $context    The context of the action.
	 * @param    mixed     $object_id  The object ID (optional).
	 * @return   boolean               True if user can perform action, false otherwise.
	 */
	public function user_can( $user_id, $action, $context = 'default', $object_id = null ) {
		// Parse action and operation
		$action_parts = explode( '.', $action );
		if ( count( $action_parts ) < 2 ) {
			return false;
		}

		$resource = $action_parts[0];
		$operation = $action_parts[1];

		// Check if user exists and is active
		$user = get_user_by( 'id', $user_id );
		if ( ! $user || ! $this->is_user_active( $user_id ) ) {
			$this->log_access_attempt( $action, $context, false, 'User not found or inactive' );
			return false;
		}

		// Super admin can do everything
		if ( is_super_admin( $user_id ) ) {
			$this->log_access_attempt( $action, $context, true, 'Super admin access' );
			return true;
		}

		// Get required capability for this action and context
		$required_capability = $this->get_required_capability( $resource, $operation, $context );
		if ( ! $required_capability ) {
			$this->log_access_attempt( $action, $context, false, 'No capability defined' );
			return false;
		}

		// Check basic capability
		$has_capability = user_can( $user_id, $required_capability );
		if ( ! $has_capability ) {
			$this->log_access_attempt( $action, $context, false, 'Missing capability: ' . $required_capability );
			return false;
		}

		// Additional context-specific checks
		$contextual_check = $this->check_contextual_permissions( $user_id, $resource, $operation, $context, $object_id );
		if ( ! $contextual_check ) {
			$this->log_access_attempt( $action, $context, false, 'Failed contextual check' );
			return false;
		}

		// Check multisite permissions if applicable
		if ( is_multisite() && ! $this->check_multisite_permissions( $user_id, $action, $object_id ) ) {
			$this->log_access_attempt( $action, $context, false, 'Failed multisite check' );
			return false;
		}

		// Log successful capability check
		$this->log_access_attempt( $action, $context, true, 'Access granted' );
		
		// Trigger capability check action for monitoring
		do_action( 'wp_breach_check_capability', $user_id, $action, $context, true );

		return true;
	}

	/**
	 * Get required capability for action and context
	 *
	 * @since    1.0.0
	 * @access   private
	 * @param    string    $resource    The resource.
	 * @param    string    $operation   The operation.
	 * @param    string    $context     The context.
	 * @return   string|false           The required capability or false.
	 */
	private function get_required_capability( $resource, $operation, $context ) {
		if ( ! isset( $this->capability_contexts[ $resource ][ $operation ] ) ) {
			return false;
		}

		$operation_config = $this->capability_contexts[ $resource ][ $operation ];

		// Check for context-specific capability
		if ( isset( $operation_config['contexts'][ $context ] ) ) {
			return $operation_config['contexts'][ $context ];
		}

		// Fall back to base capability
		return $operation_config['capability'];
	}

	/**
	 * Check contextual permissions
	 *
	 * @since    1.0.0
	 * @access   private
	 * @param    int       $user_id     The user ID.
	 * @param    string    $resource    The resource.
	 * @param    string    $operation   The operation.
	 * @param    string    $context     The context.
	 * @param    mixed     $object_id   The object ID.
	 * @return   boolean                True if contextual check passes.
	 */
	private function check_contextual_permissions( $user_id, $resource, $operation, $context, $object_id ) {
		// Handle ownership-based permissions
		if ( $context === 'own' && $object_id ) {
			return $this->check_ownership( $user_id, $resource, $object_id );
		}

		// Handle time-based restrictions
		if ( $this->has_time_restrictions( $user_id ) ) {
			return $this->check_time_restrictions( $user_id );
		}

		// Handle rate limiting
		if ( $this->is_rate_limited_action( $resource, $operation ) ) {
			return $this->check_rate_limit( $user_id, $resource, $operation );
		}

		// Handle delegation checks
		if ( $context === 'delegated' ) {
			return $this->check_delegation_permissions( $user_id, $resource, $operation, $object_id );
		}

		return true;
	}

	/**
	 * Check ownership permissions
	 *
	 * @since    1.0.0
	 * @access   private
	 * @param    int       $user_id     The user ID.
	 * @param    string    $resource    The resource type.
	 * @param    mixed     $object_id   The object ID.
	 * @return   boolean                True if user owns the object.
	 */
	private function check_ownership( $user_id, $resource, $object_id ) {
		global $wpdb;

		// Define ownership tables for different resources
		$ownership_tables = array(
			'scan' => $wpdb->prefix . 'wp_breach_scans',
			'report' => $wpdb->prefix . 'wp_breach_reports',
			'vulnerability' => $wpdb->prefix . 'wp_breach_vulnerabilities'
		);

		if ( ! isset( $ownership_tables[ $resource ] ) ) {
			return false;
		}

		$table = $ownership_tables[ $resource ];
		$owner_id = $wpdb->get_var( $wpdb->prepare(
			"SELECT user_id FROM {$table} WHERE id = %d",
			$object_id
		) );

		return $owner_id == $user_id;
	}

	/**
	 * Check if user has time restrictions
	 *
	 * @since    1.0.0
	 * @access   private
	 * @param    int    $user_id    The user ID.
	 * @return   boolean            True if user has time restrictions.
	 */
	private function has_time_restrictions( $user_id ) {
		$time_restrictions = get_user_meta( $user_id, 'wp_breach_time_restrictions', true );
		return ! empty( $time_restrictions );
	}

	/**
	 * Check time restrictions
	 *
	 * @since    1.0.0
	 * @access   private
	 * @param    int    $user_id    The user ID.
	 * @return   boolean            True if current time is allowed.
	 */
	private function check_time_restrictions( $user_id ) {
		$restrictions = get_user_meta( $user_id, 'wp_breach_time_restrictions', true );
		if ( empty( $restrictions ) ) {
			return true;
		}

		$current_time = current_time( 'H:i' );
		$current_day = date( 'w' ); // 0 = Sunday, 6 = Saturday

		// Check daily restrictions
		if ( isset( $restrictions['daily'] ) ) {
			$start_time = $restrictions['daily']['start'];
			$end_time = $restrictions['daily']['end'];
			
			if ( $current_time < $start_time || $current_time > $end_time ) {
				return false;
			}
		}

		// Check weekly restrictions
		if ( isset( $restrictions['weekly'] ) && ! in_array( $current_day, $restrictions['weekly'] ) ) {
			return false;
		}

		return true;
	}

	/**
	 * Check if action is rate limited
	 *
	 * @since    1.0.0
	 * @access   private
	 * @param    string    $resource    The resource.
	 * @param    string    $operation   The operation.
	 * @return   boolean                True if action is rate limited.
	 */
	private function is_rate_limited_action( $resource, $operation ) {
		$rate_limited_actions = array(
			'scan.run',
			'report.generate',
			'vulnerability.fix'
		);

		return in_array( $resource . '.' . $operation, $rate_limited_actions );
	}

	/**
	 * Check rate limit
	 *
	 * @since    1.0.0
	 * @access   private
	 * @param    int       $user_id     The user ID.
	 * @param    string    $resource    The resource.
	 * @param    string    $operation   The operation.
	 * @return   boolean                True if within rate limit.
	 */
	private function check_rate_limit( $user_id, $resource, $operation ) {
		$action = $resource . '.' . $operation;
		$rate_limits = array(
			'scan.run' => array( 'limit' => 10, 'period' => 3600 ), // 10 scans per hour
			'report.generate' => array( 'limit' => 5, 'period' => 3600 ), // 5 reports per hour
			'vulnerability.fix' => array( 'limit' => 20, 'period' => 3600 ) // 20 fixes per hour
		);

		if ( ! isset( $rate_limits[ $action ] ) ) {
			return true;
		}

		$limit_config = $rate_limits[ $action ];
		$cache_key = "wp_breach_rate_limit_{$user_id}_{$action}";
		$current_count = wp_cache_get( $cache_key );

		if ( $current_count === false ) {
			// No cache entry, start counting
			wp_cache_set( $cache_key, 1, '', $limit_config['period'] );
			return true;
		}

		if ( $current_count >= $limit_config['limit'] ) {
			return false;
		}

		// Increment counter
		wp_cache_set( $cache_key, $current_count + 1, '', $limit_config['period'] );
		return true;
	}

	/**
	 * Check delegation permissions
	 *
	 * @since    1.0.0
	 * @access   private
	 * @param    int       $user_id     The user ID.
	 * @param    string    $resource    The resource.
	 * @param    string    $operation   The operation.
	 * @param    mixed     $object_id   The object ID.
	 * @return   boolean                True if delegation is valid.
	 */
	private function check_delegation_permissions( $user_id, $resource, $operation, $object_id ) {
		global $wpdb;

		$table_name = $wpdb->prefix . 'wp_breach_delegations';
		
		$delegation = $wpdb->get_row( $wpdb->prepare(
			"SELECT * FROM {$table_name} 
			WHERE delegated_to = %d 
			AND resource = %s 
			AND operation = %s 
			AND (object_id IS NULL OR object_id = %d)
			AND start_date <= NOW() 
			AND (end_date IS NULL OR end_date >= NOW())
			AND status = 'active'",
			$user_id,
			$resource,
			$operation,
			$object_id
		) );

		return ! empty( $delegation );
	}

	/**
	 * Check multisite permissions
	 *
	 * @since    1.0.0
	 * @access   private
	 * @param    int       $user_id    The user ID.
	 * @param    string    $action     The action.
	 * @param    mixed     $object_id  The object ID.
	 * @return   boolean               True if multisite permissions are valid.
	 */
	private function check_multisite_permissions( $user_id, $action, $object_id ) {
		if ( ! is_multisite() ) {
			return true;
		}

		// Network admin can access everything
		if ( is_super_admin( $user_id ) ) {
			return true;
		}

		// Check if user has access to current site
		if ( ! is_user_member_of_blog( $user_id, get_current_blog_id() ) ) {
			return false;
		}

		// Check cross-site access for specific actions
		$cross_site_actions = array(
			'scan.view.all_sites',
			'vulnerability.view.all_sites',
			'report.generate.network'
		);

		if ( in_array( $action, $cross_site_actions ) ) {
			return user_can( $user_id, 'manage_network' );
		}

		return true;
	}

	/**
	 * Check if user is active
	 *
	 * @since    1.0.0
	 * @access   private
	 * @param    int    $user_id    The user ID.
	 * @return   boolean            True if user is active.
	 */
	private function is_user_active( $user_id ) {
		$user_status = get_user_meta( $user_id, 'wp_breach_user_status', true );
		return empty( $user_status ) || $user_status === 'active';
	}

	/**
	 * Log access attempt
	 *
	 * @since    1.0.0
	 * @access   private
	 * @param    string    $action     The action attempted.
	 * @param    string    $context    The context.
	 * @param    boolean   $success    Whether access was granted.
	 * @param    string    $reason     The reason for the result.
	 */
	private function log_access_attempt( $action, $context, $success, $reason ) {
		$this->audit_logger->log_access_attempt(
			$action,
			$context,
			$success,
			array( 'reason' => $reason )
		);
	}

	/**
	 * Filter user capabilities
	 *
	 * @since    1.0.0
	 * @param    array     $allcaps    All capabilities.
	 * @param    array     $caps       Required capabilities.
	 * @param    array     $args       Additional arguments.
	 * @param    WP_User   $user       User object.
	 * @return   array                 Filtered capabilities.
	 */
	public function filter_user_capabilities( $allcaps, $caps, $args, $user ) {
		// Add dynamic capability checking here if needed
		return $allcaps;
	}

	/**
	 * Log capability check
	 *
	 * @since    1.0.0
	 * @param    int       $user_id    The user ID.
	 * @param    string    $action     The action.
	 * @param    string    $context    The context.
	 * @param    boolean   $result     The check result.
	 */
	public function log_capability_check( $user_id, $action, $context, $result ) {
		// This is called via action hook for monitoring purposes
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			error_log( sprintf(
				'WP-Breach Capability Check: User %d, Action %s, Context %s, Result %s',
				$user_id,
				$action,
				$context,
				$result ? 'GRANTED' : 'DENIED'
			) );
		}
	}

	/**
	 * Delegate permissions
	 *
	 * @since    1.0.0
	 * @param    int       $delegator_id    The user delegating permissions.
	 * @param    int       $delegated_to    The user receiving permissions.
	 * @param    string    $resource        The resource.
	 * @param    string    $operation       The operation.
	 * @param    string    $start_date      Start date for delegation.
	 * @param    string    $end_date        End date for delegation.
	 * @param    mixed     $object_id       Specific object ID (optional).
	 * @return   boolean                    True on success, false on failure.
	 */
	public function delegate_permissions( $delegator_id, $delegated_to, $resource, $operation, $start_date, $end_date = null, $object_id = null ) {
		global $wpdb;

		// Check if delegator can perform the action
		if ( ! $this->user_can( $delegator_id, $resource . '.' . $operation ) ) {
			return false;
		}

		// Check if delegator can delegate
		if ( ! user_can( $delegator_id, 'wp_breach_manage_permissions' ) ) {
			return false;
		}

		$table_name = $wpdb->prefix . 'wp_breach_delegations';

		$result = $wpdb->insert(
			$table_name,
			array(
				'delegated_by' => $delegator_id,
				'delegated_to' => $delegated_to,
				'resource' => $resource,
				'operation' => $operation,
				'object_id' => $object_id,
				'start_date' => $start_date,
				'end_date' => $end_date,
				'status' => 'active',
				'created_at' => current_time( 'mysql' )
			),
			array( '%d', '%d', '%s', '%s', '%d', '%s', '%s', '%s', '%s' )
		);

		if ( $result ) {
			$this->audit_logger->log_permission_change(
				$delegated_to,
				'permission_delegated',
				array(
					'delegated_by' => $delegator_id,
					'resource' => $resource,
					'operation' => $operation,
					'object_id' => $object_id,
					'start_date' => $start_date,
					'end_date' => $end_date
				)
			);
		}

		return $result !== false;
	}

	/**
	 * Revoke delegation
	 *
	 * @since    1.0.0
	 * @param    int    $delegation_id    The delegation ID.
	 * @param    int    $revoker_id       The user revoking the delegation.
	 * @return   boolean                  True on success, false on failure.
	 */
	public function revoke_delegation( $delegation_id, $revoker_id ) {
		global $wpdb;

		$table_name = $wpdb->prefix . 'wp_breach_delegations';

		// Get delegation details
		$delegation = $wpdb->get_row( $wpdb->prepare(
			"SELECT * FROM {$table_name} WHERE id = %d",
			$delegation_id
		) );

		if ( ! $delegation ) {
			return false;
		}

		// Check if revoker can revoke this delegation
		if ( $delegation->delegated_by != $revoker_id && ! user_can( $revoker_id, 'wp_breach_manage_permissions' ) ) {
			return false;
		}

		$result = $wpdb->update(
			$table_name,
			array( 'status' => 'revoked' ),
			array( 'id' => $delegation_id ),
			array( '%s' ),
			array( '%d' )
		);

		if ( $result ) {
			$this->audit_logger->log_permission_change(
				$delegation->delegated_to,
				'delegation_revoked',
				array(
					'revoked_by' => $revoker_id,
					'delegation_id' => $delegation_id,
					'resource' => $delegation->resource,
					'operation' => $delegation->operation
				)
			);
		}

		return $result !== false;
	}

	/**
	 * Get user delegations
	 *
	 * @since    1.0.0
	 * @param    int    $user_id    The user ID.
	 * @return   array              Array of delegations.
	 */
	public function get_user_delegations( $user_id ) {
		global $wpdb;

		$table_name = $wpdb->prefix . 'wp_breach_delegations';

		return $wpdb->get_results( $wpdb->prepare(
			"SELECT * FROM {$table_name} 
			WHERE delegated_to = %d 
			AND status = 'active'
			AND start_date <= NOW() 
			AND (end_date IS NULL OR end_date >= NOW())
			ORDER BY created_at DESC",
			$user_id
		) );
	}
}

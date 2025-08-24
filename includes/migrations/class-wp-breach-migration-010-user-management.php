<?php
/**
 * Database migration for User Management and Permissions System
 *
 * This migration creates the necessary database tables for Issue #010:
 * - Audit logs table
 * - Delegations table
 * - User sessions table
 *
 * @link       https://github.com/luozongbao
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/migrations
 */

/**
 * Migration class for User Management and Permissions System
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/migrations
 * @author     luozongbao <luo.zongbao@outlook.com>
 */
class WP_Breach_Migration_010_User_Management {

	/**
	 * The database instance
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      WP_Breach_Database    $database    Database instance.
	 */
	private $database;

	/**
	 * Initialize the migration
	 *
	 * @since    1.0.0
	 */
	public function __construct() {
		global $wpdb;
		require_once WP_BREACH_PLUGIN_DIR . 'includes/class-wp-breach-database.php';
		$this->database = new WP_Breach_Database();
	}

	/**
	 * Run the migration
	 *
	 * @since    1.0.0
	 * @return   boolean    True on success, false on failure.
	 */
	public function up() {
		$success = true;

		try {
			// Create audit logs table
			$success = $success && $this->create_audit_logs_table();
			
			// Create delegations table
			$success = $success && $this->create_delegations_table();
			
			// Create user sessions table
			$success = $success && $this->create_user_sessions_table();
			
			// Create user meta indexes
			$success = $success && $this->create_user_meta_indexes();
			
			// Insert default settings
			$success = $success && $this->insert_default_settings();

			if ( $success ) {
				// Update migration status
				update_option( 'wp_breach_migration_010_status', 'completed' );
				update_option( 'wp_breach_migration_010_date', current_time( 'mysql' ) );
				
				// Log migration completion
				error_log( 'WP-Breach: Migration 010 (User Management) completed successfully' );
			}

		} catch ( Exception $e ) {
			error_log( 'WP-Breach: Migration 010 failed - ' . $e->getMessage() );
			$success = false;
		}

		return $success;
	}

	/**
	 * Rollback the migration
	 *
	 * @since    1.0.0
	 * @return   boolean    True on success, false on failure.
	 */
	public function down() {
		global $wpdb;

		$success = true;

		try {
			// Drop tables
			$tables = array(
				$wpdb->prefix . 'wp_breach_audit_logs',
				$wpdb->prefix . 'wp_breach_delegations',
				$wpdb->prefix . 'wp_breach_user_sessions'
			);

			foreach ( $tables as $table ) {
				$result = $wpdb->query( "DROP TABLE IF EXISTS {$table}" );
				if ( $result === false ) {
					$success = false;
					error_log( "WP-Breach: Failed to drop table {$table}" );
				}
			}

			// Remove settings
			delete_option( 'wp_breach_user_management_settings' );
			delete_option( 'wp_breach_migration_010_status' );
			delete_option( 'wp_breach_migration_010_date' );

			if ( $success ) {
				error_log( 'WP-Breach: Migration 010 rollback completed successfully' );
			}

		} catch ( Exception $e ) {
			error_log( 'WP-Breach: Migration 010 rollback failed - ' . $e->getMessage() );
			$success = false;
		}

		return $success;
	}

	/**
	 * Create audit logs table
	 *
	 * @since    1.0.0
	 * @access   private
	 * @return   boolean    True on success, false on failure.
	 */
	private function create_audit_logs_table() {
		global $wpdb;

		$table_name = $wpdb->prefix . 'wp_breach_audit_logs';
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table_name} (
			id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			user_id bigint(20) UNSIGNED NOT NULL DEFAULT 0,
			action varchar(100) NOT NULL,
			actor_id bigint(20) UNSIGNED NOT NULL DEFAULT 0,
			ip_address varchar(45) NOT NULL,
			user_agent text,
			details longtext,
			timestamp datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
			severity enum('low','medium','high') NOT NULL DEFAULT 'low',
			PRIMARY KEY (id),
			KEY idx_user_id (user_id),
			KEY idx_action (action),
			KEY idx_actor_id (actor_id),
			KEY idx_timestamp (timestamp),
			KEY idx_severity (severity),
			KEY idx_ip_address (ip_address),
			KEY idx_composite_user_action (user_id, action),
			KEY idx_composite_timestamp_severity (timestamp, severity)
		) {$charset_collate};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );

		// Check if table was created successfully
		$table_exists = $wpdb->get_var( $wpdb->prepare( 
			"SHOW TABLES LIKE %s", 
			$table_name 
		) ) === $table_name;

		if ( ! $table_exists ) {
			error_log( "WP-Breach: Failed to create audit logs table: {$table_name}" );
			return false;
		}

		return true;
	}

	/**
	 * Create delegations table
	 *
	 * @since    1.0.0
	 * @access   private
	 * @return   boolean    True on success, false on failure.
	 */
	private function create_delegations_table() {
		global $wpdb;

		$table_name = $wpdb->prefix . 'wp_breach_delegations';
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table_name} (
			id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			delegated_by bigint(20) UNSIGNED NOT NULL,
			delegated_to bigint(20) UNSIGNED NOT NULL,
			resource varchar(50) NOT NULL,
			operation varchar(50) NOT NULL,
			object_id bigint(20) UNSIGNED NULL,
			start_date datetime NOT NULL,
			end_date datetime NULL,
			status enum('active','revoked','expired') NOT NULL DEFAULT 'active',
			created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			PRIMARY KEY (id),
			KEY idx_delegated_by (delegated_by),
			KEY idx_delegated_to (delegated_to),
			KEY idx_resource_operation (resource, operation),
			KEY idx_status (status),
			KEY idx_dates (start_date, end_date),
			KEY idx_active_delegations (delegated_to, status, start_date, end_date),
			UNIQUE KEY idx_unique_delegation (delegated_by, delegated_to, resource, operation, object_id, start_date)
		) {$charset_collate};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );

		// Check if table was created successfully
		$table_exists = $wpdb->get_var( $wpdb->prepare( 
			"SHOW TABLES LIKE %s", 
			$table_name 
		) ) === $table_name;

		if ( ! $table_exists ) {
			error_log( "WP-Breach: Failed to create delegations table: {$table_name}" );
			return false;
		}

		return true;
	}

	/**
	 * Create user sessions table
	 *
	 * @since    1.0.0
	 * @access   private
	 * @return   boolean    True on success, false on failure.
	 */
	private function create_user_sessions_table() {
		global $wpdb;

		$table_name = $wpdb->prefix . 'wp_breach_user_sessions';
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table_name} (
			id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			user_id bigint(20) UNSIGNED NOT NULL,
			session_token varchar(255) NOT NULL,
			ip_address varchar(45) NOT NULL,
			user_agent text,
			login_time datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_activity datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
			logout_time datetime NULL,
			status enum('active','expired','terminated') NOT NULL DEFAULT 'active',
			location varchar(255) NULL,
			device_info text NULL,
			PRIMARY KEY (id),
			KEY idx_user_id (user_id),
			KEY idx_session_token (session_token),
			KEY idx_status (status),
			KEY idx_ip_address (ip_address),
			KEY idx_last_activity (last_activity),
			KEY idx_active_sessions (user_id, status, last_activity),
			UNIQUE KEY idx_unique_session (user_id, session_token)
		) {$charset_collate};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );

		// Check if table was created successfully
		$table_exists = $wpdb->get_var( $wpdb->prepare( 
			"SHOW TABLES LIKE %s", 
			$table_name 
		) ) === $table_name;

		if ( ! $table_exists ) {
			error_log( "WP-Breach: Failed to create user sessions table: {$table_name}" );
			return false;
		}

		return true;
	}

	/**
	 * Create user meta indexes for performance
	 *
	 * @since    1.0.0
	 * @access   private
	 * @return   boolean    True on success, false on failure.
	 */
	private function create_user_meta_indexes() {
		global $wpdb;

		$success = true;

		// WP-Breach specific user meta keys that need indexing
		$meta_keys = array(
			'wp_breach_user_status',
			'wp_breach_time_restrictions',
			'wp_breach_last_login',
			'wp_breach_failed_login_count',
			'wp_breach_account_locked_until'
		);

		foreach ( $meta_keys as $meta_key ) {
			$index_name = 'idx_wp_breach_' . md5( $meta_key );
			
			// Check if index already exists
			$index_exists = $wpdb->get_var( $wpdb->prepare(
				"SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS 
				WHERE TABLE_SCHEMA = %s 
				AND TABLE_NAME = %s 
				AND INDEX_NAME = %s",
				DB_NAME,
				$wpdb->usermeta,
				$index_name
			) );

			if ( ! $index_exists ) {
				$sql = "ALTER TABLE {$wpdb->usermeta} 
						ADD INDEX {$index_name} (meta_key(191), meta_value(191))";
				
				$result = $wpdb->query( $sql );
				if ( $result === false ) {
					error_log( "WP-Breach: Failed to create index for meta_key: {$meta_key}" );
					$success = false;
				}
			}
		}

		return $success;
	}

	/**
	 * Insert default settings
	 *
	 * @since    1.0.0
	 * @access   private
	 * @return   boolean    True on success, false on failure.
	 */
	private function insert_default_settings() {
		$default_settings = array(
			'auto_assign_role' => 'none',
			'permission_inheritance' => 'disabled',
			'audit_retention' => 90,
			'max_failed_logins' => 5,
			'account_lockout_duration' => 1800, // 30 minutes
			'session_timeout' => 86400, // 24 hours
			'force_logout_on_role_change' => true,
			'enable_delegation' => true,
			'max_delegations_per_user' => 10,
			'delegation_approval_required' => false,
			'audit_sensitive_actions' => true,
			'enable_ip_tracking' => true,
			'enable_device_tracking' => true,
			'notification_on_role_change' => true,
			'notification_on_failed_login' => true
		);

		$success = update_option( 'wp_breach_user_management_settings', $default_settings );

		if ( ! $success ) {
			error_log( 'WP-Breach: Failed to insert default user management settings' );
		}

		return $success;
	}

	/**
	 * Migrate existing data if any
	 *
	 * @since    1.0.0
	 * @access   private
	 * @return   boolean    True on success, false on failure.
	 */
	private function migrate_existing_data() {
		// This method can be used to migrate data from previous versions
		// Currently no existing data to migrate for new installation
		return true;
	}

	/**
	 * Verify migration integrity
	 *
	 * @since    1.0.0
	 * @return   boolean    True if migration is valid, false otherwise.
	 */
	public function verify() {
		global $wpdb;

		// Check if all required tables exist
		$required_tables = array(
			$wpdb->prefix . 'wp_breach_audit_logs',
			$wpdb->prefix . 'wp_breach_delegations',
			$wpdb->prefix . 'wp_breach_user_sessions'
		);

		foreach ( $required_tables as $table ) {
			$table_exists = $wpdb->get_var( $wpdb->prepare( 
				"SHOW TABLES LIKE %s", 
				$table 
			) ) === $table;

			if ( ! $table_exists ) {
				error_log( "WP-Breach: Migration verification failed - table {$table} does not exist" );
				return false;
			}
		}

		// Check if settings exist
		$settings = get_option( 'wp_breach_user_management_settings' );
		if ( empty( $settings ) ) {
			error_log( 'WP-Breach: Migration verification failed - user management settings not found' );
			return false;
		}

		// Check migration status
		$migration_status = get_option( 'wp_breach_migration_010_status' );
		if ( $migration_status !== 'completed' ) {
			error_log( 'WP-Breach: Migration verification failed - migration status is not completed' );
			return false;
		}

		return true;
	}

	/**
	 * Get migration information
	 *
	 * @since    1.0.0
	 * @return   array    Migration information.
	 */
	public function get_info() {
		return array(
			'version' => '010',
			'name' => 'User Management and Permissions System',
			'description' => 'Creates audit logs, delegations, and user sessions tables for comprehensive user management and permission tracking',
			'tables' => array(
				'wp_breach_audit_logs',
				'wp_breach_delegations',
				'wp_breach_user_sessions'
			),
			'dependencies' => array(),
			'status' => get_option( 'wp_breach_migration_010_status', 'pending' ),
			'date' => get_option( 'wp_breach_migration_010_date', null )
		);
	}

	/**
	 * Clean up orphaned data
	 *
	 * @since    1.0.0
	 * @return   boolean    True on success, false on failure.
	 */
	public function cleanup() {
		global $wpdb;

		$success = true;

		try {
			// Clean up orphaned audit logs (users that no longer exist)
			$result = $wpdb->query(
				"DELETE al FROM {$wpdb->prefix}wp_breach_audit_logs al 
				 LEFT JOIN {$wpdb->users} u ON al.user_id = u.ID 
				 WHERE al.user_id > 0 AND u.ID IS NULL"
			);

			// Clean up orphaned delegations
			$result = $wpdb->query(
				"DELETE d FROM {$wpdb->prefix}wp_breach_delegations d 
				 LEFT JOIN {$wpdb->users} u1 ON d.delegated_by = u1.ID 
				 LEFT JOIN {$wpdb->users} u2 ON d.delegated_to = u2.ID 
				 WHERE u1.ID IS NULL OR u2.ID IS NULL"
			);

			// Clean up orphaned user sessions
			$result = $wpdb->query(
				"DELETE s FROM {$wpdb->prefix}wp_breach_user_sessions s 
				 LEFT JOIN {$wpdb->users} u ON s.user_id = u.ID 
				 WHERE u.ID IS NULL"
			);

			// Clean up expired sessions
			$result = $wpdb->query( $wpdb->prepare(
				"UPDATE {$wpdb->prefix}wp_breach_user_sessions 
				 SET status = 'expired' 
				 WHERE status = 'active' 
				 AND last_activity < %s",
				date( 'Y-m-d H:i:s', time() - 86400 ) // 24 hours ago
			) );

			// Clean up expired delegations
			$result = $wpdb->query( $wpdb->prepare(
				"UPDATE {$wpdb->prefix}wp_breach_delegations 
				 SET status = 'expired' 
				 WHERE status = 'active' 
				 AND end_date IS NOT NULL 
				 AND end_date < %s",
				current_time( 'mysql' )
			) );

		} catch ( Exception $e ) {
			error_log( 'WP-Breach: Migration 010 cleanup failed - ' . $e->getMessage() );
			$success = false;
		}

		return $success;
	}
}

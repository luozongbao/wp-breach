<?php
/**
 * The audit logger for WP-Breach permissions.
 *
 * This class handles logging of all permission-related changes and access events
 * for auditing and compliance purposes.
 *
 * @link       https://github.com/luozongbao
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes
 */

/**
 * The audit logger class.
 *
 * This class logs all permission-related activities including role changes,
 * capability modifications, and access events for security auditing.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes
 * @author     luozongbao <luo.zongbao@outlook.com>
 */
class WP_Breach_Audit_Logger {

	/**
	 * Database instance
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      WP_Breach_Database    $database    Database instance.
	 */
	private $database;

	/**
	 * Table name for audit logs
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      string    $table_name    Audit log table name.
	 */
	private $table_name;

	/**
	 * Initialize the audit logger.
	 *
	 * @since    1.0.0
	 */
	public function __construct() {
		global $wpdb;
		
		require_once WP_BREACH_PLUGIN_DIR . 'includes/class-wp-breach-database.php';
		$this->database = new WP_Breach_Database();
		$this->table_name = $wpdb->prefix . 'wp_breach_audit_logs';
		
		$this->init_hooks();
	}

	/**
	 * Initialize WordPress hooks
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function init_hooks() {
		add_action( 'wp_login', array( $this, 'log_user_login' ), 10, 2 );
		add_action( 'wp_logout', array( $this, 'log_user_logout' ) );
		add_action( 'wp_login_failed', array( $this, 'log_login_failure' ) );
	}

	/**
	 * Log permission change
	 *
	 * @since    1.0.0
	 * @param    int       $user_id      The user ID affected.
	 * @param    string    $action       The action performed.
	 * @param    array     $details      Additional details about the change.
	 * @return   boolean                 True on success, false on failure.
	 */
	public function log_permission_change( $user_id, $action, $details = array() ) {
		global $wpdb;

		$current_user_id = get_current_user_id();
		$ip_address = $this->get_client_ip();
		$user_agent = $this->get_user_agent();

		$log_data = array(
			'user_id' => $user_id,
			'action' => $action,
			'actor_id' => $current_user_id,
			'ip_address' => $ip_address,
			'user_agent' => $user_agent,
			'details' => wp_json_encode( $details ),
			'timestamp' => current_time( 'mysql' ),
			'severity' => $this->get_action_severity( $action )
		);

		$result = $wpdb->insert(
			$this->table_name,
			$log_data,
			array( '%d', '%s', '%d', '%s', '%s', '%s', '%s', '%s' )
		);

		if ( $result === false ) {
			error_log( 'WP-Breach: Failed to log permission change - ' . $wpdb->last_error );
			return false;
		}

		// Trigger alert for high-severity actions
		if ( $log_data['severity'] === 'high' ) {
			$this->trigger_security_alert( $log_data );
		}

		return true;
	}

	/**
	 * Log access attempt
	 *
	 * @since    1.0.0
	 * @param    string    $resource     The resource being accessed.
	 * @param    string    $action       The action attempted.
	 * @param    boolean   $success      Whether the access was successful.
	 * @param    array     $details      Additional details.
	 * @return   boolean                 True on success, false on failure.
	 */
	public function log_access_attempt( $resource, $action, $success, $details = array() ) {
		global $wpdb;

		$current_user_id = get_current_user_id();
		$ip_address = $this->get_client_ip();
		$user_agent = $this->get_user_agent();

		$action_type = $success ? 'access_granted' : 'access_denied';
		$severity = $success ? 'low' : 'medium';

		$log_data = array(
			'user_id' => $current_user_id,
			'action' => $action_type,
			'actor_id' => $current_user_id,
			'ip_address' => $ip_address,
			'user_agent' => $user_agent,
			'details' => wp_json_encode( array_merge( $details, array(
				'resource' => $resource,
				'attempted_action' => $action,
				'success' => $success
			) ) ),
			'timestamp' => current_time( 'mysql' ),
			'severity' => $severity
		);

		$result = $wpdb->insert(
			$this->table_name,
			$log_data,
			array( '%d', '%s', '%d', '%s', '%s', '%s', '%s', '%s' )
		);

		return $result !== false;
	}

	/**
	 * Log user login
	 *
	 * @since    1.0.0
	 * @param    string    $user_login    The user login name.
	 * @param    WP_User   $user          The user object.
	 */
	public function log_user_login( $user_login, $user ) {
		$this->log_permission_change(
			$user->ID,
			'user_login',
			array(
				'user_login' => $user_login,
				'login_time' => current_time( 'mysql' )
			)
		);
	}

	/**
	 * Log user logout
	 *
	 * @since    1.0.0
	 */
	public function log_user_logout() {
		$current_user_id = get_current_user_id();
		if ( $current_user_id ) {
			$this->log_permission_change(
				$current_user_id,
				'user_logout',
				array(
					'logout_time' => current_time( 'mysql' )
				)
			);
		}
	}

	/**
	 * Log login failure
	 *
	 * @since    1.0.0
	 * @param    string    $username    The attempted username.
	 */
	public function log_login_failure( $username ) {
		global $wpdb;

		$ip_address = $this->get_client_ip();
		$user_agent = $this->get_user_agent();

		// Try to get user ID if username exists
		$user = get_user_by( 'login', $username );
		$user_id = $user ? $user->ID : 0;

		$log_data = array(
			'user_id' => $user_id,
			'action' => 'login_failed',
			'actor_id' => 0,
			'ip_address' => $ip_address,
			'user_agent' => $user_agent,
			'details' => wp_json_encode( array(
				'attempted_username' => $username,
				'failure_time' => current_time( 'mysql' )
			) ),
			'timestamp' => current_time( 'mysql' ),
			'severity' => 'medium'
		);

		$wpdb->insert(
			$this->table_name,
			$log_data,
			array( '%d', '%s', '%d', '%s', '%s', '%s', '%s', '%s' )
		);

		// Check for brute force attempts
		$this->check_brute_force_attempts( $ip_address, $username );
	}

	/**
	 * Get permission logs
	 *
	 * @since    1.0.0
	 * @param    array    $args    Query arguments.
	 * @return   array            Array of log entries.
	 */
	public function get_permission_logs( $args = array() ) {
		global $wpdb;

		$defaults = array(
			'user_id' => null,
			'action' => null,
			'severity' => null,
			'start_date' => null,
			'end_date' => null,
			'limit' => 100,
			'offset' => 0,
			'orderby' => 'timestamp',
			'order' => 'DESC'
		);

		$args = wp_parse_args( $args, $defaults );

		$where_conditions = array( '1=1' );
		$where_values = array();

		if ( $args['user_id'] ) {
			$where_conditions[] = 'user_id = %d';
			$where_values[] = $args['user_id'];
		}

		if ( $args['action'] ) {
			$where_conditions[] = 'action = %s';
			$where_values[] = $args['action'];
		}

		if ( $args['severity'] ) {
			$where_conditions[] = 'severity = %s';
			$where_values[] = $args['severity'];
		}

		if ( $args['start_date'] ) {
			$where_conditions[] = 'timestamp >= %s';
			$where_values[] = $args['start_date'];
		}

		if ( $args['end_date'] ) {
			$where_conditions[] = 'timestamp <= %s';
			$where_values[] = $args['end_date'];
		}

		$where_clause = implode( ' AND ', $where_conditions );
		$orderby = sanitize_sql_orderby( $args['orderby'] . ' ' . $args['order'] );

		$query = "SELECT * FROM {$this->table_name} WHERE {$where_clause} ORDER BY {$orderby} LIMIT %d OFFSET %d";
		$where_values[] = $args['limit'];
		$where_values[] = $args['offset'];

		if ( ! empty( $where_values ) ) {
			$query = $wpdb->prepare( $query, $where_values );
		}

		$results = $wpdb->get_results( $query, ARRAY_A );

		// Decode JSON details
		foreach ( $results as &$result ) {
			$result['details'] = json_decode( $result['details'], true );
		}

		return $results;
	}

	/**
	 * Get audit statistics
	 *
	 * @since    1.0.0
	 * @param    array    $args    Query arguments.
	 * @return   array            Statistics array.
	 */
	public function get_audit_statistics( $args = array() ) {
		global $wpdb;

		$defaults = array(
			'start_date' => date( 'Y-m-d', strtotime( '-30 days' ) ),
			'end_date' => date( 'Y-m-d' )
		);

		$args = wp_parse_args( $args, $defaults );

		$stats = array();

		// Total log entries
		$stats['total_entries'] = $wpdb->get_var( $wpdb->prepare(
			"SELECT COUNT(*) FROM {$this->table_name} WHERE timestamp BETWEEN %s AND %s",
			$args['start_date'],
			$args['end_date']
		) );

		// Entries by severity
		$severity_stats = $wpdb->get_results( $wpdb->prepare(
			"SELECT severity, COUNT(*) as count FROM {$this->table_name} 
			WHERE timestamp BETWEEN %s AND %s GROUP BY severity",
			$args['start_date'],
			$args['end_date']
		), ARRAY_A );

		$stats['by_severity'] = array();
		foreach ( $severity_stats as $stat ) {
			$stats['by_severity'][ $stat['severity'] ] = $stat['count'];
		}

		// Entries by action
		$action_stats = $wpdb->get_results( $wpdb->prepare(
			"SELECT action, COUNT(*) as count FROM {$this->table_name} 
			WHERE timestamp BETWEEN %s AND %s GROUP BY action ORDER BY count DESC LIMIT 10",
			$args['start_date'],
			$args['end_date']
		), ARRAY_A );

		$stats['by_action'] = array();
		foreach ( $action_stats as $stat ) {
			$stats['by_action'][ $stat['action'] ] = $stat['count'];
		}

		// Unique users
		$stats['unique_users'] = $wpdb->get_var( $wpdb->prepare(
			"SELECT COUNT(DISTINCT user_id) FROM {$this->table_name} 
			WHERE timestamp BETWEEN %s AND %s AND user_id > 0",
			$args['start_date'],
			$args['end_date']
		) );

		// Failed login attempts
		$stats['failed_logins'] = $wpdb->get_var( $wpdb->prepare(
			"SELECT COUNT(*) FROM {$this->table_name} 
			WHERE action = 'login_failed' AND timestamp BETWEEN %s AND %s",
			$args['start_date'],
			$args['end_date']
		) );

		return $stats;
	}

	/**
	 * Clean old audit logs
	 *
	 * @since    1.0.0
	 * @param    int    $days    Number of days to keep logs.
	 * @return   int            Number of deleted records.
	 */
	public function clean_old_logs( $days = 90 ) {
		global $wpdb;

		$cutoff_date = date( 'Y-m-d H:i:s', strtotime( "-{$days} days" ) );

		$deleted = $wpdb->query( $wpdb->prepare(
			"DELETE FROM {$this->table_name} WHERE timestamp < %s",
			$cutoff_date
		) );

		if ( $deleted > 0 ) {
			$this->log_permission_change(
				0,
				'audit_logs_cleaned',
				array(
					'deleted_count' => $deleted,
					'cutoff_date' => $cutoff_date
				)
			);
		}

		return $deleted;
	}

	/**
	 * Get client IP address
	 *
	 * @since    1.0.0
	 * @access   private
	 * @return   string    Client IP address.
	 */
	private function get_client_ip() {
		$ip_keys = array(
			'HTTP_CF_CONNECTING_IP',
			'HTTP_X_FORWARDED_FOR',
			'HTTP_X_FORWARDED',
			'HTTP_X_CLUSTER_CLIENT_IP',
			'HTTP_FORWARDED_FOR',
			'HTTP_FORWARDED',
			'REMOTE_ADDR'
		);

		foreach ( $ip_keys as $key ) {
			if ( ! empty( $_SERVER[ $key ] ) ) {
				$ip = $_SERVER[ $key ];
				// Handle comma-separated IPs
				if ( strpos( $ip, ',' ) !== false ) {
					$ip = explode( ',', $ip )[0];
				}
				$ip = trim( $ip );
				if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
					return $ip;
				}
			}
		}

		return isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : '0.0.0.0';
	}

	/**
	 * Get user agent
	 *
	 * @since    1.0.0
	 * @access   private
	 * @return   string    User agent string.
	 */
	private function get_user_agent() {
		return isset( $_SERVER['HTTP_USER_AGENT'] ) ? $_SERVER['HTTP_USER_AGENT'] : '';
	}

	/**
	 * Get action severity
	 *
	 * @since    1.0.0
	 * @access   private
	 * @param    string    $action    The action.
	 * @return   string              The severity level.
	 */
	private function get_action_severity( $action ) {
		$high_severity_actions = array(
			'role_assigned',
			'role_removed',
			'capability_added',
			'capability_removed',
			'user_created',
			'user_removed_from_site',
			'permission_escalation'
		);

		$medium_severity_actions = array(
			'login_failed',
			'access_denied',
			'role_changed',
			'user_added_to_site'
		);

		if ( in_array( $action, $high_severity_actions, true ) ) {
			return 'high';
		} elseif ( in_array( $action, $medium_severity_actions, true ) ) {
			return 'medium';
		}

		return 'low';
	}

	/**
	 * Trigger security alert
	 *
	 * @since    1.0.0
	 * @access   private
	 * @param    array    $log_data    The log data.
	 */
	private function trigger_security_alert( $log_data ) {
		// This would integrate with the monitoring system from Issue #008
		do_action( 'wp_breach_security_alert', array(
			'type' => 'permission_change',
			'severity' => $log_data['severity'],
			'message' => sprintf(
				'High-severity permission change: %s for user %d',
				$log_data['action'],
				$log_data['user_id']
			),
			'details' => $log_data
		) );
	}

	/**
	 * Check for brute force attempts
	 *
	 * @since    1.0.0
	 * @access   private
	 * @param    string    $ip_address    The IP address.
	 * @param    string    $username      The attempted username.
	 */
	private function check_brute_force_attempts( $ip_address, $username ) {
		global $wpdb;

		$threshold = 5; // Number of failed attempts to trigger alert
		$time_window = 300; // 5 minutes in seconds

		$cutoff_time = date( 'Y-m-d H:i:s', time() - $time_window );

		// Check by IP
		$ip_attempts = $wpdb->get_var( $wpdb->prepare(
			"SELECT COUNT(*) FROM {$this->table_name} 
			WHERE action = 'login_failed' AND ip_address = %s AND timestamp >= %s",
			$ip_address,
			$cutoff_time
		) );

		// Check by username
		$username_attempts = $wpdb->get_var( $wpdb->prepare(
			"SELECT COUNT(*) FROM {$this->table_name} 
			WHERE action = 'login_failed' AND details LIKE %s AND timestamp >= %s",
			'%"attempted_username":"' . $username . '"%',
			$cutoff_time
		) );

		if ( $ip_attempts >= $threshold || $username_attempts >= $threshold ) {
			do_action( 'wp_breach_brute_force_detected', array(
				'ip_address' => $ip_address,
				'username' => $username,
				'ip_attempts' => $ip_attempts,
				'username_attempts' => $username_attempts,
				'time_window' => $time_window
			) );
		}
	}

	/**
	 * Export audit logs
	 *
	 * @since    1.0.0
	 * @param    array     $args    Export arguments.
	 * @param    string    $format  Export format (csv, json).
	 * @return   string             Exported data.
	 */
	public function export_logs( $args = array(), $format = 'csv' ) {
		$logs = $this->get_permission_logs( $args );

		if ( $format === 'json' ) {
			return wp_json_encode( $logs );
		}

		// CSV format
		$csv_data = "ID,User ID,Action,Actor ID,IP Address,Timestamp,Severity,Details\n";
		
		foreach ( $logs as $log ) {
			$details = is_array( $log['details'] ) ? wp_json_encode( $log['details'] ) : $log['details'];
			$csv_data .= sprintf(
				"%d,%d,%s,%d,%s,%s,%s,\"%s\"\n",
				$log['id'],
				$log['user_id'],
				$log['action'],
				$log['actor_id'],
				$log['ip_address'],
				$log['timestamp'],
				$log['severity'],
				str_replace( '"', '""', $details )
			);
		}

		return $csv_data;
	}
}

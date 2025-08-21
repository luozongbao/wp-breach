<?php
/**
 * Alert model class for database operations.
 *
 * @link       https://github.com/luozongbao
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/database
 */

/**
 * Alert model class for database operations.
 *
 * Handles all database operations related to security alerts
 * including creation, status management, and notification tracking.
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/database
 * @author     luozongbao <luo.zongbao@outlook.com>
 */
class WP_Breach_Alert_Model extends WP_Breach_Base_Model {

	/**
	 * Get the table suffix for this model.
	 *
	 * @since    1.0.0
	 * @return   string    The table suffix.
	 */
	protected function get_table_suffix() {
		return 'breach_alerts';
	}

	/**
	 * Get the validation rules for this model.
	 *
	 * @since    1.0.0
	 * @return   array    The validation rules.
	 */
	protected function get_validation_rules() {
		return array(
			'alert_type' => array(
				'required'   => true,
				'type'       => 'string',
				'max_length' => 50,
			),
			'severity' => array(
				'required'   => true,
				'type'       => 'string',
				'max_length' => 20,
			),
			'title' => array(
				'required'   => true,
				'type'       => 'string',
				'max_length' => 255,
			),
			'message' => array(
				'required' => true,
				'type'     => 'string',
			),
		);
	}

	/**
	 * Create a new alert.
	 *
	 * @since    1.0.0
	 * @param    array    $data    The alert data.
	 * @return   int|false    The alert ID or false on failure.
	 */
	public function create_alert( $data ) {
		$defaults = array(
			'status'     => 'active',
			'read_status' => 'unread',
			'created_at' => current_time( 'mysql' ),
		);

		$data = wp_parse_args( $data, $defaults );

		// Generate alert hash for deduplication
		$data['alert_hash'] = $this->generate_alert_hash( $data );

		// Check for duplicate alerts
		if ( $this->is_duplicate_alert( $data['alert_hash'] ) ) {
			return $this->increment_duplicate_count( $data['alert_hash'] );
		}

		return $this->create( $data );
	}

	/**
	 * Create vulnerability alert.
	 *
	 * @since    1.0.0
	 * @param    int      $vulnerability_id    The vulnerability ID.
	 * @param    string   $severity           Alert severity.
	 * @param    array    $additional_data    Additional alert data.
	 * @return   int|false    The alert ID or false on failure.
	 */
	public function create_vulnerability_alert( $vulnerability_id, $severity, $additional_data = array() ) {
		$alert_data = array_merge( $additional_data, array(
			'alert_type'       => 'vulnerability',
			'severity'         => $severity,
			'reference_type'   => 'vulnerability',
			'reference_id'     => $vulnerability_id,
		) );

		return $this->create_alert( $alert_data );
	}

	/**
	 * Create scan alert.
	 *
	 * @since    1.0.0
	 * @param    int      $scan_id           The scan ID.
	 * @param    string   $alert_type        Specific alert type.
	 * @param    string   $severity          Alert severity.
	 * @param    array    $additional_data   Additional alert data.
	 * @return   int|false    The alert ID or false on failure.
	 */
	public function create_scan_alert( $scan_id, $alert_type, $severity, $additional_data = array() ) {
		$alert_data = array_merge( $additional_data, array(
			'alert_type'     => $alert_type,
			'severity'       => $severity,
			'reference_type' => 'scan',
			'reference_id'   => $scan_id,
		) );

		return $this->create_alert( $alert_data );
	}

	/**
	 * Create system alert.
	 *
	 * @since    1.0.0
	 * @param    string   $alert_type        The alert type.
	 * @param    string   $severity          Alert severity.
	 * @param    string   $title             Alert title.
	 * @param    string   $message           Alert message.
	 * @param    array    $additional_data   Additional alert data.
	 * @return   int|false    The alert ID or false on failure.
	 */
	public function create_system_alert( $alert_type, $severity, $title, $message, $additional_data = array() ) {
		$alert_data = array_merge( $additional_data, array(
			'alert_type'     => $alert_type,
			'severity'       => $severity,
			'title'          => $title,
			'message'        => $message,
			'reference_type' => 'system',
		) );

		return $this->create_alert( $alert_data );
	}

	/**
	 * Update alert status.
	 *
	 * @since    1.0.0
	 * @param    int      $alert_id    The alert ID.
	 * @param    string   $status      The new status.
	 * @return   bool     True on success, false on failure.
	 */
	public function update_alert_status( $alert_id, $status ) {
		$update_data = array( 'status' => $status );

		if ( $status === 'resolved' ) {
			$update_data['resolved_at'] = current_time( 'mysql' );
			$update_data['resolved_by'] = get_current_user_id();
		} elseif ( $status === 'dismissed' ) {
			$update_data['dismissed_at'] = current_time( 'mysql' );
			$update_data['dismissed_by'] = get_current_user_id();
		}

		return $this->update( $alert_id, $update_data );
	}

	/**
	 * Mark alert as read.
	 *
	 * @since    1.0.0
	 * @param    int    $alert_id    The alert ID.
	 * @param    int    $user_id     Optional user ID.
	 * @return   bool   True on success, false on failure.
	 */
	public function mark_as_read( $alert_id, $user_id = null ) {
		if ( ! $user_id ) {
			$user_id = get_current_user_id();
		}

		return $this->update( $alert_id, array(
			'read_status' => 'read',
			'read_at'     => current_time( 'mysql' ),
			'read_by'     => $user_id,
		) );
	}

	/**
	 * Mark alert as unread.
	 *
	 * @since    1.0.0
	 * @param    int    $alert_id    The alert ID.
	 * @return   bool   True on success, false on failure.
	 */
	public function mark_as_unread( $alert_id ) {
		return $this->update( $alert_id, array(
			'read_status' => 'unread',
			'read_at'     => null,
			'read_by'     => null,
		) );
	}

	/**
	 * Dismiss alert.
	 *
	 * @since    1.0.0
	 * @param    int      $alert_id    The alert ID.
	 * @param    string   $reason      Optional dismissal reason.
	 * @return   bool     True on success, false on failure.
	 */
	public function dismiss_alert( $alert_id, $reason = '' ) {
		return $this->update_alert_status( $alert_id, 'dismissed' );
	}

	/**
	 * Resolve alert.
	 *
	 * @since    1.0.0
	 * @param    int      $alert_id    The alert ID.
	 * @param    string   $resolution  Optional resolution notes.
	 * @return   bool     True on success, false on failure.
	 */
	public function resolve_alert( $alert_id, $resolution = '' ) {
		$update_data = array( 'resolution_notes' => $resolution );
		return $this->update_alert_status( $alert_id, 'resolved' );
	}

	/**
	 * Get alerts by status.
	 *
	 * @since    1.0.0
	 * @param    string   $status    The alert status.
	 * @param    array    $args      Additional query arguments.
	 * @return   array    Array of alert objects.
	 */
	public function get_alerts_by_status( $status, $args = array() ) {
		$args['where'] = array( 'status' => $status );
		return $this->get_all( $args );
	}

	/**
	 * Get alerts by severity.
	 *
	 * @since    1.0.0
	 * @param    string   $severity    The alert severity.
	 * @param    array    $args        Additional query arguments.
	 * @return   array    Array of alert objects.
	 */
	public function get_alerts_by_severity( $severity, $args = array() ) {
		$args['where'] = array( 'severity' => $severity );
		return $this->get_all( $args );
	}

	/**
	 * Get alerts by type.
	 *
	 * @since    1.0.0
	 * @param    string   $alert_type    The alert type.
	 * @param    array    $args          Additional query arguments.
	 * @return   array    Array of alert objects.
	 */
	public function get_alerts_by_type( $alert_type, $args = array() ) {
		$args['where'] = array( 'alert_type' => $alert_type );
		return $this->get_all( $args );
	}

	/**
	 * Get active alerts.
	 *
	 * @since    1.0.0
	 * @param    array    $args    Additional query arguments.
	 * @return   array    Array of active alert objects.
	 */
	public function get_active_alerts( $args = array() ) {
		$args['where'] = array( 'status' => 'active' );
		return $this->get_all( $args );
	}

	/**
	 * Get unread alerts.
	 *
	 * @since    1.0.0
	 * @param    array    $args    Additional query arguments.
	 * @return   array    Array of unread alert objects.
	 */
	public function get_unread_alerts( $args = array() ) {
		$args['where'] = array( 'read_status' => 'unread' );
		return $this->get_all( $args );
	}

	/**
	 * Get critical alerts.
	 *
	 * @since    1.0.0
	 * @param    array    $args    Additional query arguments.
	 * @return   array    Array of critical alert objects.
	 */
	public function get_critical_alerts( $args = array() ) {
		$args['where'] = array(
			'severity' => 'critical',
			'status'   => 'active',
		);
		return $this->get_all( $args );
	}

	/**
	 * Get recent alerts.
	 *
	 * @since    1.0.0
	 * @param    int    $limit    Number of alerts to retrieve.
	 * @return   array  Array of recent alert objects.
	 */
	public function get_recent_alerts( $limit = 20 ) {
		return $this->get_all( array(
			'limit'    => $limit,
			'order_by' => 'created_at',
			'order'    => 'DESC',
		) );
	}

	/**
	 * Get alert count by status.
	 *
	 * @since    1.0.0
	 * @return   array    Array of status counts.
	 */
	public function get_alert_counts_by_status() {
		$sql = "SELECT 
			status,
			COUNT(*) as count
		FROM {$this->table_name}
		GROUP BY status";

		$results = $this->wpdb->get_results( $sql );
		
		$counts = array();
		foreach ( $results as $result ) {
			$counts[ $result->status ] = intval( $result->count );
		}

		return $counts;
	}

	/**
	 * Get alert count by severity.
	 *
	 * @since    1.0.0
	 * @return   array    Array of severity counts.
	 */
	public function get_alert_counts_by_severity() {
		$sql = "SELECT 
			severity,
			COUNT(*) as count
		FROM {$this->table_name}
		WHERE status = 'active'
		GROUP BY severity";

		$results = $this->wpdb->get_results( $sql );
		
		$counts = array();
		foreach ( $results as $result ) {
			$counts[ $result->severity ] = intval( $result->count );
		}

		return $counts;
	}

	/**
	 * Get alert statistics.
	 *
	 * @since    1.0.0
	 * @param    array    $args    Query arguments (date range, etc.).
	 * @return   array    Alert statistics.
	 */
	public function get_alert_statistics( $args = array() ) {
		$where_clause = 'WHERE 1=1';
		$where_params = array();

		// Add date range filter
		if ( ! empty( $args['date_from'] ) ) {
			$where_clause .= ' AND created_at >= %s';
			$where_params[] = $args['date_from'];
		}

		if ( ! empty( $args['date_to'] ) ) {
			$where_clause .= ' AND created_at <= %s';
			$where_params[] = $args['date_to'];
		}

		$sql = "SELECT 
			COUNT(*) as total_alerts,
			SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active_alerts,
			SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) as resolved_alerts,
			SUM(CASE WHEN status = 'dismissed' THEN 1 ELSE 0 END) as dismissed_alerts,
			SUM(CASE WHEN read_status = 'unread' THEN 1 ELSE 0 END) as unread_alerts,
			SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical_alerts,
			SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high_alerts,
			SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium_alerts,
			SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low_alerts
		FROM {$this->table_name} 
		{$where_clause}";

		if ( ! empty( $where_params ) ) {
			$sql = $this->wpdb->prepare( $sql, $where_params );
		}

		$result = $this->wpdb->get_row( $sql );

		return array(
			'total_alerts'     => intval( $result->total_alerts ),
			'active_alerts'    => intval( $result->active_alerts ),
			'resolved_alerts'  => intval( $result->resolved_alerts ),
			'dismissed_alerts' => intval( $result->dismissed_alerts ),
			'unread_alerts'    => intval( $result->unread_alerts ),
			'severity_counts'  => array(
				'critical' => intval( $result->critical_alerts ),
				'high'     => intval( $result->high_alerts ),
				'medium'   => intval( $result->medium_alerts ),
				'low'      => intval( $result->low_alerts ),
			),
		);
	}

	/**
	 * Get alert trends.
	 *
	 * @since    1.0.0
	 * @param    string   $period    Time period (daily, weekly, monthly).
	 * @param    int      $limit     Number of periods to retrieve.
	 * @return   array    Trend data.
	 */
	public function get_alert_trends( $period = 'daily', $limit = 30 ) {
		$date_format = '%Y-%m-%d';
		$interval = '1 DAY';

		switch ( $period ) {
			case 'weekly':
				$date_format = '%Y-%u';
				$interval = '1 WEEK';
				break;
			case 'monthly':
				$date_format = '%Y-%m';
				$interval = '1 MONTH';
				break;
		}

		$sql = "SELECT 
			DATE_FORMAT(created_at, '{$date_format}') as period,
			COUNT(*) as total_count,
			SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical_count,
			SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high_count,
			SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium_count,
			SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low_count
		FROM {$this->table_name}
		WHERE created_at >= DATE_SUB(NOW(), INTERVAL %d {$interval})
		GROUP BY period
		ORDER BY period DESC
		LIMIT %d";

		return $this->wpdb->get_results( $this->wpdb->prepare( $sql, $limit, $limit ) );
	}

	/**
	 * Bulk mark alerts as read.
	 *
	 * @since    1.0.0
	 * @param    array    $alert_ids    Array of alert IDs.
	 * @param    int      $user_id      Optional user ID.
	 * @return   int      Number of alerts marked as read.
	 */
	public function bulk_mark_as_read( $alert_ids, $user_id = null ) {
		if ( empty( $alert_ids ) ) {
			return 0;
		}

		if ( ! $user_id ) {
			$user_id = get_current_user_id();
		}

		$ids_placeholder = implode( ',', array_fill( 0, count( $alert_ids ), '%d' ) );
		
		$sql = "UPDATE {$this->table_name} 
		        SET read_status = 'read', read_at = %s, read_by = %d
		        WHERE id IN ({$ids_placeholder})";

		$params = array_merge( 
			array( current_time( 'mysql' ), $user_id ), 
			$alert_ids 
		);

		return $this->wpdb->query( $this->wpdb->prepare( $sql, $params ) );
	}

	/**
	 * Bulk update alert status.
	 *
	 * @since    1.0.0
	 * @param    array    $alert_ids    Array of alert IDs.
	 * @param    string   $status       New status.
	 * @return   int      Number of alerts updated.
	 */
	public function bulk_update_status( $alert_ids, $status ) {
		if ( empty( $alert_ids ) ) {
			return 0;
		}

		$ids_placeholder = implode( ',', array_fill( 0, count( $alert_ids ), '%d' ) );
		$update_fields = array( 'status = %s' );
		$params = array( $status );

		// Add status-specific fields
		if ( $status === 'resolved' ) {
			$update_fields[] = 'resolved_at = %s';
			$update_fields[] = 'resolved_by = %d';
			$params[] = current_time( 'mysql' );
			$params[] = get_current_user_id();
		} elseif ( $status === 'dismissed' ) {
			$update_fields[] = 'dismissed_at = %s';
			$update_fields[] = 'dismissed_by = %d';
			$params[] = current_time( 'mysql' );
			$params[] = get_current_user_id();
		}

		$sql = "UPDATE {$this->table_name} 
		        SET " . implode( ', ', $update_fields ) . "
		        WHERE id IN ({$ids_placeholder})";

		$params = array_merge( $params, $alert_ids );

		return $this->wpdb->query( $this->wpdb->prepare( $sql, $params ) );
	}

	/**
	 * Clean up old resolved/dismissed alerts.
	 *
	 * @since    1.0.0
	 * @param    int    $days_old    Number of days to keep.
	 * @return   int    Number of alerts deleted.
	 */
	public function cleanup_old_alerts( $days_old = 90 ) {
		$cutoff_date = date( 'Y-m-d H:i:s', strtotime( "-{$days_old} days" ) );

		$result = $this->wpdb->query( $this->wpdb->prepare(
			"DELETE FROM {$this->table_name} 
			WHERE status IN ('resolved', 'dismissed') 
			AND created_at < %s",
			$cutoff_date
		) );

		return intval( $result );
	}

	/**
	 * Check if alert is duplicate.
	 *
	 * @since    1.0.0
	 * @param    string   $alert_hash    The alert hash.
	 * @return   bool     True if duplicate, false otherwise.
	 */
	private function is_duplicate_alert( $alert_hash ) {
		$existing = $this->get_by_fields( array( 'alert_hash' => $alert_hash ) );
		return $existing !== null;
	}

	/**
	 * Increment duplicate count for existing alert.
	 *
	 * @since    1.0.0
	 * @param    string   $alert_hash    The alert hash.
	 * @return   int|false    The alert ID or false on failure.
	 */
	private function increment_duplicate_count( $alert_hash ) {
		$existing = $this->get_by_fields( array( 'alert_hash' => $alert_hash ) );
		
		if ( ! $existing ) {
			return false;
		}

		$new_count = intval( $existing->duplicate_count ) + 1;
		
		$this->update( $existing->id, array(
			'duplicate_count' => $new_count,
			'last_seen_at'    => current_time( 'mysql' ),
		) );

		return $existing->id;
	}

	/**
	 * Generate a unique hash for the alert.
	 *
	 * @since    1.0.0
	 * @param    array    $data    The alert data.
	 * @return   string   The generated hash.
	 */
	private function generate_alert_hash( $data ) {
		$hash_data = array(
			'alert_type'     => $data['alert_type'],
			'title'          => $data['title'],
			'reference_type' => $data['reference_type'] ?? '',
			'reference_id'   => $data['reference_id'] ?? '',
		);

		return hash( 'sha256', wp_json_encode( $hash_data ) );
	}

	/**
	 * Get alerts requiring immediate attention.
	 *
	 * @since    1.0.0
	 * @param    int    $limit    Number of alerts to retrieve.
	 * @return   array  Array of alert objects requiring attention.
	 */
	public function get_alerts_requiring_attention( $limit = 10 ) {
		$sql = "SELECT * FROM {$this->table_name}
		        WHERE status = 'active'
		        AND (severity IN ('critical', 'high') 
		             OR created_at < DATE_SUB(NOW(), INTERVAL 24 HOUR))
		        ORDER BY 
		            CASE severity 
		                WHEN 'critical' THEN 1 
		                WHEN 'high' THEN 2 
		                WHEN 'medium' THEN 3 
		                ELSE 4 
		            END,
		            created_at ASC
		        LIMIT %d";

		return $this->wpdb->get_results( $this->wpdb->prepare( $sql, $limit ) );
	}
}

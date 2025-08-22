<?php
/**
 * Scan model class for database operations.
 *
 * @link       https://github.com/luozongbao
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/database
 */

/**
 * Scan model class for database operations.
 *
 * Handles all database operations related to security scans including
 * creating, updating, and querying scan records.
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/database
 * @author     luozongbao <luo.zongbao@outlook.com>
 */
class WP_Breach_Scan_Model extends WP_Breach_Base_Model {

	/**
	 * Get the table suffix for this model.
	 *
	 * @since    1.0.0
	 * @return   string    The table suffix.
	 */
	protected function get_table_suffix() {
		return 'breach_scans';
	}

	/**
	 * Get the validation rules for this model.
	 *
	 * @since    1.0.0
	 * @return   array    The validation rules.
	 */
	protected function get_validation_rules() {
		return array(
			'scan_type' => array(
				'required'   => true,
				'type'       => 'string',
				'max_length' => 10,
			),
			'status' => array(
				'required'   => true,
				'type'       => 'string',
				'max_length' => 20,
			),
			'started_at' => array(
				'required' => true,
				'type'     => 'string',
			),
			'created_by' => array(
				'required' => true,
				'type'     => 'integer',
			),
		);
	}

	/**
	 * Create a new scan record.
	 *
	 * @since    1.0.0
	 * @param    array    $data    The scan data.
	 * @return   int|false    The scan ID or false on failure.
	 */
	public function create_scan( $data ) {
		$defaults = array(
			'scan_type'              => 'quick',
			'status'                 => 'pending',
			'started_at'             => current_time( 'mysql' ),
			'total_checks'           => 0,
			'vulnerabilities_found'  => 0,
			'critical_count'         => 0,
			'high_count'             => 0,
			'medium_count'           => 0,
			'low_count'              => 0,
			'created_by'             => get_current_user_id(),
		);

		$data = wp_parse_args( $data, $defaults );

		// Generate scan hash for uniqueness
		$data['scan_hash'] = $this->generate_scan_hash( $data );

		return $this->create( $data );
	}

	/**
	 * Update scan status.
	 *
	 * @since    1.0.0
	 * @param    int      $scan_id    The scan ID.
	 * @param    string   $status     The new status.
	 * @param    array    $data       Additional data to update.
	 * @return   bool     True on success, false on failure.
	 */
	public function update_scan_status( $scan_id, $status, $data = array() ) {
		$update_data = array_merge( $data, array( 'status' => $status ) );

		// Set completion time for completed/failed/cancelled scans
		if ( in_array( $status, array( 'completed', 'failed', 'cancelled' ), true ) ) {
			$update_data['completed_at'] = current_time( 'mysql' );
			
			// Calculate duration if started_at exists
			$scan = $this->get( $scan_id );
			if ( $scan && $scan->started_at ) {
				$start_time = strtotime( $scan->started_at );
				$end_time = time();
				$update_data['duration_seconds'] = $end_time - $start_time;
			}
		}

		return $this->update( $scan_id, $update_data );
	}

	/**
	 * Update scan vulnerability counts.
	 *
	 * @since    1.0.0
	 * @param    int    $scan_id    The scan ID.
	 * @param    array  $counts     Vulnerability counts by severity.
	 * @return   bool   True on success, false on failure.
	 */
	public function update_vulnerability_counts( $scan_id, $counts ) {
		$update_data = array(
			'vulnerabilities_found' => array_sum( $counts ),
			'critical_count'        => $counts['critical'] ?? 0,
			'high_count'            => $counts['high'] ?? 0,
			'medium_count'          => $counts['medium'] ?? 0,
			'low_count'             => $counts['low'] ?? 0,
		);

		return $this->update( $scan_id, $update_data );
	}

	/**
	 * Get scans by status.
	 *
	 * @since    1.0.0
	 * @param    string   $status    The scan status.
	 * @param    array    $args      Additional query arguments.
	 * @return   array    Array of scan objects.
	 */
	public function get_scans_by_status( $status, $args = array() ) {
		$args['where'] = array( 'status' => $status );
		return $this->get_all( $args );
	}

	/**
	 * Get scans by type.
	 *
	 * @since    1.0.0
	 * @param    string   $scan_type    The scan type.
	 * @param    array    $args         Additional query arguments.
	 * @return   array    Array of scan objects.
	 */
	public function get_scans_by_type( $scan_type, $args = array() ) {
		$args['where'] = array( 'scan_type' => $scan_type );
		return $this->get_all( $args );
	}

	/**
	 * Get scans by user.
	 *
	 * @since    1.0.0
	 * @param    int      $user_id    The user ID.
	 * @param    array    $args       Additional query arguments.
	 * @return   array    Array of scan objects.
	 */
	public function get_scans_by_user( $user_id, $args = array() ) {
		$args['where'] = array( 'created_by' => $user_id );
		return $this->get_all( $args );
	}

	/**
	 * Get recent scans.
	 *
	 * @since    1.0.0
	 * @param    int    $limit    Number of scans to retrieve.
	 * @return   array  Array of scan objects.
	 */
	public function get_recent_scans( $limit = 10 ) {
		return $this->get_all( array(
			'limit'    => $limit,
			'order_by' => 'created_at',
			'order'    => 'DESC',
		) );
	}

	/**
	 * Get running scans.
	 *
	 * @since    1.0.0
	 * @return   array    Array of running scan objects.
	 */
	public function get_running_scans() {
		return $this->get_scans_by_status( 'running' );
	}

	/**
	 * Get scan statistics.
	 *
	 * @since    1.0.0
	 * @param    array    $args    Query arguments (date range, user, etc.).
	 * @return   array    Scan statistics.
	 */
	public function get_scan_statistics( $args = array() ) {
		$where_clause = '';
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

		// Add user filter
		if ( ! empty( $args['user_id'] ) ) {
			$where_clause .= ' AND created_by = %d';
			$where_params[] = $args['user_id'];
		}

		$sql = "SELECT 
			COUNT(*) as total_scans,
			SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed_scans,
			SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed_scans,
			SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) as running_scans,
			SUM(vulnerabilities_found) as total_vulnerabilities,
			SUM(critical_count) as total_critical,
			SUM(high_count) as total_high,
			SUM(medium_count) as total_medium,
			SUM(low_count) as total_low,
			AVG(duration_seconds) as avg_duration
		FROM {$this->table_name} 
		WHERE 1=1 {$where_clause}";

		if ( ! empty( $where_params ) ) {
			$sql = $this->wpdb->prepare( $sql, $where_params );
		}

		$result = $this->wpdb->get_row( $sql );

		return array(
			'total_scans'          => intval( $result->total_scans ),
			'completed_scans'      => intval( $result->completed_scans ),
			'failed_scans'         => intval( $result->failed_scans ),
			'running_scans'        => intval( $result->running_scans ),
			'total_vulnerabilities' => intval( $result->total_vulnerabilities ),
			'total_critical'       => intval( $result->total_critical ),
			'total_high'           => intval( $result->total_high ),
			'total_medium'         => intval( $result->total_medium ),
			'total_low'            => intval( $result->total_low ),
			'avg_duration'         => floatval( $result->avg_duration ),
		);
	}

	/**
	 * Get scan progress data.
	 *
	 * @since    1.0.0
	 * @param    int    $scan_id    The scan ID.
	 * @return   array|null    Progress data or null if not found.
	 */
	public function get_scan_progress( $scan_id ) {
		$scan = $this->get( $scan_id );

		if ( ! $scan ) {
			return null;
		}

		$progress = array(
			'scan_id'              => $scan_id,
			'status'               => $scan->status,
			'started_at'           => $scan->started_at,
			'completed_at'         => $scan->completed_at,
			'duration_seconds'     => $scan->duration_seconds,
			'total_checks'         => $scan->total_checks,
			'vulnerabilities_found' => $scan->vulnerabilities_found,
			'severity_counts'      => array(
				'critical' => $scan->critical_count,
				'high'     => $scan->high_count,
				'medium'   => $scan->medium_count,
				'low'      => $scan->low_count,
			),
		);

		// Calculate progress percentage
		if ( $scan->status === 'completed' ) {
			$progress['progress_percent'] = 100;
		} elseif ( $scan->status === 'running' && $scan->total_checks > 0 ) {
			// This would need to be calculated based on current check progress
			// For now, we'll use a placeholder
			$progress['progress_percent'] = 50;
		} else {
			$progress['progress_percent'] = 0;
		}

		return $progress;
	}

	/**
	 * Delete old completed scans.
	 *
	 * @since    1.0.0
	 * @param    int    $days_old    Number of days to keep.
	 * @return   int    Number of scans deleted.
	 */
	public function delete_old_scans( $days_old = 90 ) {
		$cutoff_date = date( 'Y-m-d H:i:s', strtotime( "-{$days_old} days" ) );

		$result = $this->wpdb->query( $this->wpdb->prepare(
			"DELETE FROM {$this->table_name} 
			WHERE status = 'completed' 
			AND created_at < %s",
			$cutoff_date
		) );

		return intval( $result );
	}

	/**
	 * Cancel running scans older than specified time.
	 *
	 * @since    1.0.0
	 * @param    int    $hours_old    Number of hours to consider stale.
	 * @return   int    Number of scans cancelled.
	 */
	public function cancel_stale_scans( $hours_old = 2 ) {
		$cutoff_date = date( 'Y-m-d H:i:s', strtotime( "-{$hours_old} hours" ) );

		$result = $this->wpdb->query( $this->wpdb->prepare(
			"UPDATE {$this->table_name} 
			SET status = 'cancelled', completed_at = %s 
			WHERE status = 'running' 
			AND started_at < %s",
			current_time( 'mysql' ),
			$cutoff_date
		) );

		return intval( $result );
	}

	/**
	 * Generate a unique hash for the scan.
	 *
	 * @since    1.0.0
	 * @param    array    $data    The scan data.
	 * @return   string   The generated hash.
	 */
	private function generate_scan_hash( $data ) {
		$hash_data = array(
			'scan_type'  => $data['scan_type'],
			'started_at' => $data['started_at'],
			'created_by' => $data['created_by'],
			'config'     => $data['configuration'] ?? '',
		);

		return hash( 'sha256', wp_json_encode( $hash_data ) );
	}

	/**
	 * Get scans with vulnerability counts in date range.
	 *
	 * @since    1.0.0
	 * @param    string   $date_from    Start date.
	 * @param    string   $date_to      End date.
	 * @return   array    Array of scan data with counts.
	 */
	public function get_scans_with_counts( $date_from, $date_to ) {
		$sql = "SELECT 
			DATE(created_at) as scan_date,
			COUNT(*) as scan_count,
			SUM(vulnerabilities_found) as vulnerability_count,
			SUM(critical_count) as critical_count,
			SUM(high_count) as high_count,
			SUM(medium_count) as medium_count,
			SUM(low_count) as low_count
		FROM {$this->table_name}
		WHERE created_at >= %s AND created_at <= %s
		AND status = 'completed'
		GROUP BY DATE(created_at)
		ORDER BY scan_date ASC";

		return $this->wpdb->get_results( $this->wpdb->prepare( $sql, $date_from, $date_to ) );
	}

	/**
	 * Get the last completed scan.
	 *
	 * @since    1.0.0
	 * @param    string   $scan_type    Optional scan type filter.
	 * @return   object|null    The last scan or null if not found.
	 */
	public function get_last_completed_scan( $scan_type = null ) {
		$where = array( 'status' => 'completed' );
		
		if ( $scan_type ) {
			$where['scan_type'] = $scan_type;
		}

		$scans = $this->get_all( array(
			'where'    => $where,
			'limit'    => 1,
			'order_by' => 'completed_at',
			'order'    => 'DESC',
		) );

		return ! empty( $scans ) ? $scans[0] : null;
	}

	/**
	 * Get scan count with optional filters.
	 *
	 * @since    1.0.0
	 * @param    array    $filters    Optional filters.
	 * @return   int    Scan count.
	 */
	public function get_scan_count( $filters = array() ) {
		$where_clause = '1=1';
		$where_values = array();

		if ( ! empty( $filters['status'] ) ) {
			$where_clause .= ' AND status = %s';
			$where_values[] = $filters['status'];
		}

		if ( ! empty( $filters['type'] ) ) {
			$where_clause .= ' AND scan_type = %s';
			$where_values[] = $filters['type'];
		}

		if ( ! empty( $filters['user_id'] ) ) {
			$where_clause .= ' AND started_by = %d';
			$where_values[] = $filters['user_id'];
		}

		$sql = "SELECT COUNT(*) FROM {$this->table_name} WHERE {$where_clause}";

		if ( ! empty( $where_values ) ) {
			return (int) $this->wpdb->get_var( $this->wpdb->prepare( $sql, $where_values ) );
		}

		return (int) $this->wpdb->get_var( $sql );
	}

	/**
	 * Get scans with optional filters.
	 *
	 * @since    1.0.0
	 * @param    array    $filters    Optional filters.
	 * @return   array    Scans.
	 */
	public function get_scans( $filters = array() ) {
		$args = array();
		
		if ( ! empty( $filters ) ) {
			$args['where'] = array();
			
			if ( isset( $filters['status'] ) ) {
				$args['where']['status'] = $filters['status'];
			}
			
			if ( isset( $filters['type'] ) ) {
				$args['where']['scan_type'] = $filters['type'];
			}
			
			if ( isset( $filters['user_id'] ) ) {
				$args['where']['started_by'] = $filters['user_id'];
			}
			
			if ( isset( $filters['limit'] ) ) {
				$args['limit'] = intval( $filters['limit'] );
			}
			
			if ( isset( $filters['offset'] ) ) {
				$args['offset'] = intval( $filters['offset'] );
			}
		}
		
		// Default ordering
		if ( ! isset( $args['order_by'] ) ) {
			$args['order_by'] = 'created_at';
			$args['order'] = 'DESC';
		}
		
		return $this->get_all( $args );
	}

	/**
	 * Get latest completed scan.
	 *
	 * @since    1.0.0
	 * @return   object|null    Latest completed scan or null.
	 */
	public function get_latest_completed_scan() {
		$scans = $this->get_all( array(
			'where'    => array( 'status' => 'completed' ),
			'order_by' => 'completed_at',
			'order'    => 'DESC',
			'limit'    => 1
		) );
		
		return ! empty( $scans ) ? $scans[0] : null;
	}

	/**
	 * Get current running scan.
	 *
	 * @since    1.0.0
	 * @return   object|null    Current scan or null.
	 */
	public function get_current_scan() {
		$scans = $this->get_all( array(
			'where'    => array( 'status' => 'running' ),
			'order_by' => 'started_at',
			'order'    => 'DESC',
			'limit'    => 1
		) );
		
		return ! empty( $scans ) ? $scans[0] : null;
	}

	/**
	 * Get security score history for reporting.
	 *
	 * @since    1.0.0
	 * @param    int      $days    Number of days to look back.
	 * @return   array    Security score history.
	 */
	public function get_security_score_history( $days = 30 ) {
		$start_date = date( 'Y-m-d', strtotime( "-{$days} days" ) );
		
		$results = $this->wpdb->get_results(
			$this->wpdb->prepare(
				"SELECT 
					DATE(completed_at) as date,
					AVG(
						GREATEST(0, 100 - (
							(critical_count * 25) + 
							(high_count * 15) + 
							(medium_count * 5) + 
							(low_count * 1)
						))
					) as avg_score,
					COUNT(*) as scan_count,
					AVG(critical_count) as avg_critical,
					AVG(high_count) as avg_high,
					AVG(medium_count) as avg_medium,
					AVG(low_count) as avg_low
				FROM {$this->table_name} 
				WHERE status = 'completed' 
				AND completed_at >= %s 
				GROUP BY DATE(completed_at)
				ORDER BY date ASC",
				$start_date
			),
			ARRAY_A
		);

		// Fill in missing dates with null values
		$history = array();
		for ( $i = $days - 1; $i >= 0; $i-- ) {
			$date = date( 'Y-m-d', strtotime( "-{$i} days" ) );
			$found = false;
			
			foreach ( $results as $result ) {
				if ( $result['date'] === $date ) {
					$history[] = array(
						'date'        => $date,
						'score'       => round( (float) $result['avg_score'], 1 ),
						'scan_count'  => (int) $result['scan_count'],
						'critical'    => round( (float) $result['avg_critical'], 1 ),
						'high'        => round( (float) $result['avg_high'], 1 ),
						'medium'      => round( (float) $result['avg_medium'], 1 ),
						'low'         => round( (float) $result['avg_low'], 1 )
					);
					$found = true;
					break;
				}
			}
			
			if ( ! $found ) {
				$history[] = array(
					'date'        => $date,
					'score'       => null,
					'scan_count'  => 0,
					'critical'    => 0,
					'high'        => 0,
					'medium'      => 0,
					'low'         => 0
				);
			}
		}

		return $history;
	}
}

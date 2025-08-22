<?php
/**
 * Fix model class for database operations.
 *
 * @link       https://github.com/luozongbao
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/database
 */

/**
 * Fix model class for database operations.
 *
 * Handles all database operations related to vulnerability fixes
 * including applying fixes, tracking success/failure, and rollbacks.
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/database
 * @author     luozongbao <luo.zongbao@outlook.com>
 */
class WP_Breach_Fix_Model extends WP_Breach_Base_Model {

	/**
	 * Get the table suffix for this model.
	 *
	 * @since    1.0.0
	 * @return   string    The table suffix.
	 */
	protected function get_table_suffix() {
		return 'breach_fixes';
	}

	/**
	 * Get the validation rules for this model.
	 *
	 * @since    1.0.0
	 * @return   array    The validation rules.
	 */
	protected function get_validation_rules() {
		return array(
			'vulnerability_id' => array(
				'required' => true,
				'type'     => 'integer',
			),
			'fix_type' => array(
				'required'   => true,
				'type'       => 'string',
				'max_length' => 50,
			),
			'status' => array(
				'required'   => true,
				'type'       => 'string',
				'max_length' => 20,
			),
			'applied_by' => array(
				'required' => true,
				'type'     => 'integer',
			),
		);
	}

	/**
	 * Create a new fix record.
	 *
	 * @since    1.0.0
	 * @param    array    $data    The fix data.
	 * @return   int|false    The fix ID or false on failure.
	 */
	public function create_fix( $data ) {
		$defaults = array(
			'status'      => 'pending',
			'applied_by'  => get_current_user_id(),
			'applied_at'  => current_time( 'mysql' ),
			'auto_fix'    => 0,
		);

		$data = wp_parse_args( $data, $defaults );

		// Generate fix hash for tracking
		$data['fix_hash'] = $this->generate_fix_hash( $data );

		return $this->create( $data );
	}

	/**
	 * Update fix status.
	 *
	 * @since    1.0.0
	 * @param    int      $fix_id    The fix ID.
	 * @param    string   $status    The new status.
	 * @param    array    $data      Additional data to update.
	 * @return   bool     True on success, false on failure.
	 */
	public function update_fix_status( $fix_id, $status, $data = array() ) {
		$update_data = array_merge( $data, array( 'status' => $status ) );

		// Set completion time for completed/failed fixes
		if ( in_array( $status, array( 'completed', 'failed', 'rolled_back' ), true ) ) {
			$update_data['completed_at'] = current_time( 'mysql' );
		}

		// Set rollback time for rolled back fixes
		if ( $status === 'rolled_back' ) {
			$update_data['rolled_back_at'] = current_time( 'mysql' );
		}

		return $this->update( $fix_id, $update_data );
	}

	/**
	 * Apply a fix.
	 *
	 * @since    1.0.0
	 * @param    int      $vulnerability_id    The vulnerability ID.
	 * @param    string   $fix_type           The type of fix to apply.
	 * @param    array    $fix_data           Fix configuration data.
	 * @param    bool     $auto_fix           Whether this is an automatic fix.
	 * @return   int|false    The fix ID or false on failure.
	 */
	public function apply_fix( $vulnerability_id, $fix_type, $fix_data = array(), $auto_fix = false ) {
		$fix_record = array(
			'vulnerability_id' => $vulnerability_id,
			'fix_type'         => $fix_type,
			'status'           => 'applying',
			'auto_fix'         => $auto_fix ? 1 : 0,
			'fix_data'         => wp_json_encode( $fix_data ),
			'applied_by'       => get_current_user_id(),
		);

		return $this->create_fix( $fix_record );
	}

	/**
	 * Mark fix as successful.
	 *
	 * @since    1.0.0
	 * @param    int      $fix_id           The fix ID.
	 * @param    array    $verification     Verification data.
	 * @return   bool     True on success, false on failure.
	 */
	public function mark_fix_successful( $fix_id, $verification = array() ) {
		$update_data = array(
			'status'           => 'completed',
			'success'          => 1,
			'verification_data' => wp_json_encode( $verification ),
		);

		return $this->update_fix_status( $fix_id, 'completed', $update_data );
	}

	/**
	 * Mark fix as failed.
	 *
	 * @since    1.0.0
	 * @param    int      $fix_id         The fix ID.
	 * @param    string   $error_message  Error message.
	 * @param    array    $error_data     Additional error data.
	 * @return   bool     True on success, false on failure.
	 */
	public function mark_fix_failed( $fix_id, $error_message, $error_data = array() ) {
		$update_data = array(
			'success'      => 0,
			'error_message' => $error_message,
			'error_data'    => wp_json_encode( $error_data ),
		);

		return $this->update_fix_status( $fix_id, 'failed', $update_data );
	}

	/**
	 * Rollback a fix.
	 *
	 * @since    1.0.0
	 * @param    int      $fix_id           The fix ID.
	 * @param    string   $reason           Rollback reason.
	 * @param    array    $rollback_data    Rollback data.
	 * @return   bool     True on success, false on failure.
	 */
	public function rollback_fix( $fix_id, $reason, $rollback_data = array() ) {
		$update_data = array(
			'rollback_reason' => $reason,
			'rollback_data'   => wp_json_encode( $rollback_data ),
			'rolled_back_by'  => get_current_user_id(),
		);

		return $this->update_fix_status( $fix_id, 'rolled_back', $update_data );
	}

	/**
	 * Get fixes by vulnerability ID.
	 *
	 * @since    1.0.0
	 * @param    int      $vulnerability_id    The vulnerability ID.
	 * @param    array    $args                Additional query arguments.
	 * @return   array    Array of fix objects.
	 */
	public function get_fixes_by_vulnerability( $vulnerability_id, $args = array() ) {
		$args['where'] = array( 'vulnerability_id' => $vulnerability_id );
		return $this->get_all( $args );
	}

	/**
	 * Get fixes by status.
	 *
	 * @since    1.0.0
	 * @param    string   $status    The fix status.
	 * @param    array    $args      Additional query arguments.
	 * @return   array    Array of fix objects.
	 */
	public function get_fixes_by_status( $status, $args = array() ) {
		$args['where'] = array( 'status' => $status );
		return $this->get_all( $args );
	}

	/**
	 * Get fixes by type.
	 *
	 * @since    1.0.0
	 * @param    string   $fix_type    The fix type.
	 * @param    array    $args        Additional query arguments.
	 * @return   array    Array of fix objects.
	 */
	public function get_fixes_by_type( $fix_type, $args = array() ) {
		$args['where'] = array( 'fix_type' => $fix_type );
		return $this->get_all( $args );
	}

	/**
	 * Get automatic fixes.
	 *
	 * @since    1.0.0
	 * @param    array    $args    Additional query arguments.
	 * @return   array    Array of automatic fix objects.
	 */
	public function get_automatic_fixes( $args = array() ) {
		$args['where'] = array( 'auto_fix' => 1 );
		return $this->get_all( $args );
	}

	/**
	 * Get manual fixes.
	 *
	 * @since    1.0.0
	 * @param    array    $args    Additional query arguments.
	 * @return   array    Array of manual fix objects.
	 */
	public function get_manual_fixes( $args = array() ) {
		$args['where'] = array( 'auto_fix' => 0 );
		return $this->get_all( $args );
	}

	/**
	 * Get successful fixes.
	 *
	 * @since    1.0.0
	 * @param    array    $args    Additional query arguments.
	 * @return   array    Array of successful fix objects.
	 */
	public function get_successful_fixes( $args = array() ) {
		$args['where'] = array(
			'status'  => 'completed',
			'success' => 1,
		);
		return $this->get_all( $args );
	}

	/**
	 * Get failed fixes.
	 *
	 * @since    1.0.0
	 * @param    array    $args    Additional query arguments.
	 * @return   array    Array of failed fix objects.
	 */
	public function get_failed_fixes( $args = array() ) {
		$args['where'] = array(
			'status'  => 'failed',
			'success' => 0,
		);
		return $this->get_all( $args );
	}

	/**
	 * Get pending fixes.
	 *
	 * @since    1.0.0
	 * @param    array    $args    Additional query arguments.
	 * @return   array    Array of pending fix objects.
	 */
	public function get_pending_fixes( $args = array() ) {
		$args['where'] = array( 'status' => 'pending' );
		return $this->get_all( $args );
	}

	/**
	 * Get fix statistics.
	 *
	 * @since    1.0.0
	 * @param    array    $args    Query arguments (date range, user, etc.).
	 * @return   array    Fix statistics.
	 */
	public function get_fix_statistics( $args = array() ) {
		$where_clause = 'WHERE 1=1';
		$where_params = array();

		// Add date range filter
		if ( ! empty( $args['date_from'] ) ) {
			$where_clause .= ' AND applied_at >= %s';
			$where_params[] = $args['date_from'];
		}

		if ( ! empty( $args['date_to'] ) ) {
			$where_clause .= ' AND applied_at <= %s';
			$where_params[] = $args['date_to'];
		}

		// Add user filter
		if ( ! empty( $args['user_id'] ) ) {
			$where_clause .= ' AND applied_by = %d';
			$where_params[] = $args['user_id'];
		}

		$sql = "SELECT 
			COUNT(*) as total_fixes,
			SUM(CASE WHEN status = 'completed' AND success = 1 THEN 1 ELSE 0 END) as successful_fixes,
			SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed_fixes,
			SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_fixes,
			SUM(CASE WHEN status = 'applying' THEN 1 ELSE 0 END) as applying_fixes,
			SUM(CASE WHEN status = 'rolled_back' THEN 1 ELSE 0 END) as rolled_back_fixes,
			SUM(CASE WHEN auto_fix = 1 THEN 1 ELSE 0 END) as automatic_fixes,
			SUM(CASE WHEN auto_fix = 0 THEN 1 ELSE 0 END) as manual_fixes
		FROM {$this->table_name} 
		{$where_clause}";

		if ( ! empty( $where_params ) ) {
			$sql = $this->wpdb->prepare( $sql, $where_params );
		}

		$result = $this->wpdb->get_row( $sql );

		$success_rate = 0;
		if ( $result->total_fixes > 0 ) {
			$success_rate = ( $result->successful_fixes / $result->total_fixes ) * 100;
		}

		return array(
			'total_fixes'       => intval( $result->total_fixes ),
			'successful_fixes'  => intval( $result->successful_fixes ),
			'failed_fixes'      => intval( $result->failed_fixes ),
			'pending_fixes'     => intval( $result->pending_fixes ),
			'applying_fixes'    => intval( $result->applying_fixes ),
			'rolled_back_fixes' => intval( $result->rolled_back_fixes ),
			'automatic_fixes'   => intval( $result->automatic_fixes ),
			'manual_fixes'      => intval( $result->manual_fixes ),
			'success_rate'      => round( $success_rate, 2 ),
		);
	}

	/**
	 * Get fix trends.
	 *
	 * @since    1.0.0
	 * @param    string   $period    Time period (daily, weekly, monthly).
	 * @param    int      $limit     Number of periods to retrieve.
	 * @return   array    Trend data.
	 */
	public function get_fix_trends( $period = 'daily', $limit = 30 ) {
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
			DATE_FORMAT(applied_at, '{$date_format}') as period,
			COUNT(*) as total_fixes,
			SUM(CASE WHEN status = 'completed' AND success = 1 THEN 1 ELSE 0 END) as successful_fixes,
			SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed_fixes,
			SUM(CASE WHEN auto_fix = 1 THEN 1 ELSE 0 END) as automatic_fixes
		FROM {$this->table_name}
		WHERE applied_at >= DATE_SUB(NOW(), INTERVAL %d {$interval})
		GROUP BY period
		ORDER BY period DESC
		LIMIT %d";

		return $this->wpdb->get_results( $this->wpdb->prepare( $sql, $limit, $limit ) );
	}

	/**
	 * Get most common fix types.
	 *
	 * @since    1.0.0
	 * @param    int    $limit    Number of fix types to retrieve.
	 * @return   array  Array of fix type data.
	 */
	public function get_most_common_fix_types( $limit = 10 ) {
		$sql = "SELECT 
			fix_type,
			COUNT(*) as usage_count,
			SUM(CASE WHEN status = 'completed' AND success = 1 THEN 1 ELSE 0 END) as successful_count,
			ROUND((SUM(CASE WHEN status = 'completed' AND success = 1 THEN 1 ELSE 0 END) / COUNT(*)) * 100, 2) as success_rate
		FROM {$this->table_name}
		GROUP BY fix_type
		ORDER BY usage_count DESC
		LIMIT %d";

		return $this->wpdb->get_results( $this->wpdb->prepare( $sql, $limit ) );
	}

	/**
	 * Get fixes requiring review.
	 *
	 * @since    1.0.0
	 * @param    int    $limit    Number of fixes to retrieve.
	 * @return   array  Array of fix objects requiring review.
	 */
	public function get_fixes_requiring_review( $limit = 20 ) {
		$sql = "SELECT * FROM {$this->table_name}
		        WHERE status IN ('failed', 'rolled_back')
		        OR (status = 'completed' AND auto_fix = 1 AND completed_at > DATE_SUB(NOW(), INTERVAL 24 HOUR))
		        ORDER BY 
		            CASE status 
		                WHEN 'failed' THEN 1 
		                WHEN 'rolled_back' THEN 2 
		                ELSE 3 
		            END,
		            applied_at DESC
		        LIMIT %d";

		return $this->wpdb->get_results( $this->wpdb->prepare( $sql, $limit ) );
	}

	/**
	 * Get fixes by user.
	 *
	 * @since    1.0.0
	 * @param    int      $user_id    The user ID.
	 * @param    array    $args       Additional query arguments.
	 * @return   array    Array of fix objects.
	 */
	public function get_fixes_by_user( $user_id, $args = array() ) {
		$args['where'] = array( 'applied_by' => $user_id );
		return $this->get_all( $args );
	}

	/**
	 * Check if vulnerability has been fixed.
	 *
	 * @since    1.0.0
	 * @param    int    $vulnerability_id    The vulnerability ID.
	 * @return   bool   True if fixed, false otherwise.
	 */
	public function is_vulnerability_fixed( $vulnerability_id ) {
		$fixes = $this->get_fixes_by_vulnerability( $vulnerability_id );
		
		foreach ( $fixes as $fix ) {
			if ( $fix->status === 'completed' && $fix->success == 1 ) {
				return true;
			}
		}
		
		return false;
	}

	/**
	 * Get the latest successful fix for a vulnerability.
	 *
	 * @since    1.0.0
	 * @param    int    $vulnerability_id    The vulnerability ID.
	 * @return   object|null    The fix object or null if not found.
	 */
	public function get_latest_successful_fix( $vulnerability_id ) {
		$fixes = $this->get_all( array(
			'where'    => array(
				'vulnerability_id' => $vulnerability_id,
				'status'           => 'completed',
				'success'          => 1,
			),
			'limit'    => 1,
			'order_by' => 'completed_at',
			'order'    => 'DESC',
		) );

		return ! empty( $fixes ) ? $fixes[0] : null;
	}

	/**
	 * Delete old completed fixes.
	 *
	 * @since    1.0.0
	 * @param    int    $days_old    Number of days to keep.
	 * @return   int    Number of fixes deleted.
	 */
	public function delete_old_completed_fixes( $days_old = 365 ) {
		$cutoff_date = date( 'Y-m-d H:i:s', strtotime( "-{$days_old} days" ) );

		$result = $this->wpdb->query( $this->wpdb->prepare(
			"DELETE FROM {$this->table_name} 
			WHERE status = 'completed' 
			AND completed_at < %s",
			$cutoff_date
		) );

		return intval( $result );
	}

	/**
	 * Generate a unique hash for the fix.
	 *
	 * @since    1.0.0
	 * @param    array    $data    The fix data.
	 * @return   string   The generated hash.
	 */
	private function generate_fix_hash( $data ) {
		$hash_data = array(
			'vulnerability_id' => $data['vulnerability_id'],
			'fix_type'         => $data['fix_type'],
			'applied_at'       => $data['applied_at'],
			'fix_data'         => $data['fix_data'] ?? '',
		);

		return hash( 'sha256', wp_json_encode( $hash_data ) );
	}

	/**
	 * Get fix execution timeline for a vulnerability.
	 *
	 * @since    1.0.0
	 * @param    int    $vulnerability_id    The vulnerability ID.
	 * @return   array  Timeline of fix attempts.
	 */
	public function get_fix_timeline( $vulnerability_id ) {
		$fixes = $this->get_fixes_by_vulnerability( $vulnerability_id, array(
			'order_by' => 'applied_at',
			'order'    => 'ASC',
		) );

		$timeline = array();
		foreach ( $fixes as $fix ) {
			$timeline[] = array(
				'id'          => $fix->id,
				'fix_type'    => $fix->fix_type,
				'status'      => $fix->status,
				'success'     => $fix->success,
				'auto_fix'    => $fix->auto_fix,
				'applied_at'  => $fix->applied_at,
				'completed_at' => $fix->completed_at,
				'error_message' => $fix->error_message,
				'rollback_reason' => $fix->rollback_reason,
			);
		}

		return $timeline;
	}

	/**
	 * Get applied fixes with optional filtering.
	 *
	 * @since    1.0.0
	 * @param    array     $args    Query arguments.
	 * @return   array     Applied fixes.
	 */
	public function get_applied_fixes( $args = array() ) {
		$defaults = array(
			'where'     => array( 'status' => 'applied' ),
			'order_by'  => 'applied_at',
			'order'     => 'DESC',
			'limit'     => 20,
			'offset'    => 0
		);

		$args = wp_parse_args( $args, $defaults );
		return $this->get_all( $args );
	}
}

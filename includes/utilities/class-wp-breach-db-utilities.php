<?php

/**
 * Database Utilities Class
 *
 * Provides utility functions for database operations including validation,
 * sanitization, backup, restore, and optimization helpers.
 *
 * @link       https://wpsecurity.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/utilities
 */

/**
 * Database utilities for WP-Breach plugin.
 *
 * This class defines all utility functions for database operations
 * including data validation, sanitization, query optimization,
 * and backup/restore functionality.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/utilities
 * @author     Your Name <email@example.com>
 */
class WP_Breach_DB_Utilities {

	/**
	 * Validate scan data before database insertion
	 *
	 * @since    1.0.0
	 * @param    array    $data    Scan data to validate
	 * @return   array|WP_Error    Validated data or error
	 */
	public static function validate_scan_data( $data ) {
		$validated = array();
		$errors = array();

		// Validate scan type
		$allowed_types = array( 'quick', 'full', 'custom' );
		if ( empty( $data['scan_type'] ) || ! in_array( $data['scan_type'], $allowed_types ) ) {
			$errors[] = 'Invalid scan type';
		} else {
			$validated['scan_type'] = $data['scan_type'];
		}

		// Validate status
		$allowed_statuses = array( 'pending', 'running', 'completed', 'failed', 'cancelled' );
		if ( empty( $data['status'] ) || ! in_array( $data['status'], $allowed_statuses ) ) {
			$validated['status'] = 'pending'; // Default
		} else {
			$validated['status'] = $data['status'];
		}

		// Validate created_by (must be valid user ID)
		if ( empty( $data['created_by'] ) || ! get_user_by( 'id', $data['created_by'] ) ) {
			$errors[] = 'Invalid user ID';
		} else {
			$validated['created_by'] = intval( $data['created_by'] );
		}

		// Validate started_at (must be valid datetime)
		if ( ! empty( $data['started_at'] ) ) {
			$date = DateTime::createFromFormat( 'Y-m-d H:i:s', $data['started_at'] );
			if ( ! $date ) {
				$errors[] = 'Invalid started_at datetime format';
			} else {
				$validated['started_at'] = $data['started_at'];
			}
		}

		// Validate configuration JSON
		if ( ! empty( $data['configuration'] ) ) {
			if ( is_string( $data['configuration'] ) ) {
				json_decode( $data['configuration'] );
				if ( json_last_error() !== JSON_ERROR_NONE ) {
					$errors[] = 'Invalid configuration JSON';
				} else {
					$validated['configuration'] = $data['configuration'];
				}
			} elseif ( is_array( $data['configuration'] ) ) {
				$validated['configuration'] = json_encode( $data['configuration'] );
			}
		}

		if ( ! empty( $errors ) ) {
			return new WP_Error( 'validation_failed', 'Data validation failed', $errors );
		}

		return $validated;
	}

	/**
	 * Validate vulnerability data before database insertion
	 *
	 * @since    1.0.0
	 * @param    array    $data    Vulnerability data to validate
	 * @return   array|WP_Error    Validated data or error
	 */
	public static function validate_vulnerability_data( $data ) {
		$validated = array();
		$errors = array();

		// Validate vulnerability type
		$allowed_types = array( 'sql_injection', 'xss', 'csrf', 'file_inclusion', 'directory_traversal', 'weak_password', 'outdated_software', 'file_permissions', 'configuration', 'other' );
		if ( empty( $data['vulnerability_type'] ) || ! in_array( $data['vulnerability_type'], $allowed_types ) ) {
			$errors[] = 'Invalid vulnerability type';
		} else {
			$validated['vulnerability_type'] = $data['vulnerability_type'];
		}

		// Validate severity
		$allowed_severities = array( 'critical', 'high', 'medium', 'low' );
		if ( empty( $data['severity'] ) || ! in_array( $data['severity'], $allowed_severities ) ) {
			$errors[] = 'Invalid severity level';
		} else {
			$validated['severity'] = $data['severity'];
		}

		// Validate required fields
		if ( empty( $data['title'] ) ) {
			$errors[] = 'Title is required';
		} else {
			$validated['title'] = sanitize_text_field( $data['title'] );
		}

		if ( empty( $data['description'] ) ) {
			$errors[] = 'Description is required';
		} else {
			$validated['description'] = wp_kses_post( $data['description'] );
		}

		// Validate CVSS score (0.0 to 10.0)
		if ( ! empty( $data['cvss_score'] ) ) {
			$score = floatval( $data['cvss_score'] );
			if ( $score < 0.0 || $score > 10.0 ) {
				$errors[] = 'CVSS score must be between 0.0 and 10.0';
			} else {
				$validated['cvss_score'] = $score;
			}
		}

		if ( ! empty( $errors ) ) {
			return new WP_Error( 'validation_failed', 'Vulnerability validation failed', $errors );
		}

		return $validated;
	}

	/**
	 * Sanitize user input for database operations
	 *
	 * @since    1.0.0
	 * @param    mixed    $data    Data to sanitize
	 * @param    string   $type    Type of sanitization
	 * @return   mixed             Sanitized data
	 */
	public static function sanitize_data( $data, $type = 'text' ) {
		switch ( $type ) {
			case 'text':
				return sanitize_text_field( $data );
			
			case 'textarea':
				return sanitize_textarea_field( $data );
			
			case 'email':
				return sanitize_email( $data );
			
			case 'url':
				return esc_url_raw( $data );
			
			case 'int':
				return intval( $data );
			
			case 'float':
				return floatval( $data );
			
			case 'boolean':
				return (bool) $data;
			
			case 'json':
				if ( is_array( $data ) ) {
					return json_encode( $data );
				}
				return is_string( $data ) ? $data : '';
			
			case 'html':
				return wp_kses_post( $data );
			
			default:
				return sanitize_text_field( $data );
		}
	}

	/**
	 * Create database backup for WP-Breach tables
	 *
	 * @since    1.0.0
	 * @return   string|WP_Error    Backup file path or error
	 */
	public static function create_backup() {
		global $wpdb;

		$tables = array(
			$wpdb->prefix . 'breach_scans',
			$wpdb->prefix . 'breach_vulnerabilities',
			$wpdb->prefix . 'breach_fixes',
			$wpdb->prefix . 'breach_settings',
			$wpdb->prefix . 'breach_schedules',
			$wpdb->prefix . 'breach_alerts',
			$wpdb->prefix . 'breach_monitoring',
			$wpdb->prefix . 'breach_vulnerability_db',
			$wpdb->prefix . 'breach_scan_logs',
			$wpdb->prefix . 'breach_reports',
			$wpdb->prefix . 'breach_user_preferences'
		);

		$backup_data = array();
		
		foreach ( $tables as $table ) {
			// Check if table exists
			$table_exists = $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $table ) );
			if ( ! $table_exists ) {
				continue;
			}

			// Get table structure
			$create_table = $wpdb->get_row( "SHOW CREATE TABLE `$table`", ARRAY_N );
			if ( $create_table ) {
				$backup_data['structure'][$table] = $create_table[1];
			}

			// Get table data
			$rows = $wpdb->get_results( "SELECT * FROM `$table`", ARRAY_A );
			if ( $rows ) {
				$backup_data['data'][$table] = $rows;
			}
		}

		// Create backup file
		$upload_dir = wp_upload_dir();
		$backup_dir = $upload_dir['basedir'] . '/wp-breach-backups/';
		
		if ( ! file_exists( $backup_dir ) ) {
			wp_mkdir_p( $backup_dir );
		}

		$backup_file = $backup_dir . 'wp-breach-backup-' . date( 'Y-m-d-H-i-s' ) . '.json';
		
		if ( file_put_contents( $backup_file, json_encode( $backup_data, JSON_PRETTY_PRINT ) ) === false ) {
			return new WP_Error( 'backup_failed', 'Failed to create backup file' );
		}

		return $backup_file;
	}

	/**
	 * Restore database from backup file
	 *
	 * @since    1.0.0
	 * @param    string   $backup_file    Path to backup file
	 * @return   bool|WP_Error           Success or error
	 */
	public static function restore_backup( $backup_file ) {
		global $wpdb;

		if ( ! file_exists( $backup_file ) ) {
			return new WP_Error( 'file_not_found', 'Backup file not found' );
		}

		$backup_data = json_decode( file_get_contents( $backup_file ), true );
		
		if ( json_last_error() !== JSON_ERROR_NONE ) {
			return new WP_Error( 'invalid_backup', 'Invalid backup file format' );
		}

		// Restore table structures
		if ( isset( $backup_data['structure'] ) ) {
			foreach ( $backup_data['structure'] as $table => $create_sql ) {
				$wpdb->query( "DROP TABLE IF EXISTS `$table`" );
				$wpdb->query( $create_sql );
			}
		}

		// Restore table data
		if ( isset( $backup_data['data'] ) ) {
			foreach ( $backup_data['data'] as $table => $rows ) {
				foreach ( $rows as $row ) {
					$wpdb->insert( $table, $row );
				}
			}
		}

		return true;
	}

	/**
	 * Get database performance statistics
	 *
	 * @since    1.0.0
	 * @return   array    Performance statistics
	 */
	public static function get_performance_stats() {
		global $wpdb;

		$stats = array();

		// Get table sizes
		$tables = array(
			$wpdb->prefix . 'breach_scans',
			$wpdb->prefix . 'breach_vulnerabilities',
			$wpdb->prefix . 'breach_fixes',
			$wpdb->prefix . 'breach_settings',
			$wpdb->prefix . 'breach_schedules',
			$wpdb->prefix . 'breach_alerts',
			$wpdb->prefix . 'breach_monitoring',
			$wpdb->prefix . 'breach_vulnerability_db',
			$wpdb->prefix . 'breach_scan_logs',
			$wpdb->prefix . 'breach_reports',
			$wpdb->prefix . 'breach_user_preferences'
		);

		foreach ( $tables as $table ) {
			$size_query = $wpdb->prepare( 
				"SELECT 
					table_name AS 'table',
					ROUND(((data_length + index_length) / 1024 / 1024), 2) AS 'size_mb',
					table_rows AS 'rows'
				FROM information_schema.TABLES 
				WHERE table_schema = %s AND table_name = %s",
				DB_NAME,
				$table
			);
			
			$result = $wpdb->get_row( $size_query, ARRAY_A );
			if ( $result ) {
				$stats['tables'][$table] = $result;
			}
		}

		// Get index usage statistics
		$stats['indexes'] = self::get_index_usage_stats();

		// Get query performance
		$stats['queries'] = self::get_slow_query_stats();

		return $stats;
	}

	/**
	 * Get index usage statistics
	 *
	 * @since    1.0.0
	 * @return   array    Index usage statistics
	 */
	private static function get_index_usage_stats() {
		global $wpdb;

		$query = $wpdb->prepare(
			"SELECT 
				table_name,
				index_name,
				cardinality,
				nullable
			FROM information_schema.statistics 
			WHERE table_schema = %s 
			AND table_name LIKE %s
			ORDER BY table_name, index_name",
			DB_NAME,
			$wpdb->prefix . 'breach_%'
		);

		return $wpdb->get_results( $query, ARRAY_A );
	}

	/**
	 * Get slow query statistics
	 *
	 * @since    1.0.0
	 * @return   array    Slow query statistics
	 */
	private static function get_slow_query_stats() {
		// This would require enabling slow query log
		// For now, return placeholder data
		return array(
			'slow_queries_enabled' => false,
			'note' => 'Enable MySQL slow query log for detailed query performance statistics'
		);
	}

	/**
	 * Optimize database tables
	 *
	 * @since    1.0.0
	 * @return   array    Optimization results
	 */
	public static function optimize_tables() {
		global $wpdb;

		$tables = array(
			$wpdb->prefix . 'breach_scans',
			$wpdb->prefix . 'breach_vulnerabilities',
			$wpdb->prefix . 'breach_fixes',
			$wpdb->prefix . 'breach_settings',
			$wpdb->prefix . 'breach_schedules',
			$wpdb->prefix . 'breach_alerts',
			$wpdb->prefix . 'breach_monitoring',
			$wpdb->prefix . 'breach_vulnerability_db',
			$wpdb->prefix . 'breach_scan_logs',
			$wpdb->prefix . 'breach_reports',
			$wpdb->prefix . 'breach_user_preferences'
		);

		$results = array();

		foreach ( $tables as $table ) {
			$result = $wpdb->query( "OPTIMIZE TABLE `$table`" );
			$results[$table] = $result !== false ? 'optimized' : 'failed';
		}

		return $results;
	}

	/**
	 * Check database integrity
	 *
	 * @since    1.0.0
	 * @return   array    Integrity check results
	 */
	public static function check_integrity() {
		global $wpdb;

		$checks = array();

		// Check foreign key constraints
		$checks['foreign_keys'] = self::check_foreign_key_integrity();

		// Check for orphaned records
		$checks['orphaned_records'] = self::check_orphaned_records();

		// Check table structure
		$checks['table_structure'] = self::check_table_structure();

		return $checks;
	}

	/**
	 * Check foreign key integrity
	 *
	 * @since    1.0.0
	 * @return   array    Foreign key check results
	 */
	private static function check_foreign_key_integrity() {
		global $wpdb;

		$checks = array();

		// Check vulnerabilities -> scans relationship
		$orphaned_vulns = $wpdb->get_var(
			"SELECT COUNT(*) FROM {$wpdb->prefix}breach_vulnerabilities v 
			 LEFT JOIN {$wpdb->prefix}breach_scans s ON v.scan_id = s.id 
			 WHERE s.id IS NULL"
		);
		$checks['vulnerabilities_scans'] = intval( $orphaned_vulns );

		// Check fixes -> vulnerabilities relationship
		$orphaned_fixes = $wpdb->get_var(
			"SELECT COUNT(*) FROM {$wpdb->prefix}breach_fixes f 
			 LEFT JOIN {$wpdb->prefix}breach_vulnerabilities v ON f.vulnerability_id = v.id 
			 WHERE v.id IS NULL"
		);
		$checks['fixes_vulnerabilities'] = intval( $orphaned_fixes );

		return $checks;
	}

	/**
	 * Check for orphaned records
	 *
	 * @since    1.0.0
	 * @return   array    Orphaned records check results
	 */
	private static function check_orphaned_records() {
		// This would check for records that reference non-existent data
		// Implementation depends on specific business logic
		return array(
			'note' => 'Orphaned records check not implemented - requires business logic definition'
		);
	}

	/**
	 * Check table structure against expected schema
	 *
	 * @since    1.0.0
	 * @return   array    Table structure check results
	 */
	private static function check_table_structure() {
		global $wpdb;

		$tables = array(
			$wpdb->prefix . 'breach_scans',
			$wpdb->prefix . 'breach_vulnerabilities',
			$wpdb->prefix . 'breach_fixes',
			$wpdb->prefix . 'breach_settings',
			$wpdb->prefix . 'breach_schedules',
			$wpdb->prefix . 'breach_alerts',
			$wpdb->prefix . 'breach_monitoring',
			$wpdb->prefix . 'breach_vulnerability_db',
			$wpdb->prefix . 'breach_scan_logs',
			$wpdb->prefix . 'breach_reports',
			$wpdb->prefix . 'breach_user_preferences'
		);

		$results = array();

		foreach ( $tables as $table ) {
			$table_exists = $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $table ) );
			$results[$table] = $table_exists ? 'exists' : 'missing';
		}

		return $results;
	}
}

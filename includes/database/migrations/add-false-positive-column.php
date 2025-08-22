<?php
/**
 * Migration: Add false_positive column to vulnerabilities table
 *
 * @package    WP_Breach
 * @since      1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Add false_positive column to vulnerabilities table
 */
function wp_breach_migrate_add_false_positive_column() {
	global $wpdb;

	$table_name = $wpdb->prefix . 'breach_vulnerabilities';

	// Check if column already exists
	$column_exists = $wpdb->get_results(
		$wpdb->prepare(
			"SHOW COLUMNS FROM `{$table_name}` LIKE %s",
			'false_positive'
		)
	);

	if ( ! empty( $column_exists ) ) {
		return array( 'success' => true, 'message' => 'Column false_positive already exists' );
	}

	// Add the column
	$sql = "ALTER TABLE `{$table_name}` ADD COLUMN `false_positive` TINYINT(1) NOT NULL DEFAULT 0 AFTER `status`";
	
	$result = $wpdb->query( $sql );

	if ( $result === false ) {
		return array( 
			'success' => false, 
			'message' => 'Failed to add false_positive column: ' . $wpdb->last_error 
		);
	}

	// Add index for better performance
	$index_sql = "ALTER TABLE `{$table_name}` ADD INDEX `idx_false_positive` (`false_positive`)";
	$wpdb->query( $index_sql );

	return array( 
		'success' => true, 
		'message' => 'Successfully added false_positive column and index' 
	);
}

// Run the migration
$migration_result = wp_breach_migrate_add_false_positive_column();

if ( $migration_result['success'] ) {
	error_log( 'WP-Breach Migration: ' . $migration_result['message'] );
} else {
	error_log( 'WP-Breach Migration Error: ' . $migration_result['message'] );
}

return $migration_result;

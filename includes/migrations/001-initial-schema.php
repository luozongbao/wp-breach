<?php

/**
 * Initial Schema Migration
 *
 * Creates the initial database schema for WP-Breach plugin.
 * This migration sets up all required tables and indexes.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/migrations
 */

class WP_Breach_Migration_001_Initial_Schema {

	/**
	 * Run the migration
	 *
	 * @since    1.0.0
	 * @return   bool|WP_Error    Success or error
	 */
	public function up() {
		// Load database class to create tables
		require_once plugin_dir_path( dirname( __FILE__ ) ) . 'class-wp-breach-database.php';
		
		try {
			$database = new WP_Breach_Database();
			$database->create_tables();
			
			return true;
			
		} catch ( Exception $e ) {
			return new WP_Error( 
				'initial_schema_failed', 
				'Failed to create initial schema: ' . $e->getMessage() 
			);
		}
	}

	/**
	 * Rollback the migration
	 *
	 * @since    1.0.0
	 * @return   bool|WP_Error    Success or error
	 */
	public function down() {
		// Load database class to drop tables
		require_once plugin_dir_path( dirname( __FILE__ ) ) . 'class-wp-breach-database.php';
		
		try {
			$database = new WP_Breach_Database();
			$database->drop_tables();
			
			return true;
			
		} catch ( Exception $e ) {
			return new WP_Error( 
				'initial_schema_rollback_failed', 
				'Failed to rollback initial schema: ' . $e->getMessage() 
			);
		}
	}
}

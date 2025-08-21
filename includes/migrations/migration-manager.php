<?php

/**
 * Migration Manager Class
 *
 * Handles database schema migrations for WP-Breach plugin.
 * Provides framework for version-based schema updates.
 *
 * @link       https://wpsecurity.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/migrations
 */

/**
 * Migration manager for WP-Breach plugin.
 *
 * This class defines the migration system for handling database
 * schema changes across different plugin versions.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/migrations
 * @author     Your Name <email@example.com>
 */
class WP_Breach_Migration_Manager {

	/**
	 * Current database version
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      string    $db_version    Current database version
	 */
	private $db_version;

	/**
	 * Migration files directory
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      string    $migrations_dir    Path to migrations directory
	 */
	private $migrations_dir;

	/**
	 * Initialize the migration manager
	 *
	 * @since    1.0.0
	 */
	public function __construct() {
		$this->db_version = '1.0.0';
		$this->migrations_dir = plugin_dir_path( __FILE__ );
	}

	/**
	 * Run pending migrations
	 *
	 * @since    1.0.0
	 * @return   bool|WP_Error    Success or error
	 */
	public function run_migrations() {
		$current_version = get_option( 'wp_breach_db_version', '0.0.0' );
		
		if ( version_compare( $current_version, $this->db_version, '>=' ) ) {
			return true; // No migrations needed
		}

		$migrations = $this->get_pending_migrations( $current_version );
		
		if ( empty( $migrations ) ) {
			return true; // No pending migrations
		}

		foreach ( $migrations as $migration ) {
			$result = $this->run_migration( $migration );
			
			if ( is_wp_error( $result ) ) {
				return $result;
			}
		}

		// Update database version
		update_option( 'wp_breach_db_version', $this->db_version );
		
		return true;
	}

	/**
	 * Get list of pending migrations
	 *
	 * @since    1.0.0
	 * @param    string   $from_version    Current database version
	 * @return   array                     List of pending migrations
	 */
	private function get_pending_migrations( $from_version ) {
		$migrations = array();
		$migration_files = glob( $this->migrations_dir . '*.php' );
		
		foreach ( $migration_files as $file ) {
			$filename = basename( $file, '.php' );
			
			// Extract version from filename (e.g., 001-initial-schema -> 1.0.0)
			if ( preg_match( '/^(\d+)-/', $filename, $matches ) ) {
				$migration_version = $this->get_version_from_migration_number( $matches[1] );
				
				if ( version_compare( $migration_version, $from_version, '>' ) ) {
					$migrations[] = array(
						'file' => $file,
						'version' => $migration_version,
						'number' => intval( $matches[1] )
					);
				}
			}
		}

		// Sort by migration number
		usort( $migrations, function( $a, $b ) {
			return $a['number'] - $b['number'];
		});

		return $migrations;
	}

	/**
	 * Run a single migration
	 *
	 * @since    1.0.0
	 * @param    array    $migration    Migration details
	 * @return   bool|WP_Error         Success or error
	 */
	private function run_migration( $migration ) {
		try {
			require_once $migration['file'];
			
			$migration_class = $this->get_migration_class_name( $migration['file'] );
			
			if ( ! class_exists( $migration_class ) ) {
				return new WP_Error( 
					'migration_class_not_found', 
					sprintf( 'Migration class %s not found', $migration_class )
				);
			}

			$migration_instance = new $migration_class();
			
			if ( ! method_exists( $migration_instance, 'up' ) ) {
				return new WP_Error( 
					'migration_method_not_found', 
					sprintf( 'Migration method "up" not found in %s', $migration_class )
				);
			}

			// Run the migration
			$result = $migration_instance->up();
			
			if ( is_wp_error( $result ) ) {
				return $result;
			}

			// Log successful migration
			error_log( sprintf( 'WP-Breach: Migration %s completed successfully', $migration['version'] ) );
			
			return true;

		} catch ( Exception $e ) {
			return new WP_Error( 
				'migration_failed', 
				sprintf( 'Migration failed: %s', $e->getMessage() )
			);
		}
	}

	/**
	 * Rollback a migration
	 *
	 * @since    1.0.0
	 * @param    string   $version    Version to rollback
	 * @return   bool|WP_Error       Success or error
	 */
	public function rollback_migration( $version ) {
		$migration_file = $this->get_migration_file_by_version( $version );
		
		if ( ! $migration_file ) {
			return new WP_Error( 'migration_not_found', 'Migration file not found' );
		}

		try {
			require_once $migration_file;
			
			$migration_class = $this->get_migration_class_name( $migration_file );
			$migration_instance = new $migration_class();
			
			if ( ! method_exists( $migration_instance, 'down' ) ) {
				return new WP_Error( 
					'rollback_method_not_found', 
					sprintf( 'Rollback method "down" not found in %s', $migration_class )
				);
			}

			// Run the rollback
			$result = $migration_instance->down();
			
			if ( is_wp_error( $result ) ) {
				return $result;
			}

			// Log successful rollback
			error_log( sprintf( 'WP-Breach: Migration %s rolled back successfully', $version ) );
			
			return true;

		} catch ( Exception $e ) {
			return new WP_Error( 
				'rollback_failed', 
				sprintf( 'Migration rollback failed: %s', $e->getMessage() )
			);
		}
	}

	/**
	 * Get migration class name from file path
	 *
	 * @since    1.0.0
	 * @param    string   $file_path    Path to migration file
	 * @return   string                 Migration class name
	 */
	private function get_migration_class_name( $file_path ) {
		$filename = basename( $file_path, '.php' );
		
		// Convert filename to class name (e.g., 001-initial-schema -> WP_Breach_Migration_001_Initial_Schema)
		$class_name = 'WP_Breach_Migration_';
		$parts = explode( '-', $filename );
		
		foreach ( $parts as $part ) {
			$class_name .= ucfirst( $part ) . '_';
		}
		
		return rtrim( $class_name, '_' );
	}

	/**
	 * Get migration file by version
	 *
	 * @since    1.0.0
	 * @param    string   $version    Version to find
	 * @return   string|false         Migration file path or false
	 */
	private function get_migration_file_by_version( $version ) {
		$migration_files = glob( $this->migrations_dir . '*.php' );
		
		foreach ( $migration_files as $file ) {
			$filename = basename( $file, '.php' );
			
			if ( preg_match( '/^(\d+)-/', $filename, $matches ) ) {
				$migration_version = $this->get_version_from_migration_number( $matches[1] );
				
				if ( $migration_version === $version ) {
					return $file;
				}
			}
		}
		
		return false;
	}

	/**
	 * Convert migration number to version
	 *
	 * @since    1.0.0
	 * @param    string   $number    Migration number
	 * @return   string             Version string
	 */
	private function get_version_from_migration_number( $number ) {
		// Simple mapping for now - can be made more sophisticated
		$version_map = array(
			'001' => '1.0.0',
			'002' => '1.0.1',
			'003' => '1.0.2',
			// Add more as needed
		);
		
		return isset( $version_map[ $number ] ) ? $version_map[ $number ] : '1.0.0';
	}

	/**
	 * Get migration status
	 *
	 * @since    1.0.0
	 * @return   array    Migration status information
	 */
	public function get_migration_status() {
		$current_version = get_option( 'wp_breach_db_version', '0.0.0' );
		$pending_migrations = $this->get_pending_migrations( $current_version );
		
		return array(
			'current_version' => $current_version,
			'target_version' => $this->db_version,
			'pending_migrations' => count( $pending_migrations ),
			'migrations_needed' => ! empty( $pending_migrations ),
			'migrations' => $pending_migrations
		);
	}

	/**
	 * Create a new migration file template
	 *
	 * @since    1.0.0
	 * @param    string   $name    Migration name
	 * @return   string|WP_Error  Migration file path or error
	 */
	public function create_migration( $name ) {
		// Get next migration number
		$migration_files = glob( $this->migrations_dir . '*.php' );
		$next_number = 1;
		
		foreach ( $migration_files as $file ) {
			$filename = basename( $file, '.php' );
			if ( preg_match( '/^(\d+)-/', $filename, $matches ) ) {
				$next_number = max( $next_number, intval( $matches[1] ) + 1 );
			}
		}

		$migration_number = str_pad( $next_number, 3, '0', STR_PAD_LEFT );
		$migration_filename = $migration_number . '-' . sanitize_file_name( $name ) . '.php';
		$migration_path = $this->migrations_dir . $migration_filename;
		
		$class_name = $this->get_migration_class_name( $migration_path );
		
		$template = $this->get_migration_template( $class_name, $name );
		
		if ( file_put_contents( $migration_path, $template ) === false ) {
			return new WP_Error( 'migration_create_failed', 'Failed to create migration file' );
		}
		
		return $migration_path;
	}

	/**
	 * Get migration file template
	 *
	 * @since    1.0.0
	 * @param    string   $class_name        Migration class name
	 * @param    string   $migration_name    Migration description
	 * @return   string                      Migration file template
	 */
	private function get_migration_template( $class_name, $migration_name ) {
		return "<?php

/**
 * Migration: {$migration_name}
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/migrations
 */

class {$class_name} {

	/**
	 * Run the migration
	 *
	 * @since    1.0.0
	 * @return   bool|WP_Error    Success or error
	 */
	public function up() {
		global \$wpdb;
		
		// Add your migration code here
		// Example:
		// \$wpdb->query( \"ALTER TABLE {\$wpdb->prefix}breach_scans ADD COLUMN new_column VARCHAR(255) NULL\" );
		
		return true;
	}

	/**
	 * Rollback the migration
	 *
	 * @since    1.0.0
	 * @return   bool|WP_Error    Success or error
	 */
	public function down() {
		global \$wpdb;
		
		// Add your rollback code here
		// Example:
		// \$wpdb->query( \"ALTER TABLE {\$wpdb->prefix}breach_scans DROP COLUMN new_column\" );
		
		return true;
	}
}";
	}
}

<?php
/**
 * The database-specific functionality of the plugin.
 *
 * @link       https://github.com/luozongbao
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes
 */

/**
 * The database-specific functionality of the plugin.
 *
 * Defines the plugin database schema, handles table creation, migrations,
 * and database operations.
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes
 * @author     luozongbao <luo.zongbao@outlook.com>
 */
class WP_Breach_Database {

	/**
	 * The database version.
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      string    $db_version    The current database version.
	 */
	private $db_version = '1.0.0';

	/**
	 * The WordPress database object.
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      wpdb    $wpdb    The WordPress database object.
	 */
	private $wpdb;

	/**
	 * Initialize the database class.
	 *
	 * @since    1.0.0
	 */
	public function __construct() {
		global $wpdb;
		$this->wpdb = $wpdb;
	}

	/**
	 * Create all plugin database tables.
	 *
	 * @since    1.0.0
	 * @return   bool    True on success, false on failure.
	 */
	public function create_tables() {
		require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );

		$success = true;

		// Create tables in dependency order
		$tables = array(
			'create_scans_table',
			'create_vulnerabilities_table',
			'create_fixes_table',
			'create_settings_table',
			'create_schedules_table',
			'create_alerts_table',
			'create_monitoring_table',
			'create_vulnerability_db_table',
			'create_scan_logs_table',
			'create_reports_table',
			'create_user_preferences_table',
		);

		foreach ( $tables as $table_method ) {
			if ( ! $this->$table_method() ) {
				$success = false;
				error_log( "WP-Breach: Failed to create table using method {$table_method}" );
			}
		}

		if ( $success ) {
			$this->update_database_version();
		}

		return $success;
	}

	/**
	 * Create the scans table.
	 *
	 * @since    1.0.0
	 * @return   bool    True on success, false on failure.
	 */
	private function create_scans_table() {
		$table_name = $this->wpdb->prefix . 'breach_scans';

		$sql = "CREATE TABLE {$table_name} (
			id BIGINT(20) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
			scan_type ENUM('quick', 'full', 'custom') NOT NULL,
			status ENUM('pending', 'running', 'completed', 'failed', 'cancelled') NOT NULL DEFAULT 'pending',
			started_at DATETIME NOT NULL,
			completed_at DATETIME NULL,
			duration_seconds INT UNSIGNED NULL,
			total_checks INT UNSIGNED DEFAULT 0,
			vulnerabilities_found INT UNSIGNED DEFAULT 0,
			critical_count INT UNSIGNED DEFAULT 0,
			high_count INT UNSIGNED DEFAULT 0,
			medium_count INT UNSIGNED DEFAULT 0,
			low_count INT UNSIGNED DEFAULT 0,
			configuration TEXT NULL,
			summary_data TEXT NULL,
			scan_hash VARCHAR(64) NULL,
			created_by BIGINT(20) UNSIGNED NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			
			INDEX idx_status (status),
			INDEX idx_scan_type (scan_type),
			INDEX idx_started_at (started_at),
			INDEX idx_created_by (created_by),
			INDEX idx_scan_hash (scan_hash),
			INDEX idx_created_at (created_at)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";

		$result = dbDelta( $sql );
		return ! empty( $result );
	}

	/**
	 * Create the vulnerabilities table.
	 *
	 * @since    1.0.0
	 * @return   bool    True on success, false on failure.
	 */
	private function create_vulnerabilities_table() {
		$table_name = $this->wpdb->prefix . 'breach_vulnerabilities';

		$sql = "CREATE TABLE {$table_name} (
			id BIGINT(20) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
			scan_id BIGINT(20) UNSIGNED NOT NULL,
			vulnerability_type ENUM('sql_injection', 'xss', 'csrf', 'file_inclusion', 'directory_traversal', 'weak_password', 'outdated_software', 'file_permissions', 'configuration', 'malware', 'other') NOT NULL,
			severity ENUM('critical', 'high', 'medium', 'low') NOT NULL,
			title VARCHAR(255) NOT NULL,
			description TEXT NOT NULL,
			component_type ENUM('core', 'plugin', 'theme', 'database', 'file_system', 'user_account', 'configuration') NOT NULL,
			component_name VARCHAR(255) NULL,
			component_version VARCHAR(50) NULL,
			affected_file VARCHAR(500) NULL,
			line_number INT UNSIGNED NULL,
			cvss_score DECIMAL(3,1) NULL,
			cve_id VARCHAR(20) NULL,
			cwe_id VARCHAR(20) NULL,
			risk_level ENUM('low', 'medium', 'high', 'critical') NOT NULL,
			status ENUM('open', 'fixed', 'ignored', 'false_positive', 'in_progress') NOT NULL DEFAULT 'open',
			fix_available BOOLEAN DEFAULT FALSE,
			auto_fixable BOOLEAN DEFAULT FALSE,
			fix_complexity ENUM('easy', 'medium', 'hard') NULL,
			detected_at DATETIME NOT NULL,
			first_detected_at DATETIME NULL,
			last_seen_at DATETIME NULL,
			fix_applied_at DATETIME NULL,
			fixed_by BIGINT(20) UNSIGNED NULL,
			raw_data TEXT NULL,
			hash VARCHAR(64) NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			
			INDEX idx_scan_id (scan_id),
			INDEX idx_severity (severity),
			INDEX idx_status (status),
			INDEX idx_component (component_type, component_name),
			INDEX idx_vulnerability_type (vulnerability_type),
			INDEX idx_detected_at (detected_at),
			INDEX idx_hash (hash),
			INDEX idx_cve_id (cve_id),
			INDEX idx_risk_level (risk_level),
			UNIQUE KEY unique_hash (hash)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";

		$result = dbDelta( $sql );
		return ! empty( $result );
	}

	/**
	 * Create the fixes table.
	 *
	 * @since    1.0.0
	 * @return   bool    True on success, false on failure.
	 */
	private function create_fixes_table() {
		$table_name = $this->wpdb->prefix . 'breach_fixes';

		$sql = "CREATE TABLE {$table_name} (
			id BIGINT(20) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
			vulnerability_id BIGINT(20) UNSIGNED NOT NULL,
			fix_type ENUM('automatic', 'manual', 'update', 'configuration', 'file_modification', 'permission_change') NOT NULL,
			fix_method VARCHAR(100) NOT NULL,
			status ENUM('pending', 'in_progress', 'completed', 'failed', 'rolled_back') NOT NULL DEFAULT 'pending',
			applied_at DATETIME NULL,
			applied_by BIGINT(20) UNSIGNED NOT NULL,
			rollback_available BOOLEAN DEFAULT FALSE,
			rollback_data TEXT NULL,
			fix_details TEXT NULL,
			before_snapshot TEXT NULL,
			after_snapshot TEXT NULL,
			error_message TEXT NULL,
			success_rate DECIMAL(5,2) DEFAULT 0.00,
			execution_time INT UNSIGNED NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			
			INDEX idx_vulnerability_id (vulnerability_id),
			INDEX idx_status (status),
			INDEX idx_fix_type (fix_type),
			INDEX idx_applied_at (applied_at),
			INDEX idx_applied_by (applied_by)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";

		$result = dbDelta( $sql );
		return ! empty( $result );
	}

	/**
	 * Create the settings table.
	 *
	 * @since    1.0.0
	 * @return   bool    True on success, false on failure.
	 */
	private function create_settings_table() {
		$table_name = $this->wpdb->prefix . 'breach_settings';

		$sql = "CREATE TABLE {$table_name} (
			id BIGINT(20) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
			setting_key VARCHAR(100) NOT NULL,
			setting_value LONGTEXT NULL,
			setting_type ENUM('string', 'integer', 'boolean', 'array', 'object') NOT NULL DEFAULT 'string',
			is_encrypted BOOLEAN DEFAULT FALSE,
			autoload BOOLEAN DEFAULT TRUE,
			description TEXT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			
			UNIQUE KEY unique_setting_key (setting_key),
			INDEX idx_autoload (autoload),
			INDEX idx_setting_type (setting_type)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";

		$result = dbDelta( $sql );
		return ! empty( $result );
	}

	/**
	 * Create the schedules table.
	 *
	 * @since    1.0.0
	 * @return   bool    True on success, false on failure.
	 */
	private function create_schedules_table() {
		$table_name = $this->wpdb->prefix . 'breach_schedules';

		$sql = "CREATE TABLE {$table_name} (
			id BIGINT(20) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			scan_type ENUM('quick', 'full', 'custom') NOT NULL,
			frequency ENUM('hourly', 'daily', 'weekly', 'monthly') NOT NULL,
			next_run DATETIME NOT NULL,
			last_run DATETIME NULL,
			is_active BOOLEAN DEFAULT TRUE,
			configuration TEXT NULL,
			created_by BIGINT(20) UNSIGNED NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			
			INDEX idx_next_run (next_run),
			INDEX idx_is_active (is_active),
			INDEX idx_frequency (frequency),
			INDEX idx_created_by (created_by)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";

		$result = dbDelta( $sql );
		return ! empty( $result );
	}

	/**
	 * Create the alerts table.
	 *
	 * @since    1.0.0
	 * @return   bool    True on success, false on failure.
	 */
	private function create_alerts_table() {
		$table_name = $this->wpdb->prefix . 'breach_alerts';

		$sql = "CREATE TABLE {$table_name} (
			id BIGINT(20) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
			alert_type ENUM('vulnerability_found', 'scan_completed', 'fix_applied', 'system_error', 'threshold_exceeded') NOT NULL,
			severity ENUM('info', 'warning', 'error', 'critical') NOT NULL,
			title VARCHAR(255) NOT NULL,
			message TEXT NOT NULL,
			related_id BIGINT(20) UNSIGNED NULL,
			related_type ENUM('scan', 'vulnerability', 'fix', 'schedule') NULL,
			is_read BOOLEAN DEFAULT FALSE,
			is_dismissed BOOLEAN DEFAULT FALSE,
			sent_email BOOLEAN DEFAULT FALSE,
			email_sent_at DATETIME NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			
			INDEX idx_alert_type (alert_type),
			INDEX idx_severity (severity),
			INDEX idx_is_read (is_read),
			INDEX idx_is_dismissed (is_dismissed),
			INDEX idx_related (related_type, related_id),
			INDEX idx_created_at (created_at)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";

		$result = dbDelta( $sql );
		return ! empty( $result );
	}

	/**
	 * Create the monitoring table.
	 *
	 * @since    1.0.0
	 * @return   bool    True on success, false on failure.
	 */
	private function create_monitoring_table() {
		$table_name = $this->wpdb->prefix . 'breach_monitoring';

		$sql = "CREATE TABLE {$table_name} (
			id BIGINT(20) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
			monitor_type ENUM('file_integrity', 'user_activity', 'login_attempts', 'suspicious_requests', 'performance') NOT NULL,
			event_type VARCHAR(100) NOT NULL,
			file_path VARCHAR(500) NULL,
			file_hash VARCHAR(64) NULL,
			user_id BIGINT(20) UNSIGNED NULL,
			ip_address VARCHAR(45) NULL,
			user_agent TEXT NULL,
			request_data TEXT NULL,
			severity ENUM('low', 'medium', 'high', 'critical') NOT NULL DEFAULT 'low',
			status ENUM('active', 'resolved', 'ignored') NOT NULL DEFAULT 'active',
			event_data TEXT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			
			INDEX idx_monitor_type (monitor_type),
			INDEX idx_event_type (event_type),
			INDEX idx_file_path (file_path),
			INDEX idx_user_id (user_id),
			INDEX idx_ip_address (ip_address),
			INDEX idx_severity (severity),
			INDEX idx_status (status),
			INDEX idx_created_at (created_at)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";

		$result = dbDelta( $sql );
		return ! empty( $result );
	}

	/**
	 * Create the vulnerability database cache table.
	 *
	 * @since    1.0.0
	 * @return   bool    True on success, false on failure.
	 */
	private function create_vulnerability_db_table() {
		$table_name = $this->wpdb->prefix . 'breach_vulnerability_db';

		$sql = "CREATE TABLE {$table_name} (
			id BIGINT(20) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
			cve_id VARCHAR(20) NOT NULL,
			cwe_id VARCHAR(20) NULL,
			title VARCHAR(255) NOT NULL,
			description TEXT NOT NULL,
			severity ENUM('critical', 'high', 'medium', 'low') NOT NULL,
			cvss_score DECIMAL(3,1) NULL,
			published_date DATE NULL,
			modified_date DATE NULL,
			affected_software TEXT NULL,
			`references` TEXT NULL,
			last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			
			UNIQUE KEY unique_cve_id (cve_id),
			INDEX idx_severity (severity),
			INDEX idx_cvss_score (cvss_score),
			INDEX idx_published_date (published_date),
			INDEX idx_last_updated (last_updated)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";

		$result = dbDelta( $sql );
		return ! empty( $result );
	}

	/**
	 * Create the scan logs table.
	 *
	 * @since    1.0.0
	 * @return   bool    True on success, false on failure.
	 */
	private function create_scan_logs_table() {
		$table_name = $this->wpdb->prefix . 'breach_scan_logs';

		$sql = "CREATE TABLE {$table_name} (
			id BIGINT(20) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
			scan_id BIGINT(20) UNSIGNED NOT NULL,
			log_level ENUM('debug', 'info', 'warning', 'error', 'critical') NOT NULL,
			message TEXT NOT NULL,
			context TEXT NULL,
			execution_time DECIMAL(10,6) NULL,
			memory_usage INT UNSIGNED NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			
			INDEX idx_scan_id (scan_id),
			INDEX idx_log_level (log_level),
			INDEX idx_created_at (created_at)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";

		$result = dbDelta( $sql );
		return ! empty( $result );
	}

	/**
	 * Create the reports table.
	 *
	 * @since    1.0.0
	 * @return   bool    True on success, false on failure.
	 */
	private function create_reports_table() {
		$table_name = $this->wpdb->prefix . 'breach_reports';

		$sql = "CREATE TABLE {$table_name} (
			id BIGINT(20) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
			report_type ENUM('security_summary', 'vulnerability_detail', 'compliance', 'executive', 'custom') NOT NULL,
			title VARCHAR(255) NOT NULL,
			description TEXT NULL,
			format ENUM('pdf', 'html', 'csv', 'json') NOT NULL,
			file_path VARCHAR(500) NULL,
			file_size INT UNSIGNED NULL,
			scan_ids TEXT NULL,
			date_from DATE NULL,
			date_to DATE NULL,
			generated_by BIGINT(20) UNSIGNED NOT NULL,
			generated_at DATETIME NOT NULL,
			expires_at DATETIME NULL,
			download_count INT UNSIGNED DEFAULT 0,
			is_public BOOLEAN DEFAULT FALSE,
			access_token VARCHAR(64) NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			
			INDEX idx_report_type (report_type),
			INDEX idx_generated_by (generated_by),
			INDEX idx_generated_at (generated_at),
			INDEX idx_expires_at (expires_at),
			INDEX idx_access_token (access_token)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";

		$result = dbDelta( $sql );
		return ! empty( $result );
	}

	/**
	 * Create the user preferences table.
	 *
	 * @since    1.0.0
	 * @return   bool    True on success, false on failure.
	 */
	private function create_user_preferences_table() {
		$table_name = $this->wpdb->prefix . 'breach_user_preferences';

		$sql = "CREATE TABLE {$table_name} (
			id BIGINT(20) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
			user_id BIGINT(20) UNSIGNED NOT NULL,
			preference_key VARCHAR(100) NOT NULL,
			preference_value TEXT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			
			UNIQUE KEY unique_user_preference (user_id, preference_key),
			INDEX idx_user_id (user_id),
			INDEX idx_preference_key (preference_key)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";

		$result = dbDelta( $sql );
		return ! empty( $result );
	}

	/**
	 * Drop all plugin database tables.
	 *
	 * @since    1.0.0
	 * @return   bool    True on success, false on failure.
	 */
	public function drop_tables() {
		$tables = array(
			'breach_user_preferences',
			'breach_reports',
			'breach_scan_logs',
			'breach_vulnerability_db',
			'breach_monitoring',
			'breach_alerts',
			'breach_schedules',
			'breach_settings',
			'breach_fixes',
			'breach_vulnerabilities',
			'breach_scans',
		);

		$success = true;

		foreach ( $tables as $table ) {
			$table_name = $this->wpdb->prefix . $table;
			$result = $this->wpdb->query( "DROP TABLE IF EXISTS {$table_name}" );
			if ( false === $result ) {
				$success = false;
				error_log( "WP-Breach: Failed to drop table {$table_name}" );
			}
		}

		if ( $success ) {
			delete_option( 'wp_breach_db_version' );
		}

		return $success;
	}

	/**
	 * Get the current database version.
	 *
	 * @since    1.0.0
	 * @return   string    The current database version.
	 */
	public function get_database_version() {
		return get_option( 'wp_breach_db_version', '0.0.0' );
	}

	/**
	 * Update the database version.
	 *
	 * @since    1.0.0
	 * @param    string    $version    The new database version.
	 */
	public function update_database_version( $version = null ) {
		if ( null === $version ) {
			$version = $this->db_version;
		}
		update_option( 'wp_breach_db_version', $version );
	}

	/**
	 * Check if database migration is needed.
	 *
	 * @since    1.0.0
	 * @return   bool    True if migration is needed, false otherwise.
	 */
	public function needs_migration() {
		$current_version = $this->get_database_version();
		return version_compare( $current_version, $this->db_version, '<' );
	}

	/**
	 * Perform database migration.
	 *
	 * @since    1.0.0
	 * @return   bool    True on success, false on failure.
	 */
	public function migrate_database() {
		$current_version = $this->get_database_version();

		if ( ! $this->needs_migration() ) {
			return true;
		}

		// Create or update tables
		$success = $this->create_tables();

		if ( $success ) {
			// Run version-specific migrations if needed
			$success = $this->run_version_migrations( $current_version );
		}

		return $success;
	}

	/**
	 * Run version-specific database migrations.
	 *
	 * @since    1.0.0
	 * @param    string    $from_version    The version to migrate from.
	 * @return   bool      True on success, false on failure.
	 */
	private function run_version_migrations( $from_version ) {
		// Future version-specific migrations will be added here
		// Example:
		// if ( version_compare( $from_version, '1.1.0', '<' ) ) {
		//     $this->migrate_to_1_1_0();
		// }

		return true;
	}

	/**
	 * Get table statistics.
	 *
	 * @since    1.0.0
	 * @return   array    Array of table statistics.
	 */
	public function get_table_stats() {
		$stats = array();
		
		$tables = array(
			'breach_scans'             => 'Scans',
			'breach_vulnerabilities'   => 'Vulnerabilities',
			'breach_fixes'             => 'Fixes',
			'breach_settings'          => 'Settings',
			'breach_schedules'         => 'Schedules',
			'breach_alerts'            => 'Alerts',
			'breach_monitoring'        => 'Monitoring Events',
			'breach_vulnerability_db'  => 'CVE Database',
			'breach_scan_logs'         => 'Scan Logs',
			'breach_reports'           => 'Reports',
			'breach_user_preferences'  => 'User Preferences',
		);

		foreach ( $tables as $table => $label ) {
			$table_name = $this->wpdb->prefix . $table;
			$count = $this->wpdb->get_var( "SELECT COUNT(*) FROM {$table_name}" );
			$stats[ $table ] = array(
				'label' => $label,
				'count' => intval( $count ),
			);
		}

		return $stats;
	}

	/**
	 * Optimize database tables.
	 *
	 * @since    1.0.0
	 * @return   bool    True on success, false on failure.
	 */
	public function optimize_tables() {
		$tables = array(
			'breach_scans',
			'breach_vulnerabilities',
			'breach_fixes',
			'breach_settings',
			'breach_schedules',
			'breach_alerts',
			'breach_monitoring',
			'breach_vulnerability_db',
			'breach_scan_logs',
			'breach_reports',
			'breach_user_preferences',
		);

		$success = true;

		foreach ( $tables as $table ) {
			$table_name = $this->wpdb->prefix . $table;
			$result = $this->wpdb->query( "OPTIMIZE TABLE {$table_name}" );
			if ( false === $result ) {
				$success = false;
				error_log( "WP-Breach: Failed to optimize table {$table_name}" );
			}
		}

		return $success;
	}

	/**
	 * Clean up old data based on retention policies.
	 *
	 * @since    1.0.0
	 * @return   int    Number of records cleaned up.
	 */
	public function cleanup_old_data() {
		$retention_days = get_option( 'wp_breach_data_retention', 90 );
		$cutoff_date = date( 'Y-m-d H:i:s', strtotime( "-{$retention_days} days" ) );
		
		$cleaned_up = 0;

		// Clean up old scan logs
		$scan_logs_table = $this->wpdb->prefix . 'breach_scan_logs';
		$result = $this->wpdb->query( $this->wpdb->prepare(
			"DELETE FROM {$scan_logs_table} WHERE created_at < %s",
			$cutoff_date
		) );
		if ( false !== $result ) {
			$cleaned_up += $result;
		}

		// Clean up old monitoring events
		$monitoring_table = $this->wpdb->prefix . 'breach_monitoring';
		$result = $this->wpdb->query( $this->wpdb->prepare(
			"DELETE FROM {$monitoring_table} WHERE created_at < %s AND status = 'resolved'",
			$cutoff_date
		) );
		if ( false !== $result ) {
			$cleaned_up += $result;
		}

		// Clean up old completed scans (keep failed and cancelled for longer)
		$scans_table = $this->wpdb->prefix . 'breach_scans';
		$result = $this->wpdb->query( $this->wpdb->prepare(
			"DELETE FROM {$scans_table} WHERE created_at < %s AND status = 'completed'",
			$cutoff_date
		) );
		if ( false !== $result ) {
			$cleaned_up += $result;
		}

		return $cleaned_up;
	}

	/**
	 * Get the current database version.
	 *
	 * @since    1.0.0
	 * @return   string    The database version.
	 */
	public function get_db_version() {
		return $this->db_version;
	}

	/**
	 * Get database migration version.
	 *
	 * @since    1.0.0
	 * @return   string    The current migration version.
	 */
	public function get_migration_version() {
		return get_option( 'wp_breach_db_version', '0.0.0' );
	}

	/**
	 * Update database migration version.
	 *
	 * @since    1.0.0
	 * @param    string   $version    The new version.
	 * @return   bool     True on success, false on failure.
	 */
	public function update_migration_version( $version ) {
		return update_option( 'wp_breach_db_version', $version );
	}

	/**
	 * Load model classes.
	 *
	 * @since    1.0.0
	 * @return   void
	 */
	private function load_models() {
		// Load base model first
		require_once plugin_dir_path( __FILE__ ) . 'database/class-wp-breach-base-model.php';
		
		// Load individual models
		require_once plugin_dir_path( __FILE__ ) . 'database/class-wp-breach-scan-model.php';
		require_once plugin_dir_path( __FILE__ ) . 'database/class-wp-breach-vulnerability-model.php';
		require_once plugin_dir_path( __FILE__ ) . 'database/class-wp-breach-fix-model.php';
		require_once plugin_dir_path( __FILE__ ) . 'database/class-wp-breach-settings-model.php';
		require_once plugin_dir_path( __FILE__ ) . 'database/class-wp-breach-alert-model.php';
	}

	/**
	 * Get scan model instance.
	 *
	 * @since    1.0.0
	 * @return   WP_Breach_Scan_Model    The scan model instance.
	 */
	public function get_scan_model() {
		static $scan_model = null;
		
		if ( $scan_model === null ) {
			$this->load_models();
			$scan_model = new WP_Breach_Scan_Model();
		}
		
		return $scan_model;
	}

	/**
	 * Get vulnerability model instance.
	 *
	 * @since    1.0.0
	 * @return   WP_Breach_Vulnerability_Model    The vulnerability model instance.
	 */
	public function get_vulnerability_model() {
		static $vulnerability_model = null;
		
		if ( $vulnerability_model === null ) {
			$this->load_models();
			$vulnerability_model = new WP_Breach_Vulnerability_Model();
		}
		
		return $vulnerability_model;
	}

	/**
	 * Get fix model instance.
	 *
	 * @since    1.0.0
	 * @return   WP_Breach_Fix_Model    The fix model instance.
	 */
	public function get_fix_model() {
		static $fix_model = null;
		
		if ( $fix_model === null ) {
			$this->load_models();
			$fix_model = new WP_Breach_Fix_Model();
		}
		
		return $fix_model;
	}

	/**
	 * Get settings model instance.
	 *
	 * @since    1.0.0
	 * @return   WP_Breach_Settings_Model    The settings model instance.
	 */
	public function get_settings_model() {
		static $settings_model = null;
		
		if ( $settings_model === null ) {
			$this->load_models();
			$settings_model = new WP_Breach_Settings_Model();
		}
		
		return $settings_model;
	}

	/**
	 * Get alert model instance.
	 *
	 * @since    1.0.0
	 * @return   WP_Breach_Alert_Model    The alert model instance.
	 */
	public function get_alert_model() {
		static $alert_model = null;
		
		if ( $alert_model === null ) {
			$this->load_models();
			$alert_model = new WP_Breach_Alert_Model();
		}
		
		return $alert_model;
	}
}

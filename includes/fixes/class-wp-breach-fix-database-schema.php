<?php

/**
 * Database schema for the automated fix system.
 *
 * This file contains the database table creation and management
 * for the WP-Breach automated fix system.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/fixes
 */

/**
 * The database schema class for automated fixes.
 *
 * Handles creation, updates, and management of database tables
 * required for the automated fix system.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/fixes
 * @author     WP Breach Team
 */
class WP_Breach_Fix_Database_Schema {

    /**
     * Database version for schema management.
     *
     * @since    1.0.0
     * @access   private
     * @var      string    $db_version    Current database schema version.
     */
    private $db_version = '1.0.0';

    /**
     * WordPress database instance.
     *
     * @since    1.0.0
     * @access   private
     * @var      wpdb    $wpdb    WordPress database instance.
     */
    private $wpdb;

    /**
     * Initialize the database schema manager.
     *
     * @since    1.0.0
     */
    public function __construct() {
        global $wpdb;
        $this->wpdb = $wpdb;
    }

    /**
     * Create all required database tables.
     *
     * @since    1.0.0
     * @return   bool    True if all tables created successfully.
     */
    public function create_tables() {
        $tables_created = array();

        try {
            // Create fixes table
            $tables_created['fixes'] = $this->create_fixes_table();

            // Create backups table
            $tables_created['backups'] = $this->create_backups_table();

            // Create fix strategies table
            $tables_created['fix_strategies'] = $this->create_fix_strategies_table();

            // Create fix logs table
            $tables_created['fix_logs'] = $this->create_fix_logs_table();

            // Create manual instructions table
            $tables_created['manual_instructions'] = $this->create_manual_instructions_table();

            // Create fix dependencies table
            $tables_created['fix_dependencies'] = $this->create_fix_dependencies_table();

            // Create fix templates table
            $tables_created['fix_templates'] = $this->create_fix_templates_table();

            // Update database version
            update_option('wp_breach_fix_db_version', $this->db_version);

            // Log successful creation
            error_log('[WP-Breach Fix DB] All tables created successfully');

            return !in_array(false, $tables_created);

        } catch (Exception $e) {
            error_log('[WP-Breach Fix DB] Error creating tables: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Create the fixes table.
     *
     * @since    1.0.0
     * @return   bool    True if table created successfully.
     */
    private function create_fixes_table() {
        $table_name = $this->wpdb->prefix . 'breach_fixes';

        $sql = "CREATE TABLE IF NOT EXISTS {$table_name} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            fix_id varchar(255) NOT NULL,
            vulnerability_id bigint(20) unsigned NOT NULL,
            strategy_type varchar(100) NOT NULL,
            fix_type varchar(100) NOT NULL,
            status enum('pending', 'in_progress', 'completed', 'failed', 'rolled_back') NOT NULL DEFAULT 'pending',
            priority enum('low', 'medium', 'high', 'critical') NOT NULL DEFAULT 'medium',
            affected_component varchar(255) NULL,
            affected_files longtext NULL,
            backup_id varchar(255) NULL,
            actions_taken longtext NULL,
            changes_made longtext NULL,
            rollback_data longtext NULL,
            validation_data longtext NULL,
            safety_assessment longtext NULL,
            error_message text NULL,
            estimated_time int(10) unsigned NULL,
            actual_time int(10) unsigned NULL,
            applied_by varchar(100) NULL,
            created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            started_at datetime NULL,
            completed_at datetime NULL,
            rolled_back_at datetime NULL,
            updated_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY fix_id (fix_id),
            KEY vulnerability_id (vulnerability_id),
            KEY strategy_type (strategy_type),
            KEY fix_type (fix_type),
            KEY status (status),
            KEY priority (priority),
            KEY created_at (created_at),
            KEY backup_id (backup_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";

        return $this->execute_sql($sql, 'breach_fixes');
    }

    /**
     * Create the backups table.
     *
     * @since    1.0.0
     * @return   bool    True if table created successfully.
     */
    private function create_backups_table() {
        $table_name = $this->wpdb->prefix . 'breach_backups';

        $sql = "CREATE TABLE IF NOT EXISTS {$table_name} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            backup_id varchar(255) NOT NULL,
            vulnerability_id bigint(20) unsigned NULL,
            fix_id varchar(255) NULL,
            type enum('full', 'fix_backup', 'files_only', 'database_only') NOT NULL DEFAULT 'fix_backup',
            status enum('creating', 'completed', 'failed', 'corrupted', 'restored') NOT NULL DEFAULT 'creating',
            backup_path varchar(500) NOT NULL,
            size bigint(20) unsigned NOT NULL DEFAULT 0,
            compressed tinyint(1) NOT NULL DEFAULT 0,
            compressed_size bigint(20) unsigned NULL,
            checksum varchar(64) NULL,
            files_count int(10) unsigned NOT NULL DEFAULT 0,
            database_tables_count int(10) unsigned NOT NULL DEFAULT 0,
            metadata longtext NULL,
            verification_status enum('pending', 'verified', 'failed') NOT NULL DEFAULT 'pending',
            verification_date datetime NULL,
            expiry_date datetime NULL,
            created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY backup_id (backup_id),
            KEY vulnerability_id (vulnerability_id),
            KEY fix_id (fix_id),
            KEY type (type),
            KEY status (status),
            KEY created_at (created_at),
            KEY expiry_date (expiry_date)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";

        return $this->execute_sql($sql, 'breach_backups');
    }

    /**
     * Create the fix strategies table.
     *
     * @since    1.0.0
     * @return   bool    True if table created successfully.
     */
    private function create_fix_strategies_table() {
        $table_name = $this->wpdb->prefix . 'breach_fix_strategies';

        $sql = "CREATE TABLE IF NOT EXISTS {$table_name} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            strategy_name varchar(255) NOT NULL,
            strategy_class varchar(255) NOT NULL,
            vulnerability_types longtext NOT NULL,
            capabilities longtext NOT NULL,
            requirements longtext NULL,
            configuration longtext NULL,
            enabled tinyint(1) NOT NULL DEFAULT 1,
            auto_fix_enabled tinyint(1) NOT NULL DEFAULT 1,
            safety_threshold decimal(3,2) NOT NULL DEFAULT 0.70,
            success_rate decimal(5,2) NULL,
            total_fixes int(10) unsigned NOT NULL DEFAULT 0,
            successful_fixes int(10) unsigned NOT NULL DEFAULT 0,
            failed_fixes int(10) unsigned NOT NULL DEFAULT 0,
            average_time int(10) unsigned NULL,
            last_used datetime NULL,
            version varchar(20) NOT NULL DEFAULT '1.0.0',
            created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY strategy_name (strategy_name),
            UNIQUE KEY strategy_class (strategy_class),
            KEY enabled (enabled),
            KEY auto_fix_enabled (auto_fix_enabled),
            KEY success_rate (success_rate)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";

        return $this->execute_sql($sql, 'breach_fix_strategies');
    }

    /**
     * Create the fix logs table.
     *
     * @since    1.0.0
     * @return   bool    True if table created successfully.
     */
    private function create_fix_logs_table() {
        $table_name = $this->wpdb->prefix . 'breach_fix_logs';

        $sql = "CREATE TABLE IF NOT EXISTS {$table_name} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            fix_id varchar(255) NOT NULL,
            log_level enum('debug', 'info', 'warning', 'error', 'critical') NOT NULL DEFAULT 'info',
            operation varchar(255) NOT NULL,
            message text NOT NULL,
            context longtext NULL,
            execution_time decimal(10,4) NULL,
            memory_usage bigint(20) unsigned NULL,
            stack_trace longtext NULL,
            created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY fix_id (fix_id),
            KEY log_level (log_level),
            KEY operation (operation),
            KEY created_at (created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";

        return $this->execute_sql($sql, 'breach_fix_logs');
    }

    /**
     * Create the manual instructions table.
     *
     * @since    1.0.0
     * @return   bool    True if table created successfully.
     */
    private function create_manual_instructions_table() {
        $table_name = $this->wpdb->prefix . 'breach_manual_instructions';

        $sql = "CREATE TABLE IF NOT EXISTS {$table_name} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            instruction_id varchar(255) NOT NULL,
            vulnerability_id bigint(20) unsigned NOT NULL,
            vulnerability_type varchar(100) NOT NULL,
            title varchar(500) NOT NULL,
            difficulty_level enum('beginner', 'intermediate', 'advanced') NOT NULL DEFAULT 'intermediate',
            estimated_time_min int(10) unsigned NOT NULL,
            estimated_time_max int(10) unsigned NOT NULL,
            instructions longtext NOT NULL,
            prerequisites longtext NULL,
            verification_steps longtext NULL,
            troubleshooting longtext NULL,
            rollback_instructions longtext NULL,
            additional_resources longtext NULL,
            expert_support_info longtext NULL,
            generated_by varchar(100) NOT NULL DEFAULT 'system',
            reviewed_by varchar(100) NULL,
            review_status enum('pending', 'approved', 'rejected', 'needs_revision') NOT NULL DEFAULT 'pending',
            review_notes text NULL,
            usage_count int(10) unsigned NOT NULL DEFAULT 0,
            feedback_score decimal(3,2) NULL,
            feedback_count int(10) unsigned NOT NULL DEFAULT 0,
            version varchar(20) NOT NULL DEFAULT '1.0.0',
            created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            reviewed_at datetime NULL,
            PRIMARY KEY (id),
            UNIQUE KEY instruction_id (instruction_id),
            KEY vulnerability_id (vulnerability_id),
            KEY vulnerability_type (vulnerability_type),
            KEY difficulty_level (difficulty_level),
            KEY review_status (review_status),
            KEY usage_count (usage_count),
            KEY feedback_score (feedback_score)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";

        return $this->execute_sql($sql, 'breach_manual_instructions');
    }

    /**
     * Create the fix dependencies table.
     *
     * @since    1.0.0
     * @return   bool    True if table created successfully.
     */
    private function create_fix_dependencies_table() {
        $table_name = $this->wpdb->prefix . 'breach_fix_dependencies';

        $sql = "CREATE TABLE IF NOT EXISTS {$table_name} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            fix_id varchar(255) NOT NULL,
            dependency_type enum('prerequisite', 'conflicts_with', 'requires', 'blocks') NOT NULL,
            dependency_target varchar(255) NOT NULL,
            dependency_target_type enum('fix', 'plugin', 'theme', 'wp_version', 'php_version', 'capability') NOT NULL,
            dependency_condition varchar(500) NULL,
            is_required tinyint(1) NOT NULL DEFAULT 1,
            is_satisfied tinyint(1) NOT NULL DEFAULT 0,
            satisfaction_check_date datetime NULL,
            notes text NULL,
            created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY fix_id (fix_id),
            KEY dependency_type (dependency_type),
            KEY dependency_target (dependency_target),
            KEY dependency_target_type (dependency_target_type),
            KEY is_required (is_required),
            KEY is_satisfied (is_satisfied)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";

        return $this->execute_sql($sql, 'breach_fix_dependencies');
    }

    /**
     * Create the fix templates table.
     *
     * @since    1.0.0
     * @return   bool    True if table created successfully.
     */
    private function create_fix_templates_table() {
        $table_name = $this->wpdb->prefix . 'breach_fix_templates';

        $sql = "CREATE TABLE IF NOT EXISTS {$table_name} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            template_id varchar(255) NOT NULL,
            template_name varchar(255) NOT NULL,
            vulnerability_type varchar(100) NOT NULL,
            template_category enum('automated_fix', 'manual_instruction', 'safety_check', 'rollback') NOT NULL,
            template_content longtext NOT NULL,
            variables longtext NULL,
            conditions longtext NULL,
            enabled tinyint(1) NOT NULL DEFAULT 1,
            priority int(10) unsigned NOT NULL DEFAULT 100,
            usage_count int(10) unsigned NOT NULL DEFAULT 0,
            success_rate decimal(5,2) NULL,
            version varchar(20) NOT NULL DEFAULT '1.0.0',
            created_by varchar(100) NOT NULL DEFAULT 'system',
            reviewed_by varchar(100) NULL,
            review_status enum('pending', 'approved', 'rejected') NOT NULL DEFAULT 'approved',
            created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY template_id (template_id),
            KEY template_name (template_name),
            KEY vulnerability_type (vulnerability_type),
            KEY template_category (template_category),
            KEY enabled (enabled),
            KEY priority (priority),
            KEY review_status (review_status)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";

        return $this->execute_sql($sql, 'breach_fix_templates');
    }

    /**
     * Insert default fix strategies.
     *
     * @since    1.0.0
     * @return   bool    True if strategies inserted successfully.
     */
    public function insert_default_strategies() {
        $strategies = array(
            array(
                'strategy_name' => 'WordPress Core Fix Strategy',
                'strategy_class' => 'WP_Breach_WordPress_Core_Fix_Strategy',
                'vulnerability_types' => wp_json_encode(array('wordpress_core', 'core_vulnerability')),
                'capabilities' => wp_json_encode(array('version_updates', 'security_patches', 'configuration_fixes')),
                'requirements' => wp_json_encode(array('filesystem_access', 'wp_filesystem_api')),
                'configuration' => wp_json_encode(array(
                    'auto_update_enabled' => true,
                    'safety_threshold' => 0.7,
                    'max_version_jump' => 2
                ))
            ),
            array(
                'strategy_name' => 'Plugin Fix Strategy',
                'strategy_class' => 'WP_Breach_Plugin_Fix_Strategy',
                'vulnerability_types' => wp_json_encode(array('plugin_vulnerability', 'plugin_issue')),
                'capabilities' => wp_json_encode(array('plugin_updates', 'plugin_patches', 'plugin_deactivation', 'plugin_quarantine')),
                'requirements' => wp_json_encode(array('plugin_management_capability', 'filesystem_access')),
                'configuration' => wp_json_encode(array(
                    'auto_update_enabled' => true,
                    'auto_deactivation_enabled' => true,
                    'quarantine_enabled' => true
                ))
            ),
            array(
                'strategy_name' => 'Configuration Fix Strategy',
                'strategy_class' => 'WP_Breach_Configuration_Fix_Strategy',
                'vulnerability_types' => wp_json_encode(array('configuration', 'misconfiguration', 'settings_issue')),
                'capabilities' => wp_json_encode(array('wp_config_fixes', 'htaccess_fixes', 'option_updates')),
                'requirements' => wp_json_encode(array('filesystem_access', 'manage_options_capability')),
                'configuration' => wp_json_encode(array(
                    'backup_before_change' => true,
                    'validate_syntax' => true
                ))
            ),
            array(
                'strategy_name' => 'File Permissions Fix Strategy',
                'strategy_class' => 'WP_Breach_File_Permissions_Fix_Strategy',
                'vulnerability_types' => wp_json_encode(array('file_permissions', 'directory_permissions', 'access_control')),
                'capabilities' => wp_json_encode(array('permission_correction', 'ownership_fixes', 'security_hardening')),
                'requirements' => wp_json_encode(array('filesystem_access', 'server_permissions')),
                'configuration' => wp_json_encode(array(
                    'recommended_file_perms' => '644',
                    'recommended_dir_perms' => '755',
                    'strict_mode' => false
                ))
            ),
            array(
                'strategy_name' => 'Code Injection Fix Strategy',
                'strategy_class' => 'WP_Breach_Code_Fix_Strategy',
                'vulnerability_types' => wp_json_encode(array('code_injection', 'sql_injection', 'xss', 'malware')),
                'capabilities' => wp_json_encode(array('code_cleaning', 'malware_removal', 'input_sanitization')),
                'requirements' => wp_json_encode(array('filesystem_access', 'code_analysis_tools')),
                'configuration' => wp_json_encode(array(
                    'quarantine_suspicious_code' => true,
                    'deep_scan_enabled' => true,
                    'manual_review_required' => true
                ))
            )
        );

        $inserted = 0;
        foreach ($strategies as $strategy) {
            $result = $this->wpdb->insert(
                $this->wpdb->prefix . 'breach_fix_strategies',
                $strategy,
                array('%s', '%s', '%s', '%s', '%s', '%s')
            );
            
            if ($result !== false) {
                $inserted++;
            }
        }

        return $inserted === count($strategies);
    }

    /**
     * Insert default fix templates.
     *
     * @since    1.0.0
     * @return   bool    True if templates inserted successfully.
     */
    public function insert_default_templates() {
        $templates = array(
            array(
                'template_id' => 'wp_core_update_manual',
                'template_name' => 'WordPress Core Update Manual Instructions',
                'vulnerability_type' => 'wordpress_core',
                'template_category' => 'manual_instruction',
                'template_content' => wp_json_encode(array(
                    'title' => 'Manual WordPress Core Update',
                    'steps' => array(
                        'Create complete site backup',
                        'Download latest WordPress from wordpress.org',
                        'Replace core files via FTP/hosting panel',
                        'Run /wp-admin/upgrade.php',
                        'Test site functionality'
                    ),
                    'warnings' => array(
                        'Never update directly on live site without backup',
                        'Test in staging environment first'
                    )
                )),
                'variables' => wp_json_encode(array('current_version', 'target_version', 'site_url')),
                'priority' => 100
            ),
            array(
                'template_id' => 'plugin_update_manual',
                'template_name' => 'Plugin Update Manual Instructions',
                'vulnerability_type' => 'plugin_vulnerability',
                'template_category' => 'manual_instruction',
                'template_content' => wp_json_encode(array(
                    'title' => 'Manual Plugin Update',
                    'steps' => array(
                        'Backup website completely',
                        'Deactivate the vulnerable plugin',
                        'Download updated plugin from repository',
                        'Replace plugin files via FTP',
                        'Reactivate and test plugin functionality'
                    ),
                    'warnings' => array(
                        'Check plugin compatibility before update',
                        'Review changelog for breaking changes'
                    )
                )),
                'variables' => wp_json_encode(array('plugin_name', 'current_version', 'target_version')),
                'priority' => 100
            ),
            array(
                'template_id' => 'file_permissions_fix',
                'template_name' => 'File Permissions Fix Template',
                'vulnerability_type' => 'file_permissions',
                'template_category' => 'automated_fix',
                'template_content' => wp_json_encode(array(
                    'actions' => array(
                        array(
                            'type' => 'permission_change',
                            'target' => '{{TARGET_FILES}}',
                            'permissions' => '644',
                            'recursive' => false
                        ),
                        array(
                            'type' => 'permission_change',
                            'target' => '{{TARGET_DIRECTORIES}}',
                            'permissions' => '755',
                            'recursive' => true
                        )
                    ),
                    'validation' => array(
                        'check_file_access',
                        'verify_site_functionality'
                    )
                )),
                'variables' => wp_json_encode(array('target_files', 'target_directories')),
                'priority' => 200
            )
        );

        $inserted = 0;
        foreach ($templates as $template) {
            $result = $this->wpdb->insert(
                $this->wpdb->prefix . 'breach_fix_templates',
                $template,
                array('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%d')
            );
            
            if ($result !== false) {
                $inserted++;
            }
        }

        return $inserted === count($templates);
    }

    /**
     * Execute SQL and handle errors.
     *
     * @since    1.0.0
     * @param    string    $sql         SQL query.
     * @param    string    $table_name  Table name for logging.
     * @return   bool                   True if successful.
     */
    private function execute_sql($sql, $table_name) {
        $result = $this->wpdb->query($sql);
        
        if ($result === false) {
            error_log("[WP-Breach Fix DB] Error creating table {$table_name}: " . $this->wpdb->last_error);
            return false;
        }

        error_log("[WP-Breach Fix DB] Table {$table_name} created successfully");
        return true;
    }

    /**
     * Update database schema to newer version.
     *
     * @since    1.0.0
     * @param    string    $from_version    Current version.
     * @param    string    $to_version      Target version.
     * @return   bool                       True if update successful.
     */
    public function update_schema($from_version, $to_version) {
        // Future version updates would be handled here
        $current_version = get_option('wp_breach_fix_db_version', '0.0.0');
        
        if (version_compare($current_version, $this->db_version, '<')) {
            // Perform any necessary schema updates
            $this->create_tables(); // This will create missing tables
            update_option('wp_breach_fix_db_version', $this->db_version);
            return true;
        }
        
        return false;
    }

    /**
     * Drop all fix system tables (for uninstall).
     *
     * @since    1.0.0
     * @return   bool    True if all tables dropped successfully.
     */
    public function drop_tables() {
        $tables = array(
            'breach_fixes',
            'breach_backups',
            'breach_fix_strategies',
            'breach_fix_logs',
            'breach_manual_instructions',
            'breach_fix_dependencies',
            'breach_fix_templates'
        );

        $dropped = array();
        foreach ($tables as $table) {
            $table_name = $this->wpdb->prefix . $table;
            $sql = "DROP TABLE IF EXISTS {$table_name}";
            $dropped[] = $this->wpdb->query($sql) !== false;
        }

        // Remove database version option
        delete_option('wp_breach_fix_db_version');

        return !in_array(false, $dropped);
    }

    /**
     * Get database schema information.
     *
     * @since    1.0.0
     * @return   array    Schema information.
     */
    public function get_schema_info() {
        $tables = array(
            'breach_fixes',
            'breach_backups',
            'breach_fix_strategies',
            'breach_fix_logs',
            'breach_manual_instructions',
            'breach_fix_dependencies',
            'breach_fix_templates'
        );

        $schema_info = array(
            'version' => get_option('wp_breach_fix_db_version', 'not_installed'),
            'tables' => array()
        );

        foreach ($tables as $table) {
            $table_name = $this->wpdb->prefix . $table;
            $exists = $this->wpdb->get_var("SHOW TABLES LIKE '{$table_name}'") === $table_name;
            
            $schema_info['tables'][$table] = array(
                'exists' => $exists,
                'rows' => 0
            );

            if ($exists) {
                $row_count = $this->wpdb->get_var("SELECT COUNT(*) FROM {$table_name}");
                $schema_info['tables'][$table]['rows'] = (int) $row_count;
            }
        }

        return $schema_info;
    }

    /**
     * Verify database integrity.
     *
     * @since    1.0.0
     * @return   array    Integrity check results.
     */
    public function verify_integrity() {
        $integrity = array(
            'overall_status' => 'healthy',
            'issues' => array(),
            'recommendations' => array()
        );

        $schema_info = $this->get_schema_info();

        // Check if all tables exist
        foreach ($schema_info['tables'] as $table => $info) {
            if (!$info['exists']) {
                $integrity['issues'][] = "Table {$table} is missing";
                $integrity['overall_status'] = 'issues_found';
            }
        }

        // Check for foreign key relationships
        $foreign_key_issues = $this->check_foreign_key_integrity();
        if (!empty($foreign_key_issues)) {
            $integrity['issues'] = array_merge($integrity['issues'], $foreign_key_issues);
            $integrity['overall_status'] = 'issues_found';
        }

        // Check for orphaned records
        $orphaned_records = $this->check_orphaned_records();
        if (!empty($orphaned_records)) {
            $integrity['issues'] = array_merge($integrity['issues'], $orphaned_records);
            $integrity['overall_status'] = 'issues_found';
        }

        // Generate recommendations
        if ($integrity['overall_status'] === 'issues_found') {
            $integrity['recommendations'][] = 'Run database repair using WP-CLI or phpMyAdmin';
            $integrity['recommendations'][] = 'Consider recreating missing tables';
            $integrity['recommendations'][] = 'Clean up orphaned records';
        }

        return $integrity;
    }

    /**
     * Check foreign key integrity.
     *
     * @since    1.0.0
     * @return   array    Foreign key issues.
     */
    private function check_foreign_key_integrity() {
        $issues = array();

        // Check fixes -> vulnerabilities relationship
        $orphaned_fixes = $this->wpdb->get_var("
            SELECT COUNT(*) 
            FROM {$this->wpdb->prefix}breach_fixes f 
            LEFT JOIN {$this->wpdb->prefix}breach_vulnerabilities v ON f.vulnerability_id = v.id 
            WHERE f.vulnerability_id > 0 AND v.id IS NULL
        ");

        if ($orphaned_fixes > 0) {
            $issues[] = "{$orphaned_fixes} fixes reference non-existent vulnerabilities";
        }

        // Check backups -> fixes relationship
        $orphaned_backups = $this->wpdb->get_var("
            SELECT COUNT(*) 
            FROM {$this->wpdb->prefix}breach_backups b 
            LEFT JOIN {$this->wpdb->prefix}breach_fixes f ON b.fix_id = f.fix_id 
            WHERE b.fix_id IS NOT NULL AND b.fix_id != '' AND f.fix_id IS NULL
        ");

        if ($orphaned_backups > 0) {
            $issues[] = "{$orphaned_backups} backups reference non-existent fixes";
        }

        return $issues;
    }

    /**
     * Check for orphaned records.
     *
     * @since    1.0.0
     * @return   array    Orphaned record issues.
     */
    private function check_orphaned_records() {
        $issues = array();

        // Check for old logs without corresponding fixes
        $old_logs = $this->wpdb->get_var("
            SELECT COUNT(*) 
            FROM {$this->wpdb->prefix}breach_fix_logs l 
            LEFT JOIN {$this->wpdb->prefix}breach_fixes f ON l.fix_id = f.fix_id 
            WHERE f.fix_id IS NULL
        ");

        if ($old_logs > 0) {
            $issues[] = "{$old_logs} log entries reference deleted fixes";
        }

        // Check for expired backups
        $expired_backups = $this->wpdb->get_var("
            SELECT COUNT(*) 
            FROM {$this->wpdb->prefix}breach_backups 
            WHERE expiry_date IS NOT NULL AND expiry_date < NOW()
        ");

        if ($expired_backups > 0) {
            $issues[] = "{$expired_backups} expired backups should be cleaned up";
        }

        return $issues;
    }

    /**
     * Clean up orphaned and expired records.
     *
     * @since    1.0.0
     * @return   array    Cleanup results.
     */
    public function cleanup_database() {
        $cleanup_results = array(
            'logs_cleaned' => 0,
            'backups_cleaned' => 0,
            'dependencies_cleaned' => 0,
            'total_space_freed' => 0
        );

        // Clean orphaned logs (older than 30 days)
        $logs_deleted = $this->wpdb->query("
            DELETE l FROM {$this->wpdb->prefix}breach_fix_logs l 
            LEFT JOIN {$this->wpdb->prefix}breach_fixes f ON l.fix_id = f.fix_id 
            WHERE f.fix_id IS NULL OR l.created_at < DATE_SUB(NOW(), INTERVAL 30 DAY)
        ");
        $cleanup_results['logs_cleaned'] = (int) $logs_deleted;

        // Clean expired backups
        $expired_backups = $this->wpdb->get_results("
            SELECT backup_id, backup_path 
            FROM {$this->wpdb->prefix}breach_backups 
            WHERE expiry_date IS NOT NULL AND expiry_date < NOW()
        ");

        foreach ($expired_backups as $backup) {
            // Delete backup files
            if (!empty($backup->backup_path) && file_exists($backup->backup_path)) {
                $size = filesize($backup->backup_path);
                if (unlink($backup->backup_path)) {
                    $cleanup_results['total_space_freed'] += $size;
                }
            }
        }

        $backups_deleted = $this->wpdb->query("
            DELETE FROM {$this->wpdb->prefix}breach_backups 
            WHERE expiry_date IS NOT NULL AND expiry_date < NOW()
        ");
        $cleanup_results['backups_cleaned'] = (int) $backups_deleted;

        // Clean orphaned dependencies
        $dependencies_deleted = $this->wpdb->query("
            DELETE d FROM {$this->wpdb->prefix}breach_fix_dependencies d 
            LEFT JOIN {$this->wpdb->prefix}breach_fixes f ON d.fix_id = f.fix_id 
            WHERE f.fix_id IS NULL
        ");
        $cleanup_results['dependencies_cleaned'] = (int) $dependencies_deleted;

        return $cleanup_results;
    }
}

<?php

/**
 * The backup and rollback manager.
 *
 * This class handles creating, managing, and restoring backups for the
 * automated fix system with comprehensive validation and safety checks.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/fixes
 */

/**
 * The backup manager class.
 *
 * Provides comprehensive backup functionality for the automated fix system
 * including file backups, database snapshots, and configuration preservation.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/fixes
 * @author     WP Breach Team
 */
class WP_Breach_Backup_Manager {

    /**
     * Backup storage directory.
     *
     * @since    1.0.0
     * @access   private
     * @var      string    $backup_dir    Backup storage directory.
     */
    private $backup_dir;

    /**
     * Backup configuration.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $config    Backup configuration settings.
     */
    private $config;

    /**
     * File system handler.
     *
     * @since    1.0.0
     * @access   private
     * @var      WP_Filesystem_Base    $filesystem    WordPress filesystem.
     */
    private $filesystem;

    /**
     * Initialize the backup manager.
     *
     * @since    1.0.0
     * @param    array    $config    Backup configuration.
     */
    public function __construct($config = array()) {
        $this->config = wp_parse_args($config, $this->get_default_config());
        $this->initialize_filesystem();
        $this->setup_backup_directory();
    }

    /**
     * Get default backup configuration.
     *
     * @since    1.0.0
     * @return   array    Default configuration.
     */
    private function get_default_config() {
        return array(
            'max_backups' => 50,
            'retention_days' => 30,
            'compression_enabled' => true,
            'include_database' => true,
            'include_uploads' => false,
            'backup_timeout' => 600,
            'verify_backups' => true,
            'backup_prefix' => 'wp-breach-fix-',
            'chunk_size' => 1048576, // 1MB chunks
        );
    }

    /**
     * Initialize WordPress filesystem.
     *
     * @since    1.0.0
     */
    private function initialize_filesystem() {
        if (!function_exists('WP_Filesystem')) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
        
        WP_Filesystem();
        global $wp_filesystem;
        $this->filesystem = $wp_filesystem;
    }

    /**
     * Setup backup directory.
     *
     * @since    1.0.0
     */
    private function setup_backup_directory() {
        $upload_dir = wp_upload_dir();
        $this->backup_dir = $upload_dir['basedir'] . '/wp-breach-backups';
        
        if (!$this->filesystem->is_dir($this->backup_dir)) {
            $this->filesystem->mkdir($this->backup_dir, 0755, true);
        }

        // Create .htaccess to protect backup directory
        $htaccess_content = "Order deny,allow\nDeny from all\n";
        $this->filesystem->put_contents($this->backup_dir . '/.htaccess', $htaccess_content);

        // Create index.php to prevent directory listing
        $index_content = "<?php\n// Silence is golden.\n";
        $this->filesystem->put_contents($this->backup_dir . '/index.php', $index_content);
    }

    /**
     * Create a backup for a fix operation.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability data requiring fix.
     * @return   array                     Backup result with ID and details.
     */
    public function create_fix_backup($vulnerability) {
        $backup_id = $this->generate_backup_id();
        $backup_path = $this->backup_dir . '/' . $backup_id;

        try {
            // Create backup directory
            if (!$this->filesystem->mkdir($backup_path, 0755)) {
                throw new Exception('Failed to create backup directory');
            }

            $backup_data = array(
                'id' => $backup_id,
                'vulnerability_id' => $vulnerability['id'] ?? 0,
                'timestamp' => current_time('mysql'),
                'type' => 'fix_backup',
                'status' => 'creating',
                'files' => array(),
                'database_tables' => array(),
                'size' => 0,
                'checksum' => null
            );

            // Determine what needs to be backed up based on vulnerability
            $backup_scope = $this->determine_backup_scope($vulnerability);

            // Backup files
            if (!empty($backup_scope['files'])) {
                $file_backup_result = $this->backup_files($backup_scope['files'], $backup_path . '/files');
                $backup_data['files'] = $file_backup_result['files'];
                $backup_data['size'] += $file_backup_result['size'];
            }

            // Backup database tables
            if (!empty($backup_scope['database_tables']) && $this->config['include_database']) {
                $db_backup_result = $this->backup_database_tables($backup_scope['database_tables'], $backup_path . '/database');
                $backup_data['database_tables'] = $db_backup_result['tables'];
                $backup_data['size'] += $db_backup_result['size'];
            }

            // Backup configuration
            $config_backup_result = $this->backup_configuration($vulnerability, $backup_path . '/config');
            $backup_data['configuration'] = $config_backup_result;

            // Create manifest
            $manifest_result = $this->create_backup_manifest($backup_data, $backup_path);
            $backup_data['checksum'] = $manifest_result['checksum'];

            // Compress backup if enabled
            if ($this->config['compression_enabled']) {
                $compression_result = $this->compress_backup($backup_path);
                if ($compression_result['success']) {
                    $backup_data['compressed'] = true;
                    $backup_data['compressed_size'] = $compression_result['size'];
                }
            }

            // Verify backup integrity
            if ($this->config['verify_backups']) {
                $verification_result = $this->verify_backup($backup_path, $backup_data);
                if (!$verification_result['success']) {
                    throw new Exception('Backup verification failed: ' . $verification_result['error']);
                }
            }

            $backup_data['status'] = 'completed';
            $this->save_backup_metadata($backup_data);

            // Clean up old backups
            $this->cleanup_old_backups();

            return array(
                'success' => true,
                'backup_id' => $backup_id,
                'backup_data' => $backup_data
            );

        } catch (Exception $e) {
            // Clean up failed backup
            $this->filesystem->rmdir($backup_path, true);
            
            return array(
                'success' => false,
                'error' => $e->getMessage(),
                'backup_id' => $backup_id
            );
        }
    }

    /**
     * Determine what needs to be backed up.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability data.
     * @return   array                     Backup scope.
     */
    private function determine_backup_scope($vulnerability) {
        $scope = array(
            'files' => array(),
            'database_tables' => array(),
            'configuration' => array()
        );

        $vulnerability_type = $vulnerability['type'] ?? '';
        $affected_files = $vulnerability['affected_files'] ?? array();
        $affected_plugins = $vulnerability['affected_plugins'] ?? array();
        $affected_themes = $vulnerability['affected_themes'] ?? array();

        // Add affected files
        if (!empty($affected_files)) {
            foreach ($affected_files as $file) {
                if ($this->filesystem->exists($file)) {
                    $scope['files'][] = $file;
                }
            }
        }

        // Add plugin files
        if (!empty($affected_plugins)) {
            foreach ($affected_plugins as $plugin) {
                $plugin_dir = WP_PLUGIN_DIR . '/' . dirname($plugin);
                if ($this->filesystem->is_dir($plugin_dir)) {
                    $scope['files'][] = $plugin_dir;
                }
            }
        }

        // Add theme files
        if (!empty($affected_themes)) {
            foreach ($affected_themes as $theme) {
                $theme_dir = get_theme_root() . '/' . $theme;
                if ($this->filesystem->is_dir($theme_dir)) {
                    $scope['files'][] = $theme_dir;
                }
            }
        }

        // Add WordPress core files if needed
        if ($vulnerability_type === 'wordpress_core') {
            $scope['files'][] = ABSPATH . 'wp-includes';
            $scope['files'][] = ABSPATH . 'wp-admin';
            $scope['files'][] = ABSPATH . 'wp-config.php';
            $scope['files'][] = ABSPATH . '.htaccess';
        }

        // Add database tables based on vulnerability type
        if (in_array($vulnerability_type, array('sql_injection', 'privilege_escalation', 'configuration'))) {
            global $wpdb;
            $scope['database_tables'] = array(
                $wpdb->options,
                $wpdb->users,
                $wpdb->usermeta
            );
        }

        return $scope;
    }

    /**
     * Backup files.
     *
     * @since    1.0.0
     * @param    array     $files         Files to backup.
     * @param    string    $backup_path   Backup destination.
     * @return   array                    Backup result.
     */
    private function backup_files($files, $backup_path) {
        if (!$this->filesystem->mkdir($backup_path, 0755, true)) {
            throw new Exception('Failed to create file backup directory');
        }

        $backed_up_files = array();
        $total_size = 0;

        foreach ($files as $file) {
            if (!$this->filesystem->exists($file)) {
                continue;
            }

            try {
                if ($this->filesystem->is_file($file)) {
                    $result = $this->backup_single_file($file, $backup_path);
                } else {
                    $result = $this->backup_directory($file, $backup_path);
                }

                $backed_up_files[] = array(
                    'original_path' => $file,
                    'backup_path' => $result['backup_path'],
                    'size' => $result['size'],
                    'checksum' => $result['checksum']
                );

                $total_size += $result['size'];

            } catch (Exception $e) {
                // Log error but continue with other files
                error_log("[WP-Breach Backup] Failed to backup file {$file}: " . $e->getMessage());
            }
        }

        return array(
            'files' => $backed_up_files,
            'size' => $total_size
        );
    }

    /**
     * Backup a single file.
     *
     * @since    1.0.0
     * @param    string    $source_file   Source file path.
     * @param    string    $backup_dir    Backup directory.
     * @return   array                    Backup result.
     */
    private function backup_single_file($source_file, $backup_dir) {
        $relative_path = str_replace(ABSPATH, '', $source_file);
        $backup_file = $backup_dir . '/' . $relative_path;
        $backup_file_dir = dirname($backup_file);

        // Create directory structure
        if (!$this->filesystem->is_dir($backup_file_dir)) {
            $this->filesystem->mkdir($backup_file_dir, 0755, true);
        }

        // Copy file
        if (!$this->filesystem->copy($source_file, $backup_file)) {
            throw new Exception("Failed to backup file: {$source_file}");
        }

        $size = $this->filesystem->size($backup_file);
        $checksum = md5_file($source_file);

        return array(
            'backup_path' => $backup_file,
            'size' => $size,
            'checksum' => $checksum
        );
    }

    /**
     * Backup a directory recursively.
     *
     * @since    1.0.0
     * @param    string    $source_dir    Source directory.
     * @param    string    $backup_dir    Backup directory.
     * @return   array                    Backup result.
     */
    private function backup_directory($source_dir, $backup_dir) {
        $relative_path = str_replace(ABSPATH, '', $source_dir);
        $backup_path = $backup_dir . '/' . $relative_path;

        if (!$this->filesystem->mkdir($backup_path, 0755, true)) {
            throw new Exception("Failed to create backup directory: {$backup_path}");
        }

        $total_size = 0;
        $checksum_data = array();

        $files = $this->filesystem->dirlist($source_dir, false, true);
        if ($files) {
            foreach ($files as $file) {
                $source_file = $source_dir . '/' . $file['name'];
                
                if ($file['type'] === 'f') {
                    $result = $this->backup_single_file($source_file, $backup_dir);
                    $total_size += $result['size'];
                    $checksum_data[] = $result['checksum'];
                } elseif ($file['type'] === 'd') {
                    $result = $this->backup_directory($source_file, $backup_dir);
                    $total_size += $result['size'];
                    $checksum_data[] = $result['checksum'];
                }
            }
        }

        return array(
            'backup_path' => $backup_path,
            'size' => $total_size,
            'checksum' => md5(implode('', $checksum_data))
        );
    }

    /**
     * Backup database tables.
     *
     * @since    1.0.0
     * @param    array     $tables        Tables to backup.
     * @param    string    $backup_path   Backup destination.
     * @return   array                    Backup result.
     */
    private function backup_database_tables($tables, $backup_path) {
        if (!$this->filesystem->mkdir($backup_path, 0755, true)) {
            throw new Exception('Failed to create database backup directory');
        }

        global $wpdb;
        $backed_up_tables = array();
        $total_size = 0;

        foreach ($tables as $table) {
            try {
                $sql_file = $backup_path . '/' . $table . '.sql';
                $sql_content = $this->export_table_sql($table);
                
                if (!$this->filesystem->put_contents($sql_file, $sql_content)) {
                    throw new Exception("Failed to write SQL backup for table: {$table}");
                }

                $size = $this->filesystem->size($sql_file);
                $total_size += $size;

                $backed_up_tables[] = array(
                    'table_name' => $table,
                    'backup_file' => $sql_file,
                    'size' => $size,
                    'row_count' => $wpdb->get_var("SELECT COUNT(*) FROM {$table}")
                );

            } catch (Exception $e) {
                error_log("[WP-Breach Backup] Failed to backup table {$table}: " . $e->getMessage());
            }
        }

        return array(
            'tables' => $backed_up_tables,
            'size' => $total_size
        );
    }

    /**
     * Export table structure and data as SQL.
     *
     * @since    1.0.0
     * @param    string    $table    Table name.
     * @return   string             SQL content.
     */
    private function export_table_sql($table) {
        global $wpdb;

        $sql = '';

        // Get table structure
        $create_table = $wpdb->get_row("SHOW CREATE TABLE {$table}", ARRAY_N);
        if ($create_table) {
            $sql .= "DROP TABLE IF EXISTS `{$table}`;\n";
            $sql .= $create_table[1] . ";\n\n";
        }

        // Get table data
        $rows = $wpdb->get_results("SELECT * FROM {$table}", ARRAY_A);
        if ($rows) {
            $sql .= "INSERT INTO `{$table}` VALUES\n";
            $values = array();
            
            foreach ($rows as $row) {
                $escaped_values = array();
                foreach ($row as $value) {
                    if ($value === null) {
                        $escaped_values[] = 'NULL';
                    } else {
                        $escaped_values[] = "'" . $wpdb->_escape($value) . "'";
                    }
                }
                $values[] = '(' . implode(',', $escaped_values) . ')';
            }
            
            $sql .= implode(",\n", $values) . ";\n\n";
        }

        return $sql;
    }

    /**
     * Backup configuration settings.
     *
     * @since    1.0.0
     * @param    array     $vulnerability    Vulnerability data.
     * @param    string    $backup_path      Backup destination.
     * @return   array                       Configuration backup result.
     */
    private function backup_configuration($vulnerability, $backup_path) {
        if (!$this->filesystem->mkdir($backup_path, 0755, true)) {
            throw new Exception('Failed to create configuration backup directory');
        }

        $config_data = array();

        // WordPress configuration
        $config_data['wordpress'] = array(
            'wp_version' => get_bloginfo('version'),
            'php_version' => PHP_VERSION,
            'mysql_version' => $this->get_mysql_version(),
            'active_plugins' => get_option('active_plugins'),
            'active_theme' => get_option('stylesheet'),
            'wp_debug' => defined('WP_DEBUG') ? WP_DEBUG : false,
            'wp_debug_log' => defined('WP_DEBUG_LOG') ? WP_DEBUG_LOG : false
        );

        // Security-related options
        $security_options = array(
            'users_can_register',
            'default_role',
            'use_ssl',
            'force_ssl_admin',
            'disallow_file_edit',
            'disallow_file_mods'
        );

        $config_data['security_settings'] = array();
        foreach ($security_options as $option) {
            $config_data['security_settings'][$option] = get_option($option);
        }

        // File permissions
        $important_files = array(
            ABSPATH . 'wp-config.php',
            ABSPATH . '.htaccess',
            ABSPATH . 'index.php'
        );

        $config_data['file_permissions'] = array();
        foreach ($important_files as $file) {
            if ($this->filesystem->exists($file)) {
                $config_data['file_permissions'][$file] = substr(sprintf('%o', fileperms($file)), -4);
            }
        }

        // Save configuration
        $config_file = $backup_path . '/configuration.json';
        $json_content = wp_json_encode($config_data, JSON_PRETTY_PRINT);
        
        if (!$this->filesystem->put_contents($config_file, $json_content)) {
            throw new Exception('Failed to save configuration backup');
        }

        return array(
            'config_file' => $config_file,
            'size' => $this->filesystem->size($config_file),
            'data' => $config_data
        );
    }

    /**
     * Create backup manifest.
     *
     * @since    1.0.0
     * @param    array     $backup_data    Backup data.
     * @param    string    $backup_path    Backup path.
     * @return   array                     Manifest result.
     */
    private function create_backup_manifest($backup_data, $backup_path) {
        $manifest = array(
            'backup_id' => $backup_data['id'],
            'created_at' => $backup_data['timestamp'],
            'wp_breach_version' => WP_BREACH_VERSION,
            'wordpress_version' => get_bloginfo('version'),
            'backup_type' => $backup_data['type'],
            'vulnerability_id' => $backup_data['vulnerability_id'],
            'files_count' => count($backup_data['files']),
            'database_tables_count' => count($backup_data['database_tables']),
            'total_size' => $backup_data['size'],
            'checksums' => array()
        );

        // Calculate overall checksum
        $checksum_parts = array();
        
        // Add file checksums
        foreach ($backup_data['files'] as $file) {
            $checksum_parts[] = $file['checksum'];
            $manifest['checksums']['files'][] = array(
                'path' => $file['original_path'],
                'checksum' => $file['checksum']
            );
        }

        // Add database checksums
        foreach ($backup_data['database_tables'] as $table) {
            $table_checksum = md5_file($table['backup_file']);
            $checksum_parts[] = $table_checksum;
            $manifest['checksums']['database'][] = array(
                'table' => $table['table_name'],
                'checksum' => $table_checksum
            );
        }

        $manifest['overall_checksum'] = md5(implode('', $checksum_parts));

        // Save manifest
        $manifest_file = $backup_path . '/manifest.json';
        $json_content = wp_json_encode($manifest, JSON_PRETTY_PRINT);
        
        if (!$this->filesystem->put_contents($manifest_file, $json_content)) {
            throw new Exception('Failed to create backup manifest');
        }

        return array(
            'manifest_file' => $manifest_file,
            'checksum' => $manifest['overall_checksum']
        );
    }

    /**
     * Verify backup integrity.
     *
     * @since    1.0.0
     * @param    string    $backup_path    Backup path.
     * @param    array     $backup_data    Backup data.
     * @return   array                     Verification result.
     */
    private function verify_backup($backup_path, $backup_data) {
        try {
            $manifest_file = $backup_path . '/manifest.json';
            if (!$this->filesystem->exists($manifest_file)) {
                throw new Exception('Backup manifest not found');
            }

            $manifest_content = $this->filesystem->get_contents($manifest_file);
            $manifest = json_decode($manifest_content, true);

            if (!$manifest) {
                throw new Exception('Invalid backup manifest');
            }

            // Verify files exist and checksums match
            foreach ($backup_data['files'] as $file) {
                if (!$this->filesystem->exists($file['backup_path'])) {
                    throw new Exception("Backup file missing: {$file['backup_path']}");
                }

                $current_checksum = md5_file($file['backup_path']);
                if ($current_checksum !== $file['checksum']) {
                    throw new Exception("Checksum mismatch for: {$file['backup_path']}");
                }
            }

            // Verify database backups
            foreach ($backup_data['database_tables'] as $table) {
                if (!$this->filesystem->exists($table['backup_file'])) {
                    throw new Exception("Database backup missing: {$table['backup_file']}");
                }
            }

            return array('success' => true);

        } catch (Exception $e) {
            return array(
                'success' => false,
                'error' => $e->getMessage()
            );
        }
    }

    /**
     * Compress backup directory.
     *
     * @since    1.0.0
     * @param    string    $backup_path    Backup path.
     * @return   array                     Compression result.
     */
    private function compress_backup($backup_path) {
        if (!class_exists('ZipArchive')) {
            return array(
                'success' => false,
                'error' => 'ZipArchive not available'
            );
        }

        $zip_file = $backup_path . '.zip';
        $zip = new ZipArchive();

        if ($zip->open($zip_file, ZipArchive::CREATE) !== TRUE) {
            return array(
                'success' => false,
                'error' => 'Cannot create zip file'
            );
        }

        $this->add_directory_to_zip($zip, $backup_path, basename($backup_path));
        $zip->close();

        // Remove original directory
        $this->filesystem->rmdir($backup_path, true);

        return array(
            'success' => true,
            'zip_file' => $zip_file,
            'size' => filesize($zip_file)
        );
    }

    /**
     * Add directory to zip recursively.
     *
     * @since    1.0.0
     * @param    ZipArchive    $zip           Zip archive.
     * @param    string        $dir_path      Directory path.
     * @param    string        $zip_path      Path in zip.
     */
    private function add_directory_to_zip($zip, $dir_path, $zip_path) {
        $files = $this->filesystem->dirlist($dir_path, false, true);
        
        if ($files) {
            foreach ($files as $file) {
                $file_path = $dir_path . '/' . $file['name'];
                $file_zip_path = $zip_path . '/' . $file['name'];

                if ($file['type'] === 'f') {
                    $zip->addFile($file_path, $file_zip_path);
                } elseif ($file['type'] === 'd') {
                    $zip->addEmptyDir($file_zip_path);
                    $this->add_directory_to_zip($zip, $file_path, $file_zip_path);
                }
            }
        }
    }

    /**
     * Restore from backup.
     *
     * @since    1.0.0
     * @param    string    $backup_id    Backup ID.
     * @return   array                   Restore result.
     */
    public function restore_from_backup($backup_id) {
        try {
            $backup_data = $this->get_backup_data($backup_id);
            if (!$backup_data) {
                throw new Exception('Backup data not found');
            }

            $backup_path = $this->backup_dir . '/' . $backup_id;
            
            // Handle compressed backups
            if ($backup_data['compressed'] ?? false) {
                $zip_file = $backup_path . '.zip';
                if (!$this->filesystem->exists($zip_file)) {
                    throw new Exception('Compressed backup file not found');
                }
                
                $this->extract_backup($zip_file, $backup_path);
            }

            if (!$this->filesystem->is_dir($backup_path)) {
                throw new Exception('Backup directory not found');
            }

            // Restore files
            if (isset($backup_data['files']) && !empty($backup_data['files'])) {
                $this->restore_files($backup_data['files'], $backup_path);
            }

            // Restore database
            if (isset($backup_data['database_tables']) && !empty($backup_data['database_tables'])) {
                $this->restore_database_tables($backup_data['database_tables'], $backup_path);
            }

            // Restore configuration
            if (isset($backup_data['configuration'])) {
                $this->restore_configuration($backup_data['configuration'], $backup_path);
            }

            return array(
                'success' => true,
                'restored_files' => count($backup_data['files'] ?? array()),
                'restored_tables' => count($backup_data['database_tables'] ?? array())
            );

        } catch (Exception $e) {
            return array(
                'success' => false,
                'error' => $e->getMessage()
            );
        }
    }

    /**
     * Restore files from backup.
     *
     * @since    1.0.0
     * @param    array     $files          Files to restore.
     * @param    string    $backup_path    Backup path.
     */
    private function restore_files($files, $backup_path) {
        $files_dir = $backup_path . '/files';
        
        foreach ($files as $file) {
            $source_file = $file['backup_path'];
            $target_file = $file['original_path'];
            
            if (!$this->filesystem->exists($source_file)) {
                continue;
            }

            // Create target directory if needed
            $target_dir = dirname($target_file);
            if (!$this->filesystem->is_dir($target_dir)) {
                $this->filesystem->mkdir($target_dir, 0755, true);
            }

            // Restore file
            if (!$this->filesystem->copy($source_file, $target_file)) {
                throw new Exception("Failed to restore file: {$target_file}");
            }
        }
    }

    /**
     * Restore database tables from backup.
     *
     * @since    1.0.0
     * @param    array     $tables         Tables to restore.
     * @param    string    $backup_path    Backup path.
     */
    private function restore_database_tables($tables, $backup_path) {
        global $wpdb;
        $db_dir = $backup_path . '/database';
        
        foreach ($tables as $table) {
            $sql_file = $table['backup_file'];
            
            if (!$this->filesystem->exists($sql_file)) {
                continue;
            }

            $sql_content = $this->filesystem->get_contents($sql_file);
            if (!$sql_content) {
                continue;
            }

            // Execute SQL
            $queries = explode(';', $sql_content);
            foreach ($queries as $query) {
                $query = trim($query);
                if (!empty($query)) {
                    $wpdb->query($query);
                }
            }
        }
    }

    /**
     * Restore configuration from backup.
     *
     * @since    1.0.0
     * @param    array     $config_data    Configuration data.
     * @param    string    $backup_path    Backup path.
     */
    private function restore_configuration($config_data, $backup_path) {
        $config_file = $backup_path . '/config/configuration.json';
        
        if (!$this->filesystem->exists($config_file)) {
            return;
        }

        $config_content = $this->filesystem->get_contents($config_file);
        $config = json_decode($config_content, true);

        if (!$config) {
            return;
        }

        // Restore security settings
        if (isset($config['security_settings'])) {
            foreach ($config['security_settings'] as $option => $value) {
                update_option($option, $value);
            }
        }

        // Restore file permissions
        if (isset($config['file_permissions'])) {
            foreach ($config['file_permissions'] as $file => $permissions) {
                if ($this->filesystem->exists($file)) {
                    chmod($file, octdec($permissions));
                }
            }
        }
    }

    /**
     * Generate unique backup ID.
     *
     * @since    1.0.0
     * @return   string    Backup ID.
     */
    private function generate_backup_id() {
        return $this->config['backup_prefix'] . date('Y-m-d-H-i-s') . '-' . wp_generate_password(8, false);
    }

    /**
     * Save backup metadata.
     *
     * @since    1.0.0
     * @param    array    $backup_data    Backup data.
     */
    private function save_backup_metadata($backup_data) {
        global $wpdb;
        
        $wpdb->insert(
            "{$wpdb->prefix}breach_backups",
            array(
                'backup_id' => $backup_data['id'],
                'vulnerability_id' => $backup_data['vulnerability_id'],
                'type' => $backup_data['type'],
                'status' => $backup_data['status'],
                'size' => $backup_data['size'],
                'checksum' => $backup_data['checksum'],
                'metadata' => wp_json_encode($backup_data),
                'created_at' => $backup_data['timestamp']
            ),
            array('%s', '%d', '%s', '%s', '%d', '%s', '%s', '%s')
        );
    }

    /**
     * Get backup data.
     *
     * @since    1.0.0
     * @param    string    $backup_id    Backup ID.
     * @return   array|null              Backup data or null.
     */
    public function get_backup_data($backup_id) {
        global $wpdb;
        
        $row = $wpdb->get_row(
            $wpdb->prepare(
                "SELECT * FROM {$wpdb->prefix}breach_backups WHERE backup_id = %s",
                $backup_id
            ),
            ARRAY_A
        );

        if (!$row) {
            return null;
        }

        $metadata = json_decode($row['metadata'], true);
        return $metadata ?: $row;
    }

    /**
     * Clean up old backups.
     *
     * @since    1.0.0
     */
    private function cleanup_old_backups() {
        global $wpdb;

        // Remove old backups by count
        $old_backups = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT backup_id FROM {$wpdb->prefix}breach_backups 
                ORDER BY created_at DESC LIMIT %d, 999999",
                $this->config['max_backups']
            ),
            ARRAY_A
        );

        foreach ($old_backups as $backup) {
            $this->delete_backup($backup['backup_id']);
        }

        // Remove old backups by age
        $cutoff_date = date('Y-m-d H:i:s', strtotime("-{$this->config['retention_days']} days"));
        $expired_backups = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT backup_id FROM {$wpdb->prefix}breach_backups 
                WHERE created_at < %s",
                $cutoff_date
            ),
            ARRAY_A
        );

        foreach ($expired_backups as $backup) {
            $this->delete_backup($backup['backup_id']);
        }
    }

    /**
     * Delete a backup.
     *
     * @since    1.0.0
     * @param    string    $backup_id    Backup ID.
     * @return   bool                    Deletion success.
     */
    public function delete_backup($backup_id) {
        try {
            global $wpdb;

            // Remove backup files
            $backup_path = $this->backup_dir . '/' . $backup_id;
            if ($this->filesystem->is_dir($backup_path)) {
                $this->filesystem->rmdir($backup_path, true);
            }

            // Remove compressed backup
            $zip_file = $backup_path . '.zip';
            if ($this->filesystem->exists($zip_file)) {
                $this->filesystem->delete($zip_file);
            }

            // Remove from database
            $wpdb->delete(
                "{$wpdb->prefix}breach_backups",
                array('backup_id' => $backup_id),
                array('%s')
            );

            return true;

        } catch (Exception $e) {
            error_log("[WP-Breach Backup] Failed to delete backup {$backup_id}: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Get MySQL version.
     *
     * @since    1.0.0
     * @return   string    MySQL version.
     */
    private function get_mysql_version() {
        global $wpdb;
        return $wpdb->get_var('SELECT VERSION()');
    }

    /**
     * Extract compressed backup.
     *
     * @since    1.0.0
     * @param    string    $zip_file      Zip file path.
     * @param    string    $extract_path  Extract destination.
     * @return   bool                     Extraction success.
     */
    private function extract_backup($zip_file, $extract_path) {
        if (!class_exists('ZipArchive')) {
            throw new Exception('ZipArchive not available for extraction');
        }

        $zip = new ZipArchive();
        
        if ($zip->open($zip_file) !== TRUE) {
            throw new Exception('Cannot open zip file for extraction');
        }

        if (!$zip->extractTo(dirname($extract_path))) {
            $zip->close();
            throw new Exception('Failed to extract backup');
        }

        $zip->close();
        return true;
    }

    /**
     * Get backup success rate.
     *
     * @since    1.0.0
     * @return   float    Success rate as percentage.
     */
    public function get_success_rate() {
        global $wpdb;

        $total = $wpdb->get_var(
            "SELECT COUNT(*) FROM {$wpdb->prefix}breach_backups"
        );

        if ($total == 0) {
            return 100.0;
        }

        $successful = $wpdb->get_var(
            "SELECT COUNT(*) FROM {$wpdb->prefix}breach_backups WHERE status = 'completed'"
        );

        return ($successful / $total) * 100;
    }
}

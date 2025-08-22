<?php

/**
 * File Integrity Monitor for WP-Breach.
 *
 * This class handles real-time file integrity monitoring, detecting unauthorized
 * changes to WordPress core files, plugins, themes, and other critical files.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/monitoring
 */

/**
 * The file integrity monitoring class.
 *
 * Monitors file system changes and detects unauthorized modifications,
 * additions, or deletions in critical WordPress files.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/monitoring
 * @author     WP Breach Team
 */
class WP_Breach_File_Monitor {

    /**
     * Monitoring configuration.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $config    File monitoring configuration.
     */
    private $config;

    /**
     * Database connection.
     *
     * @since    1.0.0
     * @access   private
     * @var      WP_Breach_Database    $database    Database instance.
     */
    private $database;

    /**
     * File baselines cache.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $baselines    Cached file baselines.
     */
    private $baselines;

    /**
     * Monitored file patterns.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $monitored_patterns    File patterns to monitor.
     */
    private $monitored_patterns;

    /**
     * Whitelist manager instance.
     *
     * @since    1.0.0
     * @access   private
     * @var      WP_Breach_Whitelist_Manager    $whitelist_manager    Whitelist manager.
     */
    private $whitelist_manager;

    /**
     * Initialize the file monitor.
     *
     * @since    1.0.0
     */
    public function __construct() {
        $this->setup_config();
        $this->database = new WP_Breach_Database();
        $this->whitelist_manager = new WP_Breach_Whitelist_Manager();
        $this->baselines = array();
        $this->setup_monitored_patterns();
        
        // Register hooks
        $this->register_hooks();
        
        // Schedule monitoring tasks
        $this->schedule_monitoring();
    }

    /**
     * Setup file monitoring configuration.
     *
     * @since    1.0.0
     * @access   private
     */
    private function setup_config() {
        $this->config = array(
            'monitoring_interval' => 300, // 5 minutes
            'hash_algorithm' => 'sha256',
            'deep_scan_interval' => 3600, // 1 hour
            'baseline_retention' => 30 * DAY_IN_SECONDS,
            'change_retention' => 90 * DAY_IN_SECONDS,
            'max_file_size' => 50 * 1024 * 1024, // 50MB
            'excluded_extensions' => array('log', 'tmp', 'cache', 'backup'),
            'monitoring_enabled' => true,
            'real_time_monitoring' => true,
            'performance_mode' => 'balanced', // conservative, balanced, aggressive
            'alert_threshold' => 5, // Number of changes to trigger alert
            'batch_size' => 100 // Files to process per batch
        );
    }

    /**
     * Setup monitored file patterns.
     *
     * @since    1.0.0
     * @access   private
     */
    private function setup_monitored_patterns() {
        $wp_root = ABSPATH;
        
        $this->monitored_patterns = array(
            'core' => array(
                'paths' => array(
                    $wp_root . 'wp-admin/',
                    $wp_root . 'wp-includes/',
                    $wp_root . 'wp-config.php',
                    $wp_root . 'index.php',
                    $wp_root . '.htaccess'
                ),
                'priority' => 'critical',
                'recursive' => true,
                'exclude_patterns' => array(
                    '/cache/',
                    '/temp/',
                    '/logs/'
                )
            ),
            'plugins' => array(
                'paths' => array(
                    WP_PLUGIN_DIR . '/'
                ),
                'priority' => 'high',
                'recursive' => true,
                'exclude_patterns' => array(
                    '/cache/',
                    '/logs/',
                    '/temp/'
                )
            ),
            'themes' => array(
                'paths' => array(
                    get_theme_root() . '/'
                ),
                'priority' => 'high',
                'recursive' => true,
                'exclude_patterns' => array(
                    '/cache/',
                    '/temp/'
                )
            ),
            'uploads' => array(
                'paths' => array(
                    wp_upload_dir()['basedir'] . '/'
                ),
                'priority' => 'medium',
                'recursive' => true,
                'exclude_patterns' => array(
                    '/cache/',
                    '/temp/',
                    '/backups/'
                ),
                'scan_uploads' => true
            ),
            'config' => array(
                'paths' => array(
                    $wp_root . 'wp-config.php',
                    $wp_root . '.htaccess',
                    $wp_root . 'robots.txt'
                ),
                'priority' => 'critical',
                'recursive' => false
            )
        );
    }

    /**
     * Register WordPress hooks.
     *
     * @since    1.0.0
     * @access   private
     */
    private function register_hooks() {
        // File monitoring hooks
        add_action('wp_breach_file_monitor_scan', array($this, 'perform_monitoring_scan'));
        add_action('wp_breach_file_monitor_deep_scan', array($this, 'perform_deep_scan'));
        add_action('wp_breach_establish_baseline', array($this, 'establish_baseline'));
        
        // WordPress action hooks for file changes
        add_action('upgrader_process_complete', array($this, 'handle_wordpress_update'), 10, 2);
        add_action('activated_plugin', array($this, 'handle_plugin_activation'));
        add_action('deactivated_plugin', array($this, 'handle_plugin_deactivation'));
        add_action('switch_theme', array($this, 'handle_theme_switch'));
        add_action('wp_ajax_upload-attachment', array($this, 'monitor_file_upload'), 5);
        
        // File system hooks (if available)
        if (function_exists('inotify_init')) {
            add_action('init', array($this, 'setup_realtime_monitoring'));
        }
    }

    /**
     * Schedule monitoring tasks.
     *
     * @since    1.0.0
     * @access   private
     */
    private function schedule_monitoring() {
        // Regular monitoring scan
        if (!wp_next_scheduled('wp_breach_file_monitor_scan')) {
            wp_schedule_event(time(), 'wp_breach_file_monitor', 'wp_breach_file_monitor_scan');
        }
        
        // Deep scan
        if (!wp_next_scheduled('wp_breach_file_monitor_deep_scan')) {
            wp_schedule_event(time(), 'hourly', 'wp_breach_file_monitor_deep_scan');
        }
        
        // Baseline establishment (if needed)
        if (!$this->has_baseline()) {
            wp_schedule_single_event(time() + 60, 'wp_breach_establish_baseline');
        }
    }

    /**
     * Establish file baseline.
     *
     * Creates initial checksums and metadata for all monitored files.
     *
     * @since    1.0.0
     * @return   array    Baseline establishment result.
     */
    public function establish_baseline() {
        try {
            $baseline_data = array();
            $total_files = 0;
            $processed_files = 0;
            
            foreach ($this->monitored_patterns as $category => $pattern) {
                $files = $this->get_files_in_pattern($pattern);
                $total_files += count($files);
                
                foreach ($files as $file_path) {
                    $file_data = $this->get_file_metadata($file_path);
                    
                    if ($file_data) {
                        $baseline_data[] = array(
                            'file_path' => $file_path,
                            'category' => $category,
                            'hash_value' => $file_data['hash'],
                            'file_size' => $file_data['size'],
                            'permissions' => $file_data['permissions'],
                            'modified_time' => $file_data['mtime'],
                            'created_at' => current_time('mysql'),
                            'is_baseline' => 1
                        );
                        
                        $processed_files++;
                        
                        // Process in batches to avoid memory issues
                        if (count($baseline_data) >= $this->config['batch_size']) {
                            $this->save_baseline_batch($baseline_data);
                            $baseline_data = array();
                        }
                    }
                }
            }
            
            // Save remaining files
            if (!empty($baseline_data)) {
                $this->save_baseline_batch($baseline_data);
            }
            
            // Update baseline status
            update_option('wp_breach_baseline_established', time());
            update_option('wp_breach_baseline_file_count', $processed_files);
            
            $this->log_monitoring_event('baseline_established', array(
                'total_files' => $total_files,
                'processed_files' => $processed_files,
                'timestamp' => current_time('mysql')
            ));

            return array(
                'success' => true,
                'total_files' => $total_files,
                'processed_files' => $processed_files
            );

        } catch (Exception $e) {
            error_log("WP-Breach File Monitor Baseline Error: " . $e->getMessage());
            return array(
                'success' => false,
                'error' => $e->getMessage()
            );
        }
    }

    /**
     * Perform regular monitoring scan.
     *
     * @since    1.0.0
     * @return   array    Monitoring scan results.
     */
    public function perform_monitoring_scan() {
        if (!$this->config['monitoring_enabled']) {
            return array('success' => true, 'message' => 'Monitoring disabled');
        }

        try {
            $scan_start = microtime(true);
            $changes_detected = array();
            $files_scanned = 0;
            
            // Get high-priority files first
            $priority_files = $this->get_priority_files();
            
            foreach ($priority_files as $file_path) {
                $change = $this->check_file_integrity($file_path);
                
                if ($change) {
                    $changes_detected[] = $change;
                }
                
                $files_scanned++;
                
                // Performance throttling
                if ($files_scanned % 50 === 0) {
                    $this->performance_throttle();
                }
            }
            
            $scan_duration = microtime(true) - $scan_start;
            
            // Process detected changes
            if (!empty($changes_detected)) {
                $this->process_detected_changes($changes_detected);
            }
            
            // Log scan completion
            $this->log_monitoring_event('scan_completed', array(
                'files_scanned' => $files_scanned,
                'changes_detected' => count($changes_detected),
                'scan_duration' => $scan_duration,
                'timestamp' => current_time('mysql')
            ));

            return array(
                'success' => true,
                'files_scanned' => $files_scanned,
                'changes_detected' => count($changes_detected),
                'scan_duration' => $scan_duration
            );

        } catch (Exception $e) {
            error_log("WP-Breach File Monitor Scan Error: " . $e->getMessage());
            return array(
                'success' => false,
                'error' => $e->getMessage()
            );
        }
    }

    /**
     * Check file integrity against baseline.
     *
     * @since    1.0.0
     * @param    string   $file_path    Path to file to check.
     * @return   array|false           Change data or false if no change.
     */
    public function check_file_integrity($file_path) {
        try {
            // Skip if file doesn't exist
            if (!file_exists($file_path)) {
                return $this->handle_missing_file($file_path);
            }
            
            // Skip if file is too large
            if (filesize($file_path) > $this->config['max_file_size']) {
                return false;
            }
            
            // Get current file metadata
            $current_data = $this->get_file_metadata($file_path);
            
            if (!$current_data) {
                return false;
            }
            
            // Get baseline data
            $baseline_data = $this->get_file_baseline($file_path);
            
            if (!$baseline_data) {
                // New file detected
                return $this->handle_new_file($file_path, $current_data);
            }
            
            // Compare with baseline
            $changes = $this->compare_file_data($current_data, $baseline_data);
            
            if (!empty($changes)) {
                return array(
                    'file_path' => $file_path,
                    'change_type' => $this->determine_change_type($changes),
                    'changes' => $changes,
                    'current_data' => $current_data,
                    'baseline_data' => $baseline_data,
                    'detected_at' => current_time('mysql'),
                    'severity' => $this->assess_change_severity($file_path, $changes)
                );
            }
            
            return false;

        } catch (Exception $e) {
            error_log("WP-Breach File Integrity Check Error for {$file_path}: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Get file metadata including hash, size, permissions, etc.
     *
     * @since    1.0.0
     * @access   private
     * @param    string   $file_path    Path to file.
     * @return   array|false           File metadata or false on error.
     */
    private function get_file_metadata($file_path) {
        try {
            if (!file_exists($file_path) || !is_readable($file_path)) {
                return false;
            }
            
            $stat = stat($file_path);
            
            if ($stat === false) {
                return false;
            }
            
            // Calculate file hash
            $hash = hash_file($this->config['hash_algorithm'], $file_path);
            
            if ($hash === false) {
                return false;
            }
            
            return array(
                'hash' => $hash,
                'size' => $stat['size'],
                'permissions' => substr(sprintf('%o', $stat['mode']), -4),
                'mtime' => $stat['mtime'],
                'ctime' => $stat['ctime'],
                'uid' => $stat['uid'],
                'gid' => $stat['gid'],
                'inode' => $stat['ino']
            );

        } catch (Exception $e) {
            error_log("WP-Breach File Metadata Error for {$file_path}: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Get files matching monitoring patterns.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $pattern      File pattern configuration.
     * @return   array                  Array of file paths.
     */
    private function get_files_in_pattern($pattern) {
        $files = array();
        
        foreach ($pattern['paths'] as $path) {
            if (is_file($path)) {
                // Single file
                $files[] = $path;
            } elseif (is_dir($path)) {
                // Directory scanning
                $directory_files = $this->scan_directory($path, $pattern);
                $files = array_merge($files, $directory_files);
            }
        }
        
        return array_unique($files);
    }

    /**
     * Recursively scan directory for files.
     *
     * @since    1.0.0
     * @access   private
     * @param    string   $directory    Directory path.
     * @param    array    $pattern      Pattern configuration.
     * @return   array                  Array of file paths.
     */
    private function scan_directory($directory, $pattern) {
        $files = array();
        
        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS),
                $pattern['recursive'] ? RecursiveIteratorIterator::SELF_FIRST : RecursiveIteratorIterator::LEAVES_ONLY
            );
            
            foreach ($iterator as $file) {
                if ($file->isFile()) {
                    $file_path = $file->getRealPath();
                    
                    // Apply exclusion patterns
                    if ($this->should_exclude_file($file_path, $pattern)) {
                        continue;
                    }
                    
                    // Check file extension
                    if ($this->should_exclude_extension($file_path)) {
                        continue;
                    }
                    
                    $files[] = $file_path;
                }
            }

        } catch (Exception $e) {
            error_log("WP-Breach Directory Scan Error for {$directory}: " . $e->getMessage());
        }
        
        return $files;
    }

    /**
     * Check if file should be excluded from monitoring.
     *
     * @since    1.0.0
     * @access   private
     * @param    string   $file_path    File path.
     * @param    array    $pattern      Pattern configuration.
     * @return   bool                   True if file should be excluded.
     */
    private function should_exclude_file($file_path, $pattern) {
        if (empty($pattern['exclude_patterns'])) {
            return false;
        }
        
        foreach ($pattern['exclude_patterns'] as $exclude_pattern) {
            if (strpos($file_path, $exclude_pattern) !== false) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Check if file extension should be excluded.
     *
     * @since    1.0.0
     * @access   private
     * @param    string   $file_path    File path.
     * @return   bool                   True if extension should be excluded.
     */
    private function should_exclude_extension($file_path) {
        $extension = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
        
        return in_array($extension, $this->config['excluded_extensions']);
    }

    /**
     * Save baseline data batch to database.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $baseline_data    Batch of baseline data.
     */
    private function save_baseline_batch($baseline_data) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'breach_monitoring';
        
        $values = array();
        $placeholders = array();
        
        foreach ($baseline_data as $data) {
            $values = array_merge($values, array_values($data));
            $placeholders[] = '(' . implode(',', array_fill(0, count($data), '%s')) . ')';
        }
        
        $sql = "INSERT INTO {$table_name} (file_path, category, hash_value, file_size, permissions, modified_time, created_at, is_baseline) VALUES " . implode(',', $placeholders);
        
        $wpdb->query($wpdb->prepare($sql, $values));
    }

    /**
     * Get file baseline data.
     *
     * @since    1.0.0
     * @access   private
     * @param    string   $file_path    File path.
     * @return   array|false           Baseline data or false if not found.
     */
    private function get_file_baseline($file_path) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'breach_monitoring';
        
        $baseline = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$table_name} WHERE file_path = %s AND is_baseline = 1 ORDER BY created_at DESC LIMIT 1",
            $file_path
        ), ARRAY_A);
        
        return $baseline ?: false;
    }

    /**
     * Compare current file data with baseline.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $current      Current file data.
     * @param    array    $baseline     Baseline file data.
     * @return   array                  Array of detected changes.
     */
    private function compare_file_data($current, $baseline) {
        $changes = array();
        
        // Hash comparison (most important)
        if ($current['hash'] !== $baseline['hash_value']) {
            $changes['content'] = array(
                'old' => $baseline['hash_value'],
                'new' => $current['hash']
            );
        }
        
        // Size comparison
        if ($current['size'] != $baseline['file_size']) {
            $changes['size'] = array(
                'old' => $baseline['file_size'],
                'new' => $current['size']
            );
        }
        
        // Permission comparison
        if ($current['permissions'] !== $baseline['permissions']) {
            $changes['permissions'] = array(
                'old' => $baseline['permissions'],
                'new' => $current['permissions']
            );
        }
        
        // Modified time comparison (less critical)
        if ($current['mtime'] != $baseline['modified_time']) {
            $changes['mtime'] = array(
                'old' => $baseline['modified_time'],
                'new' => $current['mtime']
            );
        }
        
        return $changes;
    }

    /**
     * Process detected file changes.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $changes      Array of detected changes.
     */
    private function process_detected_changes($changes) {
        foreach ($changes as $change) {
            // Check whitelist
            if ($this->whitelist_manager->is_change_whitelisted($change)) {
                continue;
            }
            
            // Save change to database
            $this->save_file_change($change);
            
            // Create alert if necessary
            if ($this->should_create_alert($change)) {
                $this->create_file_change_alert($change);
            }
            
            // Trigger automated response if configured
            if ($this->should_trigger_response($change)) {
                $this->trigger_automated_response($change);
            }
        }
    }

    /**
     * Save file change to database.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $change       Change data.
     */
    private function save_file_change($change) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'breach_monitoring';
        
        $wpdb->insert(
            $table_name,
            array(
                'file_path' => $change['file_path'],
                'monitor_type' => 'file_integrity',
                'change_type' => $change['change_type'],
                'old_hash' => $change['baseline_data']['hash_value'] ?? null,
                'new_hash' => $change['current_data']['hash'] ?? null,
                'severity' => $change['severity'],
                'change_details' => json_encode($change['changes']),
                'detected_at' => $change['detected_at'],
                'created_at' => current_time('mysql')
            ),
            array('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')
        );
    }

    /**
     * Determine if alert should be created for change.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $change       Change data.
     * @return   bool                   True if alert should be created.
     */
    private function should_create_alert($change) {
        // Always alert for critical files
        if ($change['severity'] === 'critical') {
            return true;
        }
        
        // Alert for high severity changes
        if ($change['severity'] === 'high') {
            return true;
        }
        
        // Check if threshold is exceeded
        $recent_changes = $this->get_recent_changes(HOUR_IN_SECONDS);
        
        return count($recent_changes) >= $this->config['alert_threshold'];
    }

    /**
     * Create alert for file change.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $change       Change data.
     */
    private function create_file_change_alert($change) {
        $alert_manager = new WP_Breach_Alert_Manager();
        
        $alert_data = array(
            'type' => 'file_integrity_violation',
            'severity' => $change['severity'],
            'title' => 'Unauthorized File Change Detected',
            'message' => sprintf(
                'File %s has been modified. Change type: %s',
                $change['file_path'],
                $change['change_type']
            ),
            'details' => $change,
            'source' => 'file_monitor'
        );
        
        $alert_manager->create_alert($alert_data);
    }

    // Additional helper methods...
    
    private function has_baseline() {
        return get_option('wp_breach_baseline_established', false) !== false;
    }
    
    private function get_priority_files() {
        $priority_files = array();
        
        // Get critical and high priority files first
        foreach ($this->monitored_patterns as $category => $pattern) {
            if (in_array($pattern['priority'], array('critical', 'high'))) {
                $files = $this->get_files_in_pattern($pattern);
                $priority_files = array_merge($priority_files, $files);
            }
        }
        
        return array_slice($priority_files, 0, 1000); // Limit for performance
    }
    
    private function performance_throttle() {
        // Micro-sleep to prevent overwhelming the system
        if ($this->config['performance_mode'] === 'conservative') {
            usleep(10000); // 10ms
        } elseif ($this->config['performance_mode'] === 'balanced') {
            usleep(5000); // 5ms
        }
        // Aggressive mode: no throttling
    }
    
    private function handle_missing_file($file_path) {
        $baseline = $this->get_file_baseline($file_path);
        
        if ($baseline) {
            return array(
                'file_path' => $file_path,
                'change_type' => 'deleted',
                'changes' => array('deleted' => true),
                'baseline_data' => $baseline,
                'detected_at' => current_time('mysql'),
                'severity' => $this->assess_deletion_severity($file_path)
            );
        }
        
        return false;
    }
    
    private function handle_new_file($file_path, $current_data) {
        return array(
            'file_path' => $file_path,
            'change_type' => 'created',
            'changes' => array('created' => true),
            'current_data' => $current_data,
            'detected_at' => current_time('mysql'),
            'severity' => $this->assess_new_file_severity($file_path)
        );
    }
    
    private function determine_change_type($changes) {
        if (isset($changes['content'])) {
            return 'modified';
        } elseif (isset($changes['permissions'])) {
            return 'permission_changed';
        } elseif (isset($changes['size'])) {
            return 'size_changed';
        }
        
        return 'metadata_changed';
    }
    
    private function assess_change_severity($file_path, $changes) {
        // WordPress core files are always critical
        if (strpos($file_path, ABSPATH . 'wp-admin/') === 0 || 
            strpos($file_path, ABSPATH . 'wp-includes/') === 0) {
            return 'critical';
        }
        
        // Configuration files are critical
        if (basename($file_path) === 'wp-config.php' || 
            basename($file_path) === '.htaccess') {
            return 'critical';
        }
        
        // Content changes are more serious than metadata changes
        if (isset($changes['content'])) {
            return 'high';
        }
        
        return 'medium';
    }
    
    private function assess_deletion_severity($file_path) {
        // Core file deletion is critical
        if (strpos($file_path, ABSPATH . 'wp-admin/') === 0 || 
            strpos($file_path, ABSPATH . 'wp-includes/') === 0) {
            return 'critical';
        }
        
        return 'high';
    }
    
    private function assess_new_file_severity($file_path) {
        // New files in upload directory might be normal
        $upload_dir = wp_upload_dir();
        if (strpos($file_path, $upload_dir['basedir']) === 0) {
            return 'low';
        }
        
        // New files in core directories are suspicious
        if (strpos($file_path, ABSPATH . 'wp-admin/') === 0 || 
            strpos($file_path, ABSPATH . 'wp-includes/') === 0) {
            return 'high';
        }
        
        return 'medium';
    }
    
    private function get_recent_changes($time_period) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'breach_monitoring';
        $since = date('Y-m-d H:i:s', time() - $time_period);
        
        return $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM {$table_name} WHERE monitor_type = 'file_integrity' AND detected_at > %s",
            $since
        ), ARRAY_A);
    }
    
    private function log_monitoring_event($event_type, $data) {
        error_log("WP-Breach File Monitor [{$event_type}]: " . json_encode($data));
    }
    
    private function should_trigger_response($change) {
        // Only trigger automated responses for critical changes
        return $change['severity'] === 'critical' && 
               get_option('wp_breach_auto_response_enabled', false);
    }
    
    private function trigger_automated_response($change) {
        // Implementation for automated response
        // This could include file restoration, access blocking, etc.
        do_action('wp_breach_file_change_response', $change);
    }

    // WordPress update handling methods
    public function handle_wordpress_update($upgrader_object, $options) {
        // Temporarily disable monitoring during updates
        $this->config['monitoring_enabled'] = false;
        
        // Re-establish baseline after update
        wp_schedule_single_event(time() + 300, 'wp_breach_establish_baseline');
    }

    public function handle_plugin_activation($plugin) {
        // Add plugin files to monitoring baseline
        wp_schedule_single_event(time() + 60, 'wp_breach_establish_baseline');
    }

    public function handle_plugin_deactivation($plugin) {
        // Plugin deactivation doesn't require baseline changes
    }

    public function handle_theme_switch($new_name, $new_theme) {
        // Re-establish baseline for new theme
        wp_schedule_single_event(time() + 60, 'wp_breach_establish_baseline');
    }

    public function monitor_file_upload() {
        // Monitor file uploads in real-time
        if (isset($_FILES) && !empty($_FILES)) {
            foreach ($_FILES as $file) {
                if ($file['error'] === UPLOAD_ERR_OK) {
                    // Schedule scan of uploaded file
                    wp_schedule_single_event(time() + 30, 'wp_breach_scan_uploaded_file', array($file['tmp_name']));
                }
            }
        }
    }

    /**
     * Perform deep scan of all monitored files.
     *
     * @since    1.0.0
     */
    public function perform_deep_scan() {
        // Comprehensive scan of all files (scheduled hourly)
        foreach ($this->monitored_patterns as $category => $pattern) {
            $files = $this->get_files_in_pattern($pattern);
            
            foreach ($files as $file_path) {
                $change = $this->check_file_integrity($file_path);
                
                if ($change) {
                    $this->process_detected_changes(array($change));
                }
            }
        }
    }
}

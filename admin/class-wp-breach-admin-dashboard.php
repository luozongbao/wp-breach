<?php
/**
 * Admin Dashboard Class
 *
 * Handles the main dashboard functionality including security overview,
 * vulnerability management, and scan operations.
 *
 * @package WP_Breach
 * @since 1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class WP_Breach_Admin_Dashboard
 *
 * Manages the admin dashboard interface and functionality.
 */
class WP_Breach_Admin_Dashboard {
    
    /**
     * Plugin name
     *
     * @var string
     */
    private $plugin_name;
    
    /**
     * Plugin version
     *
     * @var string
     */
    private $version;
    
    /**
     * Scanner instance
     *
     * @var WP_Breach_Scanner
     */
    private $scanner;
    
    /**
     * Database instance
     *
     * @var WP_Breach_Database
     */
    private $database;
    
    /**
     * Constructor
     *
     * @param string $plugin_name Plugin name
     * @param string $version Plugin version
     */
    public function __construct($plugin_name, $version) {
        $this->plugin_name = $plugin_name;
        $this->version = $version;
        
        // Initialize dependencies
        $this->scanner = new WP_Breach_Scanner();
        $this->database = new WP_Breach_Database();
        
        // Ensure database tables exist
        $this->ensure_database_tables();
    }
    
    /**
     * Get dashboard data for main screen
     *
     * @return array Dashboard data
     */
    public function get_dashboard_data() {
        // Get latest scan results
        $latest_scan = $this->get_latest_scan_results();
        
        // Get vulnerability counts by severity
        $vulnerability_counts = $this->get_vulnerability_counts();
        
        // Get security score
        $security_score = $this->calculate_security_score($vulnerability_counts);
        
        // Get recent vulnerabilities (top 5)
        $recent_vulnerabilities = $this->get_recent_vulnerabilities(5);
        
        // Get scan history for trend chart
        $scan_history = $this->get_scan_history(30);
        
        return array(
            'security_status' => array(
                'critical' => $vulnerability_counts['critical'],
                'high' => $vulnerability_counts['high'],
                'medium' => $vulnerability_counts['medium'],
                'low' => $vulnerability_counts['low'],
                'total' => array_sum($vulnerability_counts)
            ),
            'security_score' => $security_score,
            'last_scan' => $latest_scan,
            'recent_vulnerabilities' => $recent_vulnerabilities,
            'scan_history' => $scan_history,
            'vulnerability_distribution' => $this->get_vulnerability_distribution(),
            'system_status' => $this->get_system_status()
        );
    }
    
    /**
     * Get latest scan results
     *
     * @return array|null Latest scan data
     */
    private function get_latest_scan_results() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'wp_breach_scan_results';
        
        // Check if table exists
        if (!$this->table_exists($table_name)) {
            return null;
        }
        
        $latest_scan = $wpdb->get_row(
            "SELECT * FROM {$table_name} ORDER BY created_at DESC LIMIT 1",
            ARRAY_A
        );
        
        if ($latest_scan) {
            $latest_scan['results'] = json_decode($latest_scan['results'], true);
            $latest_scan['config'] = json_decode($latest_scan['config'], true);
            $latest_scan['time_ago'] = human_time_diff(strtotime($latest_scan['created_at']));
        }
        
        return $latest_scan;
    }
    
    /**
     * Get vulnerability counts by severity
     *
     * @return array Vulnerability counts
     */
    private function get_vulnerability_counts() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'wp_breach_vulnerabilities';
        
        // Check if table exists
        if (!$this->table_exists($table_name)) {
            return array(
                'critical' => 0,
                'high' => 0,
                'medium' => 0,
                'low' => 0
            );
        }
        
        $counts = $wpdb->get_results(
            "SELECT severity, COUNT(*) as count FROM {$table_name} 
             WHERE status = 'open' GROUP BY severity",
            ARRAY_A
        );
        
        $result = array(
            'critical' => 0,
            'high' => 0,
            'medium' => 0,
            'low' => 0
        );
        
        foreach ($counts as $count) {
            if (isset($result[$count['severity']])) {
                $result[$count['severity']] = (int) $count['count'];
            }
        }
        
        return $result;
    }
    
    /**
     * Calculate security score based on vulnerabilities
     *
     * @param array $vulnerability_counts Vulnerability counts by severity
     * @return int Security score (0-100)
     */
    private function calculate_security_score($vulnerability_counts) {
        $base_score = 100;
        
        // Deduct points based on severity
        $base_score -= $vulnerability_counts['critical'] * 20; // -20 per critical
        $base_score -= $vulnerability_counts['high'] * 10;     // -10 per high
        $base_score -= $vulnerability_counts['medium'] * 5;    // -5 per medium
        $base_score -= $vulnerability_counts['low'] * 1;       // -1 per low
        
        // Ensure score doesn't go below 0
        return max(0, $base_score);
    }
    
    /**
     * Get recent vulnerabilities
     *
     * @param int $limit Number of vulnerabilities to return
     * @return array Recent vulnerabilities
     */
    private function get_recent_vulnerabilities($limit = 5) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'wp_breach_vulnerabilities';
        
        // Check if table exists
        if (!$this->table_exists($table_name)) {
            return array();
        }
        
        $vulnerabilities = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT * FROM {$table_name} 
                 WHERE status = 'open' 
                 ORDER BY detected_at DESC 
                 LIMIT %d",
                $limit
            ),
            ARRAY_A
        );
        
        foreach ($vulnerabilities as &$vulnerability) {
            $vulnerability['details'] = json_decode($vulnerability['details'], true);
            $vulnerability['time_ago'] = human_time_diff(strtotime($vulnerability['detected_at']));
        }
        
        return $vulnerabilities;
    }
    
    /**
     * Get scan history for trend analysis
     *
     * @param int $days Number of days to look back
     * @return array Scan history data
     */
    private function get_scan_history($days = 30) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'wp_breach_scan_results';
        
        // Check if table exists
        if (!$this->table_exists($table_name)) {
            return array();
        }
        
        $history = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT DATE(created_at) as scan_date, 
                        COUNT(*) as scan_count,
                        AVG(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as success_rate
                 FROM {$table_name} 
                 WHERE created_at >= DATE_SUB(NOW(), INTERVAL %d DAY)
                 GROUP BY DATE(created_at)
                 ORDER BY scan_date ASC",
                $days
            ),
            ARRAY_A
        );
        
        return $history;
    }
    
    /**
     * Get vulnerability distribution data for pie chart
     *
     * @return array Vulnerability distribution
     */
    private function get_vulnerability_distribution() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'wp_breach_vulnerabilities';
        
        // Check if table exists
        if (!$this->table_exists($table_name)) {
            return array();
        }
        
        $distribution = $wpdb->get_results(
            "SELECT type, COUNT(*) as count FROM {$table_name} 
             WHERE status = 'open' 
             GROUP BY type 
             ORDER BY count DESC 
             LIMIT 10",
            ARRAY_A
        );
        
        return $distribution;
    }
    
    /**
     * Get system status information
     *
     * @return array System status
     */
    private function get_system_status() {
        return array(
            'wordpress_version' => get_bloginfo('version'),
            'php_version' => PHP_VERSION,
            'memory_limit' => ini_get('memory_limit'),
            'memory_usage' => $this->format_bytes(memory_get_usage(true)),
            'active_plugins' => count(get_option('active_plugins', array())),
            'active_theme' => wp_get_theme()->get('Name'),
            'multisite' => is_multisite(),
            'ssl_enabled' => is_ssl()
        );
    }
    
    /**
     * Format bytes to human readable format
     *
     * @param int $bytes Bytes
     * @return string Formatted string
     */
    private function format_bytes($bytes) {
        $units = array('B', 'KB', 'MB', 'GB', 'TB');
        
        for ($i = 0; $bytes > 1024; $i++) {
            $bytes /= 1024;
        }
        
        return round($bytes, 2) . ' ' . $units[$i];
    }
    
    /**
     * Start a new security scan
     *
     * @param array $config Scan configuration
     * @return array|WP_Error Scan result or error
     */
    public function start_scan($config = array()) {
        try {
            // Initialize scanner with configuration
            $init_result = $this->scanner->initialize($config);
            
            if (!$init_result) {
                return new WP_Error('scan_init_failed', __('Failed to initialize scanner', 'wp-breach'));
            }
            
            // Start the scan
            $scan_result = $this->scanner->start_scan($config);
            
            if (!$scan_result) {
                return new WP_Error('scan_start_failed', __('Failed to start scan', 'wp-breach'));
            }
            
            return array(
                'success' => true,
                'message' => __('Scan started successfully', 'wp-breach'),
                'scan_id' => $this->scanner->get_progress()['session_id'] ?? '',
                'status' => $this->scanner->get_status()
            );
            
        } catch (Exception $e) {
            return new WP_Error('scan_exception', $e->getMessage());
        }
    }
    
    /**
     * Get current scan progress
     *
     * @return array Scan progress data
     */
    public function get_scan_progress() {
        return $this->scanner->get_progress();
    }
    
    /**
     * Cancel current scan
     *
     * @return bool Success status
     */
    public function cancel_scan() {
        return $this->scanner->stop_scan();
    }
    
    /**
     * Pause current scan
     *
     * @return bool Success status
     */
    public function pause_scan() {
        return $this->scanner->pause_scan();
    }
    
    /**
     * Resume paused scan
     *
     * @return bool Success status
     */
    public function resume_scan() {
        return $this->scanner->resume_scan();
    }
    
    /**
     * Get vulnerability details
     *
     * @param int $vulnerability_id Vulnerability ID
     * @return array|null Vulnerability details
     */
    public function get_vulnerability_details($vulnerability_id) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'wp_breach_vulnerabilities';
        
        $vulnerability = $wpdb->get_row(
            $wpdb->prepare(
                "SELECT * FROM {$table_name} WHERE id = %d",
                $vulnerability_id
            ),
            ARRAY_A
        );
        
        if ($vulnerability) {
            $vulnerability['details'] = json_decode($vulnerability['details'], true);
        }
        
        return $vulnerability;
    }
    
    /**
     * Mark vulnerability as resolved
     *
     * @param int $vulnerability_id Vulnerability ID
     * @return bool Success status
     */
    public function mark_vulnerability_resolved($vulnerability_id) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'wp_breach_vulnerabilities';
        
        $result = $wpdb->update(
            $table_name,
            array(
                'status' => 'resolved',
                'resolved_at' => current_time('mysql')
            ),
            array('id' => $vulnerability_id),
            array('%s', '%s'),
            array('%d')
        );
        
        return $result !== false;
    }
    
    /**
     * Apply automated fix for vulnerability
     *
     * @param int $vulnerability_id Vulnerability ID
     * @return array|WP_Error Fix result or error
     */
    public function apply_vulnerability_fix($vulnerability_id) {
        $vulnerability = $this->get_vulnerability_details($vulnerability_id);
        
        if (!$vulnerability) {
            return new WP_Error('vulnerability_not_found', __('Vulnerability not found', 'wp-breach'));
        }
        
        // TODO: Implement automated fix logic based on vulnerability type
        // This will be implemented in Issue #006 - Automated Fix System
        
        return new WP_Error('fix_not_implemented', __('Automated fixes will be available in a future update', 'wp-breach'));
    }
    
    /**
     * Export vulnerability data
     *
     * @param string $format Export format (csv, json, pdf)
     * @param array $filters Export filters
     * @return string|WP_Error Export data or error
     */
    public function export_vulnerabilities($format = 'csv', $filters = array()) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'wp_breach_vulnerabilities';
        
        // Build query with filters
        $where_clauses = array('1=1');
        $params = array();
        
        if (!empty($filters['severity'])) {
            $where_clauses[] = 'severity = %s';
            $params[] = $filters['severity'];
        }
        
        if (!empty($filters['status'])) {
            $where_clauses[] = 'status = %s';
            $params[] = $filters['status'];
        }
        
        if (!empty($filters['type'])) {
            $where_clauses[] = 'type = %s';
            $params[] = $filters['type'];
        }
        
        $query = "SELECT * FROM {$table_name} WHERE " . implode(' AND ', $where_clauses) . " ORDER BY detected_at DESC";
        
        if (!empty($params)) {
            $query = $wpdb->prepare($query, $params);
        }
        
        $vulnerabilities = $wpdb->get_results($query, ARRAY_A);
        
        switch ($format) {
            case 'csv':
                return $this->export_to_csv($vulnerabilities);
            
            case 'json':
                return json_encode($vulnerabilities, JSON_PRETTY_PRINT);
            
            case 'pdf':
                // TODO: Implement PDF export
                return new WP_Error('pdf_not_implemented', __('PDF export will be available in a future update', 'wp-breach'));
            
            default:
                return new WP_Error('invalid_format', __('Invalid export format', 'wp-breach'));
        }
    }
    
    /**
     * Export data to CSV format
     *
     * @param array $data Data to export
     * @return string CSV data
     */
    private function export_to_csv($data) {
        if (empty($data)) {
            return '';
        }
        
        $output = fopen('php://temp', 'r+');
        
        // Add CSV headers
        $headers = array_keys($data[0]);
        fputcsv($output, $headers);
        
        // Add data rows
        foreach ($data as $row) {
            // Decode JSON fields for CSV
            if (isset($row['details']) && is_string($row['details'])) {
                $row['details'] = json_decode($row['details'], true);
                $row['details'] = is_array($row['details']) ? implode('; ', array_map(function($k, $v) {
                    return "$k: $v";
                }, array_keys($row['details']), $row['details'])) : $row['details'];
            }
            
            fputcsv($output, $row);
        }
        
        rewind($output);
        $csv = stream_get_contents($output);
        fclose($output);
        
        return $csv;
    }
    
    /**
     * Get dashboard widgets data
     *
     * @return array Widget data
     */
    public function get_dashboard_widgets() {
        $dashboard_data = $this->get_dashboard_data();
        
        return array(
            'security_overview' => array(
                'title' => __('Security Overview', 'wp-breach'),
                'data' => $dashboard_data['security_status']
            ),
            'recent_scan' => array(
                'title' => __('Latest Scan', 'wp-breach'),
                'data' => $dashboard_data['last_scan']
            ),
            'security_score' => array(
                'title' => __('Security Score', 'wp-breach'),
                'data' => $dashboard_data['security_score']
            ),
            'quick_actions' => array(
                'title' => __('Quick Actions', 'wp-breach'),
                'actions' => array(
                    'run_scan' => __('Run Quick Scan', 'wp-breach'),
                    'view_vulnerabilities' => __('View Vulnerabilities', 'wp-breach'),
                    'apply_fixes' => __('Apply Fixes', 'wp-breach')
                )
            )
        );
    }
    
    /**
     * Check if a database table exists
     *
     * @param string $table_name Table name to check
     * @return bool True if table exists, false otherwise
     */
    private function table_exists($table_name) {
        global $wpdb;
        
        $result = $wpdb->get_var($wpdb->prepare(
            "SHOW TABLES LIKE %s",
            $table_name
        ));
        
        return $result === $table_name;
    }
    
    /**
     * Initialize database tables if they don't exist
     *
     * @return bool True if tables exist or were created successfully
     */
    public function ensure_database_tables() {
        // Check if database class exists and tables are created
        if (class_exists('WP_Breach_Database')) {
            $database = new WP_Breach_Database();
            
            // Check if tables exist
            global $wpdb;
            $scan_results_table = $wpdb->prefix . 'wp_breach_scan_results';
            $vulnerabilities_table = $wpdb->prefix . 'wp_breach_vulnerabilities';
            
            if (!$this->table_exists($scan_results_table) || !$this->table_exists($vulnerabilities_table)) {
                // Try to create tables
                return $database->create_tables();
            }
            
            return true;
        }
        
        return false;
    }
}

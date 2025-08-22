<?php
/**
 * Dashboard AJAX Handler Class
 *
 * Handles AJAX requests for dashboard functionality including
 * scan operations, data refresh, and real-time updates.
 *
 * @package WP_Breach
 * @since 1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class WP_Breach_Dashboard_Ajax
 *
 * Manages AJAX endpoints for dashboard operations.
 */
class WP_Breach_Dashboard_Ajax {
    
    /**
     * Dashboard instance
     *
     * @var WP_Breach_Admin_Dashboard
     */
    private $dashboard;
    
    /**
     * Scanner instance
     *
     * @var WP_Breach_Scanner
     */
    private $scanner;
    
    /**
     * Constructor
     */
    public function __construct() {
        $this->dashboard = new WP_Breach_Admin_Dashboard('wp-breach', WP_BREACH_VERSION);
        $this->scanner = new WP_Breach_Scanner();
        
        $this->init_hooks();
    }
    
    /**
     * Initialize WordPress hooks
     */
    private function init_hooks() {
        // Scan operations
        add_action('wp_ajax_wp_breach_start_scan', array($this, 'start_scan'));
        add_action('wp_ajax_wp_breach_scan_progress', array($this, 'get_scan_progress'));
        add_action('wp_ajax_wp_breach_scan_status', array($this, 'get_scan_status'));
        add_action('wp_ajax_wp_breach_pause_scan', array($this, 'pause_scan'));
        add_action('wp_ajax_wp_breach_resume_scan', array($this, 'resume_scan'));
        add_action('wp_ajax_wp_breach_cancel_scan', array($this, 'cancel_scan'));
        
        // Dashboard operations
        add_action('wp_ajax_wp_breach_refresh_dashboard', array($this, 'refresh_dashboard'));
        add_action('wp_ajax_wp_breach_get_vulnerability_details', array($this, 'get_vulnerability_details'));
        add_action('wp_ajax_wp_breach_mark_vulnerability_resolved', array($this, 'mark_vulnerability_resolved'));
        add_action('wp_ajax_wp_breach_apply_vulnerability_fix', array($this, 'apply_vulnerability_fix'));
        
        // Export operations
        add_action('wp_ajax_wp_breach_export_vulnerabilities', array($this, 'export_vulnerabilities'));
        add_action('wp_ajax_wp_breach_export_scan_results', array($this, 'export_scan_results'));
    }
    
    /**
     * Start security scan
     */
    public function start_scan() {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'], 'wp_breach_dashboard_nonce')) {
            wp_send_json_error(array('message' => __('Security check failed', 'wp-breach')));
            return;
        }
        
        // Check user capabilities
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('Insufficient permissions', 'wp-breach')));
            return;
        }
        
        // Get scan configuration
        $config = isset($_POST['config']) ? json_decode(stripslashes($_POST['config']), true) : array();
        
        // Validate configuration
        $config = $this->validate_scan_config($config);
        
        // Start the scan
        $result = $this->dashboard->start_scan($config);
        
        if (is_wp_error($result)) {
            wp_send_json_error(array('message' => $result->get_error_message()));
            return;
        }
        
        wp_send_json_success($result);
    }
    
    /**
     * Get scan progress
     */
    public function get_scan_progress() {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'], 'wp_breach_dashboard_nonce')) {
            wp_send_json_error(array('message' => __('Security check failed', 'wp-breach')));
            return;
        }
        
        // Check user capabilities
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('Insufficient permissions', 'wp-breach')));
            return;
        }
        
        $scan_id = sanitize_text_field($_POST['scan_id'] ?? '');
        
        $progress = $this->dashboard->get_scan_progress();
        
        wp_send_json_success($progress);
    }
    
    /**
     * Get current scan status
     */
    public function get_scan_status() {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'], 'wp_breach_dashboard_nonce')) {
            wp_send_json_error(array('message' => __('Security check failed', 'wp-breach')));
            return;
        }
        
        // Check user capabilities
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('Insufficient permissions', 'wp-breach')));
            return;
        }
        
        $status = $this->scanner->get_status();
        $progress = $this->scanner->get_progress();
        
        $result = array(
            'status' => $status,
            'scan_id' => $progress['session_id'] ?? '',
            'percentage' => $progress['percentage'] ?? 0,
            'current_phase' => $progress['current_phase'] ?? ''
        );
        
        wp_send_json_success($result);
    }
    
    /**
     * Pause current scan
     */
    public function pause_scan() {
        // Verify nonce and permissions
        if (!wp_verify_nonce($_POST['nonce'], 'wp_breach_dashboard_nonce') || 
            !current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('Security check failed', 'wp-breach')));
            return;
        }
        
        $result = $this->dashboard->pause_scan();
        
        if ($result) {
            wp_send_json_success(array('message' => __('Scan paused successfully', 'wp-breach')));
        } else {
            wp_send_json_error(array('message' => __('Failed to pause scan', 'wp-breach')));
        }
    }
    
    /**
     * Resume paused scan
     */
    public function resume_scan() {
        // Verify nonce and permissions
        if (!wp_verify_nonce($_POST['nonce'], 'wp_breach_dashboard_nonce') || 
            !current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('Security check failed', 'wp-breach')));
            return;
        }
        
        $result = $this->dashboard->resume_scan();
        
        if ($result) {
            wp_send_json_success(array('message' => __('Scan resumed successfully', 'wp-breach')));
        } else {
            wp_send_json_error(array('message' => __('Failed to resume scan', 'wp-breach')));
        }
    }
    
    /**
     * Cancel current scan
     */
    public function cancel_scan() {
        // Verify nonce and permissions
        if (!wp_verify_nonce($_POST['nonce'], 'wp_breach_dashboard_nonce') || 
            !current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('Security check failed', 'wp-breach')));
            return;
        }
        
        $result = $this->dashboard->cancel_scan();
        
        if ($result) {
            wp_send_json_success(array('message' => __('Scan cancelled successfully', 'wp-breach')));
        } else {
            wp_send_json_error(array('message' => __('Failed to cancel scan', 'wp-breach')));
        }
    }
    
    /**
     * Refresh dashboard data
     */
    public function refresh_dashboard() {
        // Verify nonce and permissions
        if (!wp_verify_nonce($_POST['nonce'], 'wp_breach_dashboard_nonce') || 
            !current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('Security check failed', 'wp-breach')));
            return;
        }
        
        $dashboard_data = $this->dashboard->get_dashboard_data();
        
        wp_send_json_success($dashboard_data);
    }
    
    /**
     * Get vulnerability details
     */
    public function get_vulnerability_details() {
        // Verify nonce and permissions
        if (!wp_verify_nonce($_POST['nonce'], 'wp_breach_dashboard_nonce') || 
            !current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('Security check failed', 'wp-breach')));
            return;
        }
        
        $vulnerability_id = absint($_POST['vulnerability_id'] ?? 0);
        
        if (!$vulnerability_id) {
            wp_send_json_error(array('message' => __('Invalid vulnerability ID', 'wp-breach')));
            return;
        }
        
        $vulnerability = $this->dashboard->get_vulnerability_details($vulnerability_id);
        
        if (!$vulnerability) {
            wp_send_json_error(array('message' => __('Vulnerability not found', 'wp-breach')));
            return;
        }
        
        wp_send_json_success($vulnerability);
    }
    
    /**
     * Mark vulnerability as resolved
     */
    public function mark_vulnerability_resolved() {
        // Verify nonce and permissions
        if (!wp_verify_nonce($_POST['nonce'], 'wp_breach_dashboard_nonce') || 
            !current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('Security check failed', 'wp-breach')));
            return;
        }
        
        $vulnerability_id = absint($_POST['vulnerability_id'] ?? 0);
        
        if (!$vulnerability_id) {
            wp_send_json_error(array('message' => __('Invalid vulnerability ID', 'wp-breach')));
            return;
        }
        
        $result = $this->dashboard->mark_vulnerability_resolved($vulnerability_id);
        
        if ($result) {
            wp_send_json_success(array('message' => __('Vulnerability marked as resolved', 'wp-breach')));
        } else {
            wp_send_json_error(array('message' => __('Failed to update vulnerability status', 'wp-breach')));
        }
    }
    
    /**
     * Apply automated fix for vulnerability
     */
    public function apply_vulnerability_fix() {
        // Verify nonce and permissions
        if (!wp_verify_nonce($_POST['nonce'], 'wp_breach_dashboard_nonce') || 
            !current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('Security check failed', 'wp-breach')));
            return;
        }
        
        $vulnerability_id = absint($_POST['vulnerability_id'] ?? 0);
        
        if (!$vulnerability_id) {
            wp_send_json_error(array('message' => __('Invalid vulnerability ID', 'wp-breach')));
            return;
        }
        
        $result = $this->dashboard->apply_vulnerability_fix($vulnerability_id);
        
        if (is_wp_error($result)) {
            wp_send_json_error(array('message' => $result->get_error_message()));
            return;
        }
        
        wp_send_json_success($result);
    }
    
    /**
     * Export vulnerabilities
     */
    public function export_vulnerabilities() {
        // Verify nonce and permissions
        if (!wp_verify_nonce($_POST['nonce'], 'wp_breach_dashboard_nonce') || 
            !current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('Security check failed', 'wp-breach')));
            return;
        }
        
        $format = sanitize_text_field($_POST['format'] ?? 'csv');
        $filters = array();
        
        // Parse filters
        if (!empty($_POST['filters'])) {
            $filters = json_decode(stripslashes($_POST['filters']), true);
            $filters = $this->sanitize_export_filters($filters);
        }
        
        $result = $this->dashboard->export_vulnerabilities($format, $filters);
        
        if (is_wp_error($result)) {
            wp_send_json_error(array('message' => $result->get_error_message()));
            return;
        }
        
        // Set appropriate headers for download
        $filename = 'wp-breach-vulnerabilities-' . date('Y-m-d-H-i-s') . '.' . $format;
        
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('Content-Length: ' . strlen($result));
        
        echo $result;
        exit;
    }
    
    /**
     * Export scan results
     */
    public function export_scan_results() {
        // Verify nonce and permissions
        if (!wp_verify_nonce($_POST['nonce'], 'wp_breach_dashboard_nonce') || 
            !current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('Security check failed', 'wp-breach')));
            return;
        }
        
        $format = sanitize_text_field($_POST['format'] ?? 'csv');
        $scan_id = absint($_POST['scan_id'] ?? 0);
        
        global $wpdb;
        $table_name = $wpdb->prefix . 'wp_breach_scan_results';
        
        $query = "SELECT * FROM {$table_name}";
        $params = array();
        
        if ($scan_id) {
            $query .= " WHERE id = %d";
            $params[] = $scan_id;
        } else {
            $query .= " ORDER BY created_at DESC LIMIT 100";
        }
        
        if (!empty($params)) {
            $query = $wpdb->prepare($query, $params);
        }
        
        $results = $wpdb->get_results($query, ARRAY_A);
        
        if (empty($results)) {
            wp_send_json_error(array('message' => __('No scan results found', 'wp-breach')));
            return;
        }
        
        // Format export data
        $export_data = $this->format_scan_results_for_export($results);
        
        switch ($format) {
            case 'json':
                $output = json_encode($export_data, JSON_PRETTY_PRINT);
                $content_type = 'application/json';
                break;
            
            case 'csv':
            default:
                $output = $this->convert_to_csv($export_data);
                $content_type = 'text/csv';
                break;
        }
        
        $filename = 'wp-breach-scan-results-' . date('Y-m-d-H-i-s') . '.' . $format;
        
        header('Content-Type: ' . $content_type);
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('Content-Length: ' . strlen($output));
        
        echo $output;
        exit;
    }
    
    /**
     * Validate scan configuration
     *
     * @param array $config Scan configuration
     * @return array Validated configuration
     */
    private function validate_scan_config($config) {
        $defaults = array(
            'type' => 'quick',
            'targets' => array('core', 'plugins', 'themes'),
            'depth' => 'basic',
            'schedule' => false,
            'email_notifications' => false
        );
        
        $config = wp_parse_args($config, $defaults);
        
        // Validate scan type
        $valid_types = array('quick', 'full', 'custom');
        if (!in_array($config['type'], $valid_types)) {
            $config['type'] = 'quick';
        }
        
        // Validate targets
        $valid_targets = array('core', 'plugins', 'themes', 'uploads', 'database');
        $config['targets'] = array_intersect($config['targets'], $valid_targets);
        
        if (empty($config['targets'])) {
            $config['targets'] = array('core', 'plugins', 'themes');
        }
        
        // Validate depth
        $valid_depths = array('basic', 'deep', 'comprehensive');
        if (!in_array($config['depth'], $valid_depths)) {
            $config['depth'] = 'basic';
        }
        
        return $config;
    }
    
    /**
     * Sanitize export filters
     *
     * @param array $filters Export filters
     * @return array Sanitized filters
     */
    private function sanitize_export_filters($filters) {
        $sanitized = array();
        
        if (isset($filters['severity'])) {
            $valid_severities = array('critical', 'high', 'medium', 'low');
            if (in_array($filters['severity'], $valid_severities)) {
                $sanitized['severity'] = $filters['severity'];
            }
        }
        
        if (isset($filters['status'])) {
            $valid_statuses = array('open', 'resolved', 'ignored');
            if (in_array($filters['status'], $valid_statuses)) {
                $sanitized['status'] = $filters['status'];
            }
        }
        
        if (isset($filters['type'])) {
            $sanitized['type'] = sanitize_text_field($filters['type']);
        }
        
        if (isset($filters['date_from'])) {
            $sanitized['date_from'] = sanitize_text_field($filters['date_from']);
        }
        
        if (isset($filters['date_to'])) {
            $sanitized['date_to'] = sanitize_text_field($filters['date_to']);
        }
        
        return $sanitized;
    }
    
    /**
     * Format scan results for export
     *
     * @param array $results Raw scan results
     * @return array Formatted results
     */
    private function format_scan_results_for_export($results) {
        $formatted = array();
        
        foreach ($results as $result) {
            $formatted[] = array(
                'scan_id' => $result['id'],
                'type' => $result['type'],
                'status' => $result['status'],
                'items_scanned' => $result['items_scanned'],
                'vulnerabilities_found' => $result['vulnerabilities_found'],
                'duration' => $result['duration'],
                'created_at' => $result['created_at'],
                'completed_at' => $result['completed_at'],
                'config' => $result['config'],
                'summary' => $this->extract_scan_summary($result['results'])
            );
        }
        
        return $formatted;
    }
    
    /**
     * Extract scan summary from results
     *
     * @param string $results JSON results string
     * @return string Summary text
     */
    private function extract_scan_summary($results) {
        $data = json_decode($results, true);
        
        if (!$data) {
            return 'No summary available';
        }
        
        $summary_parts = array();
        
        if (isset($data['vulnerabilities_found'])) {
            $summary_parts[] = $data['vulnerabilities_found'] . ' vulnerabilities found';
        }
        
        if (isset($data['files_scanned'])) {
            $summary_parts[] = $data['files_scanned'] . ' files scanned';
        }
        
        if (isset($data['plugins_checked'])) {
            $summary_parts[] = $data['plugins_checked'] . ' plugins checked';
        }
        
        return implode(', ', $summary_parts);
    }
    
    /**
     * Convert array to CSV format
     *
     * @param array $data Data to convert
     * @return string CSV string
     */
    private function convert_to_csv($data) {
        if (empty($data)) {
            return '';
        }
        
        $output = fopen('php://temp', 'r+');
        
        // Add headers
        fputcsv($output, array_keys($data[0]));
        
        // Add data rows
        foreach ($data as $row) {
            fputcsv($output, $row);
        }
        
        rewind($output);
        $csv = stream_get_contents($output);
        fclose($output);
        
        return $csv;
    }
}

// Initialize AJAX handler
new WP_Breach_Dashboard_Ajax();

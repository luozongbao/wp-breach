<?php
/**
 * Scanner Progress Tracking
 *
 * Handles progress tracking and reporting for scanner operations.
 *
 * @package WP_Breach
 * @since 1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class WP_Breach_Scanner_Progress
 *
 * Manages scanning progress tracking, storage, and reporting.
 */
class WP_Breach_Scanner_Progress {
    
    /**
     * Progress data storage key
     */
    const PROGRESS_OPTION_KEY = 'wp_breach_scan_progress';
    
    /**
     * Current scan session ID
     *
     * @var string
     */
    private $session_id;
    
    /**
     * Progress data
     *
     * @var array
     */
    private $progress_data;
    
    /**
     * Constructor
     *
     * @param string $session_id Unique scan session identifier
     */
    public function __construct($session_id = null) {
        $this->session_id = $session_id ?: $this->generate_session_id();
        $this->progress_data = $this->load_progress();
    }
    
    /**
     * Generate a unique session ID
     *
     * @return string Unique session identifier
     */
    private function generate_session_id() {
        return 'scan_' . wp_generate_uuid4();
    }
    
    /**
     * Initialize progress tracking for a new scan
     *
     * @param array $config Scan configuration
     * @return bool True on success, false on failure
     */
    public function initialize($config = array()) {
        $this->progress_data = array(
            'session_id' => $this->session_id,
            'status' => 'initializing',
            'start_time' => current_time('timestamp'),
            'current_step' => 0,
            'total_steps' => 0,
            'percentage' => 0,
            'current_item' => '',
            'items_processed' => 0,
            'items_total' => 0,
            'scan_type' => isset($config['scan_type']) ? $config['scan_type'] : 'full',
            'scanner_config' => $config,
            'errors' => array(),
            'warnings' => array(),
            'memory_usage' => 0,
            'execution_time' => 0,
            'estimated_time_remaining' => 0,
            'vulnerabilities_found' => 0,
            'files_scanned' => 0,
            'last_update' => current_time('timestamp')
        );
        
        return $this->save_progress();
    }
    
    /**
     * Update scan progress
     *
     * @param array $updates Progress updates
     * @return bool True on success, false on failure
     */
    public function update($updates = array()) {
        if (empty($this->progress_data)) {
            return false;
        }
        
        // Merge updates with existing data
        $this->progress_data = array_merge($this->progress_data, $updates);
        
        // Update calculated fields
        $this->progress_data['last_update'] = current_time('timestamp');
        $this->progress_data['execution_time'] = current_time('timestamp') - $this->progress_data['start_time'];
        $this->progress_data['memory_usage'] = memory_get_usage(true);
        
        // Calculate percentage if we have totals
        if ($this->progress_data['items_total'] > 0) {
            $this->progress_data['percentage'] = round(
                ($this->progress_data['items_processed'] / $this->progress_data['items_total']) * 100,
                2
            );
        }
        
        // Estimate remaining time
        if ($this->progress_data['percentage'] > 0 && $this->progress_data['percentage'] < 100) {
            $elapsed = $this->progress_data['execution_time'];
            $remaining_percentage = 100 - $this->progress_data['percentage'];
            $this->progress_data['estimated_time_remaining'] = round(
                ($elapsed * $remaining_percentage) / $this->progress_data['percentage']
            );
        }
        
        return $this->save_progress();
    }
    
    /**
     * Set scan status
     *
     * @param string $status New status
     * @return bool True on success, false on failure
     */
    public function set_status($status) {
        $valid_statuses = array('initializing', 'running', 'paused', 'completed', 'error', 'cancelled');
        
        if (!in_array($status, $valid_statuses)) {
            return false;
        }
        
        return $this->update(array('status' => $status));
    }
    
    /**
     * Set current scanning item
     *
     * @param string $item Current item being scanned
     * @return bool True on success, false on failure
     */
    public function set_current_item($item) {
        return $this->update(array('current_item' => $item));
    }
    
    /**
     * Increment processed items count
     *
     * @param int $count Number of items to add (default: 1)
     * @return bool True on success, false on failure
     */
    public function increment_processed($count = 1) {
        $new_count = $this->progress_data['items_processed'] + $count;
        return $this->update(array('items_processed' => $new_count));
    }
    
    /**
     * Set total items count
     *
     * @param int $total Total number of items to process
     * @return bool True on success, false on failure
     */
    public function set_total_items($total) {
        return $this->update(array('items_total' => $total));
    }
    
    /**
     * Add error to progress log
     *
     * @param string $error Error message
     * @param string $context Error context
     * @return bool True on success, false on failure
     */
    public function add_error($error, $context = '') {
        $error_entry = array(
            'message' => $error,
            'context' => $context,
            'timestamp' => current_time('timestamp')
        );
        
        $errors = $this->progress_data['errors'];
        $errors[] = $error_entry;
        
        return $this->update(array('errors' => $errors));
    }
    
    /**
     * Add warning to progress log
     *
     * @param string $warning Warning message
     * @param string $context Warning context
     * @return bool True on success, false on failure
     */
    public function add_warning($warning, $context = '') {
        $warning_entry = array(
            'message' => $warning,
            'context' => $context,
            'timestamp' => current_time('timestamp')
        );
        
        $warnings = $this->progress_data['warnings'];
        $warnings[] = $warning_entry;
        
        return $this->update(array('warnings' => $warnings));
    }
    
    /**
     * Increment vulnerabilities found count
     *
     * @param int $count Number of vulnerabilities to add (default: 1)
     * @return bool True on success, false on failure
     */
    public function increment_vulnerabilities($count = 1) {
        $new_count = $this->progress_data['vulnerabilities_found'] + $count;
        return $this->update(array('vulnerabilities_found' => $new_count));
    }
    
    /**
     * Increment files scanned count
     *
     * @param int $count Number of files to add (default: 1)
     * @return bool True on success, false on failure
     */
    public function increment_files_scanned($count = 1) {
        $new_count = $this->progress_data['files_scanned'] + $count;
        return $this->update(array('files_scanned' => $new_count));
    }
    
    /**
     * Get current progress data
     *
     * @return array Progress data
     */
    public function get_progress() {
        return $this->progress_data;
    }
    
    /**
     * Get scan status
     *
     * @return string Current status
     */
    public function get_status() {
        return isset($this->progress_data['status']) ? $this->progress_data['status'] : 'unknown';
    }
    
    /**
     * Get completion percentage
     *
     * @return float Completion percentage (0-100)
     */
    public function get_percentage() {
        return isset($this->progress_data['percentage']) ? $this->progress_data['percentage'] : 0;
    }
    
    /**
     * Check if scan is running
     *
     * @return bool True if scan is running, false otherwise
     */
    public function is_running() {
        return $this->get_status() === 'running';
    }
    
    /**
     * Check if scan is completed
     *
     * @return bool True if scan is completed, false otherwise
     */
    public function is_completed() {
        return $this->get_status() === 'completed';
    }
    
    /**
     * Check if scan is paused
     *
     * @return bool True if scan is paused, false otherwise
     */
    public function is_paused() {
        return $this->get_status() === 'paused';
    }
    
    /**
     * Get formatted execution time
     *
     * @return string Formatted execution time
     */
    public function get_formatted_execution_time() {
        $seconds = isset($this->progress_data['execution_time']) ? $this->progress_data['execution_time'] : 0;
        
        if ($seconds < 60) {
            return sprintf('%d seconds', $seconds);
        } elseif ($seconds < 3600) {
            return sprintf('%d minutes %d seconds', floor($seconds / 60), $seconds % 60);
        } else {
            $hours = floor($seconds / 3600);
            $minutes = floor(($seconds % 3600) / 60);
            $seconds = $seconds % 60;
            return sprintf('%d hours %d minutes %d seconds', $hours, $minutes, $seconds);
        }
    }
    
    /**
     * Get formatted memory usage
     *
     * @return string Formatted memory usage
     */
    public function get_formatted_memory_usage() {
        $bytes = isset($this->progress_data['memory_usage']) ? $this->progress_data['memory_usage'] : 0;
        
        $units = array('B', 'KB', 'MB', 'GB');
        $unitIndex = 0;
        
        while ($bytes >= 1024 && $unitIndex < count($units) - 1) {
            $bytes /= 1024;
            $unitIndex++;
        }
        
        return sprintf('%.2f %s', $bytes, $units[$unitIndex]);
    }
    
    /**
     * Reset progress data
     *
     * @return bool True on success, false on failure
     */
    public function reset() {
        $this->progress_data = array();
        return $this->delete_progress();
    }
    
    /**
     * Load progress data from storage
     *
     * @return array Progress data
     */
    private function load_progress() {
        $stored_progress = get_option(self::PROGRESS_OPTION_KEY, array());
        
        // Check if stored progress belongs to current session
        if (isset($stored_progress['session_id']) && $stored_progress['session_id'] === $this->session_id) {
            return $stored_progress;
        }
        
        return array();
    }
    
    /**
     * Save progress data to storage
     *
     * @return bool True on success, false on failure
     */
    private function save_progress() {
        return update_option(self::PROGRESS_OPTION_KEY, $this->progress_data);
    }
    
    /**
     * Delete progress data from storage
     *
     * @return bool True on success, false on failure
     */
    private function delete_progress() {
        return delete_option(self::PROGRESS_OPTION_KEY);
    }
    
    /**
     * Get progress summary for display
     *
     * @return array Progress summary
     */
    public function get_summary() {
        return array(
            'status' => $this->get_status(),
            'percentage' => $this->get_percentage(),
            'current_item' => isset($this->progress_data['current_item']) ? $this->progress_data['current_item'] : '',
            'items_processed' => isset($this->progress_data['items_processed']) ? $this->progress_data['items_processed'] : 0,
            'items_total' => isset($this->progress_data['items_total']) ? $this->progress_data['items_total'] : 0,
            'vulnerabilities_found' => isset($this->progress_data['vulnerabilities_found']) ? $this->progress_data['vulnerabilities_found'] : 0,
            'files_scanned' => isset($this->progress_data['files_scanned']) ? $this->progress_data['files_scanned'] : 0,
            'execution_time' => $this->get_formatted_execution_time(),
            'memory_usage' => $this->get_formatted_memory_usage(),
            'estimated_time_remaining' => isset($this->progress_data['estimated_time_remaining']) ? $this->progress_data['estimated_time_remaining'] : 0,
            'error_count' => count($this->progress_data['errors']),
            'warning_count' => count($this->progress_data['warnings'])
        );
    }
}

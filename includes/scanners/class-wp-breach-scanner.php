<?php
/**
 * Main Scanner Class
 *
 * Main scanner orchestrator that coordinates multiple scanner types and manages scanning operations.
 *
 * @package WP_Breach
 * @since 1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class WP_Breach_Scanner
 *
 * Main scanner class that orchestrates the scanning process using multiple scanner types.
 */
class WP_Breach_Scanner implements WP_Breach_Scanner_Interface {
    
    /**
     * Scanner configuration
     *
     * @var array
     */
    private $config;
    
    /**
     * Progress tracker
     *
     * @var WP_Breach_Scanner_Progress
     */
    private $progress;
    
    /**
     * Active scanner instances
     *
     * @var array
     */
    private $scanners;
    
    /**
     * Scan results
     *
     * @var array
     */
    private $results;
    
    /**
     * Current scan session ID
     *
     * @var string
     */
    private $session_id;
    
    /**
     * Default configuration
     *
     * @var array
     */
    private $default_config = array(
        'scanner_types' => array('core', 'plugin', 'theme', 'database', 'filesystem'),
        'max_execution_time' => 300, // 5 minutes
        'memory_limit' => '256M',
        'batch_size' => 100,
        'timeout_per_scanner' => 60,
        'max_vulnerabilities' => 1000,
        'enable_progress_tracking' => true,
        'enable_detailed_logging' => false,
        'vulnerability_types' => array(
            'sql_injection',
            'xss',
            'csrf',
            'file_inclusion',
            'directory_traversal',
            'command_injection',
            'code_injection',
            'insecure_permissions',
            'weak_passwords',
            'outdated_software'
        )
    );
    
    /**
     * Constructor
     */
    public function __construct() {
        $this->config = $this->default_config;
        $this->scanners = array();
        $this->results = array();
        $this->session_id = null;
        $this->progress = null;
    }
    
    /**
     * Initialize the scanner
     *
     * @param array $config Scanner configuration options
     * @return bool True on success, false on failure
     */
    public function initialize($config = array()) {
        try {
            // Merge with default configuration
            $this->config = array_merge($this->default_config, $config);
            
            // Validate configuration
            $validation_result = $this->validate_config($this->config);
            if (is_wp_error($validation_result)) {
                error_log('WP Breach Scanner: Configuration validation failed - ' . $validation_result->get_error_message());
                return false;
            }
            
            // Generate session ID
            $this->session_id = 'scan_' . wp_generate_uuid4();
            
            // Initialize progress tracker if enabled
            if ($this->config['enable_progress_tracking']) {
                $this->progress = new WP_Breach_Scanner_Progress($this->session_id);
                $this->progress->initialize($this->config);
            }
            
            // Set PHP limits
            $this->set_php_limits();
            
            // Initialize scanners
            $this->scanners = WP_Breach_Scanner_Factory::create_multiple(
                $this->config['scanner_types'],
                $this->config
            );
            
            if (empty($this->scanners)) {
                error_log('WP Breach Scanner: No scanners could be initialized');
                return false;
            }
            
            return true;
            
        } catch (Exception $e) {
            error_log('WP Breach Scanner: Initialization failed - ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Start the scanning process
     *
     * @param array $options Scan options and filters
     * @return bool True if scan started successfully, false otherwise
     */
    public function start_scan($options = array()) {
        try {
            // Check if already running
            if ($this->progress && $this->progress->is_running()) {
                return false;
            }
            
            // Update progress
            if ($this->progress) {
                $this->progress->set_status('running');
                $this->progress->set_total_items(count($this->scanners));
            }
            
            // Reset results
            $this->results = array();
            
            // Run each scanner
            foreach ($this->scanners as $type => $scanner) {
                if ($this->progress) {
                    $this->progress->set_current_item(sprintf('Running %s scanner', $type));
                }
                
                $this->log_debug(sprintf('Starting %s scanner', $type));
                
                // Set timeout for individual scanner
                set_time_limit($this->config['timeout_per_scanner']);
                
                // Run the scanner
                $scanner_result = $scanner->start_scan($options);
                
                if ($scanner_result) {
                    // Get results from scanner
                    $scanner_results = $scanner->get_results();
                    $this->results[$type] = $scanner_results;
                    
                    // Update progress with vulnerabilities found
                    if ($this->progress && isset($scanner_results['vulnerabilities'])) {
                        $this->progress->increment_vulnerabilities(count($scanner_results['vulnerabilities']));
                    }
                    
                    $this->log_debug(sprintf('%s scanner completed successfully', $type));
                } else {
                    $this->log_error(sprintf('%s scanner failed', $type));
                    if ($this->progress) {
                        $this->progress->add_error(sprintf('%s scanner failed', $type), $type);
                    }
                }
                
                // Update progress
                if ($this->progress) {
                    $this->progress->increment_processed();
                }
                
                // Check for memory/time limits
                if ($this->should_stop_scanning()) {
                    $this->log_warning('Stopping scan due to resource limits');
                    if ($this->progress) {
                        $this->progress->add_warning('Scan stopped due to resource limits');
                    }
                    break;
                }
            }
            
            // Mark as completed
            if ($this->progress) {
                $this->progress->set_status('completed');
            }
            
            // Store results in database
            $this->store_results();
            
            $this->log_debug('Scan completed successfully');
            return true;
            
        } catch (Exception $e) {
            $this->log_error('Scan failed: ' . $e->getMessage());
            if ($this->progress) {
                $this->progress->set_status('error');
                $this->progress->add_error('Scan failed: ' . $e->getMessage());
            }
            return false;
        }
    }
    
    /**
     * Pause the current scan
     *
     * @return bool True if scan paused successfully, false otherwise
     */
    public function pause_scan() {
        if (!$this->progress) {
            return false;
        }
        
        if (!$this->progress->is_running()) {
            return false;
        }
        
        return $this->progress->set_status('paused');
    }
    
    /**
     * Resume a paused scan
     *
     * @return bool True if scan resumed successfully, false otherwise
     */
    public function resume_scan() {
        if (!$this->progress) {
            return false;
        }
        
        if (!$this->progress->is_paused()) {
            return false;
        }
        
        return $this->progress->set_status('running');
    }
    
    /**
     * Stop the current scan
     *
     * @return bool True if scan stopped successfully, false otherwise
     */
    public function stop_scan() {
        if (!$this->progress) {
            return false;
        }
        
        if ($this->progress->is_completed()) {
            return true;
        }
        
        // Stop all active scanners
        foreach ($this->scanners as $scanner) {
            if (method_exists($scanner, 'stop_scan')) {
                $scanner->stop_scan();
            }
        }
        
        return $this->progress->set_status('cancelled');
    }
    
    /**
     * Get the current scan progress
     *
     * @return array Progress information including percentage, current item, etc.
     */
    public function get_progress() {
        if (!$this->progress) {
            return array(
                'status' => 'unknown',
                'percentage' => 0,
                'message' => 'Progress tracking not enabled'
            );
        }
        
        return $this->progress->get_summary();
    }
    
    /**
     * Get scan results
     *
     * @param string $format Output format (array, json, xml)
     * @return mixed Scan results in specified format
     */
    public function get_results($format = 'array') {
        switch ($format) {
            case 'json':
                return json_encode($this->results);
            
            case 'xml':
                return $this->convert_results_to_xml($this->results);
            
            case 'array':
            default:
                return $this->results;
        }
    }
    
    /**
     * Get scanner status
     *
     * @return string Current scanner status (idle, running, paused, completed, error)
     */
    public function get_status() {
        if (!$this->progress) {
            return 'idle';
        }
        
        return $this->progress->get_status();
    }
    
    /**
     * Set scanner configuration
     *
     * @param array $config Configuration options
     * @return bool True on success, false on failure
     */
    public function set_config($config) {
        $validation_result = $this->validate_config($config);
        if (is_wp_error($validation_result)) {
            return false;
        }
        
        $this->config = array_merge($this->config, $config);
        return true;
    }
    
    /**
     * Get scanner configuration
     *
     * @return array Current configuration options
     */
    public function get_config() {
        return $this->config;
    }
    
    /**
     * Validate scanner configuration
     *
     * @param array $config Configuration to validate
     * @return bool|WP_Error True if valid, WP_Error if invalid
     */
    public function validate_config($config) {
        // Check scanner types
        if (isset($config['scanner_types'])) {
            if (!is_array($config['scanner_types'])) {
                return new WP_Error('invalid_config', 'scanner_types must be an array');
            }
            
            foreach ($config['scanner_types'] as $type) {
                if (!WP_Breach_Scanner_Factory::is_valid_type($type)) {
                    return new WP_Error('invalid_config', sprintf('Invalid scanner type: %s', $type));
                }
            }
        }
        
        // Check numeric values
        $numeric_fields = array('max_execution_time', 'batch_size', 'timeout_per_scanner', 'max_vulnerabilities');
        foreach ($numeric_fields as $field) {
            if (isset($config[$field]) && (!is_numeric($config[$field]) || $config[$field] < 0)) {
                return new WP_Error('invalid_config', sprintf('%s must be a positive number', $field));
            }
        }
        
        // Check memory limit format
        if (isset($config['memory_limit'])) {
            if (!preg_match('/^\d+[KMG]?$/', $config['memory_limit'])) {
                return new WP_Error('invalid_config', 'memory_limit must be in format like 256M, 1G, etc.');
            }
        }
        
        return true;
    }
    
    /**
     * Clean up resources after scan completion
     *
     * @return bool True on success, false on failure
     */
    public function cleanup() {
        // Cleanup scanners
        foreach ($this->scanners as $scanner) {
            if (method_exists($scanner, 'cleanup')) {
                $scanner->cleanup();
            }
        }
        
        // Reset internal state
        $this->scanners = array();
        $this->results = array();
        
        // Reset progress if scan is completed
        if ($this->progress && $this->progress->is_completed()) {
            $this->progress->reset();
        }
        
        return true;
    }
    
    /**
     * Get supported vulnerability types for this scanner
     *
     * @return array Array of vulnerability type identifiers
     */
    public function get_supported_vulnerabilities() {
        return $this->config['vulnerability_types'];
    }
    
    /**
     * Get scanner metadata
     *
     * @return array Scanner metadata (name, version, description, etc.)
     */
    public function get_metadata() {
        return array(
            'name' => 'WP Breach Main Scanner',
            'version' => '1.0.0',
            'description' => 'Main scanner orchestrator that coordinates multiple scanner types',
            'author' => 'WP Breach Team',
            'supported_vulnerabilities' => $this->get_supported_vulnerabilities(),
            'scanner_types' => $this->config['scanner_types']
        );
    }
    
    /**
     * Set PHP execution limits
     *
     * @return void
     */
    private function set_php_limits() {
        // Set execution time limit
        if (function_exists('set_time_limit')) {
            set_time_limit($this->config['max_execution_time']);
        }
        
        // Set memory limit
        if (function_exists('ini_set')) {
            ini_set('memory_limit', $this->config['memory_limit']);
        }
    }
    
    /**
     * Check if scanning should be stopped due to resource limits
     *
     * @return bool True if scanning should stop, false otherwise
     */
    private function should_stop_scanning() {
        // Check memory usage
        $memory_usage = memory_get_usage(true);
        $memory_limit = $this->parse_memory_limit($this->config['memory_limit']);
        
        if ($memory_usage > ($memory_limit * 0.9)) { // 90% of memory limit
            return true;
        }
        
        // Check execution time
        if ($this->progress) {
            $execution_time = $this->progress->get_progress()['execution_time'];
            if ($execution_time > ($this->config['max_execution_time'] * 0.9)) { // 90% of time limit
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Parse memory limit string to bytes
     *
     * @param string $limit Memory limit string (e.g., "256M")
     * @return int Memory limit in bytes
     */
    private function parse_memory_limit($limit) {
        $limit = trim($limit);
        $last = strtoupper(substr($limit, -1));
        $value = (int) substr($limit, 0, -1);
        
        switch ($last) {
            case 'G':
                $value *= 1024;
            case 'M':
                $value *= 1024;
            case 'K':
                $value *= 1024;
        }
        
        return $value;
    }
    
    /**
     * Store scan results in database
     *
     * @return bool True on success, false on failure
     */
    private function store_results() {
        try {
            global $wpdb;
            
            $table_name = $wpdb->prefix . 'wp_breach_scan_results';
            
            $scan_data = array(
                'session_id' => $this->session_id,
                'scan_type' => 'full',
                'status' => $this->get_status(),
                'results' => json_encode($this->results),
                'config' => json_encode($this->config),
                'created_at' => current_time('mysql'),
                'completed_at' => current_time('mysql')
            );
            
            $result = $wpdb->insert($table_name, $scan_data);
            
            return $result !== false;
            
        } catch (Exception $e) {
            $this->log_error('Failed to store scan results: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Convert results to XML format
     *
     * @param array $results Results array
     * @return string XML formatted results
     */
    private function convert_results_to_xml($results) {
        $xml = new SimpleXMLElement('<scan_results/>');
        
        foreach ($results as $scanner_type => $scanner_results) {
            $scanner_node = $xml->addChild('scanner');
            $scanner_node->addAttribute('type', $scanner_type);
            
            if (isset($scanner_results['vulnerabilities'])) {
                $vulns_node = $scanner_node->addChild('vulnerabilities');
                foreach ($scanner_results['vulnerabilities'] as $vuln) {
                    $vuln_node = $vulns_node->addChild('vulnerability');
                    foreach ($vuln as $key => $value) {
                        $vuln_node->addChild($key, htmlspecialchars($value));
                    }
                }
            }
        }
        
        return $xml->asXML();
    }
    
    /**
     * Log debug message
     *
     * @param string $message Debug message
     * @return void
     */
    private function log_debug($message) {
        if ($this->config['enable_detailed_logging']) {
            error_log('WP Breach Scanner [DEBUG]: ' . $message);
        }
    }
    
    /**
     * Log error message
     *
     * @param string $message Error message
     * @return void
     */
    private function log_error($message) {
        error_log('WP Breach Scanner [ERROR]: ' . $message);
    }
    
    /**
     * Log warning message
     *
     * @param string $message Warning message
     * @return void
     */
    private function log_warning($message) {
        error_log('WP Breach Scanner [WARNING]: ' . $message);
    }
}

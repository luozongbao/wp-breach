<?php
/**
 * Scanner Interface
 *
 * Defines the contract that all scanner classes must implement.
 *
 * @package WP_Breach
 * @since 1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Interface WP_Breach_Scanner_Interface
 *
 * Defines the standard methods that all scanner implementations must provide.
 */
interface WP_Breach_Scanner_Interface {
    
    /**
     * Initialize the scanner
     *
     * @param array $config Scanner configuration options
     * @return bool True on success, false on failure
     */
    public function initialize($config = array());
    
    /**
     * Start the scanning process
     *
     * @param array $options Scan options and filters
     * @return bool True if scan started successfully, false otherwise
     */
    public function start_scan($options = array());
    
    /**
     * Pause the current scan
     *
     * @return bool True if scan paused successfully, false otherwise
     */
    public function pause_scan();
    
    /**
     * Resume a paused scan
     *
     * @return bool True if scan resumed successfully, false otherwise
     */
    public function resume_scan();
    
    /**
     * Stop the current scan
     *
     * @return bool True if scan stopped successfully, false otherwise
     */
    public function stop_scan();
    
    /**
     * Get the current scan progress
     *
     * @return array Progress information including percentage, current item, etc.
     */
    public function get_progress();
    
    /**
     * Get scan results
     *
     * @param string $format Output format (array, json, xml)
     * @return mixed Scan results in specified format
     */
    public function get_results($format = 'array');
    
    /**
     * Get scanner status
     *
     * @return string Current scanner status (idle, running, paused, completed, error)
     */
    public function get_status();
    
    /**
     * Set scanner configuration
     *
     * @param array $config Configuration options
     * @return bool True on success, false on failure
     */
    public function set_config($config);
    
    /**
     * Get scanner configuration
     *
     * @return array Current configuration options
     */
    public function get_config();
    
    /**
     * Validate scanner configuration
     *
     * @param array $config Configuration to validate
     * @return bool|WP_Error True if valid, WP_Error if invalid
     */
    public function validate_config($config);
    
    /**
     * Clean up resources after scan completion
     *
     * @return bool True on success, false on failure
     */
    public function cleanup();
    
    /**
     * Get supported vulnerability types for this scanner
     *
     * @return array Array of vulnerability type identifiers
     */
    public function get_supported_vulnerabilities();
    
    /**
     * Get scanner metadata
     *
     * @return array Scanner metadata (name, version, description, etc.)
     */
    public function get_metadata();
}

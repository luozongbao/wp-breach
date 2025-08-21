<?php
/**
 * Scanner Factory
 *
 * Factory pattern implementation for creating scanner instances.
 *
 * @package WP_Breach
 * @since 1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class WP_Breach_Scanner_Factory
 *
 * Factory for creating and managing scanner instances.
 */
class WP_Breach_Scanner_Factory {
    
    /**
     * Available scanner types
     *
     * @var array
     */
    private static $scanner_types = array(
        'core' => 'WP_Breach_Core_Scanner',
        'plugin' => 'WP_Breach_Plugin_Scanner',
        'theme' => 'WP_Breach_Theme_Scanner',
        'database' => 'WP_Breach_Database_Scanner',
        'filesystem' => 'WP_Breach_Filesystem_Scanner'
    );
    
    /**
     * Scanner instances cache
     *
     * @var array
     */
    private static $instances = array();
    
    /**
     * Create a scanner instance
     *
     * @param string $type Scanner type
     * @param array $config Scanner configuration
     * @return WP_Breach_Scanner_Interface|WP_Error Scanner instance or error
     */
    public static function create($type, $config = array()) {
        // Validate scanner type
        if (!self::is_valid_type($type)) {
            return new WP_Error(
                'invalid_scanner_type',
                sprintf(__('Invalid scanner type: %s', 'wp-breach'), $type)
            );
        }
        
        // Get scanner class name
        $class_name = self::$scanner_types[$type];
        
        // Check if class exists
        if (!class_exists($class_name)) {
            // Try to load the scanner class
            $result = self::load_scanner_class($type);
            if (is_wp_error($result)) {
                return $result;
            }
        }
        
        // Create scanner instance
        try {
            $scanner = new $class_name();
            
            // Verify it implements the scanner interface
            if (!$scanner instanceof WP_Breach_Scanner_Interface) {
                return new WP_Error(
                    'invalid_scanner_implementation',
                    sprintf(__('Scanner %s does not implement WP_Breach_Scanner_Interface', 'wp-breach'), $class_name)
                );
            }
            
            // Initialize the scanner
            $init_result = $scanner->initialize($config);
            if (!$init_result) {
                return new WP_Error(
                    'scanner_initialization_failed',
                    sprintf(__('Failed to initialize %s scanner', 'wp-breach'), $type)
                );
            }
            
            return $scanner;
            
        } catch (Exception $e) {
            return new WP_Error(
                'scanner_creation_failed',
                sprintf(__('Failed to create %s scanner: %s', 'wp-breach'), $type, $e->getMessage())
            );
        }
    }
    
    /**
     * Get or create a scanner instance (singleton pattern)
     *
     * @param string $type Scanner type
     * @param array $config Scanner configuration
     * @return WP_Breach_Scanner_Interface|WP_Error Scanner instance or error
     */
    public static function get_instance($type, $config = array()) {
        $cache_key = $type . '_' . md5(serialize($config));
        
        if (!isset(self::$instances[$cache_key])) {
            self::$instances[$cache_key] = self::create($type, $config);
        }
        
        return self::$instances[$cache_key];
    }
    
    /**
     * Create multiple scanner instances
     *
     * @param array $types Array of scanner types
     * @param array $config Common configuration for all scanners
     * @return array Array of scanner instances
     */
    public static function create_multiple($types, $config = array()) {
        $scanners = array();
        
        foreach ($types as $type) {
            $scanner = self::create($type, $config);
            if (!is_wp_error($scanner)) {
                $scanners[$type] = $scanner;
            } else {
                // Log error but continue with other scanners
                error_log(sprintf('WP Breach: Failed to create %s scanner: %s', $type, $scanner->get_error_message()));
            }
        }
        
        return $scanners;
    }
    
    /**
     * Get all available scanner types
     *
     * @return array Available scanner types
     */
    public static function get_available_types() {
        return array_keys(self::$scanner_types);
    }
    
    /**
     * Check if a scanner type is valid
     *
     * @param string $type Scanner type to check
     * @return bool True if valid, false otherwise
     */
    public static function is_valid_type($type) {
        return isset(self::$scanner_types[$type]);
    }
    
    /**
     * Register a custom scanner type
     *
     * @param string $type Scanner type identifier
     * @param string $class_name Scanner class name
     * @return bool True on success, false on failure
     */
    public static function register_scanner($type, $class_name) {
        // Validate inputs
        if (empty($type) || empty($class_name)) {
            return false;
        }
        
        // Check if type already exists
        if (isset(self::$scanner_types[$type])) {
            return false;
        }
        
        // Register the scanner
        self::$scanner_types[$type] = $class_name;
        
        return true;
    }
    
    /**
     * Unregister a scanner type
     *
     * @param string $type Scanner type to unregister
     * @return bool True on success, false on failure
     */
    public static function unregister_scanner($type) {
        if (!isset(self::$scanner_types[$type])) {
            return false;
        }
        
        unset(self::$scanner_types[$type]);
        
        // Clear any cached instances
        foreach (self::$instances as $cache_key => $instance) {
            if (strpos($cache_key, $type . '_') === 0) {
                unset(self::$instances[$cache_key]);
            }
        }
        
        return true;
    }
    
    /**
     * Get scanner metadata for all types
     *
     * @return array Scanner metadata for all types
     */
    public static function get_all_metadata() {
        $metadata = array();
        
        foreach (self::$scanner_types as $type => $class_name) {
            try {
                $scanner = self::create($type);
                if (!is_wp_error($scanner)) {
                    $metadata[$type] = $scanner->get_metadata();
                }
            } catch (Exception $e) {
                // Skip scanners that can't be loaded
                continue;
            }
        }
        
        return $metadata;
    }
    
    /**
     * Load a scanner class file
     *
     * @param string $type Scanner type
     * @return bool|WP_Error True on success, WP_Error on failure
     */
    private static function load_scanner_class($type) {
        $class_name = self::$scanner_types[$type];
        
        // Convert class name to filename
        $filename = 'class-' . str_replace('_', '-', strtolower($class_name)) . '.php';
        
        // Look for the file in the scanners directory
        $scanner_file = WP_BREACH_PLUGIN_DIR . 'includes/scanners/' . $filename;
        
        if (!file_exists($scanner_file)) {
            return new WP_Error(
                'scanner_file_not_found',
                sprintf(__('Scanner file not found: %s', 'wp-breach'), $scanner_file)
            );
        }
        
        require_once $scanner_file;
        
        if (!class_exists($class_name)) {
            return new WP_Error(
                'scanner_class_not_found',
                sprintf(__('Scanner class not found after loading file: %s', 'wp-breach'), $class_name)
            );
        }
        
        return true;
    }
    
    /**
     * Clear all cached scanner instances
     *
     * @return void
     */
    public static function clear_cache() {
        self::$instances = array();
    }
    
    /**
     * Get scanner capabilities for a specific type
     *
     * @param string $type Scanner type
     * @return array|WP_Error Scanner capabilities or error
     */
    public static function get_scanner_capabilities($type) {
        $scanner = self::create($type);
        
        if (is_wp_error($scanner)) {
            return $scanner;
        }
        
        return array(
            'supported_vulnerabilities' => $scanner->get_supported_vulnerabilities(),
            'metadata' => $scanner->get_metadata()
        );
    }
    
    /**
     * Validate scanner configuration for a specific type
     *
     * @param string $type Scanner type
     * @param array $config Configuration to validate
     * @return bool|WP_Error True if valid, WP_Error if invalid
     */
    public static function validate_config($type, $config) {
        if (!self::is_valid_type($type)) {
            return new WP_Error(
                'invalid_scanner_type',
                sprintf(__('Invalid scanner type: %s', 'wp-breach'), $type)
            );
        }
        
        $scanner = self::create($type);
        
        if (is_wp_error($scanner)) {
            return $scanner;
        }
        
        return $scanner->validate_config($config);
    }
    
    /**
     * Get recommended scanners for a specific vulnerability type
     *
     * @param string $vulnerability_type Vulnerability type
     * @return array Array of recommended scanner types
     */
    public static function get_recommended_scanners($vulnerability_type) {
        $recommended = array();
        
        foreach (self::$scanner_types as $type => $class_name) {
            try {
                $scanner = self::create($type);
                if (!is_wp_error($scanner)) {
                    $supported = $scanner->get_supported_vulnerabilities();
                    if (in_array($vulnerability_type, $supported)) {
                        $recommended[] = $type;
                    }
                }
            } catch (Exception $e) {
                // Skip scanners that can't be loaded
                continue;
            }
        }
        
        return $recommended;
    }
}

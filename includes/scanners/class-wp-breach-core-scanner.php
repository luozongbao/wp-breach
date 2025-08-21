<?php
/**
 * WordPress Core Scanner
 *
 * Scanner for detecting vulnerabilities in WordPress core files and configuration.
 *
 * @package WP_Breach
 * @since 1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class WP_Breach_Core_Scanner
 *
 * Scans WordPress core for vulnerabilities and security issues.
 */
class WP_Breach_Core_Scanner implements WP_Breach_Scanner_Interface {
    
    /**
     * Scanner configuration
     *
     * @var array
     */
    private $config;
    
    /**
     * Scanner status
     *
     * @var string
     */
    private $status;
    
    /**
     * Scan results
     *
     * @var array
     */
    private $results;
    
    /**
     * Progress tracker
     *
     * @var WP_Breach_Scanner_Progress
     */
    private $progress;
    
    /**
     * Default configuration
     *
     * @var array
     */
    private $default_config = array(
        'check_version' => true,
        'check_config' => true,
        'check_permissions' => true,
        'check_debug_mode' => true,
        'check_file_editing' => true,
        'check_uploads_security' => true,
        'check_database_prefix' => true,
        'check_salt_keys' => true,
        'timeout' => 60
    );
    
    /**
     * Constructor
     */
    public function __construct() {
        $this->config = $this->default_config;
        $this->status = 'idle';
        $this->results = array();
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
            // Merge configuration
            $this->config = array_merge($this->default_config, $config);
            
            // Validate configuration
            $validation_result = $this->validate_config($this->config);
            if (is_wp_error($validation_result)) {
                return false;
            }
            
            // Initialize progress tracker if needed
            if (isset($config['progress_tracker'])) {
                $this->progress = $config['progress_tracker'];
            }
            
            $this->status = 'initialized';
            return true;
            
        } catch (Exception $e) {
            error_log('WP Breach Core Scanner: Initialization failed - ' . $e->getMessage());
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
            $this->status = 'running';
            $this->results = array(
                'vulnerabilities' => array(),
                'warnings' => array(),
                'info' => array(),
                'scan_summary' => array()
            );
            
            // Check WordPress version
            if ($this->config['check_version']) {
                $this->check_wordpress_version();
            }
            
            // Check configuration security
            if ($this->config['check_config']) {
                $this->check_configuration_security();
            }
            
            // Check file permissions
            if ($this->config['check_permissions']) {
                $this->check_file_permissions();
            }
            
            // Check debug mode
            if ($this->config['check_debug_mode']) {
                $this->check_debug_mode();
            }
            
            // Check file editing capabilities
            if ($this->config['check_file_editing']) {
                $this->check_file_editing();
            }
            
            // Check uploads directory security
            if ($this->config['check_uploads_security']) {
                $this->check_uploads_security();
            }
            
            // Check database prefix
            if ($this->config['check_database_prefix']) {
                $this->check_database_prefix();
            }
            
            // Check salt keys
            if ($this->config['check_salt_keys']) {
                $this->check_salt_keys();
            }
            
            // Generate scan summary
            $this->generate_scan_summary();
            
            $this->status = 'completed';
            return true;
            
        } catch (Exception $e) {
            $this->status = 'error';
            $this->add_vulnerability('scan_error', 'high', 'Scan Error', 
                'Core scanner encountered an error: ' . $e->getMessage(), 
                'core', '', array('exception' => $e->getMessage())
            );
            return false;
        }
    }
    
    /**
     * Check WordPress version for vulnerabilities
     *
     * @return void
     */
    private function check_wordpress_version() {
        global $wp_version;
        
        $current_version = $wp_version;
        $latest_version = $this->get_latest_wordpress_version();
        
        // Check if version is outdated
        if (version_compare($current_version, $latest_version, '<')) {
            $this->add_vulnerability(
                'outdated_wordpress',
                'high',
                'Outdated WordPress Version',
                sprintf('WordPress version %s is outdated. Latest version is %s.', $current_version, $latest_version),
                'core',
                'wp-config.php',
                array(
                    'current_version' => $current_version,
                    'latest_version' => $latest_version,
                    'recommendation' => 'Update WordPress to the latest version'
                )
            );
        }
        
        // Check for known vulnerable versions
        $vulnerable_versions = $this->get_vulnerable_wordpress_versions();
        if (in_array($current_version, $vulnerable_versions)) {
            $this->add_vulnerability(
                'vulnerable_wordpress_version',
                'critical',
                'Known Vulnerable WordPress Version',
                sprintf('WordPress version %s has known security vulnerabilities.', $current_version),
                'core',
                'wp-config.php',
                array(
                    'current_version' => $current_version,
                    'recommendation' => 'Immediately update WordPress to the latest version'
                )
            );
        }
    }
    
    /**
     * Check WordPress configuration security
     *
     * @return void
     */
    private function check_configuration_security() {
        // Check if wp-config.php is in the right location
        $config_file = ABSPATH . 'wp-config.php';
        $parent_config = dirname(ABSPATH) . '/wp-config.php';
        
        if (file_exists($parent_config) && !file_exists($config_file)) {
            $this->add_warning(
                'config_in_parent_directory',
                'medium',
                'wp-config.php in Parent Directory',
                'wp-config.php is located in the parent directory, which may be accessible via web.',
                'core',
                $parent_config
            );
        }
        
        // Check if sample config files exist
        $sample_files = array(
            ABSPATH . 'wp-config-sample.php',
            ABSPATH . 'readme.html',
            ABSPATH . 'license.txt'
        );
        
        foreach ($sample_files as $file) {
            if (file_exists($file)) {
                $this->add_warning(
                    'sample_files_present',
                    'low',
                    'Sample Files Present',
                    sprintf('Sample file %s is present and may expose information.', basename($file)),
                    'core',
                    $file
                );
            }
        }
        
        // Check for backup files
        $backup_patterns = array(
            '*.bak',
            '*.backup',
            '*.old',
            '*~',
            '*.tmp'
        );
        
        foreach ($backup_patterns as $pattern) {
            $backup_files = glob(ABSPATH . $pattern);
            foreach ($backup_files as $backup_file) {
                $this->add_vulnerability(
                    'backup_files_accessible',
                    'medium',
                    'Backup Files Accessible',
                    sprintf('Backup file %s may be accessible via web.', basename($backup_file)),
                    'core',
                    $backup_file,
                    array('recommendation' => 'Remove backup files from web-accessible directories')
                );
            }
        }
    }
    
    /**
     * Check file permissions
     *
     * @return void
     */
    private function check_file_permissions() {
        $critical_files = array(
            ABSPATH . 'wp-config.php' => 0600,
            ABSPATH . '.htaccess' => 0644,
            ABSPATH . 'index.php' => 0644
        );
        
        foreach ($critical_files as $file => $recommended_perms) {
            if (file_exists($file)) {
                $current_perms = fileperms($file) & 0777;
                
                if ($current_perms !== $recommended_perms) {
                    $severity = ($current_perms & 0002) ? 'high' : 'medium'; // World writable = high
                    
                    $this->add_vulnerability(
                        'incorrect_file_permissions',
                        $severity,
                        'Incorrect File Permissions',
                        sprintf('File %s has permissions %o, recommended %o.', 
                            basename($file), $current_perms, $recommended_perms),
                        'core',
                        $file,
                        array(
                            'current_permissions' => sprintf('%o', $current_perms),
                            'recommended_permissions' => sprintf('%o', $recommended_perms),
                            'recommendation' => sprintf('chmod %o %s', $recommended_perms, $file)
                        )
                    );
                }
            }
        }
        
        // Check directory permissions
        $critical_dirs = array(
            ABSPATH => 0755,
            ABSPATH . 'wp-content/' => 0755,
            ABSPATH . 'wp-includes/' => 0755,
            ABSPATH . 'wp-admin/' => 0755
        );
        
        foreach ($critical_dirs as $dir => $recommended_perms) {
            if (is_dir($dir)) {
                $current_perms = fileperms($dir) & 0777;
                
                if ($current_perms !== $recommended_perms) {
                    $severity = ($current_perms & 0002) ? 'high' : 'medium';
                    
                    $this->add_vulnerability(
                        'incorrect_directory_permissions',
                        $severity,
                        'Incorrect Directory Permissions',
                        sprintf('Directory %s has permissions %o, recommended %o.', 
                            basename($dir), $current_perms, $recommended_perms),
                        'core',
                        $dir,
                        array(
                            'current_permissions' => sprintf('%o', $current_perms),
                            'recommended_permissions' => sprintf('%o', $recommended_perms),
                            'recommendation' => sprintf('chmod %o %s', $recommended_perms, $dir)
                        )
                    );
                }
            }
        }
    }
    
    /**
     * Check debug mode configuration
     *
     * @return void
     */
    private function check_debug_mode() {
        if (defined('WP_DEBUG') && WP_DEBUG === true) {
            $severity = 'medium';
            
            // Check if debug log is enabled and accessible
            if (defined('WP_DEBUG_LOG') && WP_DEBUG_LOG === true) {
                $log_file = WP_CONTENT_DIR . '/debug.log';
                if (file_exists($log_file) && is_readable($log_file)) {
                    $severity = 'high';
                }
            }
            
            $this->add_vulnerability(
                'debug_mode_enabled',
                $severity,
                'Debug Mode Enabled',
                'WordPress debug mode is enabled, which may expose sensitive information.',
                'core',
                'wp-config.php',
                array(
                    'wp_debug' => WP_DEBUG,
                    'wp_debug_log' => defined('WP_DEBUG_LOG') ? WP_DEBUG_LOG : false,
                    'wp_debug_display' => defined('WP_DEBUG_DISPLAY') ? WP_DEBUG_DISPLAY : true,
                    'recommendation' => 'Disable debug mode in production environments'
                )
            );
        }
    }
    
    /**
     * Check file editing capabilities
     *
     * @return void
     */
    private function check_file_editing() {
        if (!defined('DISALLOW_FILE_EDIT') || DISALLOW_FILE_EDIT !== true) {
            $this->add_vulnerability(
                'file_editing_enabled',
                'medium',
                'File Editing Enabled',
                'WordPress file editing is enabled, allowing plugin/theme editing from admin.',
                'core',
                'wp-config.php',
                array(
                    'disallow_file_edit' => defined('DISALLOW_FILE_EDIT') ? DISALLOW_FILE_EDIT : 'undefined',
                    'recommendation' => 'Add define(\'DISALLOW_FILE_EDIT\', true); to wp-config.php'
                )
            );
        }
        
        if (!defined('DISALLOW_FILE_MODS') || DISALLOW_FILE_MODS !== true) {
            $this->add_warning(
                'file_modifications_enabled',
                'low',
                'File Modifications Enabled',
                'WordPress allows file modifications (plugin/theme installation).',
                'core',
                'wp-config.php'
            );
        }
    }
    
    /**
     * Check uploads directory security
     *
     * @return void
     */
    private function check_uploads_security() {
        $upload_dir = wp_upload_dir();
        $uploads_path = $upload_dir['basedir'];
        
        // Check if uploads directory exists
        if (!is_dir($uploads_path)) {
            $this->add_warning(
                'uploads_directory_missing',
                'medium',
                'Uploads Directory Missing',
                'WordPress uploads directory does not exist.',
                'core',
                $uploads_path
            );
            return;
        }
        
        // Check uploads directory permissions
        $perms = fileperms($uploads_path) & 0777;
        if ($perms & 0002) { // World writable
            $this->add_vulnerability(
                'uploads_world_writable',
                'high',
                'Uploads Directory World Writable',
                'Uploads directory is world writable, allowing arbitrary file uploads.',
                'core',
                $uploads_path,
                array(
                    'current_permissions' => sprintf('%o', $perms),
                    'recommendation' => 'Set uploads directory permissions to 755'
                )
            );
        }
        
        // Check for .htaccess protection
        $htaccess_file = $uploads_path . '/.htaccess';
        if (!file_exists($htaccess_file)) {
            $this->add_warning(
                'uploads_no_htaccess',
                'medium',
                'Uploads Directory Not Protected',
                'Uploads directory lacks .htaccess protection against script execution.',
                'core',
                $uploads_path
            );
        } else {
            // Check .htaccess content for security rules
            $htaccess_content = file_get_contents($htaccess_file);
            if (strpos($htaccess_content, 'php') === false) {
                $this->add_warning(
                    'uploads_weak_htaccess',
                    'medium',
                    'Weak Uploads Protection',
                    'Uploads .htaccess does not prevent PHP execution.',
                    'core',
                    $htaccess_file
                );
            }
        }
    }
    
    /**
     * Check database prefix security
     *
     * @return void
     */
    private function check_database_prefix() {
        global $wpdb;
        
        if ($wpdb->prefix === 'wp_') {
            $this->add_vulnerability(
                'default_database_prefix',
                'low',
                'Default Database Prefix',
                'WordPress is using the default database prefix "wp_".',
                'core',
                'wp-config.php',
                array(
                    'current_prefix' => $wpdb->prefix,
                    'recommendation' => 'Change database prefix to something unique'
                )
            );
        }
    }
    
    /**
     * Check salt keys configuration
     *
     * @return void
     */
    private function check_salt_keys() {
        $salt_keys = array(
            'AUTH_KEY',
            'SECURE_AUTH_KEY',
            'LOGGED_IN_KEY',
            'NONCE_KEY',
            'AUTH_SALT',
            'SECURE_AUTH_SALT',
            'LOGGED_IN_SALT',
            'NONCE_SALT'
        );
        
        $weak_keys = array();
        $missing_keys = array();
        
        foreach ($salt_keys as $key) {
            if (!defined($key)) {
                $missing_keys[] = $key;
            } else {
                $value = constant($key);
                if (empty($value) || strlen($value) < 32 || $value === 'put your unique phrase here') {
                    $weak_keys[] = $key;
                }
            }
        }
        
        if (!empty($missing_keys)) {
            $this->add_vulnerability(
                'missing_salt_keys',
                'high',
                'Missing Salt Keys',
                sprintf('Missing security salt keys: %s', implode(', ', $missing_keys)),
                'core',
                'wp-config.php',
                array(
                    'missing_keys' => $missing_keys,
                    'recommendation' => 'Generate and add all required salt keys to wp-config.php'
                )
            );
        }
        
        if (!empty($weak_keys)) {
            $this->add_vulnerability(
                'weak_salt_keys',
                'medium',
                'Weak Salt Keys',
                sprintf('Weak or default salt keys detected: %s', implode(', ', $weak_keys)),
                'core',
                'wp-config.php',
                array(
                    'weak_keys' => $weak_keys,
                    'recommendation' => 'Generate new strong salt keys using WordPress.org secret key service'
                )
            );
        }
    }
    
    /**
     * Get latest WordPress version
     *
     * @return string Latest WordPress version
     */
    private function get_latest_wordpress_version() {
        $response = wp_remote_get('https://api.wordpress.org/core/version-check/1.7/');
        
        if (is_wp_error($response)) {
            return '0.0.0'; // Return minimal version if API call fails
        }
        
        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);
        
        if (isset($data['offers'][0]['version'])) {
            return $data['offers'][0]['version'];
        }
        
        return '0.0.0';
    }
    
    /**
     * Get list of known vulnerable WordPress versions
     *
     * @return array Array of vulnerable version numbers
     */
    private function get_vulnerable_wordpress_versions() {
        // This should ideally come from a vulnerability database
        // For now, including some commonly known vulnerable versions
        return array(
            '4.9.0', '4.9.1', '4.9.2', '4.9.3', '4.9.4', '4.9.5',
            '5.0.0', '5.0.1', '5.0.2', '5.0.3',
            '5.1.0', '5.1.1',
            '5.2.0', '5.2.1', '5.2.2', '5.2.3',
            '5.3.0', '5.3.1', '5.3.2',
            '5.4.0', '5.4.1', '5.4.2',
            '5.5.0', '5.5.1', '5.5.2', '5.5.3',
            '5.6.0', '5.6.1', '5.6.2', '5.6.3', '5.6.4',
            '5.7.0', '5.7.1', '5.7.2', '5.7.3', '5.7.4', '5.7.5', '5.7.6', '5.7.7', '5.7.8'
        );
    }
    
    /**
     * Add vulnerability to results
     *
     * @param string $id Vulnerability ID
     * @param string $severity Severity level
     * @param string $title Vulnerability title
     * @param string $description Vulnerability description
     * @param string $category Vulnerability category
     * @param string $file Affected file
     * @param array $details Additional details
     * @return void
     */
    private function add_vulnerability($id, $severity, $title, $description, $category, $file, $details = array()) {
        $this->results['vulnerabilities'][] = array(
            'id' => $id,
            'severity' => $severity,
            'title' => $title,
            'description' => $description,
            'category' => $category,
            'file' => $file,
            'scanner' => 'core',
            'details' => $details,
            'found_at' => current_time('mysql')
        );
    }
    
    /**
     * Add warning to results
     *
     * @param string $id Warning ID
     * @param string $severity Severity level
     * @param string $title Warning title
     * @param string $description Warning description
     * @param string $category Warning category
     * @param string $file Affected file
     * @return void
     */
    private function add_warning($id, $severity, $title, $description, $category, $file) {
        $this->results['warnings'][] = array(
            'id' => $id,
            'severity' => $severity,
            'title' => $title,
            'description' => $description,
            'category' => $category,
            'file' => $file,
            'scanner' => 'core',
            'found_at' => current_time('mysql')
        );
    }
    
    /**
     * Generate scan summary
     *
     * @return void
     */
    private function generate_scan_summary() {
        $this->results['scan_summary'] = array(
            'scanner' => 'core',
            'total_vulnerabilities' => count($this->results['vulnerabilities']),
            'total_warnings' => count($this->results['warnings']),
            'severity_breakdown' => $this->get_severity_breakdown(),
            'scan_duration' => 0, // TODO: Calculate actual duration
            'scanned_items' => array(
                'wordpress_version' => $this->config['check_version'],
                'configuration' => $this->config['check_config'],
                'file_permissions' => $this->config['check_permissions'],
                'debug_mode' => $this->config['check_debug_mode'],
                'file_editing' => $this->config['check_file_editing'],
                'uploads_security' => $this->config['check_uploads_security'],
                'database_prefix' => $this->config['check_database_prefix'],
                'salt_keys' => $this->config['check_salt_keys']
            )
        );
    }
    
    /**
     * Get severity breakdown of found issues
     *
     * @return array Severity breakdown
     */
    private function get_severity_breakdown() {
        $breakdown = array(
            'critical' => 0,
            'high' => 0,
            'medium' => 0,
            'low' => 0
        );
        
        foreach ($this->results['vulnerabilities'] as $vuln) {
            if (isset($breakdown[$vuln['severity']])) {
                $breakdown[$vuln['severity']]++;
            }
        }
        
        foreach ($this->results['warnings'] as $warning) {
            if (isset($breakdown[$warning['severity']])) {
                $breakdown[$warning['severity']]++;
            }
        }
        
        return $breakdown;
    }
    
    /**
     * Pause the current scan
     *
     * @return bool True if scan paused successfully, false otherwise
     */
    public function pause_scan() {
        if ($this->status === 'running') {
            $this->status = 'paused';
            return true;
        }
        return false;
    }
    
    /**
     * Resume a paused scan
     *
     * @return bool True if scan resumed successfully, false otherwise
     */
    public function resume_scan() {
        if ($this->status === 'paused') {
            $this->status = 'running';
            return true;
        }
        return false;
    }
    
    /**
     * Stop the current scan
     *
     * @return bool True if scan stopped successfully, false otherwise
     */
    public function stop_scan() {
        if (in_array($this->status, array('running', 'paused'))) {
            $this->status = 'stopped';
            return true;
        }
        return false;
    }
    
    /**
     * Get the current scan progress
     *
     * @return array Progress information including percentage, current item, etc.
     */
    public function get_progress() {
        if ($this->progress) {
            return $this->progress->get_progress();
        }
        
        return array(
            'status' => $this->status,
            'percentage' => $this->status === 'completed' ? 100 : 0,
            'message' => 'Core scanner progress tracking not enabled'
        );
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
                // TODO: Implement XML conversion
                return '<xml>XML format not implemented yet</xml>';
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
        return $this->status;
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
        $boolean_fields = array(
            'check_version', 'check_config', 'check_permissions', 
            'check_debug_mode', 'check_file_editing', 'check_uploads_security',
            'check_database_prefix', 'check_salt_keys'
        );
        
        foreach ($boolean_fields as $field) {
            if (isset($config[$field]) && !is_bool($config[$field])) {
                return new WP_Error('invalid_config', sprintf('%s must be a boolean', $field));
            }
        }
        
        if (isset($config['timeout']) && (!is_numeric($config['timeout']) || $config['timeout'] < 0)) {
            return new WP_Error('invalid_config', 'timeout must be a positive number');
        }
        
        return true;
    }
    
    /**
     * Clean up resources after scan completion
     *
     * @return bool True on success, false on failure
     */
    public function cleanup() {
        $this->results = array();
        $this->status = 'idle';
        return true;
    }
    
    /**
     * Get supported vulnerability types for this scanner
     *
     * @return array Array of vulnerability type identifiers
     */
    public function get_supported_vulnerabilities() {
        return array(
            'outdated_wordpress',
            'vulnerable_wordpress_version',
            'incorrect_file_permissions',
            'incorrect_directory_permissions',
            'debug_mode_enabled',
            'file_editing_enabled',
            'uploads_world_writable',
            'default_database_prefix',
            'missing_salt_keys',
            'weak_salt_keys',
            'backup_files_accessible',
            'sample_files_present'
        );
    }
    
    /**
     * Get scanner metadata
     *
     * @return array Scanner metadata (name, version, description, etc.)
     */
    public function get_metadata() {
        return array(
            'name' => 'WordPress Core Scanner',
            'version' => '1.0.0',
            'description' => 'Scans WordPress core files and configuration for security vulnerabilities',
            'author' => 'WP Breach Team',
            'supported_vulnerabilities' => $this->get_supported_vulnerabilities(),
            'scan_targets' => array(
                'WordPress version',
                'Configuration files',
                'File permissions',
                'Debug settings',
                'File editing capabilities',
                'Uploads directory',
                'Database configuration',
                'Security keys and salts'
            )
        );
    }
}

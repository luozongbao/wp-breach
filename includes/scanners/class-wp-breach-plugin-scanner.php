<?php
/**
 * WordPress Plugin Scanner
 *
 * Scanner for detecting vulnerabilities in WordPress plugins.
 *
 * @package WP_Breach
 * @since 1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class WP_Breach_Plugin_Scanner
 *
 * Scans WordPress plugins for vulnerabilities and security issues.
 */
class WP_Breach_Plugin_Scanner implements WP_Breach_Scanner_Interface {
    
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
        'scan_active_only' => false,
        'check_versions' => true,
        'check_vulnerabilities' => true,
        'check_permissions' => true,
        'check_code_patterns' => true,
        'deep_scan' => false,
        'max_files_per_plugin' => 500,
        'timeout' => 120
    );
    
    /**
     * Vulnerable patterns to search for
     *
     * @var array
     */
    private $vulnerable_patterns = array(
        'sql_injection' => array(
            '/\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*[\'"][^\'"]*[\'"]\s*\]\s*(?:(?:\.|\+|,)\s*)?(?:(?:\'|")?\s*\)\s*)?(?:;|\s+(?:FROM|WHERE|ORDER|GROUP|HAVING|UNION|SELECT|UPDATE|DELETE|INSERT))/i',
            '/(?:mysql_query|mysqli_query|wpdb->query)\s*\(\s*[\'"][^\'"]*(SELECT|UPDATE|DELETE|INSERT)[^\'"]*[\'"]\s*\.\s*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            '/\$wpdb->(?:get_var|get_row|get_col|get_results|query)\s*\(\s*[\'"][^\'"]*(SELECT|UPDATE|DELETE|INSERT)[^\'"]*[\'"]\s*\.\s*\$_(?:GET|POST|REQUEST|COOKIE)/i'
        ),
        'xss' => array(
            '/echo\s+\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/i',
            '/print\s+\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/i',
            '/<\?php\s+echo\s+\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/i',
            '/\?\>\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/i'
        ),
        'file_inclusion' => array(
            '/(?:include|require)(?:_once)?\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/i',
            '/file_get_contents\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/i',
            '/fopen\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/i'
        ),
        'command_injection' => array(
            '/(?:exec|system|shell_exec|passthru|popen|proc_open)\s*\(\s*[\'"][^\'"]*(.*?)\$_(?:GET|POST|REQUEST|COOKIE)/i',
            '/`[^`]*\$_(?:GET|POST|REQUEST|COOKIE)/i'
        ),
        'code_injection' => array(
            '/(?:eval|assert)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            '/create_function\s*\(\s*[\'"][^\']*[\'"]\s*,\s*\$_(?:GET|POST|REQUEST|COOKIE)/i'
        ),
        'csrf' => array(
            '/wp_nonce_field\s*\(\s*[\'"][^\']*[\'"]\s*\)/i',
            '/check_admin_referer\s*\(\s*[\'"][^\']*[\'"]\s*\)/i',
            '/wp_verify_nonce\s*\(\s*\$_(?:GET|POST|REQUEST)\s*\[/i'
        )
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
            error_log('WP Breach Plugin Scanner: Initialization failed - ' . $e->getMessage());
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
            
            // Get list of plugins to scan
            $plugins = $this->get_plugins_to_scan();
            
            if (empty($plugins)) {
                $this->status = 'completed';
                return true;
            }
            
            // Update progress if tracking is enabled
            if ($this->progress) {
                $this->progress->set_total_items(count($plugins));
            }
            
            // Scan each plugin
            foreach ($plugins as $plugin_file => $plugin_data) {
                if ($this->progress) {
                    $this->progress->set_current_item('Scanning ' . $plugin_data['Name']);
                }
                
                $this->scan_plugin($plugin_file, $plugin_data);
                
                if ($this->progress) {
                    $this->progress->increment_processed();
                }
                
                // Check for timeout or memory limits
                if ($this->should_stop_scanning()) {
                    break;
                }
            }
            
            // Generate scan summary
            $this->generate_scan_summary();
            
            $this->status = 'completed';
            return true;
            
        } catch (Exception $e) {
            $this->status = 'error';
            $this->add_vulnerability('scan_error', 'high', 'Scan Error', 
                'Plugin scanner encountered an error: ' . $e->getMessage(), 
                'plugin', '', array('exception' => $e->getMessage())
            );
            return false;
        }
    }
    
    /**
     * Get list of plugins to scan
     *
     * @return array Array of plugins to scan
     */
    private function get_plugins_to_scan() {
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        
        $all_plugins = get_plugins();
        
        if ($this->config['scan_active_only']) {
            $active_plugins = get_option('active_plugins', array());
            $filtered_plugins = array();
            
            foreach ($active_plugins as $plugin_file) {
                if (isset($all_plugins[$plugin_file])) {
                    $filtered_plugins[$plugin_file] = $all_plugins[$plugin_file];
                }
            }
            
            return $filtered_plugins;
        }
        
        return $all_plugins;
    }
    
    /**
     * Scan individual plugin
     *
     * @param string $plugin_file Plugin file path
     * @param array $plugin_data Plugin data
     * @return void
     */
    private function scan_plugin($plugin_file, $plugin_data) {
        $plugin_path = WP_PLUGIN_DIR . '/' . dirname($plugin_file);
        
        // Check if plugin directory exists
        if (!is_dir($plugin_path)) {
            $this->add_warning(
                'plugin_directory_missing',
                'medium',
                'Plugin Directory Missing',
                sprintf('Plugin directory does not exist: %s', $plugin_path),
                'plugin',
                $plugin_file
            );
            return;
        }
        
        // Check plugin version
        if ($this->config['check_versions']) {
            $this->check_plugin_version($plugin_file, $plugin_data);
        }
        
        // Check for known vulnerabilities
        if ($this->config['check_vulnerabilities']) {
            $this->check_known_vulnerabilities($plugin_file, $plugin_data);
        }
        
        // Check file permissions
        if ($this->config['check_permissions']) {
            $this->check_plugin_permissions($plugin_path, $plugin_file);
        }
        
        // Scan plugin code for vulnerable patterns
        if ($this->config['check_code_patterns']) {
            $this->scan_plugin_code($plugin_path, $plugin_file, $plugin_data);
        }
    }
    
    /**
     * Check plugin version for known issues
     *
     * @param string $plugin_file Plugin file path
     * @param array $plugin_data Plugin data
     * @return void
     */
    private function check_plugin_version($plugin_file, $plugin_data) {
        // Check if version is present
        if (empty($plugin_data['Version'])) {
            $this->add_warning(
                'plugin_no_version',
                'low',
                'Plugin Missing Version',
                sprintf('Plugin %s does not specify a version number.', $plugin_data['Name']),
                'plugin',
                $plugin_file
            );
            return;
        }
        
        // Check against WordPress.org repository for updates
        $latest_version = $this->get_latest_plugin_version($plugin_file, $plugin_data);
        
        if ($latest_version && version_compare($plugin_data['Version'], $latest_version, '<')) {
            $this->add_vulnerability(
                'plugin_outdated',
                'medium',
                'Outdated Plugin',
                sprintf('Plugin %s version %s is outdated. Latest version is %s.', 
                    $plugin_data['Name'], $plugin_data['Version'], $latest_version),
                'plugin',
                $plugin_file,
                array(
                    'current_version' => $plugin_data['Version'],
                    'latest_version' => $latest_version,
                    'recommendation' => 'Update plugin to the latest version'
                )
            );
        }
    }
    
    /**
     * Check for known vulnerabilities in plugin
     *
     * @param string $plugin_file Plugin file path
     * @param array $plugin_data Plugin data
     * @return void
     */
    private function check_known_vulnerabilities($plugin_file, $plugin_data) {
        // This would typically query a vulnerability database
        // For now, checking against a basic list of known vulnerable plugins
        
        $vulnerable_plugins = $this->get_known_vulnerable_plugins();
        $plugin_slug = dirname($plugin_file);
        
        if (isset($vulnerable_plugins[$plugin_slug])) {
            $vuln_info = $vulnerable_plugins[$plugin_slug];
            
            // Check if current version is vulnerable
            if (isset($vuln_info['versions']) && 
                in_array($plugin_data['Version'], $vuln_info['versions'])) {
                
                $this->add_vulnerability(
                    'known_vulnerable_plugin',
                    $vuln_info['severity'],
                    'Known Vulnerable Plugin',
                    sprintf('Plugin %s version %s has known security vulnerabilities: %s',
                        $plugin_data['Name'], $plugin_data['Version'], $vuln_info['description']),
                    'plugin',
                    $plugin_file,
                    array(
                        'vulnerability_type' => $vuln_info['type'],
                        'cve' => isset($vuln_info['cve']) ? $vuln_info['cve'] : '',
                        'recommendation' => 'Update or remove the vulnerable plugin immediately'
                    )
                );
            }
        }
    }
    
    /**
     * Check plugin file permissions
     *
     * @param string $plugin_path Plugin directory path
     * @param string $plugin_file Plugin file path
     * @return void
     */
    private function check_plugin_permissions($plugin_path, $plugin_file) {
        // Check main plugin file permissions
        $main_file = WP_PLUGIN_DIR . '/' . $plugin_file;
        if (file_exists($main_file)) {
            $perms = fileperms($main_file) & 0777;
            
            if ($perms & 0002) { // World writable
                $this->add_vulnerability(
                    'plugin_world_writable',
                    'high',
                    'Plugin File World Writable',
                    sprintf('Plugin file %s is world writable.', $plugin_file),
                    'plugin',
                    $plugin_file,
                    array(
                        'current_permissions' => sprintf('%o', $perms),
                        'recommendation' => 'Set plugin file permissions to 644'
                    )
                );
            }
        }
        
        // Check plugin directory permissions
        if (is_dir($plugin_path)) {
            $perms = fileperms($plugin_path) & 0777;
            
            if ($perms & 0002) { // World writable
                $this->add_vulnerability(
                    'plugin_directory_world_writable',
                    'high',
                    'Plugin Directory World Writable',
                    sprintf('Plugin directory %s is world writable.', basename($plugin_path)),
                    'plugin',
                    $plugin_file,
                    array(
                        'directory' => $plugin_path,
                        'current_permissions' => sprintf('%o', $perms),
                        'recommendation' => 'Set plugin directory permissions to 755'
                    )
                );
            }
        }
    }
    
    /**
     * Scan plugin code for vulnerable patterns
     *
     * @param string $plugin_path Plugin directory path
     * @param string $plugin_file Plugin file path
     * @param array $plugin_data Plugin data
     * @return void
     */
    private function scan_plugin_code($plugin_path, $plugin_file, $plugin_data) {
        $php_files = $this->get_php_files($plugin_path);
        
        // Limit number of files to scan for performance
        if (count($php_files) > $this->config['max_files_per_plugin']) {
            $php_files = array_slice($php_files, 0, $this->config['max_files_per_plugin']);
            
            $this->add_warning(
                'plugin_too_many_files',
                'low',
                'Plugin Has Too Many Files',
                sprintf('Plugin %s has more than %d PHP files. Only scanning first %d files.',
                    $plugin_data['Name'], $this->config['max_files_per_plugin'], $this->config['max_files_per_plugin']),
                'plugin',
                $plugin_file
            );
        }
        
        foreach ($php_files as $file_path) {
            $this->scan_file_for_vulnerabilities($file_path, $plugin_file, $plugin_data);
            
            // Update progress for files scanned
            if ($this->progress) {
                $this->progress->increment_files_scanned();
            }
        }
    }
    
    /**
     * Get PHP files in plugin directory
     *
     * @param string $plugin_path Plugin directory path
     * @return array Array of PHP file paths
     */
    private function get_php_files($plugin_path) {
        $php_files = array();
        
        if (!is_dir($plugin_path)) {
            return $php_files;
        }
        
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($plugin_path, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::LEAVES_ONLY
        );
        
        foreach ($iterator as $file) {
            if ($file->isFile() && pathinfo($file->getPathname(), PATHINFO_EXTENSION) === 'php') {
                $php_files[] = $file->getPathname();
            }
        }
        
        return $php_files;
    }
    
    /**
     * Scan individual file for vulnerabilities
     *
     * @param string $file_path File path to scan
     * @param string $plugin_file Plugin file path
     * @param array $plugin_data Plugin data
     * @return void
     */
    private function scan_file_for_vulnerabilities($file_path, $plugin_file, $plugin_data) {
        $content = file_get_contents($file_path);
        
        if ($content === false) {
            return;
        }
        
        foreach ($this->vulnerable_patterns as $vuln_type => $patterns) {
            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $content, $matches)) {
                    $severity = $this->get_vulnerability_severity($vuln_type);
                    
                    $this->add_vulnerability(
                        'plugin_' . $vuln_type,
                        $severity,
                        sprintf('%s Vulnerability in Plugin', ucfirst(str_replace('_', ' ', $vuln_type))),
                        sprintf('Potential %s vulnerability found in plugin %s file %s.',
                            str_replace('_', ' ', $vuln_type), $plugin_data['Name'], basename($file_path)),
                        'plugin',
                        $plugin_file,
                        array(
                            'vulnerability_type' => $vuln_type,
                            'file' => $file_path,
                            'pattern_matched' => $pattern,
                            'code_snippet' => isset($matches[0]) ? substr($matches[0], 0, 200) : '',
                            'recommendation' => $this->get_vulnerability_recommendation($vuln_type)
                        )
                    );
                }
            }
        }
        
        // Check for other security issues
        $this->check_file_security_issues($file_path, $content, $plugin_file, $plugin_data);
    }
    
    /**
     * Check for additional security issues in file
     *
     * @param string $file_path File path
     * @param string $content File content
     * @param string $plugin_file Plugin file path
     * @param array $plugin_data Plugin data
     * @return void
     */
    private function check_file_security_issues($file_path, $content, $plugin_file, $plugin_data) {
        // Check for debug information disclosure
        if (preg_match('/(?:var_dump|print_r|var_export)\s*\(/i', $content)) {
            $this->add_warning(
                'plugin_debug_functions',
                'low',
                'Debug Functions in Plugin',
                sprintf('Plugin %s contains debug functions that may expose sensitive information.',
                    $plugin_data['Name']),
                'plugin',
                $plugin_file,
                array('file' => $file_path)
            );
        }
        
        // Check for direct file access without ABSPATH check
        if (strpos($content, '<?php') !== false && 
            strpos($content, 'ABSPATH') === false && 
            strpos($content, 'defined(\'ABSPATH\')') === false) {
            
            $this->add_warning(
                'plugin_no_direct_access_protection',
                'medium',
                'No Direct Access Protection',
                sprintf('Plugin file %s lacks protection against direct access.',
                    basename($file_path)),
                'plugin',
                $plugin_file,
                array('file' => $file_path)
            );
        }
        
        // Check for hardcoded credentials
        if (preg_match('/(?:password|passwd|pwd|secret|key)\s*=\s*[\'"][^\'"]{3,}/i', $content)) {
            $this->add_vulnerability(
                'plugin_hardcoded_credentials',
                'high',
                'Hardcoded Credentials in Plugin',
                sprintf('Plugin %s may contain hardcoded credentials.',
                    $plugin_data['Name']),
                'plugin',
                $plugin_file,
                array(
                    'file' => $file_path,
                    'recommendation' => 'Remove hardcoded credentials and use secure storage methods'
                )
            );
        }
    }
    
    /**
     * Get vulnerability severity based on type
     *
     * @param string $vuln_type Vulnerability type
     * @return string Severity level
     */
    private function get_vulnerability_severity($vuln_type) {
        $severities = array(
            'sql_injection' => 'critical',
            'xss' => 'high',
            'file_inclusion' => 'high',
            'command_injection' => 'critical',
            'code_injection' => 'critical',
            'csrf' => 'medium'
        );
        
        return isset($severities[$vuln_type]) ? $severities[$vuln_type] : 'medium';
    }
    
    /**
     * Get vulnerability recommendation based on type
     *
     * @param string $vuln_type Vulnerability type
     * @return string Recommendation text
     */
    private function get_vulnerability_recommendation($vuln_type) {
        $recommendations = array(
            'sql_injection' => 'Use prepared statements and sanitize all user input',
            'xss' => 'Escape output using esc_html(), esc_attr(), or wp_kses()',
            'file_inclusion' => 'Validate and sanitize file paths, use whitelist approach',
            'command_injection' => 'Avoid executing system commands with user input',
            'code_injection' => 'Never use eval() or similar functions with user input',
            'csrf' => 'Implement proper nonce verification for all forms and actions'
        );
        
        return isset($recommendations[$vuln_type]) ? $recommendations[$vuln_type] : 'Review code for security issues';
    }
    
    /**
     * Get latest plugin version from WordPress.org repository
     *
     * @param string $plugin_file Plugin file path
     * @param array $plugin_data Plugin data
     * @return string|false Latest version or false if not found
     */
    private function get_latest_plugin_version($plugin_file, $plugin_data) {
        $plugin_slug = dirname($plugin_file);
        
        // Skip plugins that are not from WordPress.org repository
        $skip_slugs = array('hello', 'akismet');
        if (in_array($plugin_slug, $skip_slugs)) {
            return false;
        }
        
        $api_url = sprintf('https://api.wordpress.org/plugins/info/1.0/%s.json', $plugin_slug);
        $response = wp_remote_get($api_url, array('timeout' => 10));
        
        if (is_wp_error($response)) {
            return false;
        }
        
        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);
        
        if (isset($data['version'])) {
            return $data['version'];
        }
        
        return false;
    }
    
    /**
     * Get known vulnerable plugins list
     *
     * @return array Array of known vulnerable plugins
     */
    private function get_known_vulnerable_plugins() {
        // This should ideally come from a vulnerability database
        // For demonstration, including some commonly known vulnerable plugins
        return array(
            'timthumb' => array(
                'versions' => array('1.0', '1.1', '1.2', '1.3', '1.4', '2.0'),
                'severity' => 'critical',
                'type' => 'remote_code_execution',
                'description' => 'Remote code execution vulnerability in TimThumb script'
            ),
            'revslider' => array(
                'versions' => array('4.1.4', '4.2.0', '4.6.0'),
                'severity' => 'high',
                'type' => 'file_download',
                'description' => 'Arbitrary file download vulnerability'
            ),
            'mailpoet' => array(
                'versions' => array('2.6.7', '2.6.8', '2.6.9'),
                'severity' => 'high',
                'type' => 'privilege_escalation',
                'description' => 'Privilege escalation vulnerability'
            )
        );
    }
    
    /**
     * Check if scanning should be stopped due to resource limits
     *
     * @return bool True if scanning should stop, false otherwise
     */
    private function should_stop_scanning() {
        // Check memory usage
        $memory_usage = memory_get_usage(true);
        $memory_limit = wp_convert_hr_to_bytes(ini_get('memory_limit'));
        
        if ($memory_usage > ($memory_limit * 0.9)) {
            return true;
        }
        
        // Check execution time
        if (function_exists('set_time_limit')) {
            $max_execution_time = ini_get('max_execution_time');
            if ($max_execution_time > 0) {
                // Implementation would need to track start time
                // For now, just check if we're close to timeout
                return false;
            }
        }
        
        return false;
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
            'scanner' => 'plugin',
            'details' => $details,
            'found_at' => current_time('mysql')
        );
        
        // Update progress with vulnerability count
        if ($this->progress) {
            $this->progress->increment_vulnerabilities();
        }
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
     * @param array $details Additional details
     * @return void
     */
    private function add_warning($id, $severity, $title, $description, $category, $file, $details = array()) {
        $this->results['warnings'][] = array(
            'id' => $id,
            'severity' => $severity,
            'title' => $title,
            'description' => $description,
            'category' => $category,
            'file' => $file,
            'scanner' => 'plugin',
            'details' => $details,
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
            'scanner' => 'plugin',
            'total_vulnerabilities' => count($this->results['vulnerabilities']),
            'total_warnings' => count($this->results['warnings']),
            'severity_breakdown' => $this->get_severity_breakdown(),
            'plugins_scanned' => $this->progress ? $this->progress->get_progress()['items_processed'] : 0,
            'files_scanned' => $this->progress ? $this->progress->get_progress()['files_scanned'] : 0
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
    
    // Implementation of remaining interface methods...
    
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
            'message' => 'Plugin scanner progress tracking not enabled'
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
            'scan_active_only', 'check_versions', 'check_vulnerabilities', 
            'check_permissions', 'check_code_patterns', 'deep_scan'
        );
        
        foreach ($boolean_fields as $field) {
            if (isset($config[$field]) && !is_bool($config[$field])) {
                return new WP_Error('invalid_config', sprintf('%s must be a boolean', $field));
            }
        }
        
        $numeric_fields = array('max_files_per_plugin', 'timeout');
        foreach ($numeric_fields as $field) {
            if (isset($config[$field]) && (!is_numeric($config[$field]) || $config[$field] < 0)) {
                return new WP_Error('invalid_config', sprintf('%s must be a positive number', $field));
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
            'plugin_outdated',
            'known_vulnerable_plugin',
            'plugin_world_writable',
            'plugin_directory_world_writable',
            'plugin_sql_injection',
            'plugin_xss',
            'plugin_file_inclusion',
            'plugin_command_injection',
            'plugin_code_injection',
            'plugin_csrf',
            'plugin_hardcoded_credentials',
            'plugin_debug_functions',
            'plugin_no_direct_access_protection'
        );
    }
    
    /**
     * Get scanner metadata
     *
     * @return array Scanner metadata (name, version, description, etc.)
     */
    public function get_metadata() {
        return array(
            'name' => 'WordPress Plugin Scanner',
            'version' => '1.0.0',
            'description' => 'Scans WordPress plugins for security vulnerabilities and code issues',
            'author' => 'WP Breach Team',
            'supported_vulnerabilities' => $this->get_supported_vulnerabilities(),
            'scan_targets' => array(
                'Plugin versions',
                'Known vulnerabilities',
                'File permissions',
                'Code patterns',
                'Security configurations'
            )
        );
    }
}

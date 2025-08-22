<?php

/**
 * Code Fix Strategy implementation.
 *
 * This class handles automated fixes for code-related vulnerabilities
 * including malware removal, code injection fixes, and suspicious code cleanup.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/fixes/strategies
 */

/**
 * Code Fix Strategy Class.
 *
 * Implements automated fixes for code vulnerabilities including:
 * - Malware detection and removal
 * - Code injection cleanup
 * - Suspicious code quarantine
 * - XSS prevention fixes
 * - SQL injection sanitization
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/fixes/strategies
 * @author     WP Breach Team
 */
class WP_Breach_Code_Fix_Strategy implements WP_Breach_Fix_Strategy {

    /**
     * Supported vulnerability types.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $supported_types    Vulnerability types this strategy handles.
     */
    private $supported_types = array(
        'code_injection',
        'sql_injection',
        'xss',
        'malware',
        'suspicious_code',
        'backdoor',
        'shell_injection',
        'php_injection'
    );

    /**
     * WordPress filesystem instance.
     *
     * @since    1.0.0
     * @access   private
     * @var      WP_Filesystem_Base    $filesystem    WordPress filesystem.
     */
    private $filesystem;

    /**
     * Quarantine directory for suspicious files.
     *
     * @since    1.0.0
     * @access   private
     * @var      string    $quarantine_dir    Quarantine directory path.
     */
    private $quarantine_dir;

    /**
     * Code analysis patterns.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $malware_patterns    Malware detection patterns.
     */
    private $malware_patterns = array(
        'base64_decode\s*\(',
        'eval\s*\(',
        'exec\s*\(',
        'system\s*\(',
        'shell_exec\s*\(',
        'passthru\s*\(',
        'file_get_contents\s*\(\s*["\']https?://',
        'curl_exec\s*\(',
        'preg_replace.*\/e["\']',
        'create_function\s*\(',
        '\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\[.*\]\s*\(',
        'assert\s*\(',
        'mb_ereg_replace.*e["\']',
        'ob_start\s*\(\s*["\']ob_gzhandler["\']',
        '\$GLOBALS\[["\'].*["\']]\s*=.*\$_(?:GET|POST|REQUEST)'
    );

    /**
     * Safe file patterns to exclude from scanning.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $safe_file_patterns    Safe file patterns.
     */
    private $safe_file_patterns = array(
        '/wp-admin/',
        '/wp-includes/',
        '/wp-content/plugins/wp-breach/',
        '/node_modules/',
        '/vendor/',
        '/.git/',
        '/backup'
    );

    /**
     * Initialize the code fix strategy.
     *
     * @since    1.0.0
     */
    public function __construct() {
        // Initialize WordPress filesystem
        if (!function_exists('WP_Filesystem')) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
        WP_Filesystem();
        global $wp_filesystem;
        $this->filesystem = $wp_filesystem;

        // Set up quarantine directory
        $upload_dir = wp_upload_dir();
        $this->quarantine_dir = $upload_dir['basedir'] . '/wp-breach-quarantine';
        if (!$this->filesystem->exists($this->quarantine_dir)) {
            $this->filesystem->mkdir($this->quarantine_dir, FS_CHMOD_DIR);
        }
    }

    /**
     * Check if this strategy can automatically fix the vulnerability.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability details.
     * @return   bool                       True if can auto-fix.
     */
    public function can_auto_fix($vulnerability) {
        // Check if vulnerability type is supported
        if (!in_array($vulnerability['type'], $this->supported_types)) {
            return false;
        }

        // Check if we have filesystem access
        if (!$this->filesystem || !$this->filesystem->exists(ABSPATH)) {
            return false;
        }

        // Check if affected files exist and are accessible
        if (isset($vulnerability['affected_files'])) {
            foreach ($vulnerability['affected_files'] as $file) {
                if (!$this->filesystem->exists($file) || !$this->filesystem->is_writable($file)) {
                    return false;
                }
            }
        }

        // Check specific vulnerability types
        switch ($vulnerability['type']) {
            case 'malware':
            case 'backdoor':
                // These require careful analysis - enable only if confidence is high
                return isset($vulnerability['confidence']) && $vulnerability['confidence'] > 0.8;
            
            case 'code_injection':
            case 'sql_injection':
            case 'xss':
                // These can be fixed more safely
                return true;
            
            default:
                return true;
        }
    }

    /**
     * Assess the safety of applying this fix.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability details.
     * @return   array                      Safety assessment.
     */
    public function assess_fix_safety($vulnerability) {
        $assessment = array(
            'safety_score' => 0.6, // Code fixes are inherently risky
            'risk_factors' => array(),
            'requirements' => array(),
            'recommendations' => array()
        );

        // Assess risk based on vulnerability type
        switch ($vulnerability['type']) {
            case 'malware':
            case 'backdoor':
                $assessment['risk_factors'][] = 'Malware removal can break site functionality';
                $assessment['safety_score'] -= 0.2;
                $assessment['recommendations'][] = 'Manual review recommended before automated fix';
                break;
            
            case 'code_injection':
            case 'php_injection':
                $assessment['risk_factors'][] = 'Code modification can cause syntax errors';
                $assessment['safety_score'] -= 0.1;
                break;
            
            case 'sql_injection':
                $assessment['risk_factors'][] = 'Database query changes can affect functionality';
                $assessment['safety_score'] -= 0.1;
                break;
        }

        // Check if core WordPress files are affected
        if ($this->affects_core_files($vulnerability)) {
            $assessment['risk_factors'][] = 'WordPress core files affected';
            $assessment['safety_score'] -= 0.2;
            $assessment['recommendations'][] = 'Consider WordPress core integrity check';
        }

        // Check if active theme/plugin files are affected
        if ($this->affects_active_components($vulnerability)) {
            $assessment['risk_factors'][] = 'Active theme or plugin files affected';
            $assessment['safety_score'] -= 0.1;
            $assessment['recommendations'][] = 'Test site functionality after fix';
        }

        // Check if site is live
        if (!$this->is_development_environment()) {
            $assessment['risk_factors'][] = 'Code changes on live site';
            $assessment['safety_score'] -= 0.1;
            $assessment['recommendations'][] = 'Test changes in staging environment first';
        }

        // Requirements
        $assessment['requirements'] = array(
            'filesystem_access' => $this->filesystem !== null,
            'quarantine_directory' => $this->filesystem->exists($this->quarantine_dir),
            'file_backup_capability' => $this->can_create_file_backup(),
            'code_analysis_tools' => $this->has_code_analysis_capability()
        );

        return $assessment;
    }

    /**
     * Apply the automated fix.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability details.
     * @return   array                      Fix result.
     */
    public function apply_fix($vulnerability) {
        $result = array(
            'success' => false,
            'actions_taken' => array(),
            'changes_made' => array(),
            'rollback_data' => array(),
            'error_message' => ''
        );

        try {
            // Create backup of affected files
            $backup_result = $this->create_code_backup($vulnerability);
            if (!$backup_result['success']) {
                throw new Exception('Failed to create code backup: ' . $backup_result['error']);
            }

            $result['rollback_data'] = $backup_result['backup_data'];

            // Apply fix based on vulnerability type
            switch ($vulnerability['type']) {
                case 'malware':
                case 'backdoor':
                    $fix_result = $this->fix_malware($vulnerability);
                    break;
                
                case 'code_injection':
                case 'php_injection':
                    $fix_result = $this->fix_code_injection($vulnerability);
                    break;
                
                case 'sql_injection':
                    $fix_result = $this->fix_sql_injection($vulnerability);
                    break;
                
                case 'xss':
                    $fix_result = $this->fix_xss_vulnerability($vulnerability);
                    break;
                
                case 'shell_injection':
                    $fix_result = $this->fix_shell_injection($vulnerability);
                    break;
                
                default:
                    $fix_result = $this->fix_suspicious_code($vulnerability);
                    break;
            }

            if ($fix_result['success']) {
                $result['success'] = true;
                $result['actions_taken'] = array_merge($result['actions_taken'], $fix_result['actions_taken']);
                $result['changes_made'] = array_merge($result['changes_made'], $fix_result['changes_made']);
            } else {
                throw new Exception($fix_result['error_message']);
            }

        } catch (Exception $e) {
            $result['error_message'] = $e->getMessage();
            
            // Attempt to rollback if we have backup data
            if (!empty($result['rollback_data'])) {
                $this->rollback_fix($vulnerability, $result['rollback_data']);
            }
        }

        return $result;
    }

    /**
     * Validate that the fix was applied successfully.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability details.
     * @param    array    $fix_result       Fix application result.
     * @return   array                      Validation result.
     */
    public function validate_fix($vulnerability, $fix_result) {
        $validation = array(
            'is_valid' => false,
            'confidence' => 0,
            'validation_tests' => array(),
            'issues_found' => array()
        );

        try {
            // Validate based on vulnerability type
            switch ($vulnerability['type']) {
                case 'malware':
                case 'backdoor':
                    $validation = $this->validate_malware_fix($vulnerability, $fix_result);
                    break;
                
                case 'code_injection':
                case 'php_injection':
                    $validation = $this->validate_code_injection_fix($vulnerability, $fix_result);
                    break;
                
                case 'sql_injection':
                    $validation = $this->validate_sql_injection_fix($vulnerability, $fix_result);
                    break;
                
                case 'xss':
                    $validation = $this->validate_xss_fix($vulnerability, $fix_result);
                    break;
                
                default:
                    $validation = $this->validate_suspicious_code_fix($vulnerability, $fix_result);
                    break;
            }

            // Test site functionality after code changes
            $functionality_test = $this->test_site_functionality();
            $validation['validation_tests']['site_functionality'] = $functionality_test;
            
            if (!$functionality_test['passed']) {
                $validation['issues_found'][] = 'Site functionality affected by code changes';
                $validation['confidence'] -= 40;
            }

            // Check for PHP syntax errors
            $syntax_test = $this->check_php_syntax($vulnerability);
            $validation['validation_tests']['php_syntax'] = $syntax_test;
            
            if (!$syntax_test['passed']) {
                $validation['issues_found'][] = 'PHP syntax errors introduced';
                $validation['confidence'] -= 50;
            }

        } catch (Exception $e) {
            $validation['issues_found'][] = 'Validation error: ' . $e->getMessage();
            $validation['confidence'] = 0;
        }

        // Determine overall validation status
        $validation['is_valid'] = empty($validation['issues_found']) && $validation['confidence'] >= 60;

        return $validation;
    }

    /**
     * Rollback the applied fix.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability details.
     * @param    array    $rollback_data    Data needed for rollback.
     * @return   array                      Rollback result.
     */
    public function rollback_fix($vulnerability, $rollback_data) {
        $result = array(
            'success' => false,
            'actions_taken' => array(),
            'error_message' => ''
        );

        try {
            if (isset($rollback_data['file_backups'])) {
                $restored = 0;
                $total = count($rollback_data['file_backups']);

                foreach ($rollback_data['file_backups'] as $file_path => $backup_content) {
                    if ($this->filesystem->put_contents($file_path, $backup_content)) {
                        $restored++;
                    }
                }

                if ($restored === $total) {
                    $result['success'] = true;
                    $result['actions_taken'][] = "Restored {$restored} files from backup";
                } else {
                    throw new Exception("Only restored {$restored} of {$total} files");
                }
            } else {
                throw new Exception('No file backup data available for rollback');
            }

            // Restore quarantined files if any
            if (isset($rollback_data['quarantined_files'])) {
                $this->restore_quarantined_files($rollback_data['quarantined_files']);
                $result['actions_taken'][] = 'Restored quarantined files';
            }

        } catch (Exception $e) {
            $result['error_message'] = $e->getMessage();
        }

        return $result;
    }

    /**
     * Fix malware and backdoors.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability details.
     * @return   array                      Fix result.
     */
    private function fix_malware($vulnerability) {
        $result = array(
            'success' => false,
            'actions_taken' => array(),
            'changes_made' => array(),
            'error_message' => ''
        );

        try {
            $affected_files = isset($vulnerability['affected_files']) ? 
                             $vulnerability['affected_files'] : 
                             $this->scan_for_malware();

            $quarantined_files = array();
            $cleaned_files = array();

            foreach ($affected_files as $file_path) {
                if (!$this->filesystem->exists($file_path)) {
                    continue;
                }

                $file_content = $this->filesystem->get_contents($file_path);
                if ($file_content === false) {
                    continue;
                }

                // Analyze malware type and decide action
                $malware_analysis = $this->analyze_malware($file_content);
                
                if ($malware_analysis['severity'] === 'high') {
                    // Quarantine highly suspicious files
                    $quarantine_result = $this->quarantine_file($file_path);
                    if ($quarantine_result['success']) {
                        $quarantined_files[] = $file_path;
                        $result['changes_made'][] = "Quarantined malicious file: {$file_path}";
                    }
                } else {
                    // Try to clean moderate threats
                    $clean_result = $this->clean_malicious_code($file_content, $malware_analysis);
                    if ($clean_result['success']) {
                        if ($this->filesystem->put_contents($file_path, $clean_result['cleaned_content'])) {
                            $cleaned_files[] = $file_path;
                            $result['changes_made'][] = "Cleaned malicious code from: {$file_path}";
                        }
                    }
                }
            }

            if (!empty($quarantined_files) || !empty($cleaned_files)) {
                $result['success'] = true;
                $result['actions_taken'][] = "Processed " . count($affected_files) . " malicious files";
                
                if (!empty($quarantined_files)) {
                    $result['actions_taken'][] = "Quarantined " . count($quarantined_files) . " high-risk files";
                }
                
                if (!empty($cleaned_files)) {
                    $result['actions_taken'][] = "Cleaned " . count($cleaned_files) . " files";
                }
            } else {
                $result['success'] = true;
                $result['actions_taken'][] = 'No malware found or processed';
            }

        } catch (Exception $e) {
            $result['error_message'] = $e->getMessage();
        }

        return $result;
    }

    /**
     * Fix code injection vulnerabilities.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability details.
     * @return   array                      Fix result.
     */
    private function fix_code_injection($vulnerability) {
        $result = array(
            'success' => false,
            'actions_taken' => array(),
            'changes_made' => array(),
            'error_message' => ''
        );

        try {
            $affected_files = $vulnerability['affected_files'] ?? array();
            $fixed_files = 0;

            foreach ($affected_files as $file_path) {
                if (!$this->filesystem->exists($file_path)) {
                    continue;
                }

                $file_content = $this->filesystem->get_contents($file_path);
                if ($file_content === false) {
                    continue;
                }

                // Apply code injection fixes
                $fixed_content = $this->sanitize_code_injection($file_content);
                
                if ($fixed_content !== $file_content) {
                    if ($this->filesystem->put_contents($file_path, $fixed_content)) {
                        $fixed_files++;
                        $result['changes_made'][] = "Fixed code injection in: {$file_path}";
                    }
                }
            }

            $result['success'] = true;
            $result['actions_taken'][] = "Fixed code injection in {$fixed_files} files";

        } catch (Exception $e) {
            $result['error_message'] = $e->getMessage();
        }

        return $result;
    }

    /**
     * Fix SQL injection vulnerabilities.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability details.
     * @return   array                      Fix result.
     */
    private function fix_sql_injection($vulnerability) {
        $result = array(
            'success' => false,
            'actions_taken' => array(),
            'changes_made' => array(),
            'error_message' => ''
        );

        try {
            $affected_files = $vulnerability['affected_files'] ?? array();
            $fixed_files = 0;

            foreach ($affected_files as $file_path) {
                if (!$this->filesystem->exists($file_path)) {
                    continue;
                }

                $file_content = $this->filesystem->get_contents($file_path);
                if ($file_content === false) {
                    continue;
                }

                // Apply SQL injection fixes
                $fixed_content = $this->sanitize_sql_injection($file_content);
                
                if ($fixed_content !== $file_content) {
                    if ($this->filesystem->put_contents($file_path, $fixed_content)) {
                        $fixed_files++;
                        $result['changes_made'][] = "Fixed SQL injection in: {$file_path}";
                    }
                }
            }

            $result['success'] = true;
            $result['actions_taken'][] = "Fixed SQL injection in {$fixed_files} files";

        } catch (Exception $e) {
            $result['error_message'] = $e->getMessage();
        }

        return $result;
    }

    /**
     * Fix XSS vulnerabilities.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability details.
     * @return   array                      Fix result.
     */
    private function fix_xss_vulnerability($vulnerability) {
        $result = array(
            'success' => false,
            'actions_taken' => array(),
            'changes_made' => array(),
            'error_message' => ''
        );

        try {
            $affected_files = $vulnerability['affected_files'] ?? array();
            $fixed_files = 0;

            foreach ($affected_files as $file_path) {
                if (!$this->filesystem->exists($file_path)) {
                    continue;
                }

                $file_content = $this->filesystem->get_contents($file_path);
                if ($file_content === false) {
                    continue;
                }

                // Apply XSS fixes
                $fixed_content = $this->sanitize_xss_vulnerabilities($file_content);
                
                if ($fixed_content !== $file_content) {
                    if ($this->filesystem->put_contents($file_path, $fixed_content)) {
                        $fixed_files++;
                        $result['changes_made'][] = "Fixed XSS vulnerability in: {$file_path}";
                    }
                }
            }

            $result['success'] = true;
            $result['actions_taken'][] = "Fixed XSS vulnerabilities in {$fixed_files} files";

        } catch (Exception $e) {
            $result['error_message'] = $e->getMessage();
        }

        return $result;
    }

    /**
     * Create backup of code files.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability details.
     * @return   array                      Backup result.
     */
    private function create_code_backup($vulnerability) {
        $result = array(
            'success' => false,
            'backup_data' => array(),
            'error' => ''
        );

        try {
            $affected_files = isset($vulnerability['affected_files']) ? 
                             $vulnerability['affected_files'] : 
                             $this->get_all_code_files($vulnerability);

            $file_backups = array();
            foreach ($affected_files as $file_path) {
                if ($this->filesystem->exists($file_path)) {
                    $file_backups[$file_path] = $this->filesystem->get_contents($file_path);
                }
            }

            $result['backup_data'] = array(
                'file_backups' => $file_backups,
                'timestamp' => current_time('mysql')
            );
            $result['success'] = true;

        } catch (Exception $e) {
            $result['error'] = $e->getMessage();
        }

        return $result;
    }

    /**
     * Analyze malware in file content.
     *
     * @since    1.0.0
     * @param    string   $content   File content.
     * @return   array               Malware analysis.
     */
    private function analyze_malware($content) {
        $analysis = array(
            'severity' => 'low',
            'patterns_found' => array(),
            'confidence' => 0
        );

        $pattern_matches = 0;
        foreach ($this->malware_patterns as $pattern) {
            if (preg_match('/' . $pattern . '/i', $content)) {
                $analysis['patterns_found'][] = $pattern;
                $pattern_matches++;
            }
        }

        // Determine severity based on patterns found
        if ($pattern_matches >= 3) {
            $analysis['severity'] = 'high';
            $analysis['confidence'] = 0.9;
        } elseif ($pattern_matches >= 2) {
            $analysis['severity'] = 'medium';
            $analysis['confidence'] = 0.7;
        } elseif ($pattern_matches >= 1) {
            $analysis['severity'] = 'low';
            $analysis['confidence'] = 0.5;
        }

        // Check for base64 encoded content
        if (preg_match('/[A-Za-z0-9+\/]{100,}={0,2}/', $content)) {
            $analysis['patterns_found'][] = 'base64_encoded_content';
            $analysis['severity'] = 'medium';
        }

        return $analysis;
    }

    /**
     * Quarantine a suspicious file.
     *
     * @since    1.0.0
     * @param    string   $file_path   File path to quarantine.
     * @return   array                 Quarantine result.
     */
    private function quarantine_file($file_path) {
        $result = array('success' => false, 'quarantine_path' => '');

        try {
            $filename = basename($file_path);
            $quarantine_name = date('Y-m-d_H-i-s') . '_' . $filename;
            $quarantine_path = $this->quarantine_dir . '/' . $quarantine_name;

            // Copy file to quarantine
            if ($this->filesystem->copy($file_path, $quarantine_path)) {
                // Replace original with safe placeholder
                $placeholder_content = "<?php\n// File quarantined by WP-Breach on " . current_time('mysql') . "\n// Original file moved to quarantine\n";
                
                if ($this->filesystem->put_contents($file_path, $placeholder_content)) {
                    $result['success'] = true;
                    $result['quarantine_path'] = $quarantine_path;
                }
            }

        } catch (Exception $e) {
            $result['error'] = $e->getMessage();
        }

        return $result;
    }

    /**
     * Clean malicious code from file content.
     *
     * @since    1.0.0
     * @param    string   $content    File content.
     * @param    array    $analysis   Malware analysis.
     * @return   array                Cleaning result.
     */
    private function clean_malicious_code($content, $analysis) {
        $result = array(
            'success' => false,
            'cleaned_content' => $content,
            'changes_made' => array()
        );

        try {
            $cleaned_content = $content;

            // Remove obvious malicious patterns
            foreach ($analysis['patterns_found'] as $pattern) {
                switch ($pattern) {
                    case 'eval\s*\(':
                        $cleaned_content = preg_replace('/eval\s*\([^;]+;/i', '// Malicious eval() removed by WP-Breach', $cleaned_content);
                        $result['changes_made'][] = 'Removed eval() calls';
                        break;
                    
                    case 'base64_decode\s*\(':
                        // Only remove suspicious base64_decode
                        $cleaned_content = preg_replace('/\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*base64_decode\s*\([^)]+\);\s*eval\([^)]+\);/i', 
                                                       '// Malicious base64 eval removed by WP-Breach', $cleaned_content);
                        $result['changes_made'][] = 'Removed suspicious base64_decode + eval';
                        break;
                    
                    case 'system\s*\(':
                    case 'exec\s*\(':
                    case 'shell_exec\s*\(':
                        // Comment out system calls
                        $cleaned_content = preg_replace('/(' . $pattern . '[^;]+;)/i', '// $1 // Commented by WP-Breach', $cleaned_content);
                        $result['changes_made'][] = 'Commented out system execution calls';
                        break;
                }
            }

            if ($cleaned_content !== $content) {
                $result['success'] = true;
                $result['cleaned_content'] = $cleaned_content;
            }

        } catch (Exception $e) {
            $result['error'] = $e->getMessage();
        }

        return $result;
    }

    /**
     * Sanitize code injection vulnerabilities.
     *
     * @since    1.0.0
     * @param    string   $content   File content.
     * @return   string              Sanitized content.
     */
    private function sanitize_code_injection($content) {
        // Add input validation and sanitization
        $patterns = array(
            // Fix direct variable usage in dangerous functions
            '/eval\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\[/' => 'eval(sanitize_text_field($_$1[',
            '/system\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\[/' => 'system(escapeshellcmd($_$1[',
            '/exec\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\[/' => 'exec(escapeshellcmd($_$1[',
            '/shell_exec\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\[/' => 'shell_exec(escapeshellcmd($_$1[',
        );

        foreach ($patterns as $pattern => $replacement) {
            $content = preg_replace($pattern, $replacement, $content);
        }

        return $content;
    }

    /**
     * Sanitize SQL injection vulnerabilities.
     *
     * @since    1.0.0
     * @param    string   $content   File content.
     * @return   string              Sanitized content.
     */
    private function sanitize_sql_injection($content) {
        global $wpdb;
        
        // Fix common SQL injection patterns
        $patterns = array(
            // Direct variable concatenation in queries
            '/\$wpdb->query\s*\(\s*["\']([^"\']*)["\']?\s*\.\s*\$_(?:GET|POST|REQUEST)\[([^\]]+)\]/' => 
                '$wpdb->query($wpdb->prepare("$1%s", sanitize_text_field($_$2[$3]))',
            
            // Direct variable in WHERE clauses
            '/WHERE\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*["\']?\s*\$_(?:GET|POST|REQUEST)\[([^\]]+)\]/' => 
                'WHERE $1 = %s", sanitize_text_field($_$2[$3])',
        );

        foreach ($patterns as $pattern => $replacement) {
            $content = preg_replace($pattern, $replacement, $content);
        }

        return $content;
    }

    /**
     * Sanitize XSS vulnerabilities.
     *
     * @since    1.0.0
     * @param    string   $content   File content.
     * @return   string              Sanitized content.
     */
    private function sanitize_xss_vulnerabilities($content) {
        // Fix common XSS patterns
        $patterns = array(
            // Direct echo of user input
            '/echo\s+\$_(?:GET|POST|REQUEST|COOKIE)\[([^\]]+)\]/' => 'echo esc_html($_$1[$2])',
            '/print\s+\$_(?:GET|POST|REQUEST|COOKIE)\[([^\]]+)\]/' => 'print esc_html($_$1[$2])',
            
            // Direct output in HTML
            '/\?\>\s*\$_(?:GET|POST|REQUEST|COOKIE)\[([^\]]+)\]\s*\<\?/' => '?><?php echo esc_html($_$1[$2]); ?><?',
        );

        foreach ($patterns as $pattern => $replacement) {
            $content = preg_replace($pattern, $replacement, $content);
        }

        return $content;
    }

    /**
     * Test site functionality after code changes.
     *
     * @since    1.0.0
     * @return   array    Functionality test result.
     */
    private function test_site_functionality() {
        $test = array(
            'passed' => true,
            'issues' => array()
        );

        // Test if site loads
        $response = wp_remote_get(home_url());
        if (is_wp_error($response)) {
            $test['passed'] = false;
            $test['issues'][] = 'Site not responding: ' . $response->get_error_message();
        } elseif (wp_remote_retrieve_response_code($response) !== 200) {
            $test['passed'] = false;
            $test['issues'][] = 'Site returning error code: ' . wp_remote_retrieve_response_code($response);
        }

        // Test admin access
        $admin_response = wp_remote_get(admin_url());
        if (is_wp_error($admin_response) || wp_remote_retrieve_response_code($admin_response) !== 200) {
            $test['passed'] = false;
            $test['issues'][] = 'Admin area not accessible';
        }

        return $test;
    }

    /**
     * Check PHP syntax of modified files.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability details.
     * @return   array                      Syntax check result.
     */
    private function check_php_syntax($vulnerability) {
        $test = array(
            'passed' => true,
            'issues' => array()
        );

        if (!isset($vulnerability['affected_files'])) {
            return $test;
        }

        foreach ($vulnerability['affected_files'] as $file_path) {
            if (!$this->filesystem->exists($file_path) || pathinfo($file_path, PATHINFO_EXTENSION) !== 'php') {
                continue;
            }

            // Use php -l to check syntax
            $command = "php -l " . escapeshellarg($file_path) . " 2>&1";
            $output = shell_exec($command);

            if (strpos($output, 'No syntax errors') === false) {
                $test['passed'] = false;
                $test['issues'][] = "Syntax error in {$file_path}: {$output}";
            }
        }

        return $test;
    }

    /**
     * Check if vulnerability affects WordPress core files.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability details.
     * @return   bool                       True if core files affected.
     */
    private function affects_core_files($vulnerability) {
        if (!isset($vulnerability['affected_files'])) {
            return false;
        }

        $core_paths = array('/wp-admin/', '/wp-includes/', 'wp-config.php');
        
        foreach ($vulnerability['affected_files'] as $file) {
            foreach ($core_paths as $core_path) {
                if (strpos($file, $core_path) !== false) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Check if vulnerability affects active theme or plugin files.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability details.
     * @return   bool                       True if active components affected.
     */
    private function affects_active_components($vulnerability) {
        if (!isset($vulnerability['affected_files'])) {
            return false;
        }

        $active_theme_path = get_template_directory();
        $active_plugins = get_option('active_plugins', array());

        foreach ($vulnerability['affected_files'] as $file) {
            // Check active theme
            if (strpos($file, $active_theme_path) === 0) {
                return true;
            }

            // Check active plugins
            foreach ($active_plugins as $plugin) {
                $plugin_path = WP_PLUGIN_DIR . '/' . dirname($plugin);
                if (strpos($file, $plugin_path) === 0) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Check if this is a development environment.
     *
     * @since    1.0.0
     * @return   bool    True if development environment.
     */
    private function is_development_environment() {
        $dev_indicators = array('localhost', '127.0.0.1', '.local', '.dev', '.test', 'staging');
        $site_url = get_site_url();

        foreach ($dev_indicators as $indicator) {
            if (strpos($site_url, $indicator) !== false) {
                return true;
            }
        }

        return defined('WP_DEBUG') && WP_DEBUG;
    }

    /**
     * Check if file backup can be created.
     *
     * @since    1.0.0
     * @return   bool    True if backup can be created.
     */
    private function can_create_file_backup() {
        return $this->filesystem && $this->filesystem->exists(ABSPATH);
    }

    /**
     * Check if code analysis capability is available.
     *
     * @since    1.0.0
     * @return   bool    True if code analysis available.
     */
    private function has_code_analysis_capability() {
        // Check if PHP CLI is available for syntax checking
        $php_available = shell_exec('php --version 2>/dev/null');
        return !empty($php_available);
    }

    /**
     * Scan for malware in the WordPress installation.
     *
     * @since    1.0.0
     * @return   array    Suspected malicious files.
     */
    private function scan_for_malware() {
        $suspicious_files = array();
        
        // Scan wp-content directory (excluding safe areas)
        $scan_dirs = array(
            WP_CONTENT_DIR . '/themes',
            WP_CONTENT_DIR . '/plugins',
            WP_CONTENT_DIR . '/uploads'
        );

        foreach ($scan_dirs as $dir) {
            if ($this->filesystem->exists($dir)) {
                $files = $this->scan_directory_for_malware($dir);
                $suspicious_files = array_merge($suspicious_files, $files);
            }
        }

        return $suspicious_files;
    }

    /**
     * Scan a directory for malware.
     *
     * @since    1.0.0
     * @param    string   $directory   Directory to scan.
     * @return   array                 Suspicious files.
     */
    private function scan_directory_for_malware($directory) {
        $suspicious_files = array();
        
        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS),
                RecursiveIteratorIterator::LEAVES_ONLY
            );

            $scanned = 0;
            foreach ($iterator as $file) {
                if ($scanned >= 500) { // Limit to prevent timeout
                    break;
                }

                $file_path = $file->getPathname();
                
                // Skip safe files and directories
                if ($this->is_safe_file($file_path)) {
                    continue;
                }

                // Only scan PHP files
                if (pathinfo($file_path, PATHINFO_EXTENSION) !== 'php') {
                    continue;
                }

                $content = $this->filesystem->get_contents($file_path);
                if ($content !== false) {
                    $analysis = $this->analyze_malware($content);
                    if ($analysis['confidence'] > 0.5) {
                        $suspicious_files[] = $file_path;
                    }
                }

                $scanned++;
            }

        } catch (Exception $e) {
            error_log('[WP-Breach] Malware scan error: ' . $e->getMessage());
        }

        return $suspicious_files;
    }

    /**
     * Check if file is safe to scan/modify.
     *
     * @since    1.0.0
     * @param    string   $file_path   File path.
     * @return   bool                  True if safe.
     */
    private function is_safe_file($file_path) {
        foreach ($this->safe_file_patterns as $pattern) {
            if (strpos($file_path, $pattern) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get all code files affected by vulnerability.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability details.
     * @return   array                      Code files.
     */
    private function get_all_code_files($vulnerability) {
        if (isset($vulnerability['affected_files'])) {
            return $vulnerability['affected_files'];
        }

        // Default to scanning for issues
        return $this->scan_for_malware();
    }

    /**
     * Fix shell injection vulnerabilities.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability details.
     * @return   array                      Fix result.
     */
    private function fix_shell_injection($vulnerability) {
        $result = array(
            'success' => false,
            'actions_taken' => array(),
            'changes_made' => array(),
            'error_message' => ''
        );

        try {
            $affected_files = $vulnerability['affected_files'] ?? array();
            $fixed_files = 0;

            foreach ($affected_files as $file_path) {
                if (!$this->filesystem->exists($file_path)) {
                    continue;
                }

                $file_content = $this->filesystem->get_contents($file_path);
                if ($file_content === false) {
                    continue;
                }

                // Apply shell injection fixes
                $fixed_content = $this->sanitize_shell_injection($file_content);
                
                if ($fixed_content !== $file_content) {
                    if ($this->filesystem->put_contents($file_path, $fixed_content)) {
                        $fixed_files++;
                        $result['changes_made'][] = "Fixed shell injection in: {$file_path}";
                    }
                }
            }

            $result['success'] = true;
            $result['actions_taken'][] = "Fixed shell injection in {$fixed_files} files";

        } catch (Exception $e) {
            $result['error_message'] = $e->getMessage();
        }

        return $result;
    }

    /**
     * Sanitize shell injection vulnerabilities.
     *
     * @since    1.0.0
     * @param    string   $content   File content.
     * @return   string              Sanitized content.
     */
    private function sanitize_shell_injection($content) {
        // Fix common shell injection patterns
        $patterns = array(
            '/system\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\[([^\]]+)\]/' => 'system(escapeshellcmd($_$1[$2])',
            '/exec\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\[([^\]]+)\]/' => 'exec(escapeshellcmd($_$1[$2])',
            '/shell_exec\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\[([^\]]+)\]/' => 'shell_exec(escapeshellcmd($_$1[$2])',
            '/passthru\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\[([^\]]+)\]/' => 'passthru(escapeshellcmd($_$1[$2])',
        );

        foreach ($patterns as $pattern => $replacement) {
            $content = preg_replace($pattern, $replacement, $content);
        }

        return $content;
    }

    /**
     * Fix suspicious code.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability details.
     * @return   array                      Fix result.
     */
    private function fix_suspicious_code($vulnerability) {
        // Use general malware fix approach for suspicious code
        return $this->fix_malware($vulnerability);
    }

    /**
     * Restore quarantined files.
     *
     * @since    1.0.0
     * @param    array    $quarantined_files   Quarantined files list.
     * @return   bool                          True if successful.
     */
    private function restore_quarantined_files($quarantined_files) {
        foreach ($quarantined_files as $original_path => $quarantine_path) {
            if ($this->filesystem->exists($quarantine_path)) {
                $this->filesystem->copy($quarantine_path, $original_path);
                $this->filesystem->delete($quarantine_path);
            }
        }
        return true;
    }

    /**
     * Validate malware fix.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability details.
     * @param    array    $fix_result       Fix result.
     * @return   array                      Validation result.
     */
    private function validate_malware_fix($vulnerability, $fix_result) {
        $validation = array(
            'is_valid' => false,
            'confidence' => 70,
            'validation_tests' => array(),
            'issues_found' => array()
        );

        // Re-scan for malware patterns
        $remaining_malware = $this->scan_for_malware();
        if (empty($remaining_malware)) {
            $validation['validation_tests']['malware_scan'] = array(
                'passed' => true,
                'message' => 'No malware patterns detected'
            );
        } else {
            $validation['issues_found'][] = 'Malware patterns still detected';
            $validation['confidence'] -= 30;
        }

        $validation['is_valid'] = empty($validation['issues_found']);
        return $validation;
    }

    /**
     * Validate code injection fix.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability details.
     * @param    array    $fix_result       Fix result.
     * @return   array                      Validation result.
     */
    private function validate_code_injection_fix($vulnerability, $fix_result) {
        $validation = array(
            'is_valid' => false,
            'confidence' => 75,
            'validation_tests' => array(),
            'issues_found' => array()
        );

        // Check if dangerous functions are still directly accessible via user input
        $affected_files = $vulnerability['affected_files'] ?? array();
        $vulnerable_patterns = 0;

        foreach ($affected_files as $file_path) {
            if ($this->filesystem->exists($file_path)) {
                $content = $this->filesystem->get_contents($file_path);
                if (preg_match('/eval\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\[/', $content)) {
                    $vulnerable_patterns++;
                }
            }
        }

        if ($vulnerable_patterns === 0) {
            $validation['validation_tests']['code_injection_patterns'] = array(
                'passed' => true,
                'message' => 'No vulnerable code injection patterns found'
            );
        } else {
            $validation['issues_found'][] = 'Vulnerable code injection patterns still present';
            $validation['confidence'] -= 25;
        }

        $validation['is_valid'] = empty($validation['issues_found']);
        return $validation;
    }

    /**
     * Validate SQL injection fix.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability details.
     * @param    array    $fix_result       Fix result.
     * @return   array                      Validation result.
     */
    private function validate_sql_injection_fix($vulnerability, $fix_result) {
        $validation = array(
            'is_valid' => false,
            'confidence' => 75,
            'validation_tests' => array(),
            'issues_found' => array()
        );

        // Check if SQL queries are properly prepared
        $affected_files = $vulnerability['affected_files'] ?? array();
        $vulnerable_queries = 0;

        foreach ($affected_files as $file_path) {
            if ($this->filesystem->exists($file_path)) {
                $content = $this->filesystem->get_contents($file_path);
                // Look for unsanitized SQL queries
                if (preg_match('/\$wpdb->query\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)\[/', $content)) {
                    $vulnerable_queries++;
                }
            }
        }

        if ($vulnerable_queries === 0) {
            $validation['validation_tests']['sql_injection_patterns'] = array(
                'passed' => true,
                'message' => 'No vulnerable SQL injection patterns found'
            );
        } else {
            $validation['issues_found'][] = 'Vulnerable SQL injection patterns still present';
            $validation['confidence'] -= 25;
        }

        $validation['is_valid'] = empty($validation['issues_found']);
        return $validation;
    }

    /**
     * Validate XSS fix.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability details.
     * @param    array    $fix_result       Fix result.
     * @return   array                      Validation result.
     */
    private function validate_xss_fix($vulnerability, $fix_result) {
        $validation = array(
            'is_valid' => false,
            'confidence' => 75,
            'validation_tests' => array(),
            'issues_found' => array()
        );

        // Check if output is properly escaped
        $affected_files = $vulnerability['affected_files'] ?? array();
        $vulnerable_output = 0;

        foreach ($affected_files as $file_path) {
            if ($this->filesystem->exists($file_path)) {
                $content = $this->filesystem->get_contents($file_path);
                // Look for unescaped output
                if (preg_match('/echo\s+\$_(?:GET|POST|REQUEST|COOKIE)\[/', $content)) {
                    $vulnerable_output++;
                }
            }
        }

        if ($vulnerable_output === 0) {
            $validation['validation_tests']['xss_patterns'] = array(
                'passed' => true,
                'message' => 'No vulnerable XSS patterns found'
            );
        } else {
            $validation['issues_found'][] = 'Vulnerable XSS patterns still present';
            $validation['confidence'] -= 25;
        }

        $validation['is_valid'] = empty($validation['issues_found']);
        return $validation;
    }

    /**
     * Validate suspicious code fix.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability details.
     * @param    array    $fix_result       Fix result.
     * @return   array                      Validation result.
     */
    private function validate_suspicious_code_fix($vulnerability, $fix_result) {
        // Use malware validation for suspicious code
        return $this->validate_malware_fix($vulnerability, $fix_result);
    }
}

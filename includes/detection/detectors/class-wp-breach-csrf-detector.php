<?php

/**
 * The CSRF vulnerability detector.
 *
 * This class handles detection of Cross-Site Request Forgery (CSRF) vulnerabilities
 * in forms and AJAX actions.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/detection/detectors
 */

/**
 * The CSRF detector class.
 *
 * This class provides specialized detection for CSRF vulnerabilities
 * using form analysis and WordPress nonce verification.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/detection/detectors
 * @author     WP Breach Team
 */
class WP_Breach_Csrf_Detector {

    /**
     * CSRF patterns.
     *
     * @since    1.0.0
     * @access   protected
     * @var      array    $patterns    Array of CSRF patterns.
     */
    protected $patterns;

    /**
     * WordPress nonce functions.
     *
     * @since    1.0.0
     * @access   protected
     * @var      array    $nonce_functions    WordPress nonce functions.
     */
    protected $nonce_functions;

    /**
     * Sensitive actions.
     *
     * @since    1.0.0
     * @access   protected
     * @var      array    $sensitive_actions    Sensitive actions that need CSRF protection.
     */
    protected $sensitive_actions;

    /**
     * Initialize the CSRF detector.
     *
     * @since    1.0.0
     */
    public function __construct() {
        $this->init_patterns();
        $this->init_nonce_functions();
        $this->init_sensitive_actions();
    }

    /**
     * Initialize CSRF patterns.
     *
     * @since    1.0.0
     */
    private function init_patterns() {
        $this->patterns = array(
            // Forms without nonce
            'form_without_nonce' => array(
                'pattern' => '/<form[^>]*method\s*=\s*["\']post["\'][^>]*>/i',
                'severity' => 'high',
                'confidence' => 0.7,
                'description' => 'POST form without CSRF protection'
            ),
            // AJAX without nonce
            'ajax_without_nonce' => array(
                'pattern' => '/\$\.post\s*\(|wp_ajax_|admin-ajax\.php/i',
                'severity' => 'medium',
                'confidence' => 0.6,
                'description' => 'AJAX call potentially without CSRF protection'
            ),
            // Action handlers without nonce check
            'action_handler' => array(
                'pattern' => '/add_action\s*\(\s*["\']wp_ajax_\w+["\']|add_action\s*\(\s*["\']admin_post_\w+["\']/i',
                'severity' => 'medium',
                'confidence' => 0.6,
                'description' => 'Action handler potentially without CSRF verification'
            ),
            // Direct form processing
            'direct_processing' => array(
                'pattern' => '/if\s*\(\s*\$_POST\[|if\s*\(\s*isset\s*\(\s*\$_POST\[/i',
                'severity' => 'medium',
                'confidence' => 0.5,
                'description' => 'Direct POST processing without CSRF check'
            )
        );
    }

    /**
     * Initialize WordPress nonce functions.
     *
     * @since    1.0.0
     */
    private function init_nonce_functions() {
        $this->nonce_functions = array(
            'creation' => array(
                'wp_nonce_field', 'wp_nonce_url', 'wp_create_nonce'
            ),
            'verification' => array(
                'wp_verify_nonce', 'check_admin_referer', 'check_ajax_referer'
            )
        );
    }

    /**
     * Initialize sensitive actions.
     *
     * @since    1.0.0
     */
    private function init_sensitive_actions() {
        $this->sensitive_actions = array(
            'database_operations' => array(
                'insert', 'update', 'delete', 'save', 'create', 'remove', 'modify'
            ),
            'user_management' => array(
                'login', 'logout', 'register', 'password', 'profile', 'activate', 'deactivate'
            ),
            'admin_functions' => array(
                'install', 'uninstall', 'upgrade', 'activate', 'deactivate', 'configure', 'settings'
            ),
            'file_operations' => array(
                'upload', 'download', 'backup', 'restore', 'import', 'export'
            )
        );
    }

    /**
     * Detect CSRF vulnerabilities.
     *
     * @since    1.0.0
     * @param    string    $content         File content to analyze.
     * @param    string    $file_path       File path being analyzed.
     * @param    array     $file_info       File information.
     * @return   array                      Array of detected vulnerabilities.
     */
    public function detect($content, $file_path, $file_info) {
        $vulnerabilities = array();

        // Analyze forms
        $form_vulns = $this->analyze_forms($content);
        $vulnerabilities = array_merge($vulnerabilities, $form_vulns);

        // Analyze AJAX handlers
        $ajax_vulns = $this->analyze_ajax_handlers($content);
        $vulnerabilities = array_merge($vulnerabilities, $ajax_vulns);

        // Analyze action hooks
        $action_vulns = $this->analyze_action_hooks($content);
        $vulnerabilities = array_merge($vulnerabilities, $action_vulns);

        // Analyze POST processing
        $post_vulns = $this->analyze_post_processing($content);
        $vulnerabilities = array_merge($vulnerabilities, $post_vulns);

        // Check admin pages
        if ($this->is_admin_file($file_path)) {
            $admin_vulns = $this->analyze_admin_functionality($content);
            $vulnerabilities = array_merge($vulnerabilities, $admin_vulns);
        }

        return $vulnerabilities;
    }

    /**
     * Analyze forms for CSRF protection.
     *
     * @since    1.0.0
     * @param    string    $content         File content.
     * @return   array                      Detected vulnerabilities.
     */
    private function analyze_forms($content) {
        $vulnerabilities = array();
        $lines = explode("\n", $content);

        // Find all POST forms
        preg_match_all('/<form[^>]*method\s*=\s*["\']post["\'][^>]*>(.*?)<\/form>/is', $content, $form_matches, PREG_OFFSET_CAPTURE);

        foreach ($form_matches[0] as $i => $form_match) {
            $form_html = $form_match[0];
            $form_content = $form_matches[1][$i][0];
            $line_number = $this->get_line_number($content, $form_match[1]);

            // Check if form has nonce field
            if (!$this->has_nonce_field($form_content)) {
                // Check if it's a sensitive form
                $is_sensitive = $this->is_sensitive_form($form_content);
                
                $severity = $is_sensitive ? 'high' : 'medium';
                $confidence = $is_sensitive ? 0.8 : 0.6;

                $vulnerabilities[] = array(
                    'type' => 'csrf',
                    'subtype' => 'form_without_nonce',
                    'severity' => $severity,
                    'confidence' => $confidence,
                    'description' => 'POST form without CSRF protection (nonce field)',
                    'line' => $line_number,
                    'matched_text' => substr($form_html, 0, 100) . '...',
                    'context' => $this->get_context($lines, $line_number),
                    'is_sensitive' => $is_sensitive,
                    'cwe_id' => 'CWE-352',
                    'owasp_category' => 'A01:2021-Broken Access Control',
                    'recommendation' => 'Add wp_nonce_field() to the form and verify with wp_verify_nonce()'
                );
            }
        }

        return $vulnerabilities;
    }

    /**
     * Analyze AJAX handlers for CSRF protection.
     *
     * @since    1.0.0
     * @param    string    $content         File content.
     * @return   array                      Detected vulnerabilities.
     */
    private function analyze_ajax_handlers($content) {
        $vulnerabilities = array();
        $lines = explode("\n", $content);

        // Find AJAX action registrations
        preg_match_all('/add_action\s*\(\s*["\']wp_ajax_(\w+)["\']/', $content, $ajax_matches, PREG_OFFSET_CAPTURE);

        foreach ($ajax_matches[1] as $i => $action_match) {
            $action_name = $action_match[0];
            $line_number = $this->get_line_number($content, $action_match[1]);

            // Look for the corresponding function
            $function_pattern = '/function\s+\w*' . preg_quote($action_name, '/') . '\w*\s*\([^)]*\)\s*\{([^}]+|\{[^}]*\})*\}/s';
            if (preg_match($function_pattern, $content, $function_match)) {
                $function_content = $function_match[0];
                
                // Check if function has nonce verification
                if (!$this->has_nonce_verification($function_content)) {
                    $vulnerabilities[] = array(
                        'type' => 'csrf',
                        'subtype' => 'ajax_without_nonce',
                        'severity' => 'medium',
                        'confidence' => 0.7,
                        'description' => "AJAX handler '{$action_name}' without CSRF protection",
                        'line' => $line_number,
                        'matched_text' => $ajax_matches[0][$i][0],
                        'context' => $this->get_context($lines, $line_number),
                        'action_name' => $action_name,
                        'cwe_id' => 'CWE-352',
                        'owasp_category' => 'A01:2021-Broken Access Control',
                        'recommendation' => 'Add check_ajax_referer() or wp_verify_nonce() in AJAX handler'
                    );
                }
            }
        }

        return $vulnerabilities;
    }

    /**
     * Analyze action hooks for CSRF protection.
     *
     * @since    1.0.0
     * @param    string    $content         File content.
     * @return   array                      Detected vulnerabilities.
     */
    private function analyze_action_hooks($content) {
        $vulnerabilities = array();
        $lines = explode("\n", $content);

        // Find admin_post action registrations
        preg_match_all('/add_action\s*\(\s*["\']admin_post_(\w+)["\']/', $content, $post_matches, PREG_OFFSET_CAPTURE);

        foreach ($post_matches[1] as $i => $action_match) {
            $action_name = $action_match[0];
            $line_number = $this->get_line_number($content, $action_match[1]);

            // Look for the corresponding function
            $function_pattern = '/function\s+\w*' . preg_quote($action_name, '/') . '\w*\s*\([^)]*\)\s*\{([^}]+|\{[^}]*\})*\}/s';
            if (preg_match($function_pattern, $content, $function_match)) {
                $function_content = $function_match[0];
                
                // Check if function has admin referer check
                if (!$this->has_admin_referer_check($function_content)) {
                    $vulnerabilities[] = array(
                        'type' => 'csrf',
                        'subtype' => 'admin_post_without_referer',
                        'severity' => 'high',
                        'confidence' => 0.8,
                        'description' => "Admin POST handler '{$action_name}' without CSRF protection",
                        'line' => $line_number,
                        'matched_text' => $post_matches[0][$i][0],
                        'context' => $this->get_context($lines, $line_number),
                        'action_name' => $action_name,
                        'cwe_id' => 'CWE-352',
                        'owasp_category' => 'A01:2021-Broken Access Control',
                        'recommendation' => 'Add check_admin_referer() in admin POST handler'
                    );
                }
            }
        }

        return $vulnerabilities;
    }

    /**
     * Analyze POST processing for CSRF protection.
     *
     * @since    1.0.0
     * @param    string    $content         File content.
     * @return   array                      Detected vulnerabilities.
     */
    private function analyze_post_processing($content) {
        $vulnerabilities = array();
        $lines = explode("\n", $content);

        // Find direct POST processing
        preg_match_all('/if\s*\(\s*(?:isset\s*\(\s*)?\$_POST\[([^\]]+)\]/', $content, $post_matches, PREG_OFFSET_CAPTURE);

        foreach ($post_matches[0] as $i => $post_match) {
            $line_number = $this->get_line_number($content, $post_match[1]);
            
            // Get the code block that handles this POST
            $post_handler = $this->extract_post_handler($content, $post_match[1]);
            
            // Check if handler has nonce verification
            if (!empty($post_handler) && !$this->has_nonce_verification($post_handler)) {
                // Check if it performs sensitive operations
                $is_sensitive = $this->has_sensitive_operations($post_handler);
                
                if ($is_sensitive) {
                    $vulnerabilities[] = array(
                        'type' => 'csrf',
                        'subtype' => 'post_without_nonce',
                        'severity' => 'high',
                        'confidence' => 0.7,
                        'description' => 'POST processing without CSRF verification',
                        'line' => $line_number,
                        'matched_text' => $post_match[0],
                        'context' => $this->get_context($lines, $line_number),
                        'post_field' => $post_matches[1][$i][0],
                        'cwe_id' => 'CWE-352',
                        'owasp_category' => 'A01:2021-Broken Access Control',
                        'recommendation' => 'Add nonce verification before processing POST data'
                    );
                }
            }
        }

        return $vulnerabilities;
    }

    /**
     * Analyze admin functionality for CSRF protection.
     *
     * @since    1.0.0
     * @param    string    $content         File content.
     * @return   array                      Detected vulnerabilities.
     */
    private function analyze_admin_functionality($content) {
        $vulnerabilities = array();
        $lines = explode("\n", $content);

        // Check for admin menu callbacks without CSRF protection
        preg_match_all('/add_(?:menu|submenu)_page\s*\([^,]*,[^,]*,[^,]*,[^,]*,\s*["\']([^"\']+)["\']/', $content, $menu_matches, PREG_OFFSET_CAPTURE);

        foreach ($menu_matches[1] as $i => $callback_match) {
            $callback_name = $callback_match[0];
            $line_number = $this->get_line_number($content, $callback_match[1]);

            // Look for the callback function
            $function_pattern = '/function\s+' . preg_quote($callback_name, '/') . '\s*\([^)]*\)\s*\{([^}]+|\{[^}]*\})*\}/s';
            if (preg_match($function_pattern, $content, $function_match)) {
                $function_content = $function_match[0];
                
                // Check if function processes forms without CSRF protection
                if (preg_match('/\$_POST/', $function_content) && 
                    !$this->has_nonce_verification($function_content)) {
                    
                    $vulnerabilities[] = array(
                        'type' => 'csrf',
                        'subtype' => 'admin_callback_without_csrf',
                        'severity' => 'high',
                        'confidence' => 0.8,
                        'description' => "Admin page callback '{$callback_name}' processes POST without CSRF protection",
                        'line' => $line_number,
                        'matched_text' => $menu_matches[0][$i][0],
                        'context' => $this->get_context($lines, $line_number),
                        'callback_name' => $callback_name,
                        'cwe_id' => 'CWE-352',
                        'owasp_category' => 'A01:2021-Broken Access Control',
                        'recommendation' => 'Add CSRF verification in admin page callback'
                    );
                }
            }
        }

        return $vulnerabilities;
    }

    /**
     * Check if form has nonce field.
     *
     * @since    1.0.0
     * @param    string    $form_content    Form HTML content.
     * @return   bool                       True if has nonce field.
     */
    private function has_nonce_field($form_content) {
        // Check for wp_nonce_field function call
        if (preg_match('/wp_nonce_field\s*\(/', $form_content)) {
            return true;
        }

        // Check for manual nonce input field
        if (preg_match('/name\s*=\s*["\']_wpnonce["\']/', $form_content)) {
            return true;
        }

        // Check for _wp_http_referer field
        if (preg_match('/name\s*=\s*["\']_wp_http_referer["\']/', $form_content)) {
            return true;
        }

        return false;
    }

    /**
     * Check if code has nonce verification.
     *
     * @since    1.0.0
     * @param    string    $code            Code to check.
     * @return   bool                       True if has nonce verification.
     */
    private function has_nonce_verification($code) {
        $verification_functions = $this->nonce_functions['verification'];
        
        foreach ($verification_functions as $function) {
            if (strpos($code, $function) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if code has admin referer check.
     *
     * @since    1.0.0
     * @param    string    $code            Code to check.
     * @return   bool                       True if has admin referer check.
     */
    private function has_admin_referer_check($code) {
        return strpos($code, 'check_admin_referer') !== false;
    }

    /**
     * Check if form is sensitive.
     *
     * @since    1.0.0
     * @param    string    $form_content    Form content.
     * @return   bool                       True if sensitive form.
     */
    private function is_sensitive_form($form_content) {
        $sensitive_indicators = array(
            'password', 'email', 'user', 'login', 'register', 'delete', 'remove',
            'upload', 'settings', 'config', 'admin', 'update', 'save'
        );

        foreach ($sensitive_indicators as $indicator) {
            if (stripos($form_content, $indicator) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if code has sensitive operations.
     *
     * @since    1.0.0
     * @param    string    $code            Code to check.
     * @return   bool                       True if has sensitive operations.
     */
    private function has_sensitive_operations($code) {
        $all_sensitive = array();
        foreach ($this->sensitive_actions as $category => $actions) {
            $all_sensitive = array_merge($all_sensitive, $actions);
        }

        foreach ($all_sensitive as $action) {
            if (stripos($code, $action) !== false) {
                return true;
            }
        }

        // Check for database operations
        $db_patterns = array(
            '\$wpdb->insert', '\$wpdb->update', '\$wpdb->delete', '\$wpdb->query',
            'wp_insert_', 'wp_update_', 'wp_delete_', 'update_option', 'delete_option'
        );

        foreach ($db_patterns as $pattern) {
            if (preg_match('/' . preg_quote($pattern, '/') . '/i', $code)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Extract POST handler code block.
     *
     * @since    1.0.0
     * @param    string    $content         Full content.
     * @param    int       $offset          POST check offset.
     * @return   string                     POST handler code.
     */
    private function extract_post_handler($content, $offset) {
        // Find the opening brace of the if block
        $brace_start = strpos($content, '{', $offset);
        if ($brace_start === false) {
            return '';
        }

        // Find the matching closing brace
        $brace_count = 1;
        $pos = $brace_start + 1;
        
        while ($pos < strlen($content) && $brace_count > 0) {
            if ($content[$pos] === '{') {
                $brace_count++;
            } elseif ($content[$pos] === '}') {
                $brace_count--;
            }
            $pos++;
        }

        if ($brace_count === 0) {
            return substr($content, $brace_start, $pos - $brace_start);
        }

        return '';
    }

    /**
     * Check if file is admin file.
     *
     * @since    1.0.0
     * @param    string    $file_path       File path.
     * @return   bool                       True if admin file.
     */
    private function is_admin_file($file_path) {
        return (strpos($file_path, '/admin/') !== false || 
                strpos($file_path, 'wp-admin') !== false ||
                strpos($file_path, 'admin.php') !== false);
    }

    /**
     * Get line number from content offset.
     *
     * @since    1.0.0
     * @param    string    $content         Content.
     * @param    int       $offset          Offset position.
     * @return   int                        Line number.
     */
    private function get_line_number($content, $offset) {
        return substr_count(substr($content, 0, $offset), "\n") + 1;
    }

    /**
     * Get context around a line.
     *
     * @since    1.0.0
     * @param    array     $lines           Content lines.
     * @param    int       $line_number     Target line number.
     * @param    int       $context_lines   Number of context lines.
     * @return   array                      Context information.
     */
    private function get_context($lines, $line_number, $context_lines = 3) {
        $start = max(0, $line_number - $context_lines - 1);
        $end = min(count($lines), $line_number + $context_lines);
        
        $context_array = array();
        for ($i = $start; $i < $end; $i++) {
            $context_array[] = array(
                'line_number' => $i + 1,
                'content' => isset($lines[$i]) ? $lines[$i] : '',
                'is_target' => ($i + 1) === $line_number
            );
        }

        return array(
            'lines' => $context_array,
            'target_line' => $line_number
        );
    }

    /**
     * Get detector configuration.
     *
     * @since    1.0.0
     * @return   array                      Detector configuration.
     */
    public function get_config() {
        return array(
            'patterns' => $this->patterns,
            'nonce_functions' => $this->nonce_functions,
            'sensitive_actions' => $this->sensitive_actions
        );
    }

    /**
     * Update detector configuration.
     *
     * @since    1.0.0
     * @param    array     $config          New configuration.
     */
    public function update_config($config) {
        if (isset($config['patterns'])) {
            $this->patterns = array_merge($this->patterns, $config['patterns']);
        }

        if (isset($config['sensitive_actions'])) {
            $this->sensitive_actions = array_merge($this->sensitive_actions, $config['sensitive_actions']);
        }
    }
}

<?php

/**
 * The authentication bypass vulnerability detector.
 *
 * This class handles detection of authentication and authorization
 * bypass vulnerabilities in WordPress applications.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/detection/detectors
 */

/**
 * The authentication bypass detector class.
 *
 * This class provides specialized detection for authentication bypass
 * vulnerabilities using access control analysis.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/detection/detectors
 * @author     WP Breach Team
 */
class WP_Breach_Auth_Bypass_Detector {

    /**
     * Authentication bypass patterns.
     *
     * @since    1.0.0
     * @access   protected
     * @var      array    $patterns    Array of auth bypass patterns.
     */
    protected $patterns;

    /**
     * WordPress authentication functions.
     *
     * @since    1.0.0
     * @access   protected
     * @var      array    $auth_functions    WordPress auth functions.
     */
    protected $auth_functions;

    /**
     * Capability checking functions.
     *
     * @since    1.0.0
     * @access   protected
     * @var      array    $capability_functions    Capability checking functions.
     */
    protected $capability_functions;

    /**
     * Sensitive operations.
     *
     * @since    1.0.0
     * @access   protected
     * @var      array    $sensitive_operations    Operations requiring authentication.
     */
    protected $sensitive_operations;

    /**
     * Initialize the authentication bypass detector.
     *
     * @since    1.0.0
     */
    public function __construct() {
        $this->init_patterns();
        $this->init_auth_functions();
        $this->init_capability_functions();
        $this->init_sensitive_operations();
    }

    /**
     * Initialize authentication bypass patterns.
     *
     * @since    1.0.0
     */
    private function init_patterns() {
        $this->patterns = array(
            // Direct admin access without capability check
            'admin_no_cap' => array(
                'pattern' => '/add_action\s*\(\s*["\']admin_menu["\'].*?function.*?\{(?![^}]*(?:current_user_can|is_admin|wp_verify_nonce))/s',
                'severity' => 'high',
                'confidence' => 0.7,
                'description' => 'Admin menu without capability check'
            ),
            // AJAX without authentication
            'ajax_no_auth' => array(
                'pattern' => '/add_action\s*\(\s*["\']wp_ajax_nopriv_\w+["\'].*?function.*?\{(?![^}]*(?:current_user_can|is_user_logged_in))/s',
                'severity' => 'medium',
                'confidence' => 0.6,
                'description' => 'AJAX handler for non-logged users without proper checks'
            ),
            // SQL injection in authentication
            'auth_sql_injection' => array(
                'pattern' => '/(?:user_login|user_pass|password).*?\$wpdb->query.*?\$_(GET|POST|REQUEST)/i',
                'severity' => 'critical',
                'confidence' => 0.9,
                'description' => 'SQL injection in authentication code'
            ),
            // Weak session handling
            'weak_session' => array(
                'pattern' => '/session_start\(\)|setcookie\s*\([^)]*\$_(GET|POST|REQUEST)/i',
                'severity' => 'medium',
                'confidence' => 0.6,
                'description' => 'Weak session handling with user input'
            ),
            // Password comparison issues
            'weak_password_check' => array(
                'pattern' => '/if\s*\(\s*\$\w+\s*==\s*["\'][^"\']*["\']\s*\)|if\s*\(\s*["\'][^"\']*["\']\s*==\s*\$\w+\s*\)/i',
                'severity' => 'medium',
                'confidence' => 0.5,
                'description' => 'Potential weak password comparison'
            )
        );
    }

    /**
     * Initialize WordPress authentication functions.
     *
     * @since    1.0.0
     */
    private function init_auth_functions() {
        $this->auth_functions = array(
            'check' => array(
                'is_user_logged_in', 'current_user_can', 'user_can', 'is_admin',
                'wp_verify_nonce', 'check_admin_referer', 'check_ajax_referer'
            ),
            'user_info' => array(
                'wp_get_current_user', 'get_current_user_id', 'get_userdata'
            ),
            'login' => array(
                'wp_authenticate', 'wp_login', 'wp_logout', 'wp_set_auth_cookie'
            )
        );
    }

    /**
     * Initialize capability checking functions.
     *
     * @since    1.0.0
     */
    private function init_capability_functions() {
        $this->capability_functions = array(
            'admin_capabilities' => array(
                'manage_options', 'administrator', 'edit_posts', 'edit_pages',
                'edit_users', 'delete_users', 'install_plugins', 'activate_plugins'
            ),
            'editor_capabilities' => array(
                'edit_others_posts', 'edit_published_posts', 'publish_posts',
                'delete_others_posts', 'delete_published_posts'
            ),
            'user_capabilities' => array(
                'read', 'edit_posts', 'upload_files'
            )
        );
    }

    /**
     * Initialize sensitive operations.
     *
     * @since    1.0.0
     */
    private function init_sensitive_operations() {
        $this->sensitive_operations = array(
            'admin_operations' => array(
                'plugin', 'theme', 'user', 'option', 'setting', 'config',
                'install', 'activate', 'deactivate', 'delete', 'update'
            ),
            'data_operations' => array(
                'save', 'create', 'update', 'delete', 'modify', 'edit',
                'insert', 'remove', 'backup', 'restore'
            ),
            'file_operations' => array(
                'upload', 'download', 'write', 'create', 'delete', 'move'
            )
        );
    }

    /**
     * Detect authentication bypass vulnerabilities.
     *
     * @since    1.0.0
     * @param    string    $content         File content to analyze.
     * @param    string    $file_path       File path being analyzed.
     * @param    array     $file_info       File information.
     * @return   array                      Array of detected vulnerabilities.
     */
    public function detect($content, $file_path, $file_info) {
        $vulnerabilities = array();

        // Analyze admin functionality
        $admin_vulns = $this->analyze_admin_functionality($content);
        $vulnerabilities = array_merge($vulnerabilities, $admin_vulns);

        // Analyze AJAX handlers
        $ajax_vulns = $this->analyze_ajax_handlers($content);
        $vulnerabilities = array_merge($vulnerabilities, $ajax_vulns);

        // Check privilege escalation
        $privilege_vulns = $this->detect_privilege_escalation($content);
        $vulnerabilities = array_merge($vulnerabilities, $privilege_vulns);

        // Analyze authentication logic
        $auth_vulns = $this->analyze_authentication_logic($content);
        $vulnerabilities = array_merge($vulnerabilities, $auth_vulns);

        // Check session security
        $session_vulns = $this->analyze_session_security($content);
        $vulnerabilities = array_merge($vulnerabilities, $session_vulns);

        // Check direct access protection
        if ($this->is_sensitive_file($file_path)) {
            $access_vulns = $this->check_direct_access_protection($content);
            $vulnerabilities = array_merge($vulnerabilities, $access_vulns);
        }

        return $vulnerabilities;
    }

    /**
     * Analyze admin functionality for authentication issues.
     *
     * @since    1.0.0
     * @param    string    $content         File content.
     * @return   array                      Detected vulnerabilities.
     */
    private function analyze_admin_functionality($content) {
        $vulnerabilities = array();
        $lines = explode("\n", $content);

        // Find admin menu additions
        preg_match_all('/add_(?:menu|submenu)_page\s*\([^,]*,[^,]*,[^,]*,[^,]*,\s*["\']([^"\']+)["\']/', $content, $menu_matches, PREG_OFFSET_CAPTURE);

        foreach ($menu_matches[1] as $i => $callback_match) {
            $callback_name = $callback_match[0];
            $line_number = $this->get_line_number($content, $callback_match[1]);

            // Look for the callback function
            $function_pattern = '/function\s+' . preg_quote($callback_name, '/') . '\s*\([^)]*\)\s*\{([^}]+|\{[^}]*\})*\}/s';
            if (preg_match($function_pattern, $content, $function_match)) {
                $function_content = $function_match[0];
                
                // Check if function has capability check
                if (!$this->has_capability_check($function_content)) {
                    $vulnerabilities[] = array(
                        'type' => 'auth-bypass',
                        'subtype' => 'admin_no_capability',
                        'severity' => 'high',
                        'confidence' => 0.8,
                        'description' => "Admin callback '{$callback_name}' without capability check",
                        'line' => $line_number,
                        'matched_text' => $menu_matches[0][$i][0],
                        'context' => $this->get_context($lines, $line_number),
                        'callback_name' => $callback_name,
                        'cwe_id' => 'CWE-285',
                        'owasp_category' => 'A01:2021-Broken Access Control',
                        'recommendation' => 'Add current_user_can() check in admin callback'
                    );
                }
            }
        }

        return $vulnerabilities;
    }

    /**
     * Analyze AJAX handlers for authentication issues.
     *
     * @since    1.0.0
     * @param    string    $content         File content.
     * @return   array                      Detected vulnerabilities.
     */
    private function analyze_ajax_handlers($content) {
        $vulnerabilities = array();
        $lines = explode("\n", $content);

        // Find AJAX action registrations for logged-in users
        preg_match_all('/add_action\s*\(\s*["\']wp_ajax_(\w+)["\']/', $content, $ajax_matches, PREG_OFFSET_CAPTURE);

        foreach ($ajax_matches[1] as $i => $action_match) {
            $action_name = $action_match[0];
            $line_number = $this->get_line_number($content, $action_match[1]);

            // Look for the corresponding function
            $function_pattern = '/function\s+\w*' . preg_quote($action_name, '/') . '\w*\s*\([^)]*\)\s*\{([^}]+|\{[^}]*\})*\}/s';
            if (preg_match($function_pattern, $content, $function_match)) {
                $function_content = $function_match[0];
                
                // Check if sensitive operations without proper auth
                if ($this->has_sensitive_operations($function_content) && 
                    !$this->has_proper_authentication($function_content)) {
                    
                    $vulnerabilities[] = array(
                        'type' => 'auth-bypass',
                        'subtype' => 'ajax_insufficient_auth',
                        'severity' => 'high',
                        'confidence' => 0.7,
                        'description' => "AJAX handler '{$action_name}' with sensitive operations but insufficient authentication",
                        'line' => $line_number,
                        'matched_text' => $ajax_matches[0][$i][0],
                        'context' => $this->get_context($lines, $line_number),
                        'action_name' => $action_name,
                        'cwe_id' => 'CWE-285',
                        'owasp_category' => 'A01:2021-Broken Access Control',
                        'recommendation' => 'Add proper capability checks in AJAX handler'
                    );
                }
            }
        }

        // Find AJAX actions for non-logged users
        preg_match_all('/add_action\s*\(\s*["\']wp_ajax_nopriv_(\w+)["\']/', $content, $nopriv_matches, PREG_OFFSET_CAPTURE);

        foreach ($nopriv_matches[1] as $i => $action_match) {
            $action_name = $action_match[0];
            $line_number = $this->get_line_number($content, $action_match[1]);

            // Look for the corresponding function
            $function_pattern = '/function\s+\w*' . preg_quote($action_name, '/') . '\w*\s*\([^)]*\)\s*\{([^}]+|\{[^}]*\})*\}/s';
            if (preg_match($function_pattern, $content, $function_match)) {
                $function_content = $function_match[0];
                
                // Check if it performs sensitive operations
                if ($this->has_sensitive_operations($function_content)) {
                    $vulnerabilities[] = array(
                        'type' => 'auth-bypass',
                        'subtype' => 'nopriv_sensitive_operation',
                        'severity' => 'critical',
                        'confidence' => 0.9,
                        'description' => "Non-privileged AJAX handler '{$action_name}' performs sensitive operations",
                        'line' => $line_number,
                        'matched_text' => $nopriv_matches[0][$i][0],
                        'context' => $this->get_context($lines, $line_number),
                        'action_name' => $action_name,
                        'cwe_id' => 'CWE-285',
                        'owasp_category' => 'A01:2021-Broken Access Control',
                        'recommendation' => 'Move sensitive operations to authenticated AJAX handler'
                    );
                }
            }
        }

        return $vulnerabilities;
    }

    /**
     * Detect privilege escalation vulnerabilities.
     *
     * @since    1.0.0
     * @param    string    $content         File content.
     * @return   array                      Detected vulnerabilities.
     */
    private function detect_privilege_escalation($content) {
        $vulnerabilities = array();
        $lines = explode("\n", $content);

        // Check for user role modifications
        preg_match_all('/(?:wp_update_user|update_user_meta|add_user_meta)\s*\([^)]*(?:role|capability)/i', $content, $role_matches, PREG_OFFSET_CAPTURE);

        foreach ($role_matches[0] as $match) {
            $line_number = $this->get_line_number($content, $match[1]);
            
            // Check if there's proper authorization
            $surrounding_code = substr($content, max(0, $match[1] - 300), 600);
            if (!$this->has_admin_capability_check($surrounding_code)) {
                $vulnerabilities[] = array(
                    'type' => 'auth-bypass',
                    'subtype' => 'privilege_escalation',
                    'severity' => 'critical',
                    'confidence' => 0.8,
                    'description' => 'User role/capability modification without proper authorization',
                    'line' => $line_number,
                    'matched_text' => $match[0],
                    'context' => $this->get_context($lines, $line_number),
                    'cwe_id' => 'CWE-269',
                    'owasp_category' => 'A01:2021-Broken Access Control',
                    'recommendation' => 'Add administrator capability check before modifying user roles'
                );
            }
        }

        return $vulnerabilities;
    }

    /**
     * Analyze authentication logic for vulnerabilities.
     *
     * @since    1.0.0
     * @param    string    $content         File content.
     * @return   array                      Detected vulnerabilities.
     */
    private function analyze_authentication_logic($content) {
        $vulnerabilities = array();
        $lines = explode("\n", $content);

        // Check for weak password comparisons
        preg_match_all('/if\s*\(\s*(?:\$\w+\s*==\s*["\'][^"\']*["\']|\$\w+\s*===?\s*\$\w+)/i', $content, $comparison_matches, PREG_OFFSET_CAPTURE);

        foreach ($comparison_matches[0] as $match) {
            $comparison = $match[0];
            $line_number = $this->get_line_number($content, $match[1]);
            
            // Check if it's in authentication context
            $context_code = substr($content, max(0, $match[1] - 200), 400);
            if ($this->is_authentication_context($context_code)) {
                // Check for timing attack vulnerability
                if (strpos($comparison, '==') !== false && strpos($comparison, '===') === false) {
                    $vulnerabilities[] = array(
                        'type' => 'auth-bypass',
                        'subtype' => 'timing_attack',
                        'severity' => 'medium',
                        'confidence' => 0.6,
                        'description' => 'Potential timing attack in authentication comparison',
                        'line' => $line_number,
                        'matched_text' => $comparison,
                        'context' => $this->get_context($lines, $line_number),
                        'cwe_id' => 'CWE-208',
                        'owasp_category' => 'A02:2021-Cryptographic Failures',
                        'recommendation' => 'Use hash_equals() for secure string comparison'
                    );
                }
            }
        }

        // Check for hardcoded credentials
        preg_match_all('/(?:password|pass|pwd|secret|key)\s*=\s*["\'][^"\']{3,}["\']/i', $content, $cred_matches, PREG_OFFSET_CAPTURE);

        foreach ($cred_matches[0] as $match) {
            $line_number = $this->get_line_number($content, $match[1]);
            
            $vulnerabilities[] = array(
                'type' => 'auth-bypass',
                'subtype' => 'hardcoded_credentials',
                'severity' => 'high',
                'confidence' => 0.7,
                'description' => 'Potential hardcoded credentials detected',
                'line' => $line_number,
                'matched_text' => $match[0],
                'context' => $this->get_context($lines, $line_number),
                'cwe_id' => 'CWE-798',
                'owasp_category' => 'A07:2021-Identification and Authentication Failures',
                'recommendation' => 'Store credentials securely, not in source code'
            );
        }

        return $vulnerabilities;
    }

    /**
     * Analyze session security.
     *
     * @since    1.0.0
     * @param    string    $content         File content.
     * @return   array                      Detected vulnerabilities.
     */
    private function analyze_session_security($content) {
        $vulnerabilities = array();
        $lines = explode("\n", $content);

        // Check for insecure session handling
        preg_match_all('/session_start\s*\(\s*\)|setcookie\s*\(/i', $content, $session_matches, PREG_OFFSET_CAPTURE);

        foreach ($session_matches[0] as $match) {
            $line_number = $this->get_line_number($content, $match[1]);
            
            // Check for secure cookie settings
            if (strpos($match[0], 'setcookie') !== false) {
                $cookie_call = $this->extract_function_call($content, $match[1], 'setcookie');
                if (!$this->has_secure_cookie_settings($cookie_call)) {
                    $vulnerabilities[] = array(
                        'type' => 'auth-bypass',
                        'subtype' => 'insecure_cookie',
                        'severity' => 'medium',
                        'confidence' => 0.7,
                        'description' => 'Cookie set without secure flags',
                        'line' => $line_number,
                        'matched_text' => $match[0],
                        'context' => $this->get_context($lines, $line_number),
                        'cwe_id' => 'CWE-614',
                        'owasp_category' => 'A07:2021-Identification and Authentication Failures',
                        'recommendation' => 'Set secure and httponly flags for cookies'
                    );
                }
            }
        }

        return $vulnerabilities;
    }

    /**
     * Check direct access protection.
     *
     * @since    1.0.0
     * @param    string    $content         File content.
     * @return   array                      Detected vulnerabilities.
     */
    private function check_direct_access_protection($content) {
        $vulnerabilities = array();
        $lines = explode("\n", $content);

        // Check for WordPress protection
        $protection_patterns = array(
            '/defined\s*\(\s*["\']ABSPATH["\']/',
            '/if\s*\(\s*!\s*defined\s*\(\s*["\']WPINC["\']/',
            '/exit\s*\(\s*["\']No direct script access/',
            '/die\s*\(\s*["\']Access denied/'
        );

        $has_protection = false;
        foreach ($protection_patterns as $pattern) {
            if (preg_match($pattern, $content)) {
                $has_protection = true;
                break;
            }
        }

        if (!$has_protection) {
            $vulnerabilities[] = array(
                'type' => 'auth-bypass',
                'subtype' => 'no_direct_access_protection',
                'severity' => 'medium',
                'confidence' => 0.8,
                'description' => 'Sensitive file lacks direct access protection',
                'line' => 1,
                'matched_text' => '',
                'context' => $this->get_context($lines, 1),
                'cwe_id' => 'CWE-425',
                'owasp_category' => 'A01:2021-Broken Access Control',
                'recommendation' => 'Add ABSPATH check or similar protection at file start'
            );
        }

        return $vulnerabilities;
    }

    /**
     * Check if code has capability check.
     *
     * @since    1.0.0
     * @param    string    $code            Code to check.
     * @return   bool                       True if has capability check.
     */
    private function has_capability_check($code) {
        $check_functions = $this->auth_functions['check'];
        
        foreach ($check_functions as $function) {
            if (strpos($code, $function) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if code has admin capability check.
     *
     * @since    1.0.0
     * @param    string    $code            Code to check.
     * @return   bool                       True if has admin capability check.
     */
    private function has_admin_capability_check($code) {
        $admin_caps = $this->capability_functions['admin_capabilities'];
        
        foreach ($admin_caps as $capability) {
            if (strpos($code, $capability) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if code has proper authentication.
     *
     * @since    1.0.0
     * @param    string    $code            Code to check.
     * @return   bool                       True if has proper authentication.
     */
    private function has_proper_authentication($code) {
        // Check for capability checks
        if ($this->has_capability_check($code)) {
            return true;
        }

        // Check for nonce verification
        if (strpos($code, 'wp_verify_nonce') !== false || 
            strpos($code, 'check_ajax_referer') !== false) {
            return true;
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
        $all_operations = array();
        foreach ($this->sensitive_operations as $category => $operations) {
            $all_operations = array_merge($all_operations, $operations);
        }

        foreach ($all_operations as $operation) {
            if (stripos($code, $operation) !== false) {
                return true;
            }
        }

        // Check for database modifications
        if (preg_match('/\$wpdb->(?:insert|update|delete|query)/', $code)) {
            return true;
        }

        return false;
    }

    /**
     * Check if context is authentication related.
     *
     * @since    1.0.0
     * @param    string    $context         Context code.
     * @return   bool                       True if authentication context.
     */
    private function is_authentication_context($context) {
        $auth_keywords = array(
            'login', 'password', 'authenticate', 'user', 'session', 'cookie'
        );

        foreach ($auth_keywords as $keyword) {
            if (stripos($context, $keyword) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Extract function call from content.
     *
     * @since    1.0.0
     * @param    string    $content         Full content.
     * @param    int       $offset          Function start offset.
     * @param    string    $function_name   Function name.
     * @return   string                     Function call.
     */
    private function extract_function_call($content, $offset, $function_name) {
        $start = strpos($content, $function_name, $offset);
        if ($start === false) {
            return '';
        }

        $paren_start = strpos($content, '(', $start);
        if ($paren_start === false) {
            return '';
        }

        $paren_count = 1;
        $pos = $paren_start + 1;
        
        while ($pos < strlen($content) && $paren_count > 0) {
            if ($content[$pos] === '(') {
                $paren_count++;
            } elseif ($content[$pos] === ')') {
                $paren_count--;
            }
            $pos++;
        }

        if ($paren_count === 0) {
            return substr($content, $start, $pos - $start);
        }

        return '';
    }

    /**
     * Check if cookie has secure settings.
     *
     * @since    1.0.0
     * @param    string    $cookie_call     Cookie function call.
     * @return   bool                       True if secure.
     */
    private function has_secure_cookie_settings($cookie_call) {
        // Check for secure flag
        $has_secure = (strpos($cookie_call, 'true') !== false && 
                      (strpos($cookie_call, 'secure') !== false || 
                       preg_match('/,\s*true\s*,\s*true/', $cookie_call)));
        
        // Check for httponly flag
        $has_httponly = (strpos($cookie_call, 'httponly') !== false || 
                        preg_match('/,\s*true\s*\)/', $cookie_call));

        // Extract argument list from function call
        $args = $this->parse_function_arguments($cookie_call);
        // setcookie: 6th argument is secure, 7th is httponly
        $has_secure = false;
        $has_httponly = false;
        if (isset($args[5])) {
            $val = strtolower(trim($args[5]));
            $has_secure = ($val === 'true' || $val === '1');
        }
        if (isset($args[6])) {
            $val = strtolower(trim($args[6]));
            $has_httponly = ($val === 'true' || $val === '1');
        }
        return $has_secure && $has_httponly;
    }

    /**
     * Parse function arguments from a function call string.
     *
     * @param string $function_call
     * @return array
     */
    private function parse_function_arguments($function_call) {
        $paren_start = strpos($function_call, '(');
        $paren_end = strrpos($function_call, ')');
        if ($paren_start === false || $paren_end === false || $paren_end <= $paren_start) {
            return array();
        }
        $args_str = substr($function_call, $paren_start + 1, $paren_end - $paren_start - 1);
        $args = array();
        $length = strlen($args_str);
        $current = '';
        $depth = 0;
        $in_quote = false;
        $quote_char = '';
        for ($i = 0; $i < $length; $i++) {
            $char = $args_str[$i];
            if ($in_quote) {
                $current .= $char;
                if ($char === $quote_char && ($i === 0 || $args_str[$i-1] !== '\\')) {
                    $in_quote = false;
                }
            } else {
                if ($char === '"' || $char === "'") {
                    $in_quote = true;
                    $quote_char = $char;
                    $current .= $char;
                } elseif ($char === '(') {
                    $depth++;
                    $current .= $char;
                } elseif ($char === ')') {
                    if ($depth > 0) {
                        $depth--;
                        $current .= $char;
                    }
                } elseif ($char === ',' && $depth === 0) {
                    $args[] = $current;
                    $current = '';
                } else {
                    $current .= $char;
                }
            }
        }
        if (trim($current) !== '') {
            $args[] = $current;
        }
        return $args;
    }

    /**
     * Check if file is sensitive.
     *
     * @since    1.0.0
     * @param    string    $file_path       File path.
     * @return   bool                       True if sensitive file.
     */
    private function is_sensitive_file($file_path) {
        $sensitive_patterns = array(
            '/admin/', '/includes/', '/config/', '/auth/', '/login/',
            'wp-config.php', 'functions.php', 'admin.php'
        );

        foreach ($sensitive_patterns as $pattern) {
            if (strpos($file_path, $pattern) !== false) {
                return true;
            }
        }

        return false;
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
            'auth_functions' => $this->auth_functions,
            'capability_functions' => $this->capability_functions,
            'sensitive_operations' => $this->sensitive_operations
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

        if (isset($config['sensitive_operations'])) {
            $this->sensitive_operations = array_merge($this->sensitive_operations, $config['sensitive_operations']);
        }
    }
}

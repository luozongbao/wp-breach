<?php
/**
 * SQL Injection Detector
 *
 * Specialized detector for SQL injection vulnerabilities.
 *
 * @package WP_Breach
 * @since 1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class WP_Breach_SQL_Injection_Detector
 *
 * Detects SQL injection vulnerabilities in WordPress code.
 */
class WP_Breach_SQL_Injection_Detector {
    
    /**
     * Detection patterns for SQL injection vulnerabilities
     *
     * @var array
     */
    private $patterns = array(
        // Direct user input in SQL queries
        'direct_input' => array(
            '/\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*[\'"][^\'"]*[\'"]\s*\]\s*(?:(?:\.|\+|,)\s*)?(?:(?:\'|")?\s*\)\s*)?(?:;|\s+(?:FROM|WHERE|ORDER|GROUP|HAVING|UNION|SELECT|UPDATE|DELETE|INSERT))/i',
            '/(?:mysql_query|mysqli_query)\s*\(\s*[\'"][^\'"]*(SELECT|UPDATE|DELETE|INSERT)[^\'"]*[\'"]\s*\.\s*\$_(?:GET|POST|REQUEST|COOKIE)/i'
        ),
        
        // WordPress database methods with unsanitized input
        'wpdb_unsafe' => array(
            '/\$wpdb->(?:get_var|get_row|get_col|get_results|query)\s*\(\s*[\'"][^\'"]*(SELECT|UPDATE|DELETE|INSERT)[^\'"]*[\'"]\s*\.\s*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            '/\$wpdb->prepare\s*\(\s*[\'"][^\'"]*(SELECT|UPDATE|DELETE|INSERT)[^\'"]*[\'"]\s*\.\s*\$_(?:GET|POST|REQUEST|COOKIE)/i'
        ),
        
        // Dynamic SQL construction without sanitization
        'dynamic_sql' => array(
            '/(?:SELECT|UPDATE|DELETE|INSERT)[^\'"]*(WHERE|SET|VALUES)[^\'"]*([\'"]\s*\.\s*\$_(?:GET|POST|REQUEST|COOKIE)|[\'"]\s*\.\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*\.\s*[\'"]\s*\.\s*\$_(?:GET|POST|REQUEST|COOKIE))/i',
            '/\$(?:where|query|sql)\s*\.?=\s*[\'"][^\'"]*(WHERE|SET|VALUES)[^\'"]*[\'"]\s*\.\s*\$_(?:GET|POST|REQUEST|COOKIE)/i'
        ),
        
        // LIKE queries without sanitization
        'like_injection' => array(
            '/LIKE\s*[\'"][^\'"]*([\'"]\s*\.\s*\$_(?:GET|POST|REQUEST|COOKIE)|%[\'"]\s*\.\s*\$_(?:GET|POST|REQUEST|COOKIE))/i'
        ),
        
        // ORDER BY with user input
        'order_by_injection' => array(
            '/ORDER\s+BY\s*[\'"]\s*\.\s*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            '/ORDER\s+BY\s*\$_(?:GET|POST|REQUEST|COOKIE)/i'
        )
    );
    
    /**
     * Safe WordPress functions that should be used
     *
     * @var array
     */
    private $safe_functions = array(
        'wpdb' => array(
            'prepare', 'esc_sql'
        ),
        'wordpress' => array(
            'sanitize_text_field', 'sanitize_email', 'sanitize_url',
            'esc_sql', 'absint', 'intval', 'floatval'
        )
    );
    
    /**
     * Detect SQL injection vulnerabilities in content
     *
     * @param string $content File content to scan
     * @param string $file_path File path being scanned
     * @return array Array of detected vulnerabilities
     */
    public function detect($content, $file_path) {
        $vulnerabilities = array();
        
        foreach ($this->patterns as $pattern_type => $patterns) {
            foreach ($patterns as $pattern) {
                if (preg_match_all($pattern, $content, $matches, PREG_OFFSET_CAPTURE)) {
                    foreach ($matches[0] as $match) {
                        $line_number = $this->get_line_number($content, $match[1]);
                        
                        $vulnerabilities[] = array(
                            'type' => 'sql_injection',
                            'subtype' => $pattern_type,
                            'severity' => $this->get_severity($pattern_type),
                            'line' => $line_number,
                            'code' => trim($match[0]),
                            'pattern' => $pattern,
                            'description' => $this->get_description($pattern_type),
                            'recommendation' => $this->get_recommendation($pattern_type),
                            'file' => $file_path,
                            'confidence' => $this->get_confidence($pattern_type, $match[0])
                        );
                    }
                }
            }
        }
        
        return $vulnerabilities;
    }
    
    /**
     * Get detailed analysis of SQL injection vulnerability
     *
     * @param string $code Code snippet
     * @param string $file_path File path
     * @return array Detailed analysis
     */
    public function analyze($code, $file_path) {
        $analysis = array(
            'vulnerability_type' => 'SQL Injection',
            'risk_level' => 'Critical',
            'exploitable' => true,
            'impact' => array(
                'data_theft' => true,
                'data_modification' => true,
                'privilege_escalation' => true,
                'system_compromise' => true
            ),
            'attack_vectors' => array(),
            'mitigation_steps' => array(),
            'code_suggestions' => array()
        );
        
        // Analyze specific attack vectors
        if (preg_match('/\$_(?:GET|POST|REQUEST|COOKIE)/', $code)) {
            $analysis['attack_vectors'][] = 'User input directly concatenated to SQL query';
        }
        
        if (preg_match('/(?:SELECT|UPDATE|DELETE|INSERT)/', $code)) {
            $analysis['attack_vectors'][] = 'SQL statement construction with user data';
        }
        
        if (preg_match('/WHERE/', $code)) {
            $analysis['attack_vectors'][] = 'WHERE clause manipulation possible';
        }
        
        if (preg_match('/UNION/', $code)) {
            $analysis['attack_vectors'][] = 'UNION-based SQL injection possible';
        }
        
        // Generate mitigation steps
        $analysis['mitigation_steps'] = array(
            'Use WordPress prepared statements with $wpdb->prepare()',
            'Sanitize all user input with appropriate functions',
            'Validate input data types and ranges',
            'Use whitelist validation for dynamic content',
            'Implement proper error handling to avoid information disclosure'
        );
        
        // Generate code suggestions
        $analysis['code_suggestions'] = $this->generate_code_suggestions($code);
        
        return $analysis;
    }
    
    /**
     * Generate secure code suggestions
     *
     * @param string $vulnerable_code Vulnerable code snippet
     * @return array Array of secure code alternatives
     */
    private function generate_code_suggestions($vulnerable_code) {
        $suggestions = array();
        
        // Suggest using $wpdb->prepare()
        if (preg_match('/\$wpdb->(?:get_var|get_row|get_col|get_results|query)\s*\(\s*[\'"]([^\'"]*)[\'"]\s*\.\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[([^\]]+)\]/i', $vulnerable_code, $matches)) {
            $suggestions[] = array(
                'type' => 'wpdb_prepare',
                'description' => 'Use $wpdb->prepare() for parameterized queries',
                'original' => $matches[0],
                'secure' => sprintf(
                    '$wpdb->get_var($wpdb->prepare("%s %%s", sanitize_text_field($_GET[%s])))',
                    $matches[1],
                    $matches[2]
                )
            );
        }
        
        // Suggest input sanitization
        if (preg_match('/\$_(?:GET|POST|REQUEST|COOKIE)\s*\[([^\]]+)\]/', $vulnerable_code, $matches)) {
            $suggestions[] = array(
                'type' => 'input_sanitization',
                'description' => 'Sanitize user input before using in queries',
                'original' => $matches[0],
                'secure' => sprintf('sanitize_text_field(%s)', $matches[0])
            );
        }
        
        // Suggest using absint for numeric values
        if (preg_match('/\$_(?:GET|POST|REQUEST|COOKIE)\s*\[([^\]]+)\]/', $vulnerable_code)) {
            $suggestions[] = array(
                'type' => 'numeric_sanitization',
                'description' => 'Use absint() for positive integers',
                'secure_function' => 'absint($_GET["id"])'
            );
        }
        
        return $suggestions;
    }
    
    /**
     * Check if code uses safe practices
     *
     * @param string $content File content
     * @return array Array of safe practices found
     */
    public function check_safe_practices($content) {
        $safe_practices = array();
        
        // Check for $wpdb->prepare usage
        if (preg_match_all('/\$wpdb->prepare\s*\(/i', $content, $matches)) {
            $safe_practices[] = array(
                'practice' => 'wpdb_prepare',
                'description' => 'Uses $wpdb->prepare() for parameterized queries',
                'occurrences' => count($matches[0])
            );
        }
        
        // Check for input sanitization functions
        $sanitization_functions = array(
            'sanitize_text_field', 'sanitize_email', 'sanitize_url',
            'esc_sql', 'absint', 'intval', 'floatval'
        );
        
        foreach ($sanitization_functions as $function) {
            if (preg_match_all('/' . preg_quote($function) . '\s*\(/i', $content, $matches)) {
                $safe_practices[] = array(
                    'practice' => 'input_sanitization',
                    'function' => $function,
                    'description' => "Uses {$function}() for input sanitization",
                    'occurrences' => count($matches[0])
                );
            }
        }
        
        return $safe_practices;
    }
    
    /**
     * Get vulnerability severity based on pattern type
     *
     * @param string $pattern_type Pattern type
     * @return string Severity level
     */
    private function get_severity($pattern_type) {
        $severities = array(
            'direct_input' => 'critical',
            'wpdb_unsafe' => 'high',
            'dynamic_sql' => 'high',
            'like_injection' => 'medium',
            'order_by_injection' => 'medium'
        );
        
        return isset($severities[$pattern_type]) ? $severities[$pattern_type] : 'medium';
    }
    
    /**
     * Get vulnerability description based on pattern type
     *
     * @param string $pattern_type Pattern type
     * @return string Description
     */
    private function get_description($pattern_type) {
        $descriptions = array(
            'direct_input' => 'Direct user input concatenated to SQL query without sanitization',
            'wpdb_unsafe' => 'WordPress database function used with unsanitized user input',
            'dynamic_sql' => 'Dynamic SQL construction with potential user input injection',
            'like_injection' => 'LIKE query vulnerable to wildcard injection',
            'order_by_injection' => 'ORDER BY clause vulnerable to injection attacks'
        );
        
        return isset($descriptions[$pattern_type]) ? $descriptions[$pattern_type] : 'Potential SQL injection vulnerability';
    }
    
    /**
     * Get recommendation based on pattern type
     *
     * @param string $pattern_type Pattern type
     * @return string Recommendation
     */
    private function get_recommendation($pattern_type) {
        $recommendations = array(
            'direct_input' => 'Use $wpdb->prepare() with placeholders and sanitize all user input',
            'wpdb_unsafe' => 'Use $wpdb->prepare() for parameterized queries instead of concatenation',
            'dynamic_sql' => 'Use prepared statements and validate/sanitize all dynamic content',
            'like_injection' => 'Escape LIKE wildcards and use $wpdb->prepare() for LIKE queries',
            'order_by_injection' => 'Use whitelist validation for ORDER BY columns'
        );
        
        return isset($recommendations[$pattern_type]) ? $recommendations[$pattern_type] : 'Implement proper input validation and use prepared statements';
    }
    
    /**
     * Get confidence level of detection
     *
     * @param string $pattern_type Pattern type
     * @param string $matched_code Matched code
     * @return float Confidence level (0.0 to 1.0)
     */
    private function get_confidence($pattern_type, $matched_code) {
        $base_confidence = array(
            'direct_input' => 0.9,
            'wpdb_unsafe' => 0.8,
            'dynamic_sql' => 0.7,
            'like_injection' => 0.6,
            'order_by_injection' => 0.6
        );
        
        $confidence = isset($base_confidence[$pattern_type]) ? $base_confidence[$pattern_type] : 0.5;
        
        // Increase confidence if multiple indicators are present
        if (strpos($matched_code, '$_GET') !== false || 
            strpos($matched_code, '$_POST') !== false) {
            $confidence += 0.1;
        }
        
        if (strpos($matched_code, 'WHERE') !== false) {
            $confidence += 0.05;
        }
        
        if (strpos($matched_code, 'SELECT') !== false) {
            $confidence += 0.05;
        }
        
        return min(1.0, $confidence);
    }
    
    /**
     * Get line number from content offset
     *
     * @param string $content File content
     * @param int $offset Character offset
     * @return int Line number
     */
    private function get_line_number($content, $offset) {
        return substr_count(substr($content, 0, $offset), "\n") + 1;
    }
    
    /**
     * Validate if a detected vulnerability is a false positive
     *
     * @param array $vulnerability Vulnerability data
     * @param string $content Full file content
     * @return bool True if likely false positive, false otherwise
     */
    public function is_false_positive($vulnerability, $content) {
        $code = $vulnerability['code'];
        
        // Check if the code is in a comment
        if ($this->is_in_comment($content, $vulnerability['line'])) {
            return true;
        }
        
        // Check if input is already sanitized nearby
        if ($this->has_nearby_sanitization($content, $vulnerability['line'])) {
            return true;
        }
        
        // Check if it's in a string literal (not executed)
        if (preg_match('/[\'"][^\'"]*(SELECT|UPDATE|DELETE|INSERT)[^\'"]*([\'"]\s*\.\s*\$_(?:GET|POST|REQUEST|COOKIE)|%[\'"]\s*\.\s*\$_(?:GET|POST|REQUEST|COOKIE))[^\'"]*/i', $code)) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Check if code is in a comment
     *
     * @param string $content File content
     * @param int $line_number Line number
     * @return bool True if in comment, false otherwise
     */
    private function is_in_comment($content, $line_number) {
        $lines = explode("\n", $content);
        
        if (!isset($lines[$line_number - 1])) {
            return false;
        }
        
        $line = trim($lines[$line_number - 1]);
        
        // Check for single-line comments
        if (strpos($line, '//') === 0 || strpos($line, '#') === 0) {
            return true;
        }
        
        // Check for multi-line comments (basic check)
        if (strpos($line, '/*') !== false && strpos($line, '*/') !== false) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Check if there's sanitization near the vulnerable line
     *
     * @param string $content File content
     * @param int $line_number Line number
     * @return bool True if sanitization found nearby, false otherwise
     */
    private function has_nearby_sanitization($content, $line_number) {
        $lines = explode("\n", $content);
        $check_range = 3; // Check 3 lines before and after
        
        $start = max(0, $line_number - $check_range - 1);
        $end = min(count($lines) - 1, $line_number + $check_range - 1);
        
        for ($i = $start; $i <= $end; $i++) {
            if (!isset($lines[$i])) {
                continue;
            }
            
            $line = $lines[$i];
            
            // Check for sanitization functions
            if (preg_match('/(?:sanitize_|esc_|absint|intval|floatval|wp_kses)/', $line)) {
                return true;
            }
            
            // Check for $wpdb->prepare
            if (strpos($line, '$wpdb->prepare') !== false) {
                return true;
            }
        }
        
        return false;
    }
}

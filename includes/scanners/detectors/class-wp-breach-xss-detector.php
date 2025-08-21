<?php
/**
 * XSS Detector
 *
 * Specialized detector for Cross-Site Scripting (XSS) vulnerabilities.
 *
 * @package WP_Breach
 * @since 1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class WP_Breach_XSS_Detector
 *
 * Detects XSS vulnerabilities in WordPress code.
 */
class WP_Breach_XSS_Detector {
    
    /**
     * Detection patterns for XSS vulnerabilities
     *
     * @var array
     */
    private $patterns = array(
        // Direct echo/print of user input
        'direct_output' => array(
            '/echo\s+\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/i',
            '/print\s+\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/i',
            '/print_r\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/i',
            '/<\?=\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/i'
        ),
        
        // HTML attributes with user input
        'attribute_injection' => array(
            '/(?:id|class|style|onclick|onload|onerror)\s*=\s*[\'"]?[^\'">]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            '/href\s*=\s*[\'"]?[^\'">]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            '/src\s*=\s*[\'"]?[^\'">]*\$_(?:GET|POST|REQUEST|COOKIE)/i'
        ),
        
        // JavaScript context
        'javascript_injection' => array(
            '/<script[^>]*>[^<]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            '/var\s+[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*[\'"]?[^\'">]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            '/document\.(?:write|writeln)\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i'
        ),
        
        // URL/href injection
        'url_injection' => array(
            '/href\s*=\s*[\'"]?\$_(?:GET|POST|REQUEST|COOKIE)/i',
            '/window\.location\s*=\s*[\'"]?[^\'">]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            '/location\.href\s*=\s*[\'"]?[^\'">]*\$_(?:GET|POST|REQUEST|COOKIE)/i'
        ),
        
        // Form field values
        'form_injection' => array(
            '/value\s*=\s*[\'"]?[^\'">]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            '/<input[^>]*value\s*=\s*[\'"]?[^\'">]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            '/<textarea[^>]*>[^<]*\$_(?:GET|POST|REQUEST|COOKIE)/i'
        ),
        
        // Meta tag injection
        'meta_injection' => array(
            '/<meta[^>]*content\s*=\s*[\'"]?[^\'">]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            '/<title[^>]*>[^<]*\$_(?:GET|POST|REQUEST|COOKIE)/i'
        )
    );
    
    /**
     * WordPress safe output functions
     *
     * @var array
     */
    private $safe_functions = array(
        'esc_html', 'esc_attr', 'esc_url', 'esc_js', 'esc_textarea',
        'wp_kses', 'wp_kses_post', 'sanitize_text_field', 'sanitize_html_class',
        'sanitize_title', 'wp_strip_all_tags'
    );
    
    /**
     * Detect XSS vulnerabilities in content
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
                            'type' => 'xss',
                            'subtype' => $pattern_type,
                            'severity' => $this->get_severity($pattern_type),
                            'line' => $line_number,
                            'code' => trim($match[0]),
                            'pattern' => $pattern,
                            'description' => $this->get_description($pattern_type),
                            'recommendation' => $this->get_recommendation($pattern_type),
                            'file' => $file_path,
                            'confidence' => $this->get_confidence($pattern_type, $match[0]),
                            'context' => $this->get_context($pattern_type)
                        );
                    }
                }
            }
        }
        
        return $vulnerabilities;
    }
    
    /**
     * Get detailed analysis of XSS vulnerability
     *
     * @param string $code Code snippet
     * @param string $file_path File path
     * @return array Detailed analysis
     */
    public function analyze($code, $file_path) {
        $analysis = array(
            'vulnerability_type' => 'Cross-Site Scripting (XSS)',
            'risk_level' => 'High',
            'exploitable' => true,
            'impact' => array(
                'session_hijacking' => true,
                'cookie_theft' => true,
                'phishing' => true,
                'malware_distribution' => true,
                'privilege_escalation' => true
            ),
            'attack_vectors' => array(),
            'mitigation_steps' => array(),
            'code_suggestions' => array()
        );
        
        // Analyze attack context
        $analysis['context'] = $this->analyze_context($code);
        
        // Determine XSS type
        if (preg_match('/<script|javascript:|on\w+\s*=/i', $code)) {
            $analysis['xss_type'] = 'Stored/Persistent XSS';
            $analysis['risk_level'] = 'Critical';
        } elseif (preg_match('/echo|print|\?=/', $code)) {
            $analysis['xss_type'] = 'Reflected XSS';
        } else {
            $analysis['xss_type'] = 'DOM-based XSS';
        }
        
        // Analyze attack vectors
        if (preg_match('/\$_(?:GET|POST|REQUEST|COOKIE)/', $code)) {
            $analysis['attack_vectors'][] = 'User input directly output to HTML';
        }
        
        if (preg_match('/<script|javascript:/', $code)) {
            $analysis['attack_vectors'][] = 'JavaScript injection possible';
        }
        
        if (preg_match('/(?:href|src)\s*=/', $code)) {
            $analysis['attack_vectors'][] = 'URL/Link manipulation possible';
        }
        
        if (preg_match('/(?:onclick|onload|onerror)/', $code)) {
            $analysis['attack_vectors'][] = 'Event handler injection possible';
        }
        
        // Generate mitigation steps
        $analysis['mitigation_steps'] = array(
            'Escape all output using appropriate WordPress functions',
            'Validate and sanitize all user input',
            'Use Content Security Policy (CSP) headers',
            'Implement proper input validation',
            'Use context-aware output encoding'
        );
        
        // Generate code suggestions
        $analysis['code_suggestions'] = $this->generate_code_suggestions($code);
        
        return $analysis;
    }
    
    /**
     * Analyze the context of XSS vulnerability
     *
     * @param string $code Code snippet
     * @return array Context analysis
     */
    private function analyze_context($code) {
        $context = array(
            'output_context' => 'html',
            'dangerous_functions' => array(),
            'input_sources' => array()
        );
        
        // Determine output context
        if (preg_match('/<script|javascript:/', $code)) {
            $context['output_context'] = 'javascript';
        } elseif (preg_match('/(?:href|src)\s*=/', $code)) {
            $context['output_context'] = 'url';
        } elseif (preg_match('/(?:id|class|style)\s*=/', $code)) {
            $context['output_context'] = 'attribute';
        } elseif (preg_match('/<style/', $code)) {
            $context['output_context'] = 'css';
        }
        
        // Identify dangerous functions
        if (preg_match('/echo|print/', $code)) {
            $context['dangerous_functions'][] = 'direct_output';
        }
        
        if (preg_match('/document\.write/', $code)) {
            $context['dangerous_functions'][] = 'document_write';
        }
        
        // Identify input sources
        if (preg_match('/\$_GET/', $code)) {
            $context['input_sources'][] = 'GET parameter';
        }
        
        if (preg_match('/\$_POST/', $code)) {
            $context['input_sources'][] = 'POST parameter';
        }
        
        if (preg_match('/\$_COOKIE/', $code)) {
            $context['input_sources'][] = 'Cookie value';
        }
        
        if (preg_match('/\$_REQUEST/', $code)) {
            $context['input_sources'][] = 'Request parameter';
        }
        
        return $context;
    }
    
    /**
     * Generate secure code suggestions
     *
     * @param string $vulnerable_code Vulnerable code snippet
     * @return array Array of secure code alternatives
     */
    private function generate_code_suggestions($vulnerable_code) {
        $suggestions = array();
        
        // Suggest esc_html for direct output
        if (preg_match('/echo\s+\$_(?:GET|POST|REQUEST|COOKIE)\s*\[([^\]]+)\]/i', $vulnerable_code, $matches)) {
            $suggestions[] = array(
                'type' => 'esc_html',
                'description' => 'Use esc_html() for safe HTML output',
                'original' => $matches[0],
                'secure' => sprintf('echo esc_html($_GET[%s])', $matches[1])
            );
        }
        
        // Suggest esc_attr for attributes
        if (preg_match('/(?:id|class|style)\s*=\s*[\'"]?[^\'">]*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[([^\]]+)\]/i', $vulnerable_code, $matches)) {
            $suggestions[] = array(
                'type' => 'esc_attr',
                'description' => 'Use esc_attr() for HTML attribute values',
                'original' => $matches[0],
                'secure' => str_replace($matches[0], sprintf('esc_attr($_GET[%s])', $matches[1]), $matches[0])
            );
        }
        
        // Suggest esc_url for URLs
        if (preg_match('/(?:href|src)\s*=\s*[\'"]?[^\'">]*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[([^\]]+)\]/i', $vulnerable_code, $matches)) {
            $suggestions[] = array(
                'type' => 'esc_url',
                'description' => 'Use esc_url() for URL values',
                'original' => $matches[0],
                'secure' => str_replace($matches[0], sprintf('esc_url($_GET[%s])', $matches[1]), $matches[0])
            );
        }
        
        // Suggest esc_js for JavaScript context
        if (preg_match('/<script[^>]*>[^<]*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[([^\]]+)\]/i', $vulnerable_code, $matches)) {
            $suggestions[] = array(
                'type' => 'esc_js',
                'description' => 'Use esc_js() for JavaScript context',
                'original' => $matches[0],
                'secure' => str_replace($matches[0], sprintf('esc_js($_GET[%s])', $matches[1]), $matches[0])
            );
        }
        
        // Suggest wp_kses for rich content
        $suggestions[] = array(
            'type' => 'wp_kses',
            'description' => 'Use wp_kses() for filtered HTML output',
            'secure_function' => 'wp_kses($user_input, array("a" => array("href" => array()), "strong" => array()))'
        );
        
        return $suggestions;
    }
    
    /**
     * Check if code uses safe output practices
     *
     * @param string $content File content
     * @return array Array of safe practices found
     */
    public function check_safe_practices($content) {
        $safe_practices = array();
        
        foreach ($this->safe_functions as $function) {
            if (preg_match_all('/' . preg_quote($function) . '\s*\(/i', $content, $matches)) {
                $safe_practices[] = array(
                    'practice' => 'safe_output',
                    'function' => $function,
                    'description' => "Uses {$function}() for safe output",
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
            'direct_output' => 'high',
            'attribute_injection' => 'high',
            'javascript_injection' => 'critical',
            'url_injection' => 'medium',
            'form_injection' => 'medium',
            'meta_injection' => 'medium'
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
            'direct_output' => 'User input directly output to HTML without escaping',
            'attribute_injection' => 'User input used in HTML attributes without proper escaping',
            'javascript_injection' => 'User input injected into JavaScript context',
            'url_injection' => 'User input used in URL/href attributes without validation',
            'form_injection' => 'User input used in form field values without escaping',
            'meta_injection' => 'User input used in meta tags without escaping'
        );
        
        return isset($descriptions[$pattern_type]) ? $descriptions[$pattern_type] : 'Potential XSS vulnerability';
    }
    
    /**
     * Get recommendation based on pattern type
     *
     * @param string $pattern_type Pattern type
     * @return string Recommendation
     */
    private function get_recommendation($pattern_type) {
        $recommendations = array(
            'direct_output' => 'Use esc_html() to escape HTML content before output',
            'attribute_injection' => 'Use esc_attr() to escape HTML attribute values',
            'javascript_injection' => 'Use esc_js() to escape JavaScript content and avoid inline scripts',
            'url_injection' => 'Use esc_url() to validate and escape URL values',
            'form_injection' => 'Use esc_attr() for form field values and validate input',
            'meta_injection' => 'Use esc_attr() for meta tag content and validate input'
        );
        
        return isset($recommendations[$pattern_type]) ? $recommendations[$pattern_type] : 'Escape output using appropriate WordPress functions';
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
            'direct_output' => 0.9,
            'attribute_injection' => 0.8,
            'javascript_injection' => 0.95,
            'url_injection' => 0.7,
            'form_injection' => 0.7,
            'meta_injection' => 0.6
        );
        
        $confidence = isset($base_confidence[$pattern_type]) ? $base_confidence[$pattern_type] : 0.5;
        
        // Increase confidence for dangerous contexts
        if (strpos($matched_code, 'script') !== false) {
            $confidence += 0.1;
        }
        
        if (strpos($matched_code, 'onclick') !== false || 
            strpos($matched_code, 'onload') !== false) {
            $confidence += 0.05;
        }
        
        return min(1.0, $confidence);
    }
    
    /**
     * Get context information for pattern type
     *
     * @param string $pattern_type Pattern type
     * @return string Context information
     */
    private function get_context($pattern_type) {
        $contexts = array(
            'direct_output' => 'HTML content',
            'attribute_injection' => 'HTML attributes',
            'javascript_injection' => 'JavaScript code',
            'url_injection' => 'URL/href values',
            'form_injection' => 'Form fields',
            'meta_injection' => 'Meta tags'
        );
        
        return isset($contexts[$pattern_type]) ? $contexts[$pattern_type] : 'Unknown context';
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
        
        // Check if output is already escaped nearby
        if ($this->has_nearby_escaping($content, $vulnerability['line'])) {
            return true;
        }
        
        // Check if it's in a string literal (not executed)
        if ($this->is_in_string_literal($code)) {
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
     * Check if there's escaping near the vulnerable line
     *
     * @param string $content File content
     * @param int $line_number Line number
     * @return bool True if escaping found nearby, false otherwise
     */
    private function has_nearby_escaping($content, $line_number) {
        $lines = explode("\n", $content);
        $check_range = 2; // Check 2 lines before and after
        
        $start = max(0, $line_number - $check_range - 1);
        $end = min(count($lines) - 1, $line_number + $check_range - 1);
        
        for ($i = $start; $i <= $end; $i++) {
            if (!isset($lines[$i])) {
                continue;
            }
            
            $line = $lines[$i];
            
            // Check for escaping functions
            foreach ($this->safe_functions as $function) {
                if (strpos($line, $function) !== false) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    /**
     * Check if code is in a string literal
     *
     * @param string $code Code snippet
     * @return bool True if in string literal, false otherwise
     */
    private function is_in_string_literal($code) {
        // Basic check - if the code is entirely within quotes
        $trimmed = trim($code);
        
        if ((strpos($trimmed, '"') === 0 && strrpos($trimmed, '"') === strlen($trimmed) - 1) ||
            (strpos($trimmed, "'") === 0 && strrpos($trimmed, "'") === strlen($trimmed) - 1)) {
            return true;
        }
        
        return false;
    }
}

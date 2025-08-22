<?php

/**
 * The file inclusion vulnerability detector.
 *
 * This class handles detection of Local File Inclusion (LFI) and
 * Remote File Inclusion (RFI) vulnerabilities.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/detection/detectors
 */

/**
 * The file inclusion detector class.
 *
 * This class provides specialized detection for file inclusion vulnerabilities
 * using pattern matching and path analysis.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/detection/detectors
 * @author     WP Breach Team
 */
class WP_Breach_File_Inclusion_Detector {

    /**
     * File inclusion patterns.
     *
     * @since    1.0.0
     * @access   protected
     * @var      array    $patterns    Array of file inclusion patterns.
     */
    protected $patterns;

    /**
     * Dangerous file functions.
     *
     * @since    1.0.0
     * @access   protected
     * @var      array    $dangerous_functions    Dangerous file functions.
     */
    protected $dangerous_functions;

    /**
     * Path traversal patterns.
     *
     * @since    1.0.0
     * @access   protected
     * @var      array    $traversal_patterns    Path traversal patterns.
     */
    protected $traversal_patterns;

    /**
     * Safe file validation functions.
     *
     * @since    1.0.0
     * @access   protected
     * @var      array    $safe_functions    Safe file validation functions.
     */
    protected $safe_functions;

    /**
     * Initialize the file inclusion detector.
     *
     * @since    1.0.0
     */
    public function __construct() {
        $this->init_patterns();
        $this->init_dangerous_functions();
        $this->init_traversal_patterns();
        $this->init_safe_functions();
    }

    /**
     * Initialize file inclusion patterns.
     *
     * @since    1.0.0
     */
    private function init_patterns() {
        $this->patterns = array(
            // Direct inclusion with user input
            'direct_include' => array(
                'pattern' => '/(?:include|require)(?:_once)?\s*\(\s*["\']?.*?\$_(GET|POST|REQUEST|COOKIE)\[.*?\]/i',
                'severity' => 'critical',
                'confidence' => 0.9,
                'description' => 'Direct file inclusion with user input'
            ),
            // File path concatenation
            'path_concat' => array(
                'pattern' => '/(?:include|require)(?:_once)?\s*\(\s*["\'][^"\']*["\']\s*\.\s*\$\w+/i',
                'severity' => 'high',
                'confidence' => 0.8,
                'description' => 'File inclusion with path concatenation'
            ),
            // Dynamic file inclusion
            'dynamic_include' => array(
                'pattern' => '/(?:include|require)(?:_once)?\s*\(\s*\$\w+\s*\)/i',
                'severity' => 'medium',
                'confidence' => 0.6,
                'description' => 'Dynamic file inclusion - verify input validation'
            ),
            // file_get_contents with user input
            'file_get_contents' => array(
                'pattern' => '/file_get_contents\s*\(\s*.*?\$_(GET|POST|REQUEST|COOKIE)\[.*?\]/i',
                'severity' => 'high',
                'confidence' => 0.8,
                'description' => 'file_get_contents with user input'
            ),
            // fopen with user input
            'fopen_user_input' => array(
                'pattern' => '/fopen\s*\(\s*.*?\$_(GET|POST|REQUEST|COOKIE)\[.*?\]/i',
                'severity' => 'high',
                'confidence' => 0.8,
                'description' => 'fopen with user input'
            ),
            // readfile with user input
            'readfile_user_input' => array(
                'pattern' => '/readfile\s*\(\s*.*?\$_(GET|POST|REQUEST|COOKIE)\[.*?\]/i',
                'severity' => 'high',
                'confidence' => 0.8,
                'description' => 'readfile with user input'
            )
        );
    }

    /**
     * Initialize dangerous file functions.
     *
     * @since    1.0.0
     */
    private function init_dangerous_functions() {
        $this->dangerous_functions = array(
            'inclusion' => array(
                'include', 'include_once', 'require', 'require_once'
            ),
            'file_operations' => array(
                'file_get_contents', 'file_put_contents', 'fopen', 'fread',
                'fwrite', 'readfile', 'copy', 'move_uploaded_file'
            ),
            'url_operations' => array(
                'curl_init', 'curl_setopt', 'file_get_contents', 'fopen'
            )
        );
    }

    /**
     * Initialize path traversal patterns.
     *
     * @since    1.0.0
     */
    private function init_traversal_patterns() {
        $this->traversal_patterns = array(
            '../', '..\\', '%2e%2e%2f', '%2e%2e\\', '....//....',
            '%252e%252e%252f', '..%2f', '..%5c', '..%255c'
        );
    }

    /**
     * Initialize safe validation functions.
     *
     * @since    1.0.0
     */
    private function init_safe_functions() {
        $this->safe_functions = array(
            'basename', 'realpath', 'pathinfo', 'is_file', 'file_exists',
            'is_readable', 'sanitize_file_name', 'wp_normalize_path'
        );
    }

    /**
     * Detect file inclusion vulnerabilities.
     *
     * @since    1.0.0
     * @param    string    $content         File content to analyze.
     * @param    string    $file_path       File path being analyzed.
     * @param    array     $file_info       File information.
     * @return   array                      Array of detected vulnerabilities.
     */
    public function detect($content, $file_path, $file_info) {
        $vulnerabilities = array();

        // Run pattern-based detection
        $pattern_vulns = $this->detect_patterns($content);
        $vulnerabilities = array_merge($vulnerabilities, $pattern_vulns);

        // Analyze file operations
        $file_vulns = $this->analyze_file_operations($content);
        $vulnerabilities = array_merge($vulnerabilities, $file_vulns);

        // Check path traversal
        $traversal_vulns = $this->detect_path_traversal($content);
        $vulnerabilities = array_merge($vulnerabilities, $traversal_vulns);

        // Perform data flow analysis
        $dataflow_vulns = $this->analyze_data_flow($content);
        $vulnerabilities = array_merge($vulnerabilities, $dataflow_vulns);

        // Check URL inclusion
        $url_vulns = $this->detect_url_inclusion($content);
        $vulnerabilities = array_merge($vulnerabilities, $url_vulns);

        return $vulnerabilities;
    }

    /**
     * Detect file inclusion patterns.
     *
     * @since    1.0.0
     * @param    string    $content         File content.
     * @return   array                      Detected vulnerabilities.
     */
    private function detect_patterns($content) {
        $vulnerabilities = array();
        $lines = explode("\n", $content);

        foreach ($this->patterns as $pattern_name => $pattern_data) {
            preg_match_all($pattern_data['pattern'], $content, $matches, PREG_OFFSET_CAPTURE);

            foreach ($matches[0] as $match) {
                $line_number = $this->get_line_number($content, $match[1]);
                $context = $this->get_context($lines, $line_number);

                // Check if there's proper validation
                $has_validation = $this->check_input_validation($content, $match[1], $match[0]);

                $vulnerabilities[] = array(
                    'type' => 'file-inclusion',
                    'subtype' => $pattern_name,
                    'severity' => $has_validation ? $this->reduce_severity($pattern_data['severity']) : $pattern_data['severity'],
                    'confidence' => $has_validation ? $pattern_data['confidence'] * 0.5 : $pattern_data['confidence'],
                    'description' => $pattern_data['description'],
                    'line' => $line_number,
                    'matched_text' => $match[0],
                    'context' => $context,
                    'has_validation' => $has_validation,
                    'cwe_id' => 'CWE-98',
                    'owasp_category' => 'A03:2021-Injection'
                );
            }
        }

        return $vulnerabilities;
    }

    /**
     * Analyze file operations for vulnerabilities.
     *
     * @since    1.0.0
     * @param    string    $content         File content.
     * @return   array                      Detected vulnerabilities.
     */
    private function analyze_file_operations($content) {
        $vulnerabilities = array();
        $lines = explode("\n", $content);

        foreach ($this->dangerous_functions['file_operations'] as $function) {
            $pattern = '/\b' . preg_quote($function, '/') . '\s*\([^)]+\)/i';
            preg_match_all($pattern, $content, $matches, PREG_OFFSET_CAPTURE);

            foreach ($matches[0] as $match) {
                $function_call = $match[0];
                $line_number = $this->get_line_number($content, $match[1]);

                // Check if function uses user input
                if (preg_match('/\$_(GET|POST|REQUEST|COOKIE|SERVER)/', $function_call)) {
                    // Check for proper validation
                    $validation_context = substr($content, max(0, $match[1] - 200), 400);
                    $has_validation = $this->has_file_validation($validation_context);

                    $vulnerabilities[] = array(
                        'type' => 'file-inclusion',
                        'subtype' => 'unsafe_file_operation',
                        'severity' => $has_validation ? 'medium' : 'high',
                        'confidence' => 0.8,
                        'description' => "Unsafe {$function} with user input",
                        'line' => $line_number,
                        'matched_text' => $function_call,
                        'context' => $this->get_context($lines, $line_number),
                        'function' => $function,
                        'has_validation' => $has_validation,
                        'cwe_id' => 'CWE-98',
                        'owasp_category' => 'A03:2021-Injection',
                        'recommendation' => 'Validate and sanitize file paths before use'
                    );
                }
            }
        }

        return $vulnerabilities;
    }

    /**
     * Detect path traversal vulnerabilities.
     *
     * @since    1.0.0
     * @param    string    $content         File content.
     * @return   array                      Detected vulnerabilities.
     */
    private function detect_path_traversal($content) {
        $vulnerabilities = array();
        $lines = explode("\n", $content);

        foreach ($this->traversal_patterns as $pattern) {
            $escaped_pattern = preg_quote($pattern, '/');
            $regex = '/' . $escaped_pattern . '/i';
            
            preg_match_all($regex, $content, $matches, PREG_OFFSET_CAPTURE);

            foreach ($matches[0] as $match) {
                $line_number = $this->get_line_number($content, $match[1]);
                
                // Check if it's in a file operation context
                $context_code = substr($content, max(0, $match[1] - 100), 200);
                if ($this->is_file_operation_context($context_code)) {
                    $vulnerabilities[] = array(
                        'type' => 'file-inclusion',
                        'subtype' => 'path_traversal',
                        'severity' => 'high',
                        'confidence' => 0.7,
                        'description' => 'Path traversal pattern detected',
                        'line' => $line_number,
                        'matched_text' => $match[0],
                        'context' => $this->get_context($lines, $line_number),
                        'traversal_pattern' => $pattern,
                        'cwe_id' => 'CWE-22',
                        'owasp_category' => 'A01:2021-Broken Access Control',
                        'recommendation' => 'Use basename() or validate file paths to prevent directory traversal'
                    );
                }
            }
        }

        return $vulnerabilities;
    }

    /**
     * Analyze data flow for file inclusion.
     *
     * @since    1.0.0
     * @param    string    $content         File content.
     * @return   array                      Detected vulnerabilities.
     */
    private function analyze_data_flow($content) {
        $vulnerabilities = array();
        $lines = explode("\n", $content);

        // Track variable assignments from user input
        $tainted_vars = array();
        
        // Find user input assignments
        preg_match_all('/\$(\w+)\s*=.*?\$_(GET|POST|REQUEST|COOKIE)\[/', $content, $input_matches, PREG_OFFSET_CAPTURE);
        
        foreach ($input_matches[1] as $i => $var_match) {
            $var_name = $var_match[0];
            $tainted_vars[$var_name] = array(
                'source' => $input_matches[2][$i][0],
                'line' => $this->get_line_number($content, $var_match[1])
            );
        }

        // Find usage of tainted variables in file operations
        foreach ($tainted_vars as $var_name => $var_info) {
            $all_functions = array_merge(
                $this->dangerous_functions['inclusion'],
                $this->dangerous_functions['file_operations']
            );

            foreach ($all_functions as $function) {
                $pattern = '/\b' . preg_quote($function, '/') . '\s*\([^)]*\$' . preg_quote($var_name, '/') . '/';
                preg_match_all($pattern, $content, $usage_matches, PREG_OFFSET_CAPTURE);

                foreach ($usage_matches[0] as $usage_match) {
                    $line_number = $this->get_line_number($content, $usage_match[1]);
                    
                    // Check if variable is validated before use
                    $validation_context = substr($content, $var_info['line'] * 80, $usage_match[1] - $var_info['line'] * 80);
                    $has_validation = $this->has_variable_validation($validation_context, $var_name);

                    $vulnerabilities[] = array(
                        'type' => 'file-inclusion',
                        'subtype' => 'tainted_variable_inclusion',
                        'severity' => $has_validation ? 'medium' : 'critical',
                        'confidence' => 0.85,
                        'description' => "Tainted variable \${$var_name} used in {$function}",
                        'line' => $line_number,
                        'matched_text' => $usage_match[0],
                        'context' => $this->get_context($lines, $line_number),
                        'function' => $function,
                        'tainted_source' => $var_info['source'],
                        'tainted_line' => $var_info['line'],
                        'has_validation' => $has_validation,
                        'cwe_id' => 'CWE-98',
                        'owasp_category' => 'A03:2021-Injection',
                        'recommendation' => 'Validate and sanitize file paths from user input'
                    );
                }
            }
        }

        return $vulnerabilities;
    }

    /**
     * Detect URL inclusion vulnerabilities.
     *
     * @since    1.0.0
     * @param    string    $content         File content.
     * @return   array                      Detected vulnerabilities.
     */
    private function detect_url_inclusion($content) {
        $vulnerabilities = array();
        $lines = explode("\n", $content);

        // Detect remote file inclusion patterns
        $rfi_patterns = array(
            '/(?:include|require)(?:_once)?\s*\(\s*["\']?https?:\/\/.*?\$_(GET|POST|REQUEST)/i',
            '/file_get_contents\s*\(\s*["\']?https?:\/\/.*?\$_(GET|POST|REQUEST)/i',
            '/fopen\s*\(\s*["\']?https?:\/\/.*?\$_(GET|POST|REQUEST)/i'
        );

        foreach ($rfi_patterns as $pattern) {
            preg_match_all($pattern, $content, $matches, PREG_OFFSET_CAPTURE);

            foreach ($matches[0] as $match) {
                $line_number = $this->get_line_number($content, $match[1]);
                
                $vulnerabilities[] = array(
                    'type' => 'file-inclusion',
                    'subtype' => 'remote_file_inclusion',
                    'severity' => 'critical',
                    'confidence' => 0.9,
                    'description' => 'Remote file inclusion with user input',
                    'line' => $line_number,
                    'matched_text' => $match[0],
                    'context' => $this->get_context($lines, $line_number),
                    'cwe_id' => 'CWE-98',
                    'owasp_category' => 'A03:2021-Injection',
                    'recommendation' => 'Never include remote files based on user input'
                );
            }
        }

        return $vulnerabilities;
    }

    /**
     * Check input validation around file operation.
     *
     * @since    1.0.0
     * @param    string    $content         Content to check.
     * @param    int       $offset          Operation offset.
     * @param    string    $matched_text    Matched text.
     * @return   bool                       True if has validation.
     */
    private function check_input_validation($content, $offset, $matched_text) {
        // Check 300 characters before the match for validation
        $check_start = max(0, $offset - 300);
        $check_content = substr($content, $check_start, 300);

        return $this->has_file_validation($check_content);
    }

    /**
     * Check if code has file validation.
     *
     * @since    1.0.0
     * @param    string    $code            Code to check.
     * @return   bool                       True if has validation.
     */
    private function has_file_validation($code) {
        foreach ($this->safe_functions as $function) {
            if (strpos($code, $function) !== false) {
                return true;
            }
        }

        // Check for common validation patterns
        $validation_patterns = array(
            '/if\s*\(\s*!?\s*file_exists/',
            '/if\s*\(\s*!?\s*is_file/',
            '/if\s*\(\s*!?\s*is_readable/',
            '/preg_match\s*\([^)]*\$\w+/',
            '/in_array\s*\(\s*\$\w+/',
            '/strpos\s*\([^)]*\.\.[\/\\\\]/'
        );

        foreach ($validation_patterns as $pattern) {
            if (preg_match($pattern, $code)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if code has variable validation.
     *
     * @since    1.0.0
     * @param    string    $code            Code to check.
     * @param    string    $var_name        Variable name.
     * @return   bool                       True if has validation.
     */
    private function has_variable_validation($code, $var_name) {
        // Look for validation of the specific variable
        $var_validation_patterns = array(
            '/\$' . preg_quote($var_name, '/') . '\s*=\s*basename\s*\(/',
            '/\$' . preg_quote($var_name, '/') . '\s*=\s*sanitize_/',
            '/\$' . preg_quote($var_name, '/') . '\s*=\s*preg_replace/',
            '/if\s*\([^)]*\$' . preg_quote($var_name, '/') . '[^)]*\)/',
            '/preg_match\s*\([^)]*\$' . preg_quote($var_name, '/') . '/',
        );

        foreach ($var_validation_patterns as $pattern) {
            if (preg_match($pattern, $code)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if context indicates file operation.
     *
     * @since    1.0.0
     * @param    string    $context         Context code.
     * @return   bool                       True if file operation context.
     */
    private function is_file_operation_context($context) {
        $all_functions = array_merge(
            $this->dangerous_functions['inclusion'],
            $this->dangerous_functions['file_operations']
        );

        foreach ($all_functions as $function) {
            if (strpos($context, $function) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Reduce severity level.
     *
     * @since    1.0.0
     * @param    string    $severity        Original severity.
     * @return   string                     Reduced severity.
     */
    private function reduce_severity($severity) {
        $reduction_map = array(
            'critical' => 'high',
            'high' => 'medium',
            'medium' => 'low',
            'low' => 'info'
        );

        return isset($reduction_map[$severity]) ? $reduction_map[$severity] : $severity;
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
            'dangerous_functions' => $this->dangerous_functions,
            'traversal_patterns' => $this->traversal_patterns,
            'safe_functions' => $this->safe_functions
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

        if (isset($config['dangerous_functions'])) {
            $this->dangerous_functions = array_merge($this->dangerous_functions, $config['dangerous_functions']);
        }

        if (isset($config['traversal_patterns'])) {
            $this->traversal_patterns = array_merge($this->traversal_patterns, $config['traversal_patterns']);
        }
    }
}

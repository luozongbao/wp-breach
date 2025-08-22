<?php

/**
 * The XSS vulnerability detector.
 *
 * This class handles detection of Cross-Site Scripting (XSS) vulnerabilities
 * in PHP code and output contexts.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/detection/detectors
 */

/**
 * The XSS detector class.
 *
 * This class provides specialized detection for XSS vulnerabilities
 * using context-aware analysis and WordPress-specific patterns.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/detection/detectors
 * @author     WP Breach Team
 */
class WP_Breach_Xss_Detector {

    /**
     * XSS patterns.
     *
     * @since    1.0.0
     * @access   protected
     * @var      array    $patterns    Array of XSS patterns.
     */
    protected $patterns;

    /**
     * WordPress escaping functions.
     *
     * @since    1.0.0
     * @access   protected
     * @var      array    $wp_escape_functions    WordPress escape functions.
     */
    protected $wp_escape_functions;

    /**
     * Output contexts.
     *
     * @since    1.0.0
     * @access   protected
     * @var      array    $output_contexts    Different output contexts.
     */
    protected $output_contexts;

    /**
     * Dangerous HTML tags.
     *
     * @since    1.0.0
     * @access   protected
     * @var      array    $dangerous_tags    Potentially dangerous HTML tags.
     */
    protected $dangerous_tags;

    /**
     * Initialize the XSS detector.
     *
     * @since    1.0.0
     */
    public function __construct() {
        $this->init_patterns();
        $this->init_wp_escape_functions();
        $this->init_output_contexts();
        $this->init_dangerous_tags();
    }

    /**
     * Initialize XSS patterns.
     *
     * @since    1.0.0
     */
    private function init_patterns() {
        $this->patterns = array(
            // Direct echo of user input
            'direct_echo' => array(
                'pattern' => '/echo\s+(.*?\$_(GET|POST|REQUEST|COOKIE)\[.*?\])/i',
                'severity' => 'critical',
                'confidence' => 0.9,
                'description' => 'Direct echo of user input without escaping'
            ),
            // Print user input
            'direct_print' => array(
                'pattern' => '/print\s+(.*?\$_(GET|POST|REQUEST|COOKIE)\[.*?\])/i',
                'severity' => 'critical',
                'confidence' => 0.9,
                'description' => 'Direct print of user input without escaping'
            ),
            // Printf with user input
            'printf_injection' => array(
                'pattern' => '/printf\s*\(\s*["\'].*?["\']\s*,.*?\$_(GET|POST|REQUEST|COOKIE)/i',
                'severity' => 'high',
                'confidence' => 0.8,
                'description' => 'Printf with user input - potential XSS'
            ),
            // HTML attributes with user input
            'attribute_injection' => array(
                'pattern' => '/(?:href|src|action|onclick|onload|onerror)\s*=\s*["\'].*?\$_(GET|POST|REQUEST|COOKIE)/i',
                'severity' => 'high',
                'confidence' => 0.8,
                'description' => 'User input in HTML attribute without escaping'
            ),
            // JavaScript variables
            'js_variable' => array(
                'pattern' => '/var\s+\w+\s*=\s*["\'].*?\$_(GET|POST|REQUEST|COOKIE).*?["\']/i',
                'severity' => 'high',
                'confidence' => 0.8,
                'description' => 'User input in JavaScript variable'
            ),
            // Inline event handlers
            'inline_event' => array(
                'pattern' => '/on\w+\s*=\s*["\'].*?\$_(GET|POST|REQUEST|COOKIE)/i',
                'severity' => 'critical',
                'confidence' => 0.9,
                'description' => 'User input in inline event handler'
            ),
            // URL parameters in href
            'href_injection' => array(
                'pattern' => '/href\s*=\s*["\'][^"\']*\?\w*=.*?\$_(GET|POST|REQUEST|COOKIE)/i',
                'severity' => 'medium',
                'confidence' => 0.7,
                'description' => 'User input in URL parameters'
            )
        );
    }

    /**
     * Initialize WordPress escaping functions.
     *
     * @since    1.0.0
     */
    private function init_wp_escape_functions() {
        $this->wp_escape_functions = array(
            'html' => array(
                'esc_html', 'esc_html__', 'esc_html_e', 'esc_html_x'
            ),
            'attribute' => array(
                'esc_attr', 'esc_attr__', 'esc_attr_e', 'esc_attr_x'
            ),
            'url' => array(
                'esc_url', 'esc_url_raw'
            ),
            'javascript' => array(
                'esc_js'
            ),
            'css' => array(
                'esc_css'
            ),
            'generic' => array(
                'sanitize_text_field', 'sanitize_textarea_field', 'wp_kses', 'wp_kses_post'
            )
        );
    }

    /**
     * Initialize output contexts.
     *
     * @since    1.0.0
     */
    private function init_output_contexts() {
        $this->output_contexts = array(
            'html_content' => array(
                'required_escaping' => 'esc_html',
                'risk_level' => 'high'
            ),
            'html_attribute' => array(
                'required_escaping' => 'esc_attr',
                'risk_level' => 'high'
            ),
            'url' => array(
                'required_escaping' => 'esc_url',
                'risk_level' => 'medium'
            ),
            'javascript' => array(
                'required_escaping' => 'esc_js',
                'risk_level' => 'critical'
            ),
            'css' => array(
                'required_escaping' => 'esc_css',
                'risk_level' => 'medium'
            )
        );
    }

    /**
     * Initialize dangerous HTML tags.
     *
     * @since    1.0.0
     */
    private function init_dangerous_tags() {
        $this->dangerous_tags = array(
            'script', 'iframe', 'object', 'embed', 'form', 'input',
            'textarea', 'select', 'option', 'button', 'link', 'style'
        );
    }

    /**
     * Detect XSS vulnerabilities.
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

        // Analyze output contexts
        $context_vulns = $this->analyze_output_contexts($content);
        $vulnerabilities = array_merge($vulnerabilities, $context_vulns);

        // Check WordPress functions usage
        $wp_function_vulns = $this->analyze_wp_functions($content);
        $vulnerabilities = array_merge($vulnerabilities, $wp_function_vulns);

        // Perform data flow analysis
        $dataflow_vulns = $this->analyze_data_flow($content);
        $vulnerabilities = array_merge($vulnerabilities, $dataflow_vulns);

        // Check template files
        if ($this->is_template_file($file_path)) {
            $template_vulns = $this->analyze_template_file($content);
            $vulnerabilities = array_merge($vulnerabilities, $template_vulns);
        }

        return $vulnerabilities;
    }

    /**
     * Detect XSS patterns.
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

                // Check if there's proper escaping nearby
                $is_escaped = $this->check_escaping_context($content, $match[1], $match[0]);

                if (!$is_escaped) {
                    $vulnerabilities[] = array(
                        'type' => 'xss',
                        'subtype' => $pattern_name,
                        'severity' => $pattern_data['severity'],
                        'confidence' => $pattern_data['confidence'],
                        'description' => $pattern_data['description'],
                        'line' => $line_number,
                        'matched_text' => $match[0],
                        'context' => $context,
                        'cwe_id' => 'CWE-79',
                        'owasp_category' => 'A03:2021-Injection'
                    );
                }
            }
        }

        return $vulnerabilities;
    }

    /**
     * Analyze output contexts.
     *
     * @since    1.0.0
     * @param    string    $content         File content.
     * @return   array                      Detected vulnerabilities.
     */
    private function analyze_output_contexts($content) {
        $vulnerabilities = array();
        $lines = explode("\n", $content);

        // Find all variable outputs
        preg_match_all('/(?:echo|print)\s+([^;]+);/i', $content, $output_matches, PREG_OFFSET_CAPTURE);

        foreach ($output_matches[1] as $i => $output_match) {
            $output_code = $output_match[0];
            $offset = $output_match[1];
            $line_number = $this->get_line_number($content, $offset);

            // Check if output contains user input
            if (preg_match('/\$_(GET|POST|REQUEST|COOKIE|SERVER)/', $output_code)) {
                $context_type = $this->determine_output_context($content, $offset);
                $required_escaping = $this->get_required_escaping($context_type);

                // Check if proper escaping is used
                if (!$this->has_proper_escaping($output_code, $required_escaping)) {
                    $vulnerabilities[] = array(
                        'type' => 'xss',
                        'subtype' => 'unescaped_output',
                        'severity' => $this->get_context_severity($context_type),
                        'confidence' => 0.8,
                        'description' => "Unescaped output in {$context_type} context",
                        'line' => $line_number,
                        'matched_text' => $output_matches[0][$i][0],
                        'context' => $this->get_context($lines, $line_number),
                        'output_context' => $context_type,
                        'required_escaping' => $required_escaping,
                        'cwe_id' => 'CWE-79',
                        'owasp_category' => 'A03:2021-Injection',
                        'recommendation' => "Use {$required_escaping}() to escape output"
                    );
                }
            }
        }

        return $vulnerabilities;
    }

    /**
     * Analyze WordPress function usage.
     *
     * @since    1.0.0
     * @param    string    $content         File content.
     * @return   array                      Detected vulnerabilities.
     */
    private function analyze_wp_functions($content) {
        $vulnerabilities = array();
        $lines = explode("\n", $content);

        // Check for missing nonce verification in forms
        if (preg_match('/(?:method\s*=\s*["\']post["\']|wp_nonce_field)/i', $content)) {
            if (!preg_match('/wp_verify_nonce|check_admin_referer/i', $content)) {
                $line_number = 1; // Default to first line if can't determine exact location
                
                $vulnerabilities[] = array(
                    'type' => 'xss',
                    'subtype' => 'missing_nonce',
                    'severity' => 'medium',
                    'confidence' => 0.7,
                    'description' => 'Form without nonce verification - potential CSRF/XSS',
                    'line' => $line_number,
                    'matched_text' => '',
                    'context' => $this->get_context($lines, $line_number),
                    'cwe_id' => 'CWE-352',
                    'owasp_category' => 'A01:2021-Broken Access Control',
                    'recommendation' => 'Add wp_nonce_field() to form and verify with wp_verify_nonce()'
                );
            }
        }

        // Check for direct HTML output functions
        $dangerous_output_functions = array('the_content', 'the_excerpt', 'the_title');
        foreach ($dangerous_output_functions as $function) {
            $pattern = '/\b' . preg_quote($function, '/') . '\s*\(\s*[^)]*\$_(GET|POST|REQUEST)/i';
            preg_match_all($pattern, $content, $matches, PREG_OFFSET_CAPTURE);

            foreach ($matches[0] as $match) {
                $line_number = $this->get_line_number($content, $match[1]);
                
                $vulnerabilities[] = array(
                    'type' => 'xss',
                    'subtype' => 'dangerous_wp_function',
                    'severity' => 'high',
                    'confidence' => 0.8,
                    'description' => "User input in {$function}() without sanitization",
                    'line' => $line_number,
                    'matched_text' => $match[0],
                    'context' => $this->get_context($lines, $line_number),
                    'cwe_id' => 'CWE-79',
                    'owasp_category' => 'A03:2021-Injection',
                    'recommendation' => 'Sanitize user input before passing to WordPress output functions'
                );
            }
        }

        return $vulnerabilities;
    }

    /**
     * Analyze data flow for XSS.
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

        // Find usage of tainted variables in output
        foreach ($tainted_vars as $var_name => $var_info) {
            $pattern = '/(?:echo|print).*?\$' . preg_quote($var_name, '/') . '/';
            preg_match_all($pattern, $content, $usage_matches, PREG_OFFSET_CAPTURE);

            foreach ($usage_matches[0] as $usage_match) {
                $line_number = $this->get_line_number($content, $usage_match[1]);
                
                // Check if variable is escaped before output
                $surrounding_code = substr($content, max(0, $usage_match[1] - 100), 200);
                if (!$this->has_escaping_function($surrounding_code)) {
                    $vulnerabilities[] = array(
                        'type' => 'xss',
                        'subtype' => 'tainted_variable_output',
                        'severity' => 'high',
                        'confidence' => 0.85,
                        'description' => "Tainted variable \${$var_name} output without escaping",
                        'line' => $line_number,
                        'matched_text' => $usage_match[0],
                        'context' => $this->get_context($lines, $line_number),
                        'cwe_id' => 'CWE-79',
                        'owasp_category' => 'A03:2021-Injection',
                        'tainted_source' => $var_info['source'],
                        'tainted_line' => $var_info['line'],
                        'recommendation' => 'Use appropriate WordPress escaping function before output'
                    );
                }
            }
        }

        return $vulnerabilities;
    }

    /**
     * Analyze template files for XSS.
     *
     * @since    1.0.0
     * @param    string    $content         File content.
     * @return   array                      Detected vulnerabilities.
     */
    private function analyze_template_file($content) {
        $vulnerabilities = array();
        $lines = explode("\n", $content);

        // Check for PHP embedded in HTML
        preg_match_all('/<[^>]*\?\s*php.*?\?>/', $content, $php_matches, PREG_OFFSET_CAPTURE);

        foreach ($php_matches[0] as $match) {
            $php_code = $match[0];
            $line_number = $this->get_line_number($content, $match[1]);

            // Check if PHP code contains user input without escaping
            if (preg_match('/\$_(GET|POST|REQUEST|COOKIE)/', $php_code) && 
                !$this->has_escaping_function($php_code)) {
                
                $vulnerabilities[] = array(
                    'type' => 'xss',
                    'subtype' => 'template_injection',
                    'severity' => 'high',
                    'confidence' => 0.8,
                    'description' => 'Unescaped user input in template file',
                    'line' => $line_number,
                    'matched_text' => $php_code,
                    'context' => $this->get_context($lines, $line_number),
                    'cwe_id' => 'CWE-79',
                    'owasp_category' => 'A03:2021-Injection',
                    'recommendation' => 'Use WordPress escaping functions in template files'
                );
            }
        }

        return $vulnerabilities;
    }

    /**
     * Check if there's proper escaping in context.
     *
     * @since    1.0.0
     * @param    string    $content         Full content.
     * @param    int       $offset          Match offset.
     * @param    string    $matched_text    Matched text.
     * @return   bool                       True if properly escaped.
     */
    private function check_escaping_context($content, $offset, $matched_text) {
        // Check 100 characters before and after the match
        $context_start = max(0, $offset - 100);
        $context_end = min(strlen($content), $offset + strlen($matched_text) + 100);
        $context = substr($content, $context_start, $context_end - $context_start);

        return $this->has_escaping_function($context);
    }

    /**
     * Check if code has escaping function.
     *
     * @since    1.0.0
     * @param    string    $code            Code to check.
     * @return   bool                       True if has escaping.
     */
    private function has_escaping_function($code) {
        $all_escape_functions = array_merge(
            $this->wp_escape_functions['html'],
            $this->wp_escape_functions['attribute'],
            $this->wp_escape_functions['url'],
            $this->wp_escape_functions['javascript'],
            $this->wp_escape_functions['css'],
            $this->wp_escape_functions['generic']
        );

        foreach ($all_escape_functions as $function) {
            if (strpos($code, $function) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine output context.
     *
     * @since    1.0.0
     * @param    string    $content         Full content.
     * @param    int       $offset          Output offset.
     * @return   string                     Output context.
     */
    private function determine_output_context($content, $offset) {
        // Check surrounding context to determine output type
        $before = substr($content, max(0, $offset - 200), 200);
        $after = substr($content, $offset, 200);
        $context = $before . $after;

        // Check for HTML attribute context
        if (preg_match('/(?:href|src|action|onclick|style|class|id)\s*=\s*["\']?[^"\']*$/i', $before)) {
            return 'html_attribute';
        }

        // Check for JavaScript context
        if (preg_match('/(?:script[^>]*>|<script)|(?:var\s+\w+\s*=)|(?:function\s*\()/i', $context)) {
            return 'javascript';
        }

        // Check for CSS context
        if (preg_match('/(?:style[^>]*>|<style)|(?:\.[\w-]+\s*\{)/i', $context)) {
            return 'css';
        }

        // Check for URL context
        if (preg_match('/(?:href\s*=|src\s*=|action\s*=)/i', $before)) {
            return 'url';
        }

        // Default to HTML content
        return 'html_content';
    }

    /**
     * Get required escaping for context.
     *
     * @since    1.0.0
     * @param    string    $context         Output context.
     * @return   string                     Required escaping function.
     */
    private function get_required_escaping($context) {
        if (isset($this->output_contexts[$context])) {
            return $this->output_contexts[$context]['required_escaping'];
        }
        return 'esc_html';
    }

    /**
     * Get severity for context.
     *
     * @since    1.0.0
     * @param    string    $context         Output context.
     * @return   string                     Severity level.
     */
    private function get_context_severity($context) {
        if (isset($this->output_contexts[$context])) {
            $risk_level = $this->output_contexts[$context]['risk_level'];
            switch ($risk_level) {
                case 'critical':
                    return 'critical';
                case 'high':
                    return 'high';
                case 'medium':
                    return 'medium';
                default:
                    return 'low';
            }
        }
        return 'medium';
    }

    /**
     * Check if output has proper escaping.
     *
     * @since    1.0.0
     * @param    string    $output_code     Output code.
     * @param    string    $required_func   Required escaping function.
     * @return   bool                       True if properly escaped.
     */
    private function has_proper_escaping($output_code, $required_func) {
        // Check for the specific required function
        if (strpos($output_code, $required_func) !== false) {
            return true;
        }

        // Check for alternative appropriate functions
        $alternatives = array(
            'esc_html' => array('wp_kses', 'wp_kses_post', 'sanitize_text_field'),
            'esc_attr' => array('sanitize_text_field'),
            'esc_url' => array('esc_url_raw'),
            'esc_js' => array(),
            'esc_css' => array()
        );

        if (isset($alternatives[$required_func])) {
            foreach ($alternatives[$required_func] as $alt_func) {
                if (strpos($output_code, $alt_func) !== false) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Check if file is a template file.
     *
     * @since    1.0.0
     * @param    string    $file_path       File path.
     * @return   bool                       True if template file.
     */
    private function is_template_file($file_path) {
        $template_extensions = array('.php', '.html', '.htm', '.tpl');
        $template_directories = array('/templates/', '/views/', '/theme/');

        foreach ($template_extensions as $ext) {
            if (substr($file_path, -strlen($ext)) === $ext) {
                foreach ($template_directories as $dir) {
                    if (strpos($file_path, $dir) !== false) {
                        return true;
                    }
                }
            }
        }

        // Check if it's a WordPress theme file
        return strpos($file_path, get_theme_root()) === 0;
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
            'wp_escape_functions' => $this->wp_escape_functions,
            'output_contexts' => $this->output_contexts,
            'dangerous_tags' => $this->dangerous_tags
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

        if (isset($config['dangerous_tags'])) {
            $this->dangerous_tags = array_merge($this->dangerous_tags, $config['dangerous_tags']);
        }
    }
}

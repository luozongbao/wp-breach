<?php

/**
 * The SQL injection vulnerability detector.
 *
 * This class handles detection of SQL injection vulnerabilities
 * in PHP code and database interactions.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/detection/detectors
 */

/**
 * The SQL injection detector class.
 *
 * This class provides specialized detection for SQL injection
 * vulnerabilities using advanced pattern matching and code analysis.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/detection/detectors
 * @author     WP Breach Team
 */
class WP_Breach_Sql_Injection_Detector {

    /**
     * SQL injection patterns.
     *
     * @since    1.0.0
     * @access   protected
     * @var      array    $patterns    Array of SQL injection patterns.
     */
    protected $patterns;

    /**
     * WordPress database functions.
     *
     * @since    1.0.0
     * @access   protected
     * @var      array    $wp_db_functions    WordPress database functions.
     */
    protected $wp_db_functions;

    /**
     * Dangerous SQL functions.
     *
     * @since    1.0.0
     * @access   protected
     * @var      array    $dangerous_functions    Dangerous SQL functions.
     */
    protected $dangerous_functions;

    /**
     * Initialize the SQL injection detector.
     *
     * @since    1.0.0
     */
    public function __construct() {
        $this->init_patterns();
        $this->init_wp_db_functions();
        $this->init_dangerous_functions();
    }

    /**
     * Initialize SQL injection patterns.
     *
     * @since    1.0.0
     */
    private function init_patterns() {
        $this->patterns = array(
            // Direct SQL concatenation patterns
            'direct_concat' => array(
                'pattern' => '/\$wpdb->(query|get_|prepare)\s*\(\s*["\'].*?["\']?\s*\.\s*\$\w+/i',
                'severity' => 'high',
                'confidence' => 0.8,
                'description' => 'Direct concatenation in SQL query detected'
            ),
            // Unescaped user input in queries
            'unescaped_input' => array(
                'pattern' => '/\$wpdb->(query|get_)\s*\(\s*["\'].*?\$_(GET|POST|REQUEST|COOKIE)\[.*?\].*?["\']/i',
                'severity' => 'critical',
                'confidence' => 0.9,
                'description' => 'Unescaped user input in SQL query'
            ),
            // Missing prepare statements
            'missing_prepare' => array(
                'pattern' => '/\$wpdb->query\s*\(\s*["\'].*?%[sd].*?["\']\s*\)/i',
                'severity' => 'medium',
                'confidence' => 0.7,
                'description' => 'Potential missing wpdb->prepare() usage'
            ),
            // Dynamic query building
            'dynamic_query' => array(
                'pattern' => '/\$\w+\s*\.?=\s*["\']SELECT.*?FROM.*?WHERE.*?["\']\s*\.\s*\$\w+/i',
                'severity' => 'high',
                'confidence' => 0.8,
                'description' => 'Dynamic SQL query construction detected'
            ),
            // Direct mysqli/mysql usage
            'direct_mysql' => array(
                'pattern' => '/(mysqli?_query|mysql_query)\s*\(\s*.*?\$_(GET|POST|REQUEST)/i',
                'severity' => 'critical',
                'confidence' => 0.9,
                'description' => 'Direct MySQL query with user input'
            ),
            // Unsafe ORDER BY/GROUP BY
            'unsafe_order_by' => array(
                'pattern' => '/ORDER BY.*?\$_(GET|POST|REQUEST)\[.*?\]/i',
                'severity' => 'medium',
                'confidence' => 0.7,
                'description' => 'Unsafe ORDER BY clause with user input'
            ),
            // Unsafe LIMIT clause
            'unsafe_limit' => array(
                'pattern' => '/LIMIT.*?\$_(GET|POST|REQUEST)\[.*?\]/i',
                'severity' => 'medium',
                'confidence' => 0.7,
                'description' => 'Unsafe LIMIT clause with user input'
            ),
            // String interpolation in queries
            'string_interpolation' => array(
                'pattern' => '/\$wpdb->(query|get_)\s*\(\s*".*?\$\{.*?\}.*?"/i',
                'severity' => 'high',
                'confidence' => 0.8,
                'description' => 'String interpolation in SQL query'
            )
        );
    }

    /**
     * Initialize WordPress database functions.
     *
     * @since    1.0.0
     */
    private function init_wp_db_functions() {
        $this->wp_db_functions = array(
            'safe' => array(
                'prepare', 'esc_sql', '_real_escape'
            ),
            'potentially_unsafe' => array(
                'query', 'get_results', 'get_row', 'get_col', 'get_var'
            ),
            'insertion' => array(
                'insert', 'update', 'delete', 'replace'
            )
        );
    }

    /**
     * Initialize dangerous SQL functions.
     *
     * @since    1.0.0
     */
    private function init_dangerous_functions() {
        $this->dangerous_functions = array(
            'mysql_query',
            'mysqli_query',
            'mysql_real_query',
            'mysqli_real_query',
            'mysql_multi_query',
            'mysqli_multi_query',
            'PDO::query',
            'PDO::exec'
        );
    }

    /**
     * Detect SQL injection vulnerabilities.
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

        // Analyze WordPress database usage
        $wpdb_vulns = $this->analyze_wpdb_usage($content);
        $vulnerabilities = array_merge($vulnerabilities, $wpdb_vulns);

        // Check for unsafe functions
        $function_vulns = $this->check_unsafe_functions($content);
        $vulnerabilities = array_merge($vulnerabilities, $function_vulns);

        // Perform data flow analysis
        $dataflow_vulns = $this->analyze_data_flow($content);
        $vulnerabilities = array_merge($vulnerabilities, $dataflow_vulns);

        // Analyze prepared statement usage
        $prepare_vulns = $this->analyze_prepare_statements($content);
        $vulnerabilities = array_merge($vulnerabilities, $prepare_vulns);

        return $vulnerabilities;
    }

    /**
     * Detect SQL injection patterns.
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

                $vulnerabilities[] = array(
                    'type' => 'sql-injection',
                    'subtype' => $pattern_name,
                    'severity' => $pattern_data['severity'],
                    'confidence' => $pattern_data['confidence'],
                    'description' => $pattern_data['description'],
                    'line' => $line_number,
                    'matched_text' => $match[0],
                    'context' => $context,
                    'cwe_id' => 'CWE-89',
                    'owasp_category' => 'A03:2021-Injection'
                );
            }
        }

        return $vulnerabilities;
    }

    /**
     * Analyze WordPress database usage.
     *
     * @since    1.0.0
     * @param    string    $content         File content.
     * @return   array                      Detected vulnerabilities.
     */
    private function analyze_wpdb_usage($content) {
        $vulnerabilities = array();
        $lines = explode("\n", $content);

        // Find all $wpdb usage
        preg_match_all('/\$wpdb->(\w+)\s*\((.*?)\)/s', $content, $matches, PREG_OFFSET_CAPTURE);

        for ($i = 0; $i < count($matches[0]); $i++) {
            $method = $matches[1][$i][0];
            $params = $matches[2][$i][0];
            $offset = $matches[0][$i][1];
            $line_number = $this->get_line_number($content, $offset);

            // Check if method is potentially unsafe
            if (in_array($method, $this->wp_db_functions['potentially_unsafe'])) {
                $vuln = $this->analyze_wpdb_call($method, $params, $line_number, $lines, $matches[0][$i][0]);
                if ($vuln) {
                    $vulnerabilities[] = $vuln;
                }
            }
        }

        return $vulnerabilities;
    }

    /**
     * Analyze specific wpdb call.
     *
     * @since    1.0.0
     * @param    string    $method          Database method.
     * @param    string    $params          Method parameters.
     * @param    int       $line_number     Line number.
     * @param    array     $lines           File lines.
     * @param    string    $matched_text    Matched text.
     * @return   array|null                 Vulnerability or null.
     */
    private function analyze_wpdb_call($method, $params, $line_number, $lines, $matched_text) {
        // Check for user input in parameters
        if (preg_match('/\$_(GET|POST|REQUEST|COOKIE)\[/', $params)) {
            // Check if there's proper escaping
            if (!preg_match('/(esc_sql|prepare|\$wpdb->prepare)/i', $params)) {
                return array(
                    'type' => 'sql-injection',
                    'subtype' => 'wpdb_unescaped_input',
                    'severity' => 'critical',
                    'confidence' => 0.9,
                    'description' => "Unescaped user input in \$wpdb->{$method}()",
                    'line' => $line_number,
                    'matched_text' => $matched_text,
                    'context' => $this->get_context($lines, $line_number),
                    'cwe_id' => 'CWE-89',
                    'owasp_category' => 'A03:2021-Injection',
                    'recommendation' => 'Use $wpdb->prepare() or esc_sql() to escape user input'
                );
            }
        }

        // Check for string concatenation
        if (preg_match('/["\'].*?["\']\s*\.\s*\$\w+/', $params)) {
            return array(
                'type' => 'sql-injection',
                'subtype' => 'wpdb_concatenation',
                'severity' => 'high',
                'confidence' => 0.8,
                'description' => "String concatenation in \$wpdb->{$method}()",
                'line' => $line_number,
                'matched_text' => $matched_text,
                'context' => $this->get_context($lines, $line_number),
                'cwe_id' => 'CWE-89',
                'owasp_category' => 'A03:2021-Injection',
                'recommendation' => 'Use $wpdb->prepare() instead of string concatenation'
            );
        }

        return null;
    }

    /**
     * Check for unsafe SQL functions.
     *
     * @since    1.0.0
     * @param    string    $content         File content.
     * @return   array                      Detected vulnerabilities.
     */
    private function check_unsafe_functions($content) {
        $vulnerabilities = array();
        $lines = explode("\n", $content);

        foreach ($this->dangerous_functions as $function) {
            $pattern = '/\b' . preg_quote($function, '/') . '\s*\(/i';
            preg_match_all($pattern, $content, $matches, PREG_OFFSET_CAPTURE);

            foreach ($matches[0] as $match) {
                $line_number = $this->get_line_number($content, $match[1]);
                $context = $this->get_context($lines, $line_number);

                $vulnerabilities[] = array(
                    'type' => 'sql-injection',
                    'subtype' => 'dangerous_function',
                    'severity' => 'high',
                    'confidence' => 0.7,
                    'description' => "Usage of dangerous SQL function: {$function}",
                    'line' => $line_number,
                    'matched_text' => $match[0],
                    'context' => $context,
                    'cwe_id' => 'CWE-89',
                    'owasp_category' => 'A03:2021-Injection',
                    'recommendation' => 'Use WordPress database functions instead of direct SQL functions'
                );
            }
        }

        return $vulnerabilities;
    }

    /**
     * Analyze data flow for SQL injection.
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

        // Find usage of tainted variables in SQL queries
        foreach ($tainted_vars as $var_name => $var_info) {
            $pattern = '/\$wpdb->\w+\s*\(.*?\$' . preg_quote($var_name, '/') . '/';
            preg_match_all($pattern, $content, $usage_matches, PREG_OFFSET_CAPTURE);

            foreach ($usage_matches[0] as $usage_match) {
                $line_number = $this->get_line_number($content, $usage_match[1]);
                
                // Check if variable is escaped before use
                $surrounding_code = substr($content, max(0, $usage_match[1] - 200), 400);
                // First, find all esc_sql or prepare calls in the surrounding code
                $is_escaped = false;
                if (preg_match_all('/(esc_sql|prepare)\s*\(([^)]*)\)/', $surrounding_code, $func_matches, PREG_SET_ORDER)) {
                    foreach ($func_matches as $func_match) {
                        // Check if the variable is present in the argument list
                        if (strpos($func_match[2], '$' . $var_name) !== false) {
                            $is_escaped = true;
                            break;
                        }
                    }
                }
                if (!$is_escaped) {
                    $vulnerabilities[] = array(
                        'type' => 'sql-injection',
                        'subtype' => 'tainted_variable',
                        'severity' => 'critical',
                        'confidence' => 0.85,
                        'description' => "Tainted variable \${$var_name} used in SQL query without escaping",
                        'line' => $line_number,
                        'matched_text' => $usage_match[0],
                        'context' => $this->get_context($lines, $line_number),
                        'cwe_id' => 'CWE-89',
                        'owasp_category' => 'A03:2021-Injection',
                        'tainted_source' => $var_info['source'],
                        'tainted_line' => $var_info['line'],
                        'recommendation' => 'Escape the variable using esc_sql() or use $wpdb->prepare()'
                    );
                }
            }
        }

        return $vulnerabilities;
    }

    /**
     * Analyze prepared statement usage.
     *
     * @since    1.0.0
     * @param    string    $content         File content.
     * @return   array                      Detected vulnerabilities.
     */
    private function analyze_prepare_statements($content) {
        $vulnerabilities = array();
        $lines = explode("\n", $content);

        // Find prepare statements
        preg_match_all('/\$wpdb->prepare\s*\(\s*["\']([^"\']*)["\'](?:\s*,\s*(.*))?/s', $content, $matches, PREG_OFFSET_CAPTURE);

        foreach ($matches[0] as $i => $match) {
            $query = $matches[1][$i][0];
            $params = isset($matches[2][$i]) ? $matches[2][$i][0] : '';
            $line_number = $this->get_line_number($content, $match[1]);

            // Count placeholders in query
            $placeholder_count = substr_count($query, '%s') + substr_count($query, '%d') + substr_count($query, '%f');
            
            // Count parameters (rough estimation)
            $param_count = 0;
            if (!empty($params)) {
                $param_count = substr_count($params, ',') + 1;
            }

            // Check for placeholder/parameter mismatch
            if ($placeholder_count !== $param_count && !empty($params)) {
                $vulnerabilities[] = array(
                    'type' => 'sql-injection',
                    'subtype' => 'prepare_mismatch',
                    'severity' => 'medium',
                    'confidence' => 0.8,
                    'description' => 'Placeholder/parameter count mismatch in wpdb->prepare()',
                    'line' => $line_number,
                    'matched_text' => $match[0],
                    'context' => $this->get_context($lines, $line_number),
                    'cwe_id' => 'CWE-89',
                    'placeholder_count' => $placeholder_count,
                    'parameter_count' => $param_count,
                    'recommendation' => 'Ensure placeholder count matches parameter count'
                );
            }

            // Check for improper placeholder usage
            if (preg_match('/["\'].*?%[sd].*?["\'].*?\$_(GET|POST|REQUEST)/', $query . $params)) {
                $vulnerabilities[] = array(
                    'type' => 'sql-injection',
                    'subtype' => 'improper_prepare',
                    'severity' => 'high',
                    'confidence' => 0.9,
                    'description' => 'User input mixed with placeholders in prepare statement',
                    'line' => $line_number,
                    'matched_text' => $match[0],
                    'context' => $this->get_context($lines, $line_number),
                    'cwe_id' => 'CWE-89',
                    'recommendation' => 'Use placeholders for all dynamic values'
                );
            }
        }

        return $vulnerabilities;
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
            'wp_db_functions' => $this->wp_db_functions,
            'dangerous_functions' => $this->dangerous_functions
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
    }
}

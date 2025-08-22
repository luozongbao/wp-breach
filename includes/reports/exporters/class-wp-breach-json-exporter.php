<?php

/**
 * JSON report exporter.
 *
 * This class handles the export of security reports to JSON format
 * for API integration, data exchange, and machine processing.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/reports/exporters
 */

/**
 * The JSON exporter class.
 *
 * Converts security report data to structured JSON format with
 * schema validation, API compatibility, and compression support.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/reports/exporters
 * @author     WP Breach Team
 */
class WP_Breach_JSON_Exporter {

    /**
     * JSON export configuration.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $config    JSON export configuration.
     */
    private $config;

    /**
     * JSON schema definitions.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $schemas    Schema definitions for validation.
     */
    private $schemas;

    /**
     * Data transformation rules.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $transformation_rules    Rules for data transformation.
     */
    private $transformation_rules;

    /**
     * Initialize the JSON exporter.
     *
     * @since    1.0.0
     */
    public function __construct() {
        $this->setup_config();
        $this->setup_schemas();
        $this->setup_transformation_rules();
    }

    /**
     * Setup JSON export configuration.
     *
     * @since    1.0.0
     * @access   private
     */
    private function setup_config() {
        $this->config = array(
            'pretty_print' => true,
            'unescaped_unicode' => true,
            'unescaped_slashes' => true,
            'compress' => false,
            'include_metadata' => true,
            'api_version' => '1.0',
            'schema_version' => '1.0',
            'include_timestamps' => true,
            'include_environment' => true,
            'max_depth' => 10,
            'include_raw_data' => false,
            'formats' => array(
                'standard' => 'Standard JSON format',
                'api' => 'API-compatible format',
                'minimal' => 'Minimal format for bandwidth optimization',
                'extended' => 'Extended format with all available data'
            )
        );
    }

    /**
     * Setup JSON schemas for validation.
     *
     * @since    1.0.0
     * @access   private
     */
    private function setup_schemas() {
        $this->schemas = array(
            'report' => array(
                'type' => 'object',
                'required' => array('metadata', 'data', 'summary'),
                'properties' => array(
                    'metadata' => array('$ref' => '#/definitions/metadata'),
                    'data' => array('$ref' => '#/definitions/data'),
                    'summary' => array('$ref' => '#/definitions/summary')
                )
            ),
            'vulnerability' => array(
                'type' => 'object',
                'required' => array('id', 'title', 'severity'),
                'properties' => array(
                    'id' => array('type' => 'integer'),
                    'title' => array('type' => 'string'),
                    'severity' => array('type' => 'string', 'enum' => array('critical', 'high', 'medium', 'low', 'info')),
                    'cvss_score' => array('type' => 'number', 'minimum' => 0, 'maximum' => 10),
                    'cve_id' => array('type' => 'string', 'pattern' => '^CVE-\\d{4}-\\d{4,}$'),
                    'detected_at' => array('type' => 'string', 'format' => 'date-time')
                )
            )
        );
    }

    /**
     * Setup data transformation rules.
     *
     * @since    1.0.0
     * @access   private
     */
    private function setup_transformation_rules() {
        $this->transformation_rules = array(
            'convert_dates_to_iso' => true,
            'normalize_numbers' => true,
            'remove_empty_arrays' => true,
            'convert_booleans' => true,
            'sanitize_strings' => true,
            'include_null_values' => false,
            'flatten_nested_objects' => false
        );
    }

    /**
     * Export report to JSON format.
     *
     * @since    1.0.0
     * @param    array    $report     Report data.
     * @param    array    $options    Export options.
     * @return   array               Export result.
     */
    public function export($report, $options = array()) {
        try {
            $export_config = array_merge($this->config, $options);
            
            // Transform data according to selected format
            $transformed_data = $this->transform_data($report, $export_config);
            
            // Generate JSON based on format
            switch ($export_config['format'] ?? 'standard') {
                case 'api':
                    return $this->export_api_format($transformed_data, $export_config);
                case 'minimal':
                    return $this->export_minimal_format($transformed_data, $export_config);
                case 'extended':
                    return $this->export_extended_format($transformed_data, $export_config);
                default:
                    return $this->export_standard_format($transformed_data, $export_config);
            }

        } catch (Exception $e) {
            error_log("WP-Breach JSON Export Error: " . $e->getMessage());
            return array(
                'error' => true,
                'message' => $e->getMessage()
            );
        }
    }

    /**
     * Export in standard JSON format.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $data      Transformed report data.
     * @param    array    $config    Export configuration.
     * @return   array              Export result.
     */
    private function export_standard_format($data, $config) {
        // Build complete JSON structure
        $json_data = array(
            'schema_version' => $config['schema_version'],
            'api_version' => $config['api_version'],
            'generated_at' => current_time('c'),
            'report' => $data
        );

        // Add environment information if configured
        if ($config['include_environment']) {
            $json_data['environment'] = $this->get_environment_info();
        }

        // Generate JSON string
        $json_flags = $this->get_json_flags($config);
        $json_string = json_encode($json_data, $json_flags);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception('JSON encoding error: ' . json_last_error_msg());
        }

        // Save to file
        $result = $this->save_json_file($json_string, $data, 'standard', $config);
        
        // Add JSON-specific metadata
        $result['json_size'] = strlen($json_string);
        $result['json_depth'] = $this->calculate_json_depth($json_data);
        $result['compressed'] = $config['compress'];

        return $result;
    }

    /**
     * Export in API-compatible format.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $data      Transformed report data.
     * @param    array    $config    Export configuration.
     * @return   array              Export result.
     */
    private function export_api_format($data, $config) {
        // Structure for API compatibility
        $api_data = array(
            'status' => 'success',
            'version' => $config['api_version'],
            'timestamp' => current_time('U'),
            'data' => array(
                'report_id' => $data['metadata']['report_id'] ?? uniqid('report_'),
                'report_type' => $data['type'] ?? 'security',
                'site_info' => array(
                    'url' => home_url(),
                    'name' => get_bloginfo('name'),
                    'wp_version' => get_bloginfo('version')
                ),
                'security' => array(
                    'vulnerabilities' => $data['data']['vulnerabilities'] ?? array(),
                    'summary' => $data['data']['summary'] ?? array(),
                    'metrics' => $data['data']['key_metrics'] ?? array(),
                    'score' => $data['data']['security_score'] ?? array()
                ),
                'pagination' => array(
                    'total_items' => count($data['data']['vulnerabilities'] ?? array()),
                    'page' => 1,
                    'per_page' => count($data['data']['vulnerabilities'] ?? array())
                )
            ),
            'meta' => array(
                'generated_by' => 'WP-Breach Plugin',
                'export_format' => 'api',
                'processing_time' => $this->get_processing_time()
            )
        );

        // Generate JSON
        $json_flags = $this->get_json_flags($config);
        $json_string = json_encode($api_data, $json_flags);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception('JSON encoding error: ' . json_last_error_msg());
        }

        return $this->save_json_file($json_string, $data, 'api', $config);
    }

    /**
     * Export in minimal format.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $data      Transformed report data.
     * @param    array    $config    Export configuration.
     * @return   array              Export result.
     */
    private function export_minimal_format($data, $config) {
        // Minimal structure for bandwidth optimization
        $minimal_data = array(
            'v' => $config['api_version'], // version
            't' => current_time('U'), // timestamp
            's' => array( // summary
                'total' => count($data['data']['vulnerabilities'] ?? array()),
                'critical' => 0,
                'high' => 0,
                'medium' => 0,
                'low' => 0
            ),
            'vulns' => array() // vulnerabilities
        );

        // Process vulnerabilities for minimal format
        if (isset($data['data']['vulnerabilities'])) {
            foreach ($data['data']['vulnerabilities'] as $vuln) {
                // Count by severity
                $severity = strtolower($vuln['severity'] ?? 'low');
                if (isset($minimal_data['s'][$severity])) {
                    $minimal_data['s'][$severity]++;
                }

                // Add minimal vulnerability data
                $minimal_data['vulns'][] = array(
                    'id' => $vuln['id'] ?? 0,
                    'title' => substr($vuln['title'] ?? '', 0, 50), // Truncated title
                    'sev' => substr($severity, 0, 1), // First letter of severity
                    'cvss' => $vuln['cvss_score'] ?? null,
                    'file' => basename($vuln['affected_file'] ?? ''),
                    'fix' => $vuln['fix_available'] ?? false
                );
            }
        }

        // Generate compact JSON
        $json_string = json_encode($minimal_data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception('JSON encoding error: ' . json_last_error_msg());
        }

        return $this->save_json_file($json_string, $data, 'minimal', $config);
    }

    /**
     * Export in extended format with all available data.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $data      Transformed report data.
     * @param    array    $config    Export configuration.
     * @return   array              Export result.
     */
    private function export_extended_format($data, $config) {
        // Extended structure with comprehensive data
        $extended_data = array(
            'schema' => array(
                'version' => $config['schema_version'],
                'format' => 'extended',
                'specification' => 'https://wpbreach.com/api/schema/report/v1'
            ),
            'metadata' => array_merge($data['metadata'] ?? array(), array(
                'export_timestamp' => current_time('c'),
                'export_timezone' => get_option('timezone_string'),
                'export_version' => WP_BREACH_VERSION ?? '1.0.0',
                'wordpress_version' => get_bloginfo('version'),
                'php_version' => PHP_VERSION,
                'mysql_version' => $this->get_mysql_version()
            )),
            'site' => array(
                'info' => array(
                    'name' => get_bloginfo('name'),
                    'description' => get_bloginfo('description'),
                    'url' => home_url(),
                    'admin_email' => get_option('admin_email'),
                    'language' => get_locale(),
                    'charset' => get_option('blog_charset')
                ),
                'configuration' => array(
                    'active_theme' => get_option('current_theme'),
                    'active_plugins' => get_option('active_plugins'),
                    'multisite' => is_multisite(),
                    'debug_mode' => defined('WP_DEBUG') && WP_DEBUG
                )
            ),
            'report' => $data,
            'analysis' => array(
                'risk_matrix' => $this->generate_risk_matrix($data),
                'trend_analysis' => $this->generate_trend_analysis($data),
                'recommendations' => $this->generate_recommendations($data),
                'compliance_status' => $this->get_compliance_status($data)
            ),
            'raw_data' => $config['include_raw_data'] ? $this->get_raw_data($data) : null
        );

        // Remove null values if configured
        if (!$config['include_null_values']) {
            $extended_data = $this->remove_null_values($extended_data);
        }

        // Generate JSON
        $json_flags = $this->get_json_flags($config);
        $json_string = json_encode($extended_data, $json_flags);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception('JSON encoding error: ' . json_last_error_msg());
        }

        return $this->save_json_file($json_string, $data, 'extended', $config);
    }

    /**
     * Transform data according to rules and format.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $data      Original report data.
     * @param    array    $config    Export configuration.
     * @return   array              Transformed data.
     */
    private function transform_data($data, $config) {
        $transformed = $data;

        // Convert dates to ISO format
        if ($this->transformation_rules['convert_dates_to_iso']) {
            $transformed = $this->convert_dates_to_iso($transformed);
        }

        // Normalize numbers
        if ($this->transformation_rules['normalize_numbers']) {
            $transformed = $this->normalize_numbers($transformed);
        }

        // Convert boolean values
        if ($this->transformation_rules['convert_booleans']) {
            $transformed = $this->convert_booleans($transformed);
        }

        // Sanitize strings
        if ($this->transformation_rules['sanitize_strings']) {
            $transformed = $this->sanitize_strings($transformed);
        }

        // Remove empty arrays
        if ($this->transformation_rules['remove_empty_arrays']) {
            $transformed = $this->remove_empty_arrays($transformed);
        }

        return $transformed;
    }

    /**
     * Convert dates to ISO 8601 format.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $data      Data array.
     * @return   array              Data with converted dates.
     */
    private function convert_dates_to_iso($data) {
        $date_fields = array('detected_at', 'created_at', 'updated_at', 'first_detected_at', 'last_seen_at');
        
        return $this->walk_array($data, function($value, $key) use ($date_fields) {
            if (in_array($key, $date_fields) && !empty($value)) {
                $timestamp = strtotime($value);
                if ($timestamp !== false) {
                    return date('c', $timestamp); // ISO 8601 format
                }
            }
            return $value;
        });
    }

    /**
     * Normalize numeric values.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $data      Data array.
     * @return   array              Data with normalized numbers.
     */
    private function normalize_numbers($data) {
        return $this->walk_array($data, function($value, $key) {
            if (is_numeric($value)) {
                // Convert to appropriate numeric type
                if (strpos($value, '.') !== false) {
                    return (float) $value;
                } else {
                    return (int) $value;
                }
            }
            return $value;
        });
    }

    /**
     * Convert boolean-like values to proper booleans.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $data      Data array.
     * @return   array              Data with converted booleans.
     */
    private function convert_booleans($data) {
        return $this->walk_array($data, function($value, $key) {
            if (is_string($value)) {
                $lower = strtolower($value);
                if (in_array($lower, array('true', 'false', 'yes', 'no', '1', '0'))) {
                    return in_array($lower, array('true', 'yes', '1'));
                }
            }
            return $value;
        });
    }

    /**
     * Sanitize string values.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $data      Data array.
     * @return   array              Data with sanitized strings.
     */
    private function sanitize_strings($data) {
        return $this->walk_array($data, function($value, $key) {
            if (is_string($value)) {
                // Remove potentially dangerous content
                $value = strip_tags($value);
                $value = trim($value);
                
                // Ensure UTF-8 encoding
                if (!mb_check_encoding($value, 'UTF-8')) {
                    $value = mb_convert_encoding($value, 'UTF-8', 'auto');
                }
            }
            return $value;
        });
    }

    /**
     * Get JSON encoding flags based on configuration.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $config    Export configuration.
     * @return   int                JSON flags.
     */
    private function get_json_flags($config) {
        $flags = 0;

        if ($config['pretty_print']) {
            $flags |= JSON_PRETTY_PRINT;
        }

        if ($config['unescaped_unicode']) {
            $flags |= JSON_UNESCAPED_UNICODE;
        }

        if ($config['unescaped_slashes']) {
            $flags |= JSON_UNESCAPED_SLASHES;
        }

        return $flags;
    }

    /**
     * Save JSON string to file.
     *
     * @since    1.0.0
     * @access   private
     * @param    string   $json_string   JSON string.
     * @param    array    $data         Original data.
     * @param    string   $format       Export format.
     * @param    array    $config       Export configuration.
     * @return   array                  Save result.
     */
    private function save_json_file($json_string, $data, $format, $config) {
        $filename = $this->generate_json_filename($data, $format);
        $upload_dir = wp_upload_dir();
        $file_path = $upload_dir['basedir'] . '/wp-breach-reports/' . $filename;
        
        // Create directory if it doesn't exist
        wp_mkdir_p(dirname($file_path));

        // Compress if configured
        if ($config['compress']) {
            $json_string = gzcompress($json_string);
            $filename = str_replace('.json', '.json.gz', $filename);
            $file_path = str_replace('.json', '.json.gz', $file_path);
        }

        // Write file
        $bytes_written = file_put_contents($file_path, $json_string);
        
        if ($bytes_written === false) {
            throw new Exception("Could not write JSON file: {$file_path}");
        }

        return array(
            'success' => true,
            'file_path' => $file_path,
            'url' => $upload_dir['baseurl'] . '/wp-breach-reports/' . $filename,
            'filename' => $filename,
            'size' => filesize($file_path),
            'format' => 'json',
            'json_format' => $format,
            'compressed' => $config['compress']
        );
    }

    /**
     * Generate JSON filename.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $data      Report data.
     * @param    string   $format    JSON format.
     * @return   string             Generated filename.
     */
    private function generate_json_filename($data, $format) {
        $site_name = sanitize_file_name(get_bloginfo('name'));
        $report_type = $data['type'] ?? 'security';
        $date = current_time('Y-m-d_H-i-s');
        
        return sprintf('%s_%s_report_%s_%s.json', $site_name, $report_type, $format, $date);
    }

    /**
     * Walk array recursively and apply callback.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $array     Array to walk.
     * @param    callable $callback  Callback function.
     * @return   array              Modified array.
     */
    private function walk_array($array, $callback) {
        foreach ($array as $key => $value) {
            if (is_array($value)) {
                $array[$key] = $this->walk_array($value, $callback);
            } else {
                $array[$key] = $callback($value, $key);
            }
        }
        return $array;
    }

    // Additional helper methods...
    private function get_environment_info() {
        return array(
            'wp_version' => get_bloginfo('version'),
            'php_version' => PHP_VERSION,
            'mysql_version' => $this->get_mysql_version(),
            'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown'
        );
    }

    private function get_mysql_version() {
        global $wpdb;
        return $wpdb->db_version();
    }

    private function calculate_json_depth($data, $depth = 0) {
        if (!is_array($data) || $depth > 20) {
            return $depth;
        }
        
        $max_depth = $depth;
        foreach ($data as $value) {
            if (is_array($value)) {
                $max_depth = max($max_depth, $this->calculate_json_depth($value, $depth + 1));
            }
        }
        
        return $max_depth;
    }

    private function remove_null_values($array) {
        return array_filter($array, function($value) {
            return !is_null($value);
        });
    }

    private function remove_empty_arrays($array) {
        return array_filter($array, function($value) {
            return !is_array($value) || !empty($value);
        });
    }

    private function get_processing_time() {
        return round(microtime(true) - $_SERVER['REQUEST_TIME_FLOAT'], 3);
    }

    // Placeholder methods for extended format features
    private function generate_risk_matrix($data) { return array(); }
    private function generate_trend_analysis($data) { return array(); }
    private function generate_recommendations($data) { return array(); }
    private function get_compliance_status($data) { return array(); }
    private function get_raw_data($data) { return array(); }
}

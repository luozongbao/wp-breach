<?php

/**
 * Main report generation engine.
 *
 * This class serves as the central report generation system for the WP-Breach plugin.
 * It coordinates between data aggregation, template rendering, and export formatting
 * to produce comprehensive security reports in multiple formats.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/reports
 */

/**
 * The report generator class.
 *
 * Handles the generation of security reports in various formats including
 * executive summaries, technical vulnerability reports, compliance reports,
 * and trend analysis. Supports multiple export formats and delivery methods.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/reports
 * @author     WP Breach Team
 */
class WP_Breach_Report_Generator {

    /**
     * Data aggregator instance.
     *
     * @since    1.0.0
     * @access   private
     * @var      WP_Breach_Data_Aggregator    $data_aggregator    Data aggregation engine.
     */
    private $data_aggregator;

    /**
     * Template engine instance.
     *
     * @since    1.0.0
     * @access   private
     * @var      WP_Breach_Report_Template    $template_engine    Report template system.
     */
    private $template_engine;

    /**
     * Chart generator instance.
     *
     * @since    1.0.0
     * @access   private
     * @var      WP_Breach_Chart_Generator    $chart_generator    Chart and visualization generator.
     */
    private $chart_generator;

    /**
     * Supported report types.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $report_types    Available report types.
     */
    private $report_types;

    /**
     * Report cache directory.
     *
     * @since    1.0.0
     * @access   private
     * @var      string    $cache_dir    Directory for caching generated reports.
     */
    private $cache_dir;

    /**
     * Export format handlers.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $exporters    Format-specific export handlers.
     */
    private $exporters;

    /**
     * Initialize the report generator.
     *
     * @since    1.0.0
     */
    public function __construct() {
        $this->setup_dependencies();
        $this->setup_report_types();
        $this->setup_cache_directory();
        $this->setup_exporters();
    }

    /**
     * Setup required dependencies.
     *
     * @since    1.0.0
     * @access   private
     */
    private function setup_dependencies() {
        require_once plugin_dir_path(__FILE__) . 'class-wp-breach-data-aggregator.php';
        require_once plugin_dir_path(__FILE__) . 'class-wp-breach-report-template.php';
        require_once plugin_dir_path(__FILE__) . 'class-wp-breach-chart-generator.php';

        $this->data_aggregator = new WP_Breach_Data_Aggregator();
        $this->template_engine = new WP_Breach_Report_Template();
        $this->chart_generator = new WP_Breach_Chart_Generator();
    }

    /**
     * Setup available report types.
     *
     * @since    1.0.0
     * @access   private
     */
    private function setup_report_types() {
        $this->report_types = array(
            'executive' => array(
                'name' => 'Executive Summary',
                'description' => 'High-level security overview for management',
                'template' => 'executive-summary',
                'sections' => array('overview', 'metrics', 'risks', 'recommendations'),
                'audience' => 'executive'
            ),
            'technical' => array(
                'name' => 'Technical Vulnerability Report',
                'description' => 'Detailed technical analysis of vulnerabilities',
                'template' => 'technical-vulnerability',
                'sections' => array('inventory', 'details', 'systems', 'remediation'),
                'audience' => 'technical'
            ),
            'compliance' => array(
                'name' => 'Compliance Report',
                'description' => 'Security framework compliance assessment',
                'template' => 'compliance',
                'sections' => array('frameworks', 'controls', 'gaps', 'recommendations'),
                'audience' => 'auditor'
            ),
            'trend' => array(
                'name' => 'Trend Analysis Report',
                'description' => 'Historical security metrics and trends',
                'template' => 'trend-analysis',
                'sections' => array('trends', 'predictions', 'improvements', 'benchmarks'),
                'audience' => 'analyst'
            )
        );
    }

    /**
     * Setup cache directory for generated reports.
     *
     * @since    1.0.0
     * @access   private
     */
    private function setup_cache_directory() {
        $upload_dir = wp_upload_dir();
        $this->cache_dir = $upload_dir['basedir'] . '/wp-breach-reports/';

        if (!file_exists($this->cache_dir)) {
            wp_mkdir_p($this->cache_dir);
            
            // Create .htaccess for security
            $htaccess_content = "Order deny,allow\nDeny from all\n";
            file_put_contents($this->cache_dir . '.htaccess', $htaccess_content);
        }
    }

    /**
     * Setup export format handlers.
     *
     * @since    1.0.0
     * @access   private
     */
    private function setup_exporters() {
        $this->exporters = array();
        
        $exporter_files = array(
            'pdf' => 'class-wp-breach-pdf-exporter.php',
            'html' => 'class-wp-breach-html-exporter.php',
            'csv' => 'class-wp-breach-csv-exporter.php',
            'json' => 'class-wp-breach-json-exporter.php'
        );

        foreach ($exporter_files as $format => $file) {
            $file_path = plugin_dir_path(__FILE__) . 'exporters/' . $file;
            if (file_exists($file_path)) {
                require_once $file_path;
                
                $class_name = 'WP_Breach_' . ucfirst($format) . '_Exporter';
                if (class_exists($class_name)) {
                    $this->exporters[$format] = new $class_name();
                }
            }
        }
    }

    /**
     * Generate a report based on type and configuration.
     *
     * @since    1.0.0
     * @param    string    $type      Report type (executive, technical, compliance, trend).
     * @param    array     $config    Report configuration options.
     * @return   array               Generated report data and metadata.
     */
    public function generate_report($type, $config = array()) {
        try {
            // Validate report type
            if (!isset($this->report_types[$type])) {
                throw new Exception("Invalid report type: {$type}");
            }

            // Set default configuration
            $config = $this->merge_default_config($type, $config);

            // Check cache if enabled
            $cache_key = $this->generate_cache_key($type, $config);
            if ($config['use_cache'] && $cached_report = $this->get_cached_report($cache_key)) {
                return $cached_report;
            }

            // Start report generation
            $start_time = microtime(true);
            
            // Gather report data
            $report_data = $this->get_report_data($type, $config);
            
            // Generate charts and visualizations
            $charts = $this->generate_charts($type, $report_data, $config);
            
            // Apply template
            $rendered_report = $this->apply_template($type, $report_data, $charts, $config);
            
            // Calculate generation time
            $generation_time = microtime(true) - $start_time;
            
            // Prepare final report
            $report = array(
                'id' => $this->generate_report_id(),
                'type' => $type,
                'config' => $config,
                'data' => $report_data,
                'charts' => $charts,
                'content' => $rendered_report,
                'metadata' => array(
                    'generated_at' => current_time('mysql'),
                    'generated_by' => get_current_user_id(),
                    'generation_time' => $generation_time,
                    'data_points' => $this->count_data_points($report_data),
                    'version' => WP_BREACH_VERSION
                )
            );

            // Cache the report if enabled
            if ($config['use_cache']) {
                $this->cache_report($cache_key, $report);
            }

            // Log report generation
            $this->log_report_generation($report);

            return $report;

        } catch (Exception $e) {
            error_log("WP-Breach Report Generation Error: " . $e->getMessage());
            return array(
                'error' => true,
                'message' => $e->getMessage(),
                'type' => $type,
                'config' => $config
            );
        }
    }

    /**
     * Get aggregated data for report generation.
     *
     * @since    1.0.0
     * @param    string    $type      Report type.
     * @param    array     $config    Report configuration.
     * @return   array               Aggregated report data.
     */
    public function get_report_data($type, $config = array()) {
        $filters = $config['filters'] ?? array();
        $date_range = $config['date_range'] ?? array();

        // Get base data from aggregator
        $base_data = $this->data_aggregator->aggregate_data($filters, $date_range);

        // Apply report-specific data processing
        switch ($type) {
            case 'executive':
                return $this->process_executive_data($base_data, $config);
            case 'technical':
                return $this->process_technical_data($base_data, $config);
            case 'compliance':
                return $this->process_compliance_data($base_data, $config);
            case 'trend':
                return $this->process_trend_data($base_data, $config);
            default:
                return $base_data;
        }
    }

    /**
     * Export a report in the specified format.
     *
     * @since    1.0.0
     * @param    array     $report    Generated report data.
     * @param    string    $format    Export format (pdf, html, csv, json).
     * @param    array     $options   Export-specific options.
     * @return   array               Export result with file path or data.
     */
    public function export_report($report, $format, $options = array()) {
        try {
            if (!isset($this->exporters[$format])) {
                throw new Exception("Unsupported export format: {$format}");
            }

            $exporter = $this->exporters[$format];
            $exported = $exporter->export($report, $options);

            // Log export
            $this->log_report_export($report, $format, $exported);

            return $exported;

        } catch (Exception $e) {
            error_log("WP-Breach Report Export Error: " . $e->getMessage());
            return array(
                'error' => true,
                'message' => $e->getMessage(),
                'format' => $format
            );
        }
    }

    /**
     * Apply template to report data.
     *
     * @since    1.0.0
     * @param    string    $type        Report type.
     * @param    array     $data        Report data.
     * @param    array     $charts      Generated charts.
     * @param    array     $config      Report configuration.
     * @return   array                 Rendered report sections.
     */
    public function apply_template($type, $data, $charts, $config) {
        $template_name = $this->report_types[$type]['template'];
        return $this->template_engine->render_report($template_name, $data, $charts, $config);
    }

    /**
     * Generate charts for the report.
     *
     * @since    1.0.0
     * @access   private
     * @param    string    $type      Report type.
     * @param    array     $data      Report data.
     * @param    array     $config    Report configuration.
     * @return   array               Generated charts.
     */
    private function generate_charts($type, $data, $config) {
        $chart_config = $config['charts'] ?? array();
        return $this->chart_generator->generate_charts_for_report($type, $data, $chart_config);
    }

    /**
     * Process data specifically for executive reports.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $data      Base aggregated data.
     * @param    array    $config    Report configuration.
     * @return   array              Processed executive data.
     */
    private function process_executive_data($data, $config) {
        return array(
            'security_score' => $this->data_aggregator->calculate_security_score($data),
            'risk_summary' => $this->data_aggregator->summarize_risks($data),
            'key_metrics' => $this->data_aggregator->extract_key_metrics($data),
            'top_recommendations' => $this->data_aggregator->get_top_recommendations($data, 5),
            'compliance_status' => $this->data_aggregator->assess_compliance($data),
            'trend_indicators' => $this->data_aggregator->get_trend_indicators($data)
        );
    }

    /**
     * Process data specifically for technical reports.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $data      Base aggregated data.
     * @param    array    $config    Report configuration.
     * @return   array              Processed technical data.
     */
    private function process_technical_data($data, $config) {
        return array(
            'vulnerability_details' => $this->data_aggregator->get_detailed_vulnerabilities($data),
            'affected_components' => $this->data_aggregator->analyze_affected_components($data),
            'fix_procedures' => $this->data_aggregator->generate_fix_procedures($data),
            'technical_metrics' => $this->data_aggregator->calculate_technical_metrics($data),
            'system_analysis' => $this->data_aggregator->analyze_system_state($data),
            'remediation_plan' => $this->data_aggregator->create_remediation_plan($data)
        );
    }

    /**
     * Process data specifically for compliance reports.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $data      Base aggregated data.
     * @param    array    $config    Report configuration.
     * @return   array              Processed compliance data.
     */
    private function process_compliance_data($data, $config) {
        $frameworks = $config['frameworks'] ?? array('owasp', 'nist');
        
        return array(
            'framework_assessment' => $this->data_aggregator->assess_frameworks($data, $frameworks),
            'control_effectiveness' => $this->data_aggregator->evaluate_controls($data, $frameworks),
            'compliance_gaps' => $this->data_aggregator->identify_compliance_gaps($data, $frameworks),
            'audit_trail' => $this->data_aggregator->generate_audit_trail($data),
            'recommendations' => $this->data_aggregator->get_compliance_recommendations($data, $frameworks)
        );
    }

    /**
     * Process data specifically for trend reports.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $data      Base aggregated data.
     * @param    array    $config    Report configuration.
     * @return   array              Processed trend data.
     */
    private function process_trend_data($data, $config) {
        $timeframe = $config['timeframe'] ?? '30d';
        
        return array(
            'historical_trends' => $this->data_aggregator->analyze_historical_trends($data, $timeframe),
            'security_progression' => $this->data_aggregator->track_security_progression($data, $timeframe),
            'vulnerability_patterns' => $this->data_aggregator->identify_vulnerability_patterns($data, $timeframe),
            'fix_effectiveness' => $this->data_aggregator->measure_fix_effectiveness($data, $timeframe),
            'predictions' => $this->data_aggregator->generate_predictions($data, $timeframe),
            'benchmarks' => $this->data_aggregator->compare_benchmarks($data)
        );
    }

    /**
     * Merge default configuration with provided config.
     *
     * @since    1.0.0
     * @access   private
     * @param    string    $type      Report type.
     * @param    array     $config    Provided configuration.
     * @return   array               Merged configuration.
     */
    private function merge_default_config($type, $config) {
        $defaults = array(
            'use_cache' => true,
            'cache_duration' => 3600, // 1 hour
            'include_charts' => true,
            'date_range' => array(
                'start' => date('Y-m-d', strtotime('-30 days')),
                'end' => date('Y-m-d')
            ),
            'filters' => array(),
            'charts' => array(
                'format' => 'svg',
                'dimensions' => array('width' => 800, 'height' => 400)
            ),
            'styling' => array(
                'theme' => 'default',
                'branding' => true
            )
        );

        return array_merge($defaults, $config);
    }

    /**
     * Generate cache key for report.
     *
     * @since    1.0.0
     * @access   private
     * @param    string    $type      Report type.
     * @param    array     $config    Report configuration.
     * @return   string              Cache key.
     */
    private function generate_cache_key($type, $config) {
        $key_data = array(
            'type' => $type,
            'filters' => $config['filters'],
            'date_range' => $config['date_range'],
            'version' => WP_BREACH_VERSION
        );
        
        return 'wp_breach_report_' . md5(serialize($key_data));
    }

    /**
     * Get cached report if available and valid.
     *
     * @since    1.0.0
     * @access   private
     * @param    string    $cache_key    Cache key.
     * @return   mixed                  Cached report or false.
     */
    private function get_cached_report($cache_key) {
        $cache_file = $this->cache_dir . $cache_key . '.cache';
        
        if (file_exists($cache_file)) {
            $cache_data = unserialize(file_get_contents($cache_file));
            
            if ($cache_data && isset($cache_data['expires']) && $cache_data['expires'] > time()) {
                return $cache_data['report'];
            }
        }
        
        return false;
    }

    /**
     * Cache generated report.
     *
     * @since    1.0.0
     * @access   private
     * @param    string    $cache_key    Cache key.
     * @param    array     $report       Generated report.
     */
    private function cache_report($cache_key, $report) {
        $cache_file = $this->cache_dir . $cache_key . '.cache';
        $cache_data = array(
            'report' => $report,
            'cached_at' => time(),
            'expires' => time() + $report['config']['cache_duration']
        );
        
        file_put_contents($cache_file, serialize($cache_data));
    }

    /**
     * Generate unique report ID.
     *
     * @since    1.0.0
     * @access   private
     * @return   string    Unique report identifier.
     */
    private function generate_report_id() {
        return 'wp_breach_report_' . uniqid() . '_' . time();
    }

    /**
     * Count data points in report data.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $data    Report data.
     * @return   int              Number of data points.
     */
    private function count_data_points($data) {
        $count = 0;
        
        if (isset($data['vulnerabilities'])) {
            $count += count($data['vulnerabilities']);
        }
        
        if (isset($data['scans'])) {
            $count += count($data['scans']);
        }
        
        return $count;
    }

    /**
     * Log report generation.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $report    Generated report.
     */
    private function log_report_generation($report) {
        $log_entry = array(
            'action' => 'report_generated',
            'report_id' => $report['id'],
            'report_type' => $report['type'],
            'user_id' => get_current_user_id(),
            'timestamp' => current_time('mysql'),
            'generation_time' => $report['metadata']['generation_time'],
            'data_points' => $report['metadata']['data_points']
        );

        do_action('wp_breach_report_generated', $log_entry);
    }

    /**
     * Log report export.
     *
     * @since    1.0.0
     * @access   private
     * @param    array     $report       Report data.
     * @param    string    $format       Export format.
     * @param    array     $exported     Export result.
     */
    private function log_report_export($report, $format, $exported) {
        $log_entry = array(
            'action' => 'report_exported',
            'report_id' => $report['id'],
            'format' => $format,
            'user_id' => get_current_user_id(),
            'timestamp' => current_time('mysql'),
            'success' => !isset($exported['error'])
        );

        do_action('wp_breach_report_exported', $log_entry);
    }

    /**
     * Get available report types.
     *
     * @since    1.0.0
     * @return   array    Available report types and their configurations.
     */
    public function get_report_types() {
        return $this->report_types;
    }

    /**
     * Get available export formats.
     *
     * @since    1.0.0
     * @return   array    Available export formats.
     */
    public function get_export_formats() {
        return array_keys($this->exporters);
    }

    /**
     * Clean up old cached reports.
     *
     * @since    1.0.0
     * @param    int    $max_age    Maximum age in seconds (default: 24 hours).
     */
    public function cleanup_cache($max_age = 86400) {
        $files = glob($this->cache_dir . '*.cache');
        $cutoff_time = time() - $max_age;
        
        foreach ($files as $file) {
            if (filemtime($file) < $cutoff_time) {
                unlink($file);
            }
        }
    }
}

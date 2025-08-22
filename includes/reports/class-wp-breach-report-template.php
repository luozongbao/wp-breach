<?php

/**
 * Report template engine.
 *
 * This class handles the template system for generating formatted security reports.
 * It manages template loading, rendering, and customization for different report types.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/reports
 */

/**
 * The report template class.
 *
 * Manages template loading, data injection, and rendering for security reports.
 * Supports multiple template formats and customization options.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/reports
 * @author     WP Breach Team
 */
class WP_Breach_Report_Template {

    /**
     * Template directory path.
     *
     * @since    1.0.0
     * @access   private
     * @var      string    $template_dir    Template directory path.
     */
    private $template_dir;

    /**
     * Loaded templates cache.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $template_cache    Cached template contents.
     */
    private $template_cache;

    /**
     * Template configuration.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $config    Template configuration options.
     */
    private $config;

    /**
     * Initialize the template engine.
     *
     * @since    1.0.0
     */
    public function __construct() {
        $this->template_dir = plugin_dir_path(__FILE__) . 'templates/';
        $this->template_cache = array();
        $this->setup_configuration();
    }

    /**
     * Setup template configuration.
     *
     * @since    1.0.0
     * @access   private
     */
    private function setup_configuration() {
        $this->config = array(
            'date_format' => get_option('date_format', 'Y-m-d'),
            'time_format' => get_option('time_format', 'H:i:s'),
            'timezone' => get_option('timezone_string', 'UTC'),
            'site_name' => get_bloginfo('name'),
            'site_url' => get_site_url(),
            'plugin_version' => WP_BREACH_VERSION,
            'branding' => array(
                'show_logo' => true,
                'show_plugin_info' => true,
                'custom_css' => ''
            )
        );
    }

    /**
     * Render a complete report using the specified template.
     *
     * @since    1.0.0
     * @param    string    $template_name    Template name.
     * @param    array     $data            Report data.
     * @param    array     $charts          Chart data.
     * @param    array     $config          Render configuration.
     * @return   array                     Rendered report sections.
     */
    public function render_report($template_name, $data, $charts, $config = array()) {
        try {
            $template = $this->load_template($template_name);
            
            if (!$template) {
                throw new Exception("Template not found: {$template_name}");
            }

            $render_config = array_merge($this->config, $config);
            $context = $this->build_template_context($data, $charts, $render_config);

            $rendered_sections = array();

            foreach ($template['sections'] as $section_name => $section_config) {
                $rendered_sections[$section_name] = $this->render_section(
                    $section_name,
                    $section_config,
                    $context,
                    $render_config
                );
            }

            return array(
                'template' => $template_name,
                'sections' => $rendered_sections,
                'metadata' => array(
                    'rendered_at' => current_time('mysql'),
                    'template_version' => $template['version'] ?? '1.0.0',
                    'render_time' => $this->calculate_render_time()
                )
            );

        } catch (Exception $e) {
            error_log("WP-Breach Template Render Error: " . $e->getMessage());
            return array(
                'error' => true,
                'message' => $e->getMessage(),
                'template' => $template_name
            );
        }
    }

    /**
     * Load a template configuration.
     *
     * @since    1.0.0
     * @param    string    $template_name    Template name.
     * @return   mixed                      Template configuration or false.
     */
    public function load_template($template_name) {
        if (isset($this->template_cache[$template_name])) {
            return $this->template_cache[$template_name];
        }

        $template_file = $this->template_dir . $template_name . '.php';
        
        if (!file_exists($template_file)) {
            return false;
        }

        ob_start();
        $template_config = include $template_file;
        ob_end_clean();

        if (!is_array($template_config)) {
            return false;
        }

        $this->template_cache[$template_name] = $template_config;
        return $template_config;
    }

    /**
     * Render a specific report section.
     *
     * @since    1.0.0
     * @param    string    $section_name      Section name.
     * @param    array     $section_config    Section configuration.
     * @param    array     $context          Template context.
     * @param    array     $render_config    Render configuration.
     * @return   array                       Rendered section.
     */
    public function render_section($section_name, $section_config, $context, $render_config) {
        $section_data = array(
            'name' => $section_name,
            'title' => $section_config['title'] ?? ucwords(str_replace('_', ' ', $section_name)),
            'content' => '',
            'html' => '',
            'data' => array()
        );

        // Render section content based on type
        switch ($section_config['type']) {
            case 'overview':
                $section_data = $this->render_overview_section($section_data, $context, $render_config);
                break;
            case 'metrics':
                $section_data = $this->render_metrics_section($section_data, $context, $render_config);
                break;
            case 'vulnerabilities':
                $section_data = $this->render_vulnerabilities_section($section_data, $context, $render_config);
                break;
            case 'charts':
                $section_data = $this->render_charts_section($section_data, $context, $render_config);
                break;
            case 'recommendations':
                $section_data = $this->render_recommendations_section($section_data, $context, $render_config);
                break;
            case 'compliance':
                $section_data = $this->render_compliance_section($section_data, $context, $render_config);
                break;
            case 'trends':
                $section_data = $this->render_trends_section($section_data, $context, $render_config);
                break;
            default:
                $section_data = $this->render_custom_section($section_data, $section_config, $context, $render_config);
        }

        return $section_data;
    }

    /**
     * Apply format-specific styling.
     *
     * @since    1.0.0
     * @param    string    $format       Output format (html, pdf, etc.).
     * @param    array     $content      Content to style.
     * @param    array     $options      Styling options.
     * @return   array                  Styled content.
     */
    public function apply_styling($format, $content, $options = array()) {
        switch ($format) {
            case 'html':
                return $this->apply_html_styling($content, $options);
            case 'pdf':
                return $this->apply_pdf_styling($content, $options);
            case 'email':
                return $this->apply_email_styling($content, $options);
            default:
                return $content;
        }
    }

    /**
     * Build template context from data and configuration.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $data            Report data.
     * @param    array    $charts          Chart data.
     * @param    array    $render_config   Render configuration.
     * @return   array                    Template context.
     */
    private function build_template_context($data, $charts, $render_config) {
        return array(
            'data' => $data,
            'charts' => $charts,
            'config' => $render_config,
            'helpers' => array(
                'format_date' => array($this, 'format_date'),
                'format_number' => array($this, 'format_number'),
                'format_percentage' => array($this, 'format_percentage'),
                'severity_badge' => array($this, 'render_severity_badge'),
                'status_badge' => array($this, 'render_status_badge'),
                'truncate_text' => array($this, 'truncate_text')
            ),
            'site' => array(
                'name' => $this->config['site_name'],
                'url' => $this->config['site_url'],
                'timezone' => $this->config['timezone']
            ),
            'report' => array(
                'generated_at' => current_time('mysql'),
                'version' => $this->config['plugin_version']
            )
        );
    }

    /**
     * Render overview section.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $section_data      Section data.
     * @param    array    $context          Template context.
     * @param    array    $render_config    Render configuration.
     * @return   array                      Rendered section.
     */
    private function render_overview_section($section_data, $context, $render_config) {
        $data = $context['data'];
        
        $overview_content = array(
            'summary' => $data['summary'] ?? array(),
            'security_score' => $data['security_score'] ?? null,
            'risk_summary' => $data['risk_summary'] ?? null,
            'scan_info' => array(
                'total_scans' => count($data['scans'] ?? array()),
                'last_scan' => $this->get_last_scan_info($data['scans'] ?? array()),
                'scan_coverage' => $this->calculate_scan_coverage($data)
            )
        );

        $section_data['data'] = $overview_content;
        $section_data['html'] = $this->render_overview_html($overview_content, $render_config);
        $section_data['content'] = $this->render_overview_text($overview_content);

        return $section_data;
    }

    /**
     * Render metrics section.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $section_data      Section data.
     * @param    array    $context          Template context.
     * @param    array    $render_config    Render configuration.
     * @return   array                      Rendered section.
     */
    private function render_metrics_section($section_data, $context, $render_config) {
        $data = $context['data'];
        $metrics = $data['key_metrics'] ?? array();

        $metrics_content = array(
            'primary_metrics' => $this->extract_primary_metrics($metrics),
            'secondary_metrics' => $this->extract_secondary_metrics($metrics),
            'comparison_data' => $this->get_comparison_metrics($data),
            'trend_data' => $data['trend_indicators'] ?? array()
        );

        $section_data['data'] = $metrics_content;
        $section_data['html'] = $this->render_metrics_html($metrics_content, $render_config);
        $section_data['content'] = $this->render_metrics_text($metrics_content);

        return $section_data;
    }

    /**
     * Render vulnerabilities section.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $section_data      Section data.
     * @param    array    $context          Template context.
     * @param    array    $render_config    Render configuration.
     * @return   array                      Rendered section.
     */
    private function render_vulnerabilities_section($section_data, $context, $render_config) {
        $vulnerabilities = $context['data']['vulnerabilities'] ?? array();
        
        $vuln_content = array(
            'total_count' => count($vulnerabilities),
            'by_severity' => $this->group_vulnerabilities_by_severity($vulnerabilities),
            'by_component' => $this->group_vulnerabilities_by_component($vulnerabilities),
            'by_status' => $this->group_vulnerabilities_by_status($vulnerabilities),
            'recent_vulnerabilities' => $this->get_recent_vulnerabilities($vulnerabilities, 10),
            'critical_vulnerabilities' => $this->get_critical_vulnerabilities($vulnerabilities)
        );

        $section_data['data'] = $vuln_content;
        $section_data['html'] = $this->render_vulnerabilities_html($vuln_content, $render_config);
        $section_data['content'] = $this->render_vulnerabilities_text($vuln_content);

        return $section_data;
    }

    /**
     * Render charts section.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $section_data      Section data.
     * @param    array    $context          Template context.
     * @param    array    $render_config    Render configuration.
     * @return   array                      Rendered section.
     */
    private function render_charts_section($section_data, $context, $render_config) {
        $charts = $context['charts'] ?? array();
        
        $chart_content = array(
            'charts' => $charts,
            'chart_count' => count($charts),
            'chart_urls' => $this->generate_chart_urls($charts),
            'chart_descriptions' => $this->generate_chart_descriptions($charts)
        );

        $section_data['data'] = $chart_content;
        $section_data['html'] = $this->render_charts_html($chart_content, $render_config);
        $section_data['content'] = $this->render_charts_text($chart_content);

        return $section_data;
    }

    /**
     * Render recommendations section.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $section_data      Section data.
     * @param    array    $context          Template context.
     * @param    array    $render_config    Render configuration.
     * @return   array                      Rendered section.
     */
    private function render_recommendations_section($section_data, $context, $render_config) {
        $recommendations = $context['data']['top_recommendations'] ?? array();
        
        $rec_content = array(
            'recommendations' => $recommendations,
            'count' => count($recommendations),
            'by_priority' => $this->group_recommendations_by_priority($recommendations),
            'actionable_items' => $this->extract_actionable_items($recommendations)
        );

        $section_data['data'] = $rec_content;
        $section_data['html'] = $this->render_recommendations_html($rec_content, $render_config);
        $section_data['content'] = $this->render_recommendations_text($rec_content);

        return $section_data;
    }

    /**
     * Format date using configured format.
     *
     * @since    1.0.0
     * @param    string    $date    Date string.
     * @return   string           Formatted date.
     */
    public function format_date($date) {
        if (empty($date)) {
            return 'N/A';
        }
        
        $timestamp = strtotime($date);
        return date($this->config['date_format'] . ' ' . $this->config['time_format'], $timestamp);
    }

    /**
     * Format number with thousands separators.
     *
     * @since    1.0.0
     * @param    mixed    $number    Number to format.
     * @return   string             Formatted number.
     */
    public function format_number($number) {
        if (!is_numeric($number)) {
            return 'N/A';
        }
        
        return number_format($number);
    }

    /**
     * Format percentage with symbol.
     *
     * @since    1.0.0
     * @param    mixed    $value      Value to format as percentage.
     * @param    int      $decimals   Decimal places.
     * @return   string              Formatted percentage.
     */
    public function format_percentage($value, $decimals = 1) {
        if (!is_numeric($value)) {
            return 'N/A';
        }
        
        return number_format($value, $decimals) . '%';
    }

    /**
     * Render severity badge HTML.
     *
     * @since    1.0.0
     * @param    string    $severity    Severity level.
     * @return   string                Severity badge HTML.
     */
    public function render_severity_badge($severity) {
        $severity = strtolower($severity);
        $colors = array(
            'critical' => '#dc3545',
            'high' => '#fd7e14',
            'medium' => '#ffc107',
            'low' => '#28a745'
        );
        
        $color = $colors[$severity] ?? '#6c757d';
        
        return sprintf(
            '<span class="severity-badge severity-%s" style="background-color: %s; color: white; padding: 2px 8px; border-radius: 4px; font-size: 12px;">%s</span>',
            $severity,
            $color,
            ucfirst($severity)
        );
    }

    /**
     * Render status badge HTML.
     *
     * @since    1.0.0
     * @param    string    $status    Status value.
     * @return   string              Status badge HTML.
     */
    public function render_status_badge($status) {
        $status = strtolower($status);
        $colors = array(
            'open' => '#dc3545',
            'fixed' => '#28a745',
            'ignored' => '#6c757d',
            'false_positive' => '#17a2b8'
        );
        
        $color = $colors[$status] ?? '#6c757d';
        
        return sprintf(
            '<span class="status-badge status-%s" style="background-color: %s; color: white; padding: 2px 8px; border-radius: 4px; font-size: 12px;">%s</span>',
            $status,
            $color,
            ucwords(str_replace('_', ' ', $status))
        );
    }

    /**
     * Truncate text to specified length.
     *
     * @since    1.0.0
     * @param    string    $text      Text to truncate.
     * @param    int       $length    Maximum length.
     * @param    string    $append    Append string for truncated text.
     * @return   string              Truncated text.
     */
    public function truncate_text($text, $length = 100, $append = '...') {
        if (strlen($text) <= $length) {
            return $text;
        }
        
        return substr($text, 0, $length) . $append;
    }

    // Additional helper methods for rendering different types of content...
    
    /**
     * Render overview HTML content.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $content          Overview content.
     * @param    array    $render_config    Render configuration.
     * @return   string                    HTML content.
     */
    private function render_overview_html($content, $render_config) {
        ob_start();
        ?>
        <div class="overview-section">
            <h2>Security Overview</h2>
            
            <?php if (isset($content['security_score'])): ?>
            <div class="security-score">
                <h3>Overall Security Score</h3>
                <div class="score-display">
                    <span class="score-number"><?php echo $content['security_score']['score']; ?></span>
                    <span class="score-grade"><?php echo $content['security_score']['grade']; ?></span>
                    <span class="score-status"><?php echo ucfirst($content['security_score']['status']); ?></span>
                </div>
            </div>
            <?php endif; ?>
            
            <?php if (isset($content['risk_summary'])): ?>
            <div class="risk-summary">
                <h3>Risk Distribution</h3>
                <div class="risk-counts">
                    <?php foreach ($content['risk_summary']['counts'] as $level => $count): ?>
                        <div class="risk-item">
                            <?php echo $this->render_severity_badge($level); ?>
                            <span class="count"><?php echo $count; ?></span>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>
            <?php endif; ?>
            
            <div class="scan-info">
                <h3>Scan Information</h3>
                <p>Total Scans: <?php echo $content['scan_info']['total_scans']; ?></p>
                <?php if ($content['scan_info']['last_scan']): ?>
                    <p>Last Scan: <?php echo $this->format_date($content['scan_info']['last_scan']['completed_at']); ?></p>
                <?php endif; ?>
            </div>
        </div>
        <?php
        return ob_get_clean();
    }

    /**
     * Get information about the last scan.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $scans    Scan data array.
     * @return   mixed             Last scan info or null.
     */
    private function get_last_scan_info($scans) {
        if (empty($scans)) {
            return null;
        }
        
        usort($scans, function($a, $b) {
            return strtotime($b['completed_at']) - strtotime($a['completed_at']);
        });
        
        return $scans[0];
    }

    // Additional helper methods would continue here...
}

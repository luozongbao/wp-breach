<?php

/**
 * Chart and visualization generator for security reports.
 *
 * This class handles the generation of charts, graphs, and other visualizations
 * for security reports using various charting libraries and output formats.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/reports
 */

/**
 * The chart generator class.
 *
 * Generates charts and visualizations for security data including trend lines,
 * pie charts, bar charts, and heat maps in various formats (SVG, PNG, HTML).
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/reports
 * @author     WP Breach Team
 */
class WP_Breach_Chart_Generator {

    /**
     * Chart configuration defaults.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $default_config    Default chart configuration.
     */
    private $default_config;

    /**
     * Chart cache directory.
     *
     * @since    1.0.0
     * @access   private
     * @var      string    $cache_dir    Directory for caching generated charts.
     */
    private $cache_dir;

    /**
     * Supported chart types.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $chart_types    Supported chart types and configurations.
     */
    private $chart_types;

    /**
     * Color palettes for different themes.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $color_palettes    Color schemes for charts.
     */
    private $color_palettes;

    /**
     * Initialize the chart generator.
     *
     * @since    1.0.0
     */
    public function __construct() {
        $this->setup_default_config();
        $this->setup_cache_directory();
        $this->setup_chart_types();
        $this->setup_color_palettes();
    }

    /**
     * Setup default chart configuration.
     *
     * @since    1.0.0
     * @access   private
     */
    private function setup_default_config() {
        $this->default_config = array(
            'width' => 800,
            'height' => 400,
            'format' => 'svg',
            'theme' => 'default',
            'responsive' => true,
            'animation' => true,
            'legend' => array(
                'show' => true,
                'position' => 'right'
            ),
            'grid' => array(
                'show' => true,
                'color' => '#e0e0e0'
            ),
            'font' => array(
                'family' => 'Arial, sans-serif',
                'size' => 12,
                'color' => '#333333'
            )
        );
    }

    /**
     * Setup cache directory for generated charts.
     *
     * @since    1.0.0
     * @access   private
     */
    private function setup_cache_directory() {
        $upload_dir = wp_upload_dir();
        $this->cache_dir = $upload_dir['basedir'] . '/wp-breach-charts/';

        if (!file_exists($this->cache_dir)) {
            wp_mkdir_p($this->cache_dir);
        }
    }

    /**
     * Setup supported chart types.
     *
     * @since    1.0.0
     * @access   private
     */
    private function setup_chart_types() {
        $this->chart_types = array(
            'pie' => array(
                'name' => 'Pie Chart',
                'best_for' => 'Distribution data',
                'max_categories' => 8
            ),
            'doughnut' => array(
                'name' => 'Doughnut Chart',
                'best_for' => 'Distribution with center space',
                'max_categories' => 8
            ),
            'bar' => array(
                'name' => 'Bar Chart',
                'best_for' => 'Categorical comparisons',
                'max_categories' => 20
            ),
            'line' => array(
                'name' => 'Line Chart',
                'best_for' => 'Trends over time',
                'max_data_points' => 100
            ),
            'area' => array(
                'name' => 'Area Chart',
                'best_for' => 'Volume trends over time',
                'max_data_points' => 100
            ),
            'scatter' => array(
                'name' => 'Scatter Plot',
                'best_for' => 'Correlation analysis',
                'max_data_points' => 500
            ),
            'heatmap' => array(
                'name' => 'Heat Map',
                'best_for' => 'Matrix data visualization',
                'max_cells' => 1000
            )
        );
    }

    /**
     * Setup color palettes.
     *
     * @since    1.0.0
     * @access   private
     */
    private function setup_color_palettes() {
        $this->color_palettes = array(
            'security' => array(
                'critical' => '#dc3545',
                'high' => '#fd7e14',
                'medium' => '#ffc107',
                'low' => '#28a745',
                'info' => '#17a2b8',
                'success' => '#28a745',
                'warning' => '#ffc107',
                'danger' => '#dc3545'
            ),
            'default' => array(
                '#007cba', '#00a0d2', '#0073aa', '#005177',
                '#32373c', '#464646', '#606060', '#78909c'
            ),
            'grayscale' => array(
                '#212529', '#495057', '#6c757d', '#adb5bd',
                '#ced4da', '#dee2e6', '#e9ecef', '#f8f9fa'
            ),
            'colorful' => array(
                '#ff6384', '#36a2eb', '#ffce56', '#4bc0c0',
                '#9966ff', '#ff9f40', '#ff6384', '#c9cbcf'
            )
        );
    }

    /**
     * Generate charts for a specific report type.
     *
     * @since    1.0.0
     * @param    string    $report_type    Report type.
     * @param    array     $data          Report data.
     * @param    array     $config        Chart configuration.
     * @return   array                   Generated charts.
     */
    public function generate_charts_for_report($report_type, $data, $config = array()) {
        $charts = array();
        $chart_config = array_merge($this->default_config, $config);

        switch ($report_type) {
            case 'executive':
                $charts = $this->generate_executive_charts($data, $chart_config);
                break;
            case 'technical':
                $charts = $this->generate_technical_charts($data, $chart_config);
                break;
            case 'compliance':
                $charts = $this->generate_compliance_charts($data, $chart_config);
                break;
            case 'trend':
                $charts = $this->generate_trend_charts($data, $chart_config);
                break;
        }

        return $charts;
    }

    /**
     * Generate a specific chart.
     *
     * @since    1.0.0
     * @param    string    $type        Chart type.
     * @param    array     $data        Chart data.
     * @param    array     $config      Chart configuration.
     * @return   array                 Generated chart information.
     */
    public function generate_chart($type, $data, $config = array()) {
        try {
            $chart_config = array_merge($this->default_config, $config);
            
            // Validate chart type
            if (!isset($this->chart_types[$type])) {
                throw new Exception("Unsupported chart type: {$type}");
            }

            // Generate chart based on format
            switch ($chart_config['format']) {
                case 'svg':
                    return $this->generate_svg_chart($type, $data, $chart_config);
                case 'png':
                    return $this->generate_png_chart($type, $data, $chart_config);
                case 'html':
                    return $this->generate_html_chart($type, $data, $chart_config);
                case 'json':
                    return $this->generate_chart_js_config($type, $data, $chart_config);
                default:
                    throw new Exception("Unsupported chart format: {$chart_config['format']}");
            }

        } catch (Exception $e) {
            error_log("WP-Breach Chart Generation Error: " . $e->getMessage());
            return array(
                'error' => true,
                'message' => $e->getMessage(),
                'type' => $type
            );
        }
    }

    /**
     * Generate charts for executive reports.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $data      Report data.
     * @param    array    $config    Chart configuration.
     * @return   array              Generated charts.
     */
    private function generate_executive_charts($data, $config) {
        $charts = array();

        // Security Score Gauge
        if (isset($data['security_score'])) {
            $charts['security_score_gauge'] = $this->generate_gauge_chart(
                $data['security_score']['score'],
                array_merge($config, array(
                    'title' => 'Overall Security Score',
                    'min' => 0,
                    'max' => 100,
                    'thresholds' => array(
                        array('min' => 0, 'max' => 60, 'color' => '#dc3545'),
                        array('min' => 60, 'max' => 80, 'color' => '#ffc107'),
                        array('min' => 80, 'max' => 100, 'color' => '#28a745')
                    )
                ))
            );
        }

        // Risk Distribution Pie Chart
        if (isset($data['risk_summary']['counts'])) {
            $pie_data = array();
            foreach ($data['risk_summary']['counts'] as $level => $count) {
                if ($count > 0) {
                    $pie_data[] = array(
                        'label' => ucfirst($level),
                        'value' => $count,
                        'color' => $this->color_palettes['security'][$level]
                    );
                }
            }

            if (!empty($pie_data)) {
                $charts['risk_distribution'] = $this->generate_chart('pie', $pie_data, array_merge($config, array(
                    'title' => 'Risk Distribution',
                    'height' => 300
                )));
            }
        }

        // Key Metrics Bar Chart
        if (isset($data['key_metrics'])) {
            $metrics_data = array();
            $metrics = $data['key_metrics'];
            
            if (isset($metrics['total_vulnerabilities'])) {
                $metrics_data[] = array('label' => 'Total Vulnerabilities', 'value' => $metrics['total_vulnerabilities']);
            }
            if (isset($metrics['vulnerabilities_fixed'])) {
                $metrics_data[] = array('label' => 'Fixed', 'value' => $metrics['vulnerabilities_fixed']);
            }
            if (isset($metrics['total_scans'])) {
                $metrics_data[] = array('label' => 'Total Scans', 'value' => $metrics['total_scans']);
            }

            if (!empty($metrics_data)) {
                $charts['key_metrics'] = $this->generate_chart('bar', $metrics_data, array_merge($config, array(
                    'title' => 'Key Security Metrics',
                    'orientation' => 'horizontal'
                )));
            }
        }

        return $charts;
    }

    /**
     * Generate charts for technical reports.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $data      Report data.
     * @param    array    $config    Chart configuration.
     * @return   array              Generated charts.
     */
    private function generate_technical_charts($data, $config) {
        $charts = array();

        // Vulnerability Timeline
        if (isset($data['vulnerabilities'])) {
            $timeline_data = $this->prepare_vulnerability_timeline_data($data['vulnerabilities']);
            if (!empty($timeline_data)) {
                $charts['vulnerability_timeline'] = $this->generate_chart('line', $timeline_data, array_merge($config, array(
                    'title' => 'Vulnerability Detection Timeline',
                    'x_axis_title' => 'Date',
                    'y_axis_title' => 'Number of Vulnerabilities'
                )));
            }
        }

        // Component Analysis
        if (isset($data['affected_components'])) {
            $component_data = array();
            foreach ($data['affected_components']['top_affected'] as $component) {
                $component_data[] = array(
                    'label' => $component['name'],
                    'value' => $component['vulnerability_count']
                );
            }

            if (!empty($component_data)) {
                $charts['component_analysis'] = $this->generate_chart('bar', $component_data, array_merge($config, array(
                    'title' => 'Most Affected Components',
                    'orientation' => 'horizontal'
                )));
            }
        }

        // Severity Distribution by Component Type
        if (isset($data['vulnerabilities'])) {
            $severity_by_component = $this->analyze_severity_by_component($data['vulnerabilities']);
            if (!empty($severity_by_component)) {
                $charts['severity_by_component'] = $this->generate_stacked_bar_chart($severity_by_component, array_merge($config, array(
                    'title' => 'Vulnerability Severity by Component Type'
                )));
            }
        }

        return $charts;
    }

    /**
     * Generate charts for compliance reports.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $data      Report data.
     * @param    array    $config    Chart configuration.
     * @return   array              Generated charts.
     */
    private function generate_compliance_charts($data, $config) {
        $charts = array();

        // Framework Compliance Radar Chart
        if (isset($data['framework_assessment'])) {
            $compliance_data = array();
            foreach ($data['framework_assessment'] as $framework => $assessment) {
                $compliance_data[] = array(
                    'label' => strtoupper($framework),
                    'value' => $assessment['score']
                );
            }

            if (!empty($compliance_data)) {
                $charts['framework_compliance'] = $this->generate_radar_chart($compliance_data, array_merge($config, array(
                    'title' => 'Framework Compliance Scores'
                )));
            }
        }

        // Control Effectiveness Heatmap
        if (isset($data['control_effectiveness'])) {
            $heatmap_data = $this->prepare_control_effectiveness_heatmap($data['control_effectiveness']);
            if (!empty($heatmap_data)) {
                $charts['control_effectiveness'] = $this->generate_chart('heatmap', $heatmap_data, array_merge($config, array(
                    'title' => 'Security Control Effectiveness'
                )));
            }
        }

        return $charts;
    }

    /**
     * Generate charts for trend reports.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $data      Report data.
     * @param    array    $config    Chart configuration.
     * @return   array              Generated charts.
     */
    private function generate_trend_charts($data, $config) {
        $charts = array();

        // Security Score Trend
        if (isset($data['security_progression'])) {
            $trend_data = $this->prepare_security_score_trend_data($data['security_progression']);
            if (!empty($trend_data)) {
                $charts['security_score_trend'] = $this->generate_chart('line', $trend_data, array_merge($config, array(
                    'title' => 'Security Score Progression',
                    'x_axis_title' => 'Date',
                    'y_axis_title' => 'Security Score'
                )));
            }
        }

        // Vulnerability Discovery vs Fix Rate
        if (isset($data['fix_effectiveness'])) {
            $discovery_fix_data = $this->prepare_discovery_fix_data($data['fix_effectiveness']);
            if (!empty($discovery_fix_data)) {
                $charts['discovery_vs_fix'] = $this->generate_multi_line_chart($discovery_fix_data, array_merge($config, array(
                    'title' => 'Vulnerability Discovery vs Fix Rate'
                )));
            }
        }

        // Prediction Chart
        if (isset($data['predictions'])) {
            $prediction_data = $this->prepare_prediction_data($data['predictions']);
            if (!empty($prediction_data)) {
                $charts['predictions'] = $this->generate_prediction_chart($prediction_data, array_merge($config, array(
                    'title' => 'Security Trend Predictions'
                )));
            }
        }

        return $charts;
    }

    /**
     * Generate SVG chart.
     *
     * @since    1.0.0
     * @access   private
     * @param    string    $type      Chart type.
     * @param    array     $data      Chart data.
     * @param    array     $config    Chart configuration.
     * @return   array               SVG chart information.
     */
    private function generate_svg_chart($type, $data, $config) {
        $svg_content = $this->create_svg_chart($type, $data, $config);
        $filename = $this->generate_chart_filename($type, $data, 'svg');
        $file_path = $this->cache_dir . $filename;
        
        file_put_contents($file_path, $svg_content);
        
        return array(
            'type' => $type,
            'format' => 'svg',
            'file_path' => $file_path,
            'url' => wp_upload_dir()['baseurl'] . '/wp-breach-charts/' . $filename,
            'content' => $svg_content,
            'width' => $config['width'],
            'height' => $config['height']
        );
    }

    /**
     * Generate Chart.js configuration.
     *
     * @since    1.0.0
     * @access   private
     * @param    string    $type      Chart type.
     * @param    array     $data      Chart data.
     * @param    array     $config    Chart configuration.
     * @return   array               Chart.js configuration.
     */
    private function generate_chart_js_config($type, $data, $config) {
        $chart_config = array(
            'type' => $this->map_chart_type_to_chartjs($type),
            'data' => $this->format_data_for_chartjs($data, $config),
            'options' => $this->generate_chartjs_options($config)
        );

        return array(
            'type' => $type,
            'format' => 'chartjs',
            'config' => $chart_config,
            'html_id' => 'wp-breach-chart-' . uniqid(),
            'width' => $config['width'],
            'height' => $config['height']
        );
    }

    /**
     * Create SVG chart content.
     *
     * @since    1.0.0
     * @access   private
     * @param    string    $type      Chart type.
     * @param    array     $data      Chart data.
     * @param    array     $config    Chart configuration.
     * @return   string              SVG content.
     */
    private function create_svg_chart($type, $data, $config) {
        switch ($type) {
            case 'pie':
                return $this->create_svg_pie_chart($data, $config);
            case 'bar':
                return $this->create_svg_bar_chart($data, $config);
            case 'line':
                return $this->create_svg_line_chart($data, $config);
            default:
                return $this->create_svg_placeholder($config);
        }
    }

    /**
     * Create SVG pie chart.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $data      Chart data.
     * @param    array    $config    Chart configuration.
     * @return   string             SVG content.
     */
    private function create_svg_pie_chart($data, $config) {
        $width = $config['width'];
        $height = $config['height'];
        $center_x = $width / 2;
        $center_y = $height / 2;
        $radius = min($width, $height) / 2 - 20;
        
        $total = array_sum(array_column($data, 'value'));
        $current_angle = -90; // Start at top
        
        $svg = sprintf('<svg width="%d" height="%d" xmlns="http://www.w3.org/2000/svg">', $width, $height);
        
        // Add title if provided
        if (isset($config['title'])) {
            $svg .= sprintf('<text x="%d" y="20" text-anchor="middle" font-family="%s" font-size="16" fill="%s">%s</text>',
                $center_x, $config['font']['family'], $config['font']['color'], $config['title']);
        }
        
        foreach ($data as $index => $item) {
            $percentage = ($item['value'] / $total) * 100;
            $angle = ($item['value'] / $total) * 360;
            
            $start_angle = deg2rad($current_angle);
            $end_angle = deg2rad($current_angle + $angle);
            
            $x1 = $center_x + $radius * cos($start_angle);
            $y1 = $center_y + $radius * sin($start_angle);
            $x2 = $center_x + $radius * cos($end_angle);
            $y2 = $center_y + $radius * sin($end_angle);
            
            $large_arc = $angle > 180 ? 1 : 0;
            $color = $item['color'] ?? $this->color_palettes['default'][$index % count($this->color_palettes['default'])];
            
            $path = sprintf('M %f %f A %f %f 0 %d 1 %f %f L %f %f Z',
                $x1, $y1, $radius, $radius, $large_arc, $x2, $y2, $center_x, $center_y);
            
            $svg .= sprintf('<path d="%s" fill="%s" stroke="white" stroke-width="2" />', $path, $color);
            
            $current_angle += $angle;
        }
        
        $svg .= '</svg>';
        return $svg;
    }

    /**
     * Generate unique filename for chart.
     *
     * @since    1.0.0
     * @access   private
     * @param    string    $type        Chart type.
     * @param    array     $data        Chart data.
     * @param    string    $extension   File extension.
     * @return   string                Filename.
     */
    private function generate_chart_filename($type, $data, $extension) {
        $hash = md5(serialize($data) . $type . time());
        return sprintf('chart_%s_%s.%s', $type, substr($hash, 0, 8), $extension);
    }

    /**
     * Map internal chart type to Chart.js type.
     *
     * @since    1.0.0
     * @access   private
     * @param    string    $type    Internal chart type.
     * @return   string            Chart.js type.
     */
    private function map_chart_type_to_chartjs($type) {
        $mapping = array(
            'pie' => 'pie',
            'doughnut' => 'doughnut',
            'bar' => 'bar',
            'line' => 'line',
            'area' => 'line',
            'scatter' => 'scatter'
        );
        
        return $mapping[$type] ?? 'bar';
    }

    /**
     * Format data for Chart.js.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $data      Chart data.
     * @param    array    $config    Chart configuration.
     * @return   array              Formatted data for Chart.js.
     */
    private function format_data_for_chartjs($data, $config) {
        $labels = array();
        $values = array();
        $colors = array();
        
        foreach ($data as $index => $item) {
            $labels[] = $item['label'];
            $values[] = $item['value'];
            $colors[] = $item['color'] ?? $this->color_palettes['default'][$index % count($this->color_palettes['default'])];
        }
        
        return array(
            'labels' => $labels,
            'datasets' => array(
                array(
                    'data' => $values,
                    'backgroundColor' => $colors,
                    'borderColor' => $colors,
                    'borderWidth' => 1
                )
            )
        );
    }

    /**
     * Generate Chart.js options.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $config    Chart configuration.
     * @return   array              Chart.js options.
     */
    private function generate_chartjs_options($config) {
        $options = array(
            'responsive' => $config['responsive'],
            'plugins' => array(
                'legend' => array(
                    'display' => $config['legend']['show'],
                    'position' => $config['legend']['position']
                )
            )
        );
        
        if (isset($config['title'])) {
            $options['plugins']['title'] = array(
                'display' => true,
                'text' => $config['title']
            );
        }
        
        return $options;
    }

    // Additional helper methods for data preparation and chart generation...
}

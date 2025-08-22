<?php

/**
 * HTML report exporter.
 *
 * This class handles the export of security reports to interactive HTML format
 * with responsive design, interactive charts, and filtering capabilities.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/reports/exporters
 */

/**
 * The HTML exporter class.
 *
 * Converts security reports to interactive HTML documents with responsive
 * design, Chart.js integration, and modern web features.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/reports/exporters
 * @author     WP Breach Team
 */
class WP_Breach_HTML_Exporter {

    /**
     * HTML template structure.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $template_structure    HTML template configuration.
     */
    private $template_structure;

    /**
     * JavaScript dependencies.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $js_dependencies    Required JavaScript libraries.
     */
    private $js_dependencies;

    /**
     * CSS styling configuration.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $css_config    CSS styling options.
     */
    private $css_config;

    /**
     * Initialize the HTML exporter.
     *
     * @since    1.0.0
     */
    public function __construct() {
        $this->setup_template_structure();
        $this->setup_js_dependencies();
        $this->setup_css_config();
    }

    /**
     * Setup HTML template structure.
     *
     * @since    1.0.0
     * @access   private
     */
    private function setup_template_structure() {
        $this->template_structure = array(
            'header' => array(
                'title' => true,
                'navigation' => true,
                'search' => true,
                'filters' => true
            ),
            'sidebar' => array(
                'enabled' => true,
                'table_of_contents' => true,
                'quick_stats' => true,
                'export_options' => true
            ),
            'main_content' => array(
                'sections' => true,
                'charts' => true,
                'tables' => true,
                'expandable_details' => true
            ),
            'footer' => array(
                'enabled' => true,
                'generation_info' => true,
                'plugin_info' => true
            )
        );
    }

    /**
     * Setup JavaScript dependencies.
     *
     * @since    1.0.0
     * @access   private
     */
    private function setup_js_dependencies() {
        $this->js_dependencies = array(
            'chart_js' => array(
                'url' => 'https://cdn.jsdelivr.net/npm/chart.js',
                'version' => '3.9.1',
                'required' => true
            ),
            'bootstrap' => array(
                'url' => 'https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js',
                'version' => '5.1.3',
                'required' => false
            ),
            'datatables' => array(
                'url' => 'https://cdn.datatables.net/1.12.1/js/jquery.dataTables.min.js',
                'version' => '1.12.1',
                'required' => false
            )
        );
    }

    /**
     * Setup CSS configuration.
     *
     * @since    1.0.0
     * @access   private
     */
    private function setup_css_config() {
        $this->css_config = array(
            'framework' => 'bootstrap', // or 'custom'
            'responsive' => true,
            'dark_mode' => false,
            'print_styles' => true,
            'custom_themes' => array(
                'default' => array(
                    'primary' => '#007cba',
                    'secondary' => '#0073aa',
                    'success' => '#28a745',
                    'warning' => '#ffc107',
                    'danger' => '#dc3545',
                    'info' => '#17a2b8'
                )
            )
        );
    }

    /**
     * Export report to HTML format.
     *
     * @since    1.0.0
     * @param    array    $report     Report data.
     * @param    array    $options    Export options.
     * @return   array               Export result.
     */
    public function export($report, $options = array()) {
        try {
            $export_options = array_merge(array(
                'standalone' => true,
                'responsive' => true,
                'interactive' => true,
                'include_charts' => true,
                'include_filters' => true,
                'theme' => 'default'
            ), $options);

            // Generate HTML content
            $html_content = $this->generate_html_report($report, $export_options);
            
            // Save to file
            $filename = $this->generate_html_filename($report);
            $upload_dir = wp_upload_dir();
            $file_path = $upload_dir['basedir'] . '/wp-breach-reports/' . $filename;
            
            // Create directory if it doesn't exist
            wp_mkdir_p(dirname($file_path));
            
            // Write HTML file
            file_put_contents($file_path, $html_content);

            return array(
                'success' => true,
                'file_path' => $file_path,
                'url' => $upload_dir['baseurl'] . '/wp-breach-reports/' . $filename,
                'filename' => $filename,
                'size' => filesize($file_path),
                'format' => 'html',
                'interactive' => $export_options['interactive']
            );

        } catch (Exception $e) {
            error_log("WP-Breach HTML Export Error: " . $e->getMessage());
            return array(
                'error' => true,
                'message' => $e->getMessage()
            );
        }
    }

    /**
     * Generate complete HTML report.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $report     Report data.
     * @param    array    $options    Export options.
     * @return   string              Complete HTML document.
     */
    private function generate_html_report($report, $options) {
        ob_start();
        ?>
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title><?php echo $this->format_report_title($report); ?></title>
            
            <?php echo $this->generate_css_includes($options); ?>
            <?php echo $this->generate_custom_css($report, $options); ?>
        </head>
        <body>
            <?php echo $this->generate_header($report, $options); ?>
            
            <div class="container-fluid">
                <div class="row">
                    <?php if ($this->template_structure['sidebar']['enabled']): ?>
                        <div class="col-md-3 sidebar">
                            <?php echo $this->generate_sidebar($report, $options); ?>
                        </div>
                        <div class="col-md-9 main-content">
                    <?php else: ?>
                        <div class="col-12 main-content">
                    <?php endif; ?>
                    
                            <?php echo $this->generate_main_content($report, $options); ?>
                        </div>
                </div>
            </div>
            
            <?php echo $this->generate_footer($report, $options); ?>
            <?php echo $this->generate_js_includes($options); ?>
            <?php echo $this->generate_custom_js($report, $options); ?>
        </body>
        </html>
        <?php
        return ob_get_clean();
    }

    /**
     * Generate CSS includes.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $options    Export options.
     * @return   string              CSS include tags.
     */
    private function generate_css_includes($options) {
        $css_includes = '';
        
        if ($this->css_config['framework'] === 'bootstrap') {
            $css_includes .= '<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">' . "\n";
        }
        
        if ($options['include_filters']) {
            $css_includes .= '<link href="https://cdn.datatables.net/1.12.1/css/jquery.dataTables.min.css" rel="stylesheet">' . "\n";
        }
        
        // Font Awesome for icons
        $css_includes .= '<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">' . "\n";
        
        return $css_includes;
    }

    /**
     * Generate custom CSS styles.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $report     Report data.
     * @param    array    $options    Export options.
     * @return   string              Custom CSS styles.
     */
    private function generate_custom_css($report, $options) {
        $theme = $this->css_config['custom_themes'][$options['theme']] ?? $this->css_config['custom_themes']['default'];
        
        ob_start();
        ?>
        <style>
            :root {
                --primary-color: <?php echo $theme['primary']; ?>;
                --secondary-color: <?php echo $theme['secondary']; ?>;
                --success-color: <?php echo $theme['success']; ?>;
                --warning-color: <?php echo $theme['warning']; ?>;
                --danger-color: <?php echo $theme['danger']; ?>;
                --info-color: <?php echo $theme['info']; ?>;
            }

            body {
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                line-height: 1.6;
                color: #333;
            }

            .report-header {
                background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
                color: white;
                padding: 2rem 0;
                margin-bottom: 2rem;
            }

            .security-score {
                text-align: center;
                margin: 2rem 0;
            }

            .score-circle {
                width: 150px;
                height: 150px;
                border-radius: 50%;
                display: inline-flex;
                align-items: center;
                justify-content: center;
                font-size: 2.5rem;
                font-weight: bold;
                color: white;
                margin: 1rem;
            }

            .score-excellent { background-color: var(--success-color); }
            .score-good { background-color: var(--info-color); }
            .score-fair { background-color: var(--warning-color); }
            .score-poor { background-color: var(--danger-color); }

            .severity-badge {
                padding: 0.25rem 0.5rem;
                border-radius: 0.25rem;
                font-size: 0.75rem;
                font-weight: 600;
                text-transform: uppercase;
            }

            .severity-critical {
                background-color: var(--danger-color);
                color: white;
            }

            .severity-high {
                background-color: #fd7e14;
                color: white;
            }

            .severity-medium {
                background-color: var(--warning-color);
                color: #000;
            }

            .severity-low {
                background-color: var(--success-color);
                color: white;
            }

            .status-badge {
                padding: 0.25rem 0.5rem;
                border-radius: 0.25rem;
                font-size: 0.75rem;
                font-weight: 600;
                text-transform: uppercase;
            }

            .status-open {
                background-color: var(--danger-color);
                color: white;
            }

            .status-fixed {
                background-color: var(--success-color);
                color: white;
            }

            .status-ignored {
                background-color: #6c757d;
                color: white;
            }

            .chart-container {
                position: relative;
                height: 400px;
                margin: 2rem 0;
            }

            .sidebar {
                background-color: #f8f9fa;
                min-height: 100vh;
                padding: 1rem;
            }

            .sidebar .nav-link {
                color: #495057;
                padding: 0.5rem 1rem;
                border-left: 3px solid transparent;
                transition: all 0.3s;
            }

            .sidebar .nav-link:hover,
            .sidebar .nav-link.active {
                color: var(--primary-color);
                background-color: rgba(0, 124, 186, 0.1);
                border-left-color: var(--primary-color);
            }

            .metric-card {
                border: none;
                border-radius: 0.5rem;
                box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
                transition: transform 0.2s, box-shadow 0.2s;
            }

            .metric-card:hover {
                transform: translateY(-2px);
                box-shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.15);
            }

            .vulnerability-table th {
                background-color: var(--primary-color);
                color: white;
                border: none;
            }

            .expandable-section {
                border: 1px solid #dee2e6;
                border-radius: 0.375rem;
                margin-bottom: 1rem;
            }

            .expandable-header {
                background-color: #f8f9fa;
                padding: 0.75rem 1rem;
                cursor: pointer;
                border-bottom: 1px solid #dee2e6;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }

            .expandable-content {
                padding: 1rem;
                display: none;
            }

            .expandable-content.show {
                display: block;
            }

            .filter-controls {
                background-color: #f8f9fa;
                padding: 1rem;
                border-radius: 0.375rem;
                margin-bottom: 1rem;
            }

            @media print {
                .sidebar,
                .filter-controls,
                .no-print {
                    display: none !important;
                }
                
                .main-content {
                    width: 100% !important;
                    margin: 0 !important;
                }
                
                .chart-container {
                    height: 300px;
                }
            }

            @media (max-width: 768px) {
                .sidebar {
                    min-height: auto;
                    margin-bottom: 1rem;
                }
                
                .score-circle {
                    width: 100px;
                    height: 100px;
                    font-size: 1.5rem;
                }
                
                .chart-container {
                    height: 300px;
                }
            }
        </style>
        <?php
        return ob_get_clean();
    }

    /**
     * Generate report header.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $report     Report data.
     * @param    array    $options    Export options.
     * @return   string              Header HTML.
     */
    private function generate_header($report, $options) {
        ob_start();
        ?>
        <header class="report-header">
            <div class="container">
                <div class="row align-items-center">
                    <div class="col-md-8">
                        <h1 class="mb-0"><?php echo $this->format_report_title($report); ?></h1>
                        <p class="mb-0 mt-2"><?php echo get_bloginfo('name'); ?> - <?php echo current_time('F j, Y'); ?></p>
                    </div>
                    <div class="col-md-4 text-end">
                        <?php if (isset($report['data']['security_score'])): ?>
                            <div class="security-score">
                                <?php
                                $score = $report['data']['security_score'];
                                $score_class = $this->get_score_css_class($score['score']);
                                ?>
                                <div class="score-circle <?php echo $score_class; ?>">
                                    <?php echo $score['score']; ?>%
                                </div>
                                <div class="mt-2">
                                    <strong>Grade: <?php echo $score['grade']; ?></strong><br>
                                    <small><?php echo ucfirst($score['status']); ?></small>
                                </div>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </header>
        <?php
        return ob_get_clean();
    }

    /**
     * Generate sidebar content.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $report     Report data.
     * @param    array    $options    Export options.
     * @return   string              Sidebar HTML.
     */
    private function generate_sidebar($report, $options) {
        ob_start();
        ?>
        <nav class="sidebar-nav">
            <h5>Table of Contents</h5>
            <ul class="nav flex-column">
                <?php foreach ($report['content']['sections'] as $section_name => $section_data): ?>
                    <li class="nav-item">
                        <a class="nav-link" href="#section-<?php echo $section_name; ?>">
                            <?php echo $section_data['title']; ?>
                        </a>
                    </li>
                <?php endforeach; ?>
            </ul>
        </nav>

        <div class="mt-4">
            <h5>Quick Stats</h5>
            <?php echo $this->generate_quick_stats($report); ?>
        </div>

        <div class="mt-4 no-print">
            <h5>Export Options</h5>
            <div class="d-grid gap-2">
                <button class="btn btn-outline-primary btn-sm" onclick="window.print()">
                    <i class="fas fa-print"></i> Print Report
                </button>
                <button class="btn btn-outline-secondary btn-sm" onclick="exportToCSV()">
                    <i class="fas fa-file-csv"></i> Export CSV
                </button>
            </div>
        </div>
        <?php
        return ob_get_clean();
    }

    /**
     * Generate main content area.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $report     Report data.
     * @param    array    $options    Export options.
     * @return   string              Main content HTML.
     */
    private function generate_main_content($report, $options) {
        ob_start();
        
        foreach ($report['content']['sections'] as $section_name => $section_data) {
            echo $this->generate_section_html($section_name, $section_data, $report, $options);
        }
        
        return ob_get_clean();
    }

    /**
     * Generate section HTML.
     *
     * @since    1.0.0
     * @access   private
     * @param    string   $section_name   Section name.
     * @param    array    $section_data   Section data.
     * @param    array    $report         Report data.
     * @param    array    $options        Export options.
     * @return   string                  Section HTML.
     */
    private function generate_section_html($section_name, $section_data, $report, $options) {
        ob_start();
        ?>
        <section id="section-<?php echo $section_name; ?>" class="mb-5">
            <div class="d-flex justify-content-between align-items-center mb-3">
                <h2><?php echo $section_data['title']; ?></h2>
                <button class="btn btn-outline-secondary btn-sm no-print" onclick="toggleSection('<?php echo $section_name; ?>')">
                    <i class="fas fa-expand-alt"></i>
                </button>
            </div>
            
            <div class="section-content" id="content-<?php echo $section_name; ?>">
                <?php
                // Render section content based on type
                if (isset($section_data['html'])) {
                    echo $section_data['html'];
                }
                
                // Add charts if available
                if ($options['include_charts'] && isset($report['charts'])) {
                    echo $this->generate_section_charts($section_name, $report['charts'], $options);
                }
                
                // Add data tables if available
                if (isset($section_data['data'])) {
                    echo $this->generate_section_tables($section_name, $section_data['data'], $options);
                }
                ?>
            </div>
        </section>
        <?php
        return ob_get_clean();
    }

    /**
     * Generate JavaScript includes.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $options    Export options.
     * @return   string              JavaScript include tags.
     */
    private function generate_js_includes($options) {
        $js_includes = '';
        
        // jQuery (required for Bootstrap and DataTables)
        $js_includes .= '<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>' . "\n";
        
        // Bootstrap JS
        if ($this->css_config['framework'] === 'bootstrap') {
            $js_includes .= '<script src="' . $this->js_dependencies['bootstrap']['url'] . '"></script>' . "\n";
        }
        
        // Chart.js for interactive charts
        if ($options['include_charts']) {
            $js_includes .= '<script src="' . $this->js_dependencies['chart_js']['url'] . '"></script>' . "\n";
        }
        
        // DataTables for advanced table features
        if ($options['include_filters']) {
            $js_includes .= '<script src="' . $this->js_dependencies['datatables']['url'] . '"></script>' . "\n";
        }
        
        return $js_includes;
    }

    /**
     * Generate custom JavaScript.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $report     Report data.
     * @param    array    $options    Export options.
     * @return   string              Custom JavaScript code.
     */
    private function generate_custom_js($report, $options) {
        ob_start();
        ?>
        <script>
            // Initialize interactive features
            $(document).ready(function() {
                // Initialize DataTables
                <?php if ($options['include_filters']): ?>
                $('.data-table').DataTable({
                    responsive: true,
                    pageLength: 25,
                    order: [[0, 'desc']]
                });
                <?php endif; ?>

                // Initialize charts
                <?php if ($options['include_charts'] && isset($report['charts'])): ?>
                    <?php echo $this->generate_chart_js($report['charts']); ?>
                <?php endif; ?>

                // Smooth scrolling for navigation
                $('.sidebar-nav a').click(function(e) {
                    e.preventDefault();
                    const target = $(this.getAttribute('href'));
                    if (target.length) {
                        $('html, body').animate({
                            scrollTop: target.offset().top - 100
                        }, 500);
                    }
                });
            });

            // Toggle section visibility
            function toggleSection(sectionName) {
                const content = document.getElementById('content-' + sectionName);
                const icon = event.target.querySelector('i');
                
                if (content.style.display === 'none') {
                    content.style.display = 'block';
                    icon.className = 'fas fa-compress-alt';
                } else {
                    content.style.display = 'none';
                    icon.className = 'fas fa-expand-alt';
                }
            }

            // Export to CSV function
            function exportToCSV() {
                // Basic CSV export functionality
                alert('CSV export functionality would be implemented here');
            }

            // Print optimization
            window.addEventListener('beforeprint', function() {
                // Expand all sections for printing
                document.querySelectorAll('.section-content').forEach(function(content) {
                    content.style.display = 'block';
                });
            });
        </script>
        <?php
        return ob_get_clean();
    }

    /**
     * Format report title.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $report    Report data.
     * @return   string             Formatted title.
     */
    private function format_report_title($report) {
        return ucwords(str_replace('_', ' ', $report['type'])) . ' Security Report';
    }

    /**
     * Get CSS class for security score.
     *
     * @since    1.0.0
     * @access   private
     * @param    int      $score    Security score.
     * @return   string            CSS class name.
     */
    private function get_score_css_class($score) {
        if ($score >= 80) return 'score-excellent';
        if ($score >= 60) return 'score-good';
        if ($score >= 40) return 'score-fair';
        return 'score-poor';
    }

    /**
     * Generate HTML filename.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $report    Report data.
     * @return   string            Generated filename.
     */
    private function generate_html_filename($report) {
        $site_name = sanitize_file_name(get_bloginfo('name'));
        $report_type = $report['type'];
        $date = current_time('Y-m-d_H-i-s');
        
        return sprintf('%s_%s_report_%s.html', $site_name, $report_type, $date);
    }

    // Additional helper methods for generating specific content sections...
}

<?php

/**
 * PDF report exporter.
 *
 * This class handles the export of security reports to PDF format using
 * TCPDF library for professional document generation.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/reports/exporters
 */

/**
 * The PDF exporter class.
 *
 * Converts security reports to professionally formatted PDF documents
 * with proper styling, charts, and page layout.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/reports/exporters
 * @author     WP Breach Team
 */
class WP_Breach_PDF_Exporter {

    /**
     * PDF library instance.
     *
     * @since    1.0.0
     * @access   private
     * @var      mixed    $pdf_engine    PDF generation library instance.
     */
    private $pdf_engine;

    /**
     * Export configuration.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $config    Export configuration options.
     */
    private $config;

    /**
     * Initialize the PDF exporter.
     *
     * @since    1.0.0
     */
    public function __construct() {
        $this->setup_pdf_engine();
        $this->setup_default_config();
    }

    /**
     * Setup PDF generation engine.
     *
     * @since    1.0.0
     * @access   private
     */
    private function setup_pdf_engine() {
        // Check if TCPDF is available
        if (class_exists('TCPDF')) {
            $this->pdf_engine = 'tcpdf';
        } else {
            // Fallback to basic HTML to PDF conversion
            $this->pdf_engine = 'html';
        }
    }

    /**
     * Setup default export configuration.
     *
     * @since    1.0.0
     * @access   private
     */
    private function setup_default_config() {
        $this->config = array(
            'page_size' => 'A4',
            'orientation' => 'P', // Portrait
            'margins' => array(
                'top' => 15,
                'right' => 15,
                'bottom' => 15,
                'left' => 15
            ),
            'font' => array(
                'family' => 'helvetica',
                'size' => 10
            ),
            'header' => array(
                'enabled' => true,
                'height' => 20,
                'logo' => true
            ),
            'footer' => array(
                'enabled' => true,
                'height' => 15,
                'page_numbers' => true
            ),
            'styling' => array(
                'colors' => array(
                    'primary' => '#2271b1',
                    'secondary' => '#135e96',
                    'text' => '#1d2327',
                    'border' => '#c3c4c7'
                )
            )
        );
    }

    /**
     * Export report to PDF format.
     *
     * @since    1.0.0
     * @param    array    $report     Report data.
     * @param    array    $options    Export options.
     * @return   array               Export result.
     */
    public function export($report, $options = array()) {
        try {
            $export_config = array_merge($this->config, $options);
            
            // Generate PDF based on available engine
            switch ($this->pdf_engine) {
                case 'tcpdf':
                    return $this->export_with_tcpdf($report, $export_config);
                default:
                    return $this->export_with_html($report, $export_config);
            }

        } catch (Exception $e) {
            error_log("WP-Breach PDF Export Error: " . $e->getMessage());
            return array(
                'error' => true,
                'message' => $e->getMessage()
            );
        }
    }

    /**
     * Export using TCPDF library.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $report     Report data.
     * @param    array    $config     Export configuration.
     * @return   array               Export result.
     */
    private function export_with_tcpdf($report, $config) {
        // Initialize TCPDF
        $pdf = new TCPDF(
            $config['orientation'],
            'mm',
            $config['page_size'],
            true,
            'UTF-8',
            false
        );

        // Set document information
        $pdf->SetCreator('WP-Breach Security Plugin');
        $pdf->SetAuthor(get_bloginfo('name'));
        $pdf->SetTitle($report['type'] . ' Security Report');
        $pdf->SetSubject('Security Analysis Report');

        // Set margins
        $pdf->SetMargins(
            $config['margins']['left'],
            $config['margins']['top'],
            $config['margins']['right']
        );
        $pdf->SetHeaderMargin(5);
        $pdf->SetFooterMargin(10);

        // Set auto page breaks
        $pdf->SetAutoPageBreak(true, $config['margins']['bottom']);

        // Set font
        $pdf->SetFont($config['font']['family'], '', $config['font']['size']);

        // Add header and footer
        if ($config['header']['enabled']) {
            $this->setup_pdf_header($pdf, $report, $config);
        }
        
        if ($config['footer']['enabled']) {
            $this->setup_pdf_footer($pdf, $report, $config);
        }

        // Add content
        $this->add_pdf_content($pdf, $report, $config);

        // Generate file
        $filename = $this->generate_pdf_filename($report);
        $upload_dir = wp_upload_dir();
        $file_path = $upload_dir['basedir'] . '/wp-breach-reports/' . $filename;

        // Create directory if it doesn't exist
        wp_mkdir_p(dirname($file_path));

        // Output PDF to file
        $pdf->Output($file_path, 'F');

        return array(
            'success' => true,
            'file_path' => $file_path,
            'url' => $upload_dir['baseurl'] . '/wp-breach-reports/' . $filename,
            'filename' => $filename,
            'size' => filesize($file_path),
            'format' => 'pdf'
        );
    }

    /**
     * Export using HTML to PDF conversion.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $report     Report data.
     * @param    array    $config     Export configuration.
     * @return   array               Export result.
     */
    private function export_with_html($report, $config) {
        // Generate HTML content
        $html_content = $this->generate_html_for_pdf($report, $config);
        
        // Use browser print CSS for basic PDF conversion
        $filename = $this->generate_pdf_filename($report);
        $upload_dir = wp_upload_dir();
        $html_file = $upload_dir['basedir'] . '/wp-breach-reports/' . str_replace('.pdf', '.html', $filename);
        
        // Create directory if it doesn't exist
        wp_mkdir_p(dirname($html_file));
        
        // Save HTML file with print styles
        file_put_contents($html_file, $html_content);

        return array(
            'success' => true,
            'file_path' => $html_file,
            'url' => $upload_dir['baseurl'] . '/wp-breach-reports/' . str_replace('.pdf', '.html', $filename),
            'filename' => str_replace('.pdf', '.html', $filename),
            'size' => filesize($html_file),
            'format' => 'html',
            'note' => 'PDF library not available. Generated HTML file instead.'
        );
    }

    /**
     * Setup PDF header.
     *
     * @since    1.0.0
     * @access   private
     * @param    object   $pdf        PDF instance.
     * @param    array    $report     Report data.
     * @param    array    $config     Export configuration.
     */
    private function setup_pdf_header($pdf, $report, $config) {
        $pdf->setHeaderCallback(function($pdf) use ($report, $config) {
            $pdf->SetY(15);
            $pdf->SetFont($config['font']['family'], 'B', 16);
            $pdf->Cell(0, 15, ucwords(str_replace('_', ' ', $report['type'])) . ' Security Report', 0, false, 'C', 0, '', 0, false, 'M', 'M');
            $pdf->SetY(25);
            $pdf->SetFont($config['font']['family'], '', 10);
            $pdf->Cell(0, 10, get_bloginfo('name') . ' - Generated: ' . current_time('Y-m-d H:i:s'), 0, false, 'C', 0, '', 0, false, 'M', 'M');
            $pdf->Line(15, 35, 195, 35);
        });
    }

    /**
     * Setup PDF footer.
     *
     * @since    1.0.0
     * @access   private
     * @param    object   $pdf        PDF instance.
     * @param    array    $report     Report data.
     * @param    array    $config     Export configuration.
     */
    private function setup_pdf_footer($pdf, $report, $config) {
        $pdf->setFooterCallback(function($pdf) use ($config) {
            $pdf->SetY(-15);
            $pdf->SetFont($config['font']['family'], '', 8);
            $pdf->Cell(0, 10, 'Generated by WP-Breach Security Plugin - Page ' . $pdf->getAliasNumPage() . '/' . $pdf->getAliasNbPages(), 0, false, 'C', 0, '', 0, false, 'T', 'M');
        });
    }

    /**
     * Add content to PDF.
     *
     * @since    1.0.0
     * @access   private
     * @param    object   $pdf        PDF instance.
     * @param    array    $report     Report data.
     * @param    array    $config     Export configuration.
     */
    private function add_pdf_content($pdf, $report, $config) {
        $pdf->AddPage();

        // Add title page
        $this->add_title_page($pdf, $report, $config);
        
        // Add table of contents
        $pdf->AddPage();
        $this->add_table_of_contents($pdf, $report, $config);

        // Add each section
        foreach ($report['content']['sections'] as $section_name => $section_data) {
            $pdf->AddPage();
            $this->add_section_to_pdf($pdf, $section_name, $section_data, $config);
        }
    }

    /**
     * Add title page to PDF.
     *
     * @since    1.0.0
     * @access   private
     * @param    object   $pdf        PDF instance.
     * @param    array    $report     Report data.
     * @param    array    $config     Export configuration.
     */
    private function add_title_page($pdf, $report, $config) {
        $pdf->SetY(60);
        
        // Report title
        $pdf->SetFont($config['font']['family'], 'B', 24);
        $pdf->Cell(0, 20, ucwords(str_replace('_', ' ', $report['type'])), 0, true, 'C');
        
        $pdf->SetFont($config['font']['family'], 'B', 18);
        $pdf->Cell(0, 15, 'Security Report', 0, true, 'C');
        
        $pdf->Ln(20);
        
        // Report details
        $pdf->SetFont($config['font']['family'], '', 12);
        $pdf->Cell(0, 10, 'Website: ' . get_bloginfo('name'), 0, true, 'C');
        $pdf->Cell(0, 10, 'URL: ' . get_site_url(), 0, true, 'C');
        $pdf->Cell(0, 10, 'Generated: ' . current_time('F j, Y \a\t g:i A'), 0, true, 'C');
        
        if (isset($report['metadata']['generation_time'])) {
            $pdf->Cell(0, 10, 'Generation Time: ' . round($report['metadata']['generation_time'], 2) . ' seconds', 0, true, 'C');
        }
        
        $pdf->Ln(30);
        
        // Security score if available
        if (isset($report['data']['security_score'])) {
            $score = $report['data']['security_score'];
            $pdf->SetFont($config['font']['family'], 'B', 16);
            $pdf->Cell(0, 15, 'Overall Security Score', 0, true, 'C');
            
            $pdf->SetFont($config['font']['family'], 'B', 36);
            $color = $this->get_score_color($score['score']);
            $pdf->SetTextColor($color[0], $color[1], $color[2]);
            $pdf->Cell(0, 25, $score['score'] . '%', 0, true, 'C');
            
            $pdf->SetTextColor(0, 0, 0); // Reset to black
            $pdf->SetFont($config['font']['family'], 'B', 14);
            $pdf->Cell(0, 10, 'Grade: ' . $score['grade'], 0, true, 'C');
        }
    }

    /**
     * Add table of contents to PDF.
     *
     * @since    1.0.0
     * @access   private
     * @param    object   $pdf        PDF instance.
     * @param    array    $report     Report data.
     * @param    array    $config     Export configuration.
     */
    private function add_table_of_contents($pdf, $report, $config) {
        $pdf->SetFont($config['font']['family'], 'B', 16);
        $pdf->Cell(0, 15, 'Table of Contents', 0, true, 'L');
        $pdf->Ln(5);
        
        $pdf->SetFont($config['font']['family'], '', 11);
        $page_num = 4; // Starting page after title and TOC
        
        foreach ($report['content']['sections'] as $section_name => $section_data) {
            $title = $section_data['title'] ?? ucwords(str_replace('_', ' ', $section_name));
            $pdf->Cell(150, 8, $title, 0, false, 'L');
            $pdf->Cell(30, 8, $page_num, 0, true, 'R');
            $page_num++;
        }
    }

    /**
     * Add section content to PDF.
     *
     * @since    1.0.0
     * @access   private
     * @param    object   $pdf          PDF instance.
     * @param    string   $section_name Section name.
     * @param    array    $section_data Section data.
     * @param    array    $config       Export configuration.
     */
    private function add_section_to_pdf($pdf, $section_name, $section_data, $config) {
        // Section title
        $pdf->SetFont($config['font']['family'], 'B', 14);
        $pdf->Cell(0, 12, $section_data['title'], 0, true, 'L');
        $pdf->Ln(3);
        
        // Section content
        $pdf->SetFont($config['font']['family'], '', 10);
        
        // Convert HTML content to PDF text
        $content = $this->convert_html_to_pdf_text($section_data['content'] ?? '', $pdf, $config);
        
        // Add data tables if available
        if (isset($section_data['data']) && is_array($section_data['data'])) {
            $this->add_data_tables($pdf, $section_data['data'], $config);
        }
    }

    /**
     * Convert HTML content to PDF-compatible text.
     *
     * @since    1.0.0
     * @access   private
     * @param    string   $html     HTML content.
     * @param    object   $pdf      PDF instance.
     * @param    array    $config   Export configuration.
     * @return   string            Plain text content.
     */
    private function convert_html_to_pdf_text($html, $pdf, $config) {
        // Basic HTML to text conversion
        $text = strip_tags($html);
        $text = html_entity_decode($text);
        
        // Add text to PDF with proper wrapping
        $pdf->MultiCell(0, 6, $text, 0, 'L');
        $pdf->Ln(5);
        
        return $text;
    }

    /**
     * Add data tables to PDF.
     *
     * @since    1.0.0
     * @access   private
     * @param    object   $pdf      PDF instance.
     * @param    array    $data     Section data.
     * @param    array    $config   Export configuration.
     */
    private function add_data_tables($pdf, $data, $config) {
        // Example: Add vulnerability table
        if (isset($data['vulnerabilities']) && is_array($data['vulnerabilities'])) {
            $pdf->SetFont($config['font']['family'], 'B', 10);
            $pdf->Cell(0, 8, 'Vulnerabilities Summary', 0, true, 'L');
            
            // Table header
            $pdf->SetFont($config['font']['family'], 'B', 8);
            $pdf->Cell(60, 6, 'Title', 1, false, 'L');
            $pdf->Cell(25, 6, 'Severity', 1, false, 'C');
            $pdf->Cell(25, 6, 'Status', 1, false, 'C');
            $pdf->Cell(70, 6, 'Component', 1, true, 'L');
            
            // Table data
            $pdf->SetFont($config['font']['family'], '', 8);
            $count = 0;
            foreach ($data['vulnerabilities'] as $vuln) {
                if ($count++ >= 20) break; // Limit for PDF space
                
                $pdf->Cell(60, 5, $this->truncate_text($vuln['title'] ?? 'N/A', 30), 1, false, 'L');
                $pdf->Cell(25, 5, $vuln['severity'] ?? 'N/A', 1, false, 'C');
                $pdf->Cell(25, 5, $vuln['status'] ?? 'N/A', 1, false, 'C');
                $pdf->Cell(70, 5, $this->truncate_text($vuln['component_name'] ?? 'N/A', 35), 1, true, 'L');
            }
            
            $pdf->Ln(5);
        }
    }

    /**
     * Generate HTML content for PDF conversion.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $report     Report data.
     * @param    array    $config     Export configuration.
     * @return   string              HTML content.
     */
    private function generate_html_for_pdf($report, $config) {
        ob_start();
        ?>
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title><?php echo ucwords(str_replace('_', ' ', $report['type'])); ?> Security Report</title>
            <style>
                @media print {
                    body { margin: 0; padding: 20px; font-family: Arial, sans-serif; font-size: 12px; }
                    .page-break { page-break-before: always; }
                    .no-print { display: none; }
                }
                body { font-family: Arial, sans-serif; line-height: 1.4; color: #333; }
                h1 { color: <?php echo $config['styling']['colors']['primary']; ?>; }
                h2 { color: <?php echo $config['styling']['colors']['secondary']; ?>; border-bottom: 2px solid #eee; padding-bottom: 5px; }
                .header { text-align: center; margin-bottom: 30px; }
                .score { font-size: 2em; font-weight: bold; text-align: center; margin: 20px 0; }
                table { width: 100%; border-collapse: collapse; margin: 15px 0; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f5f5f5; font-weight: bold; }
                .severity-critical { color: #d63638; font-weight: bold; }
                .severity-high { color: #fd7e14; font-weight: bold; }
                .severity-medium { color: #dba617; font-weight: bold; }
                .severity-low { color: #28a745; font-weight: bold; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1><?php echo ucwords(str_replace('_', ' ', $report['type'])); ?> Security Report</h1>
                <p><?php echo get_bloginfo('name'); ?> - <?php echo current_time('F j, Y'); ?></p>
            </div>

            <?php foreach ($report['content']['sections'] as $section_name => $section_data): ?>
                <div class="page-break">
                    <h2><?php echo $section_data['title']; ?></h2>
                    <?php echo $section_data['html'] ?? ''; ?>
                </div>
            <?php endforeach; ?>
        </body>
        </html>
        <?php
        return ob_get_clean();
    }

    /**
     * Generate PDF filename.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $report    Report data.
     * @return   string            Generated filename.
     */
    private function generate_pdf_filename($report) {
        $site_name = sanitize_file_name(get_bloginfo('name'));
        $report_type = $report['type'];
        $date = current_time('Y-m-d_H-i-s');
        
        return sprintf('%s_%s_report_%s.pdf', $site_name, $report_type, $date);
    }

    /**
     * Get color array for score.
     *
     * @since    1.0.0
     * @access   private
     * @param    int      $score    Security score.
     * @return   array             RGB color array.
     */
    private function get_score_color($score) {
        if ($score >= 80) return array(40, 167, 69);  // Green
        if ($score >= 60) return array(255, 193, 7);  // Yellow
        return array(220, 53, 69); // Red
    }

    /**
     * Truncate text to specified length.
     *
     * @since    1.0.0
     * @access   private
     * @param    string   $text      Text to truncate.
     * @param    int      $length    Maximum length.
     * @return   string             Truncated text.
     */
    private function truncate_text($text, $length) {
        return strlen($text) > $length ? substr($text, 0, $length - 3) . '...' : $text;
    }
}

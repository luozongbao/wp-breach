<?php

/**
 * CSV report exporter.
 *
 * This class handles the export of security reports to CSV format
 * for data analysis and spreadsheet applications.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/reports/exporters
 */

/**
 * The CSV exporter class.
 *
 * Converts security report data to CSV format with proper escaping,
 * multiple sheet support, and data normalization.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/reports/exporters
 * @author     WP Breach Team
 */
class WP_Breach_CSV_Exporter {

    /**
     * CSV configuration options.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $config    CSV export configuration.
     */
    private $config;

    /**
     * Data normalization rules.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $normalization_rules    Rules for data normalization.
     */
    private $normalization_rules;

    /**
     * Initialize the CSV exporter.
     *
     * @since    1.0.0
     */
    public function __construct() {
        $this->setup_config();
        $this->setup_normalization_rules();
    }

    /**
     * Setup CSV export configuration.
     *
     * @since    1.0.0
     * @access   private
     */
    private function setup_config() {
        $this->config = array(
            'delimiter' => ',',
            'enclosure' => '"',
            'escape' => '\\',
            'encoding' => 'UTF-8',
            'include_bom' => true,
            'max_rows_per_file' => 50000,
            'date_format' => 'Y-m-d H:i:s',
            'null_value' => '',
            'boolean_format' => array('true', 'false'),
            'sheets' => array(
                'vulnerabilities' => true,
                'scans' => true,
                'fixes' => true,
                'summary' => true,
                'metrics' => true
            )
        );
    }

    /**
     * Setup data normalization rules.
     *
     * @since    1.0.0
     * @access   private
     */
    private function setup_normalization_rules() {
        $this->normalization_rules = array(
            'remove_html' => true,
            'flatten_arrays' => true,
            'normalize_dates' => true,
            'escape_special_chars' => true,
            'handle_null_values' => true,
            'convert_objects' => true
        );
    }

    /**
     * Export report to CSV format.
     *
     * @since    1.0.0
     * @param    array    $report     Report data.
     * @param    array    $options    Export options.
     * @return   array               Export result.
     */
    public function export($report, $options = array()) {
        try {
            $export_config = array_merge($this->config, $options);
            
            // Determine export mode
            if ($export_config['multiple_files'] ?? false) {
                return $this->export_multiple_files($report, $export_config);
            } else {
                return $this->export_single_file($report, $export_config);
            }

        } catch (Exception $e) {
            error_log("WP-Breach CSV Export Error: " . $e->getMessage());
            return array(
                'error' => true,
                'message' => $e->getMessage()
            );
        }
    }

    /**
     * Export to single CSV file.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $report     Report data.
     * @param    array    $config     Export configuration.
     * @return   array               Export result.
     */
    private function export_single_file($report, $config) {
        $filename = $this->generate_csv_filename($report, 'combined');
        $upload_dir = wp_upload_dir();
        $file_path = $upload_dir['basedir'] . '/wp-breach-reports/' . $filename;
        
        // Create directory if it doesn't exist
        wp_mkdir_p(dirname($file_path));
        
        // Open file for writing
        $handle = fopen($file_path, 'w');
        
        if (!$handle) {
            throw new Exception("Could not create CSV file: {$file_path}");
        }

        // Add BOM for UTF-8 if configured
        if ($config['include_bom']) {
            fwrite($handle, "\xEF\xBB\xBF");
        }

        // Export each data type as separate sections
        $this->export_vulnerabilities_section($handle, $report, $config);
        $this->export_summary_section($handle, $report, $config);
        $this->export_metrics_section($handle, $report, $config);

        fclose($handle);

        return array(
            'success' => true,
            'file_path' => $file_path,
            'url' => $upload_dir['baseurl'] . '/wp-breach-reports/' . $filename,
            'filename' => $filename,
            'size' => filesize($file_path),
            'format' => 'csv',
            'type' => 'single_file'
        );
    }

    /**
     * Export to multiple CSV files.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $report     Report data.
     * @param    array    $config     Export configuration.
     * @return   array               Export result.
     */
    private function export_multiple_files($report, $config) {
        $exported_files = array();
        $upload_dir = wp_upload_dir();
        $base_dir = $upload_dir['basedir'] . '/wp-breach-reports/';
        
        // Create directory if it doesn't exist
        wp_mkdir_p($base_dir);

        // Export vulnerabilities
        if ($config['sheets']['vulnerabilities'] && isset($report['data']['vulnerabilities'])) {
            $filename = $this->generate_csv_filename($report, 'vulnerabilities');
            $file_path = $base_dir . $filename;
            $this->export_vulnerabilities_to_file($file_path, $report['data']['vulnerabilities'], $config);
            $exported_files['vulnerabilities'] = array(
                'filename' => $filename,
                'path' => $file_path,
                'url' => $upload_dir['baseurl'] . '/wp-breach-reports/' . $filename,
                'size' => filesize($file_path)
            );
        }

        // Export scans
        if ($config['sheets']['scans'] && isset($report['data']['scans'])) {
            $filename = $this->generate_csv_filename($report, 'scans');
            $file_path = $base_dir . $filename;
            $this->export_scans_to_file($file_path, $report['data']['scans'], $config);
            $exported_files['scans'] = array(
                'filename' => $filename,
                'path' => $file_path,
                'url' => $upload_dir['baseurl'] . '/wp-breach-reports/' . $filename,
                'size' => filesize($file_path)
            );
        }

        // Export fixes
        if ($config['sheets']['fixes'] && isset($report['data']['fixes'])) {
            $filename = $this->generate_csv_filename($report, 'fixes');
            $file_path = $base_dir . $filename;
            $this->export_fixes_to_file($file_path, $report['data']['fixes'], $config);
            $exported_files['fixes'] = array(
                'filename' => $filename,
                'path' => $file_path,
                'url' => $upload_dir['baseurl'] . '/wp-breach-reports/' . $filename,
                'size' => filesize($file_path)
            );
        }

        // Export summary
        if ($config['sheets']['summary']) {
            $filename = $this->generate_csv_filename($report, 'summary');
            $file_path = $base_dir . $filename;
            $this->export_summary_to_file($file_path, $report, $config);
            $exported_files['summary'] = array(
                'filename' => $filename,
                'path' => $file_path,
                'url' => $upload_dir['baseurl'] . '/wp-breach-reports/' . $filename,
                'size' => filesize($file_path)
            );
        }

        // Create ZIP archive if multiple files
        if (count($exported_files) > 1) {
            $zip_result = $this->create_zip_archive($exported_files, $report);
            if ($zip_result['success']) {
                return array(
                    'success' => true,
                    'files' => $exported_files,
                    'archive' => $zip_result,
                    'format' => 'csv',
                    'type' => 'multiple_files'
                );
            }
        }

        return array(
            'success' => true,
            'files' => $exported_files,
            'format' => 'csv',
            'type' => 'multiple_files'
        );
    }

    /**
     * Export vulnerabilities section to CSV.
     *
     * @since    1.0.0
     * @access   private
     * @param    resource $handle     File handle.
     * @param    array    $report     Report data.
     * @param    array    $config     Export configuration.
     */
    private function export_vulnerabilities_section($handle, $report, $config) {
        if (!isset($report['data']['vulnerabilities'])) {
            return;
        }

        // Add section header
        fputcsv($handle, array('VULNERABILITIES'), $config['delimiter'], $config['enclosure'], $config['escape']);
        fputcsv($handle, array(''), $config['delimiter'], $config['enclosure'], $config['escape']); // Empty line

        // Add column headers
        $headers = array(
            'ID',
            'Title',
            'Severity',
            'Status',
            'Type',
            'Component Type',
            'Component Name',
            'Component Version',
            'Affected File',
            'Line Number',
            'CVSS Score',
            'CVE ID',
            'CWE ID',
            'Risk Level',
            'Fix Available',
            'Auto Fixable',
            'Fix Complexity',
            'Detected At',
            'First Detected',
            'Last Seen',
            'Description'
        );
        
        fputcsv($handle, $headers, $config['delimiter'], $config['enclosure'], $config['escape']);

        // Add vulnerability data
        foreach ($report['data']['vulnerabilities'] as $vuln) {
            $row = array(
                $vuln['id'] ?? '',
                $this->normalize_value($vuln['title'] ?? '', $config),
                $vuln['severity'] ?? '',
                $vuln['status'] ?? '',
                $vuln['vulnerability_type'] ?? '',
                $vuln['component_type'] ?? '',
                $vuln['component_name'] ?? '',
                $vuln['component_version'] ?? '',
                $vuln['affected_file'] ?? '',
                $vuln['line_number'] ?? '',
                $vuln['cvss_score'] ?? '',
                $vuln['cve_id'] ?? '',
                $vuln['cwe_id'] ?? '',
                $vuln['risk_level'] ?? '',
                $this->format_boolean($vuln['fix_available'] ?? false, $config),
                $this->format_boolean($vuln['auto_fixable'] ?? false, $config),
                $vuln['fix_complexity'] ?? '',
                $this->format_date($vuln['detected_at'] ?? '', $config),
                $this->format_date($vuln['first_detected_at'] ?? '', $config),
                $this->format_date($vuln['last_seen_at'] ?? '', $config),
                $this->normalize_value($vuln['description'] ?? '', $config)
            );
            
            fputcsv($handle, $row, $config['delimiter'], $config['enclosure'], $config['escape']);
        }

        // Add empty lines to separate sections
        fputcsv($handle, array(''), $config['delimiter'], $config['enclosure'], $config['escape']);
        fputcsv($handle, array(''), $config['delimiter'], $config['enclosure'], $config['escape']);
    }

    /**
     * Export summary section to CSV.
     *
     * @since    1.0.0
     * @access   private
     * @param    resource $handle     File handle.
     * @param    array    $report     Report data.
     * @param    array    $config     Export configuration.
     */
    private function export_summary_section($handle, $report, $config) {
        // Add section header
        fputcsv($handle, array('SUMMARY'), $config['delimiter'], $config['enclosure'], $config['escape']);
        fputcsv($handle, array(''), $config['delimiter'], $config['enclosure'], $config['escape']); // Empty line

        // Add summary data
        $summary_data = array();
        
        if (isset($report['data']['summary'])) {
            foreach ($report['data']['summary'] as $key => $value) {
                $summary_data[] = array(
                    ucwords(str_replace('_', ' ', $key)),
                    $this->normalize_value($value, $config)
                );
            }
        }

        // Add security score if available
        if (isset($report['data']['security_score'])) {
            $score = $report['data']['security_score'];
            $summary_data[] = array('Security Score', $score['score'] ?? '');
            $summary_data[] = array('Security Grade', $score['grade'] ?? '');
            $summary_data[] = array('Security Status', $score['status'] ?? '');
        }

        // Add risk summary if available
        if (isset($report['data']['risk_summary']['counts'])) {
            foreach ($report['data']['risk_summary']['counts'] as $level => $count) {
                $summary_data[] = array(ucfirst($level) . ' Risks', $count);
            }
        }

        // Write summary data
        fputcsv($handle, array('Metric', 'Value'), $config['delimiter'], $config['enclosure'], $config['escape']);
        foreach ($summary_data as $row) {
            fputcsv($handle, $row, $config['delimiter'], $config['enclosure'], $config['escape']);
        }

        // Add empty lines
        fputcsv($handle, array(''), $config['delimiter'], $config['enclosure'], $config['escape']);
        fputcsv($handle, array(''), $config['delimiter'], $config['enclosure'], $config['escape']);
    }

    /**
     * Export metrics section to CSV.
     *
     * @since    1.0.0
     * @access   private
     * @param    resource $handle     File handle.
     * @param    array    $report     Report data.
     * @param    array    $config     Export configuration.
     */
    private function export_metrics_section($handle, $report, $config) {
        if (!isset($report['data']['key_metrics'])) {
            return;
        }

        // Add section header
        fputcsv($handle, array('KEY METRICS'), $config['delimiter'], $config['enclosure'], $config['escape']);
        fputcsv($handle, array(''), $config['delimiter'], $config['enclosure'], $config['escape']); // Empty line

        // Add column headers
        fputcsv($handle, array('Metric', 'Value'), $config['delimiter'], $config['enclosure'], $config['escape']);

        // Add metrics data
        foreach ($report['data']['key_metrics'] as $metric => $value) {
            $row = array(
                ucwords(str_replace('_', ' ', $metric)),
                $this->normalize_value($value, $config)
            );
            fputcsv($handle, $row, $config['delimiter'], $config['enclosure'], $config['escape']);
        }
    }

    /**
     * Export vulnerabilities to dedicated file.
     *
     * @since    1.0.0
     * @access   private
     * @param    string   $file_path       File path.
     * @param    array    $vulnerabilities Vulnerability data.
     * @param    array    $config         Export configuration.
     */
    private function export_vulnerabilities_to_file($file_path, $vulnerabilities, $config) {
        $handle = fopen($file_path, 'w');
        
        if (!$handle) {
            throw new Exception("Could not create vulnerabilities CSV file: {$file_path}");
        }

        // Add BOM for UTF-8 if configured
        if ($config['include_bom']) {
            fwrite($handle, "\xEF\xBB\xBF");
        }

        // Add headers
        $headers = array(
            'ID', 'Title', 'Severity', 'Status', 'Type', 'Component Type',
            'Component Name', 'Component Version', 'Affected File', 'Line Number',
            'CVSS Score', 'CVE ID', 'CWE ID', 'Risk Level', 'Fix Available',
            'Auto Fixable', 'Fix Complexity', 'Detected At', 'First Detected',
            'Last Seen', 'Description'
        );
        
        fputcsv($handle, $headers, $config['delimiter'], $config['enclosure'], $config['escape']);

        // Add data
        foreach ($vulnerabilities as $vuln) {
            $row = array(
                $vuln['id'] ?? '',
                $this->normalize_value($vuln['title'] ?? '', $config),
                $vuln['severity'] ?? '',
                $vuln['status'] ?? '',
                $vuln['vulnerability_type'] ?? '',
                $vuln['component_type'] ?? '',
                $vuln['component_name'] ?? '',
                $vuln['component_version'] ?? '',
                $vuln['affected_file'] ?? '',
                $vuln['line_number'] ?? '',
                $vuln['cvss_score'] ?? '',
                $vuln['cve_id'] ?? '',
                $vuln['cwe_id'] ?? '',
                $vuln['risk_level'] ?? '',
                $this->format_boolean($vuln['fix_available'] ?? false, $config),
                $this->format_boolean($vuln['auto_fixable'] ?? false, $config),
                $vuln['fix_complexity'] ?? '',
                $this->format_date($vuln['detected_at'] ?? '', $config),
                $this->format_date($vuln['first_detected_at'] ?? '', $config),
                $this->format_date($vuln['last_seen_at'] ?? '', $config),
                $this->normalize_value($vuln['description'] ?? '', $config)
            );
            
            fputcsv($handle, $row, $config['delimiter'], $config['enclosure'], $config['escape']);
        }

        fclose($handle);
    }

    /**
     * Normalize value for CSV export.
     *
     * @since    1.0.0
     * @access   private
     * @param    mixed    $value     Value to normalize.
     * @param    array    $config    Export configuration.
     * @return   string             Normalized value.
     */
    private function normalize_value($value, $config) {
        if (is_null($value)) {
            return $config['null_value'];
        }

        if (is_array($value) || is_object($value)) {
            if ($this->normalization_rules['flatten_arrays']) {
                return is_array($value) ? implode('; ', $value) : serialize($value);
            }
            return json_encode($value);
        }

        if (is_string($value)) {
            if ($this->normalization_rules['remove_html']) {
                $value = strip_tags($value);
            }
            
            if ($this->normalization_rules['escape_special_chars']) {
                $value = str_replace(array("\r", "\n", "\t"), array(' ', ' ', ' '), $value);
            }
        }

        return (string) $value;
    }

    /**
     * Format boolean value for CSV.
     *
     * @since    1.0.0
     * @access   private
     * @param    mixed    $value     Boolean value.
     * @param    array    $config    Export configuration.
     * @return   string             Formatted boolean.
     */
    private function format_boolean($value, $config) {
        if (is_null($value)) {
            return $config['null_value'];
        }
        
        return $value ? $config['boolean_format'][0] : $config['boolean_format'][1];
    }

    /**
     * Format date for CSV export.
     *
     * @since    1.0.0
     * @access   private
     * @param    string   $date      Date string.
     * @param    array    $config    Export configuration.
     * @return   string             Formatted date.
     */
    private function format_date($date, $config) {
        if (empty($date)) {
            return $config['null_value'];
        }
        
        $timestamp = strtotime($date);
        if ($timestamp === false) {
            return $date; // Return original if parsing fails
        }
        
        return date($config['date_format'], $timestamp);
    }

    /**
     * Generate CSV filename.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $report    Report data.
     * @param    string   $suffix    Filename suffix.
     * @return   string             Generated filename.
     */
    private function generate_csv_filename($report, $suffix = '') {
        $site_name = sanitize_file_name(get_bloginfo('name'));
        $report_type = $report['type'];
        $date = current_time('Y-m-d_H-i-s');
        
        if (!empty($suffix)) {
            return sprintf('%s_%s_%s_%s.csv', $site_name, $report_type, $suffix, $date);
        }
        
        return sprintf('%s_%s_report_%s.csv', $site_name, $report_type, $date);
    }

    /**
     * Create ZIP archive of multiple CSV files.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $files     File information array.
     * @param    array    $report    Report data.
     * @return   array              ZIP creation result.
     */
    private function create_zip_archive($files, $report) {
        if (!class_exists('ZipArchive')) {
            return array('success' => false, 'message' => 'ZipArchive not available');
        }

        $zip = new ZipArchive();
        $zip_filename = str_replace('.csv', '_archive.zip', $files[array_key_first($files)]['filename']);
        $upload_dir = wp_upload_dir();
        $zip_path = $upload_dir['basedir'] . '/wp-breach-reports/' . $zip_filename;

        if ($zip->open($zip_path, ZipArchive::CREATE) === TRUE) {
            foreach ($files as $type => $file_info) {
                $zip->addFile($file_info['path'], $file_info['filename']);
            }
            $zip->close();

            return array(
                'success' => true,
                'filename' => $zip_filename,
                'path' => $zip_path,
                'url' => $upload_dir['baseurl'] . '/wp-breach-reports/' . $zip_filename,
                'size' => filesize($zip_path)
            );
        }

        return array('success' => false, 'message' => 'Could not create ZIP archive');
    }

    // Additional helper methods for other data types...
}

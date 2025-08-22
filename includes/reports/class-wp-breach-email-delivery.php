<?php

/**
 * Email delivery system for security reports.
 *
 * This class handles the automated delivery of security reports via email
 * with support for multiple formats, scheduling, and recipient management.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/reports
 */

/**
 * The email delivery class.
 *
 * Manages email delivery of security reports with template support,
 * attachment handling, and delivery tracking.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/reports
 * @author     WP Breach Team
 */
class WP_Breach_Email_Delivery {

    /**
     * Email configuration settings.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $config    Email configuration.
     */
    private $config;

    /**
     * Email templates.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $templates    Email templates.
     */
    private $templates;

    /**
     * Delivery tracking.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $delivery_log    Delivery tracking log.
     */
    private $delivery_log;

    /**
     * Initialize the email delivery system.
     *
     * @since    1.0.0
     */
    public function __construct() {
        $this->setup_config();
        $this->setup_templates();
        $this->delivery_log = array();
        
        // Hook into WordPress email system
        add_filter('wp_mail_content_type', array($this, 'set_html_content_type'));
        add_action('wp_mail_failed', array($this, 'handle_mail_failure'));
    }

    /**
     * Setup email delivery configuration.
     *
     * @since    1.0.0
     * @access   private
     */
    private function setup_config() {
        $this->config = array(
            'from_name' => get_bloginfo('name') . ' Security Reports',
            'from_email' => get_option('admin_email'),
            'reply_to' => get_option('admin_email'),
            'content_type' => 'text/html',
            'charset' => 'UTF-8',
            'max_attachment_size' => 10 * 1024 * 1024, // 10MB
            'allowed_formats' => array('pdf', 'html', 'csv', 'json'),
            'rate_limit' => array(
                'enabled' => true,
                'max_per_hour' => 50,
                'max_per_day' => 200
            ),
            'retry_settings' => array(
                'max_attempts' => 3,
                'retry_delay' => 300, // 5 minutes
                'exponential_backoff' => true
            ),
            'delivery_tracking' => array(
                'enabled' => true,
                'track_opens' => false, // Privacy consideration
                'track_clicks' => false
            )
        );
    }

    /**
     * Setup email templates.
     *
     * @since    1.0.0
     * @access   private
     */
    private function setup_templates() {
        $this->templates = array(
            'security_report' => array(
                'subject' => '[{site_name}] Security Report - {report_date}',
                'template' => 'security-report-email.php'
            ),
            'vulnerability_alert' => array(
                'subject' => '[{site_name}] URGENT: Critical Vulnerabilities Detected',
                'template' => 'vulnerability-alert-email.php'
            ),
            'scheduled_report' => array(
                'subject' => '[{site_name}] Scheduled Security Report - {report_period}',
                'template' => 'scheduled-report-email.php'
            ),
            'compliance_report' => array(
                'subject' => '[{site_name}] Compliance Report - {compliance_framework}',
                'template' => 'compliance-report-email.php'
            ),
            'summary_digest' => array(
                'subject' => '[{site_name}] Security Summary Digest',
                'template' => 'summary-digest-email.php'
            )
        );
    }

    /**
     * Send security report via email.
     *
     * @since    1.0.0
     * @param    array    $report_data      Report data.
     * @param    array    $recipients       Email recipients.
     * @param    array    $options          Delivery options.
     * @return   array                      Delivery result.
     */
    public function send_report($report_data, $recipients, $options = array()) {
        try {
            // Validate inputs
            $this->validate_delivery_request($report_data, $recipients, $options);
            
            // Check rate limits
            if (!$this->check_rate_limits()) {
                throw new Exception('Rate limit exceeded. Please try again later.');
            }

            // Prepare email data
            $email_data = $this->prepare_email_data($report_data, $options);
            
            // Generate attachments if requested
            $attachments = $this->prepare_attachments($report_data, $options);
            
            // Send emails to all recipients
            $delivery_results = array();
            foreach ($recipients as $recipient) {
                $result = $this->send_individual_email($recipient, $email_data, $attachments, $options);
                $delivery_results[] = $result;
                
                // Log delivery attempt
                $this->log_delivery_attempt($recipient, $result, $report_data);
            }

            // Cleanup temporary files
            $this->cleanup_attachments($attachments);

            return array(
                'success' => true,
                'total_recipients' => count($recipients),
                'successful_deliveries' => count(array_filter($delivery_results, function($r) { return $r['success']; })),
                'failed_deliveries' => count(array_filter($delivery_results, function($r) { return !$r['success']; })),
                'delivery_results' => $delivery_results
            );

        } catch (Exception $e) {
            error_log("WP-Breach Email Delivery Error: " . $e->getMessage());
            return array(
                'success' => false,
                'error' => $e->getMessage()
            );
        }
    }

    /**
     * Send individual email to recipient.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $recipient       Recipient information.
     * @param    array    $email_data      Email content data.
     * @param    array    $attachments     Email attachments.
     * @param    array    $options         Delivery options.
     * @return   array                     Delivery result.
     */
    private function send_individual_email($recipient, $email_data, $attachments, $options) {
        $attempts = 0;
        $max_attempts = $this->config['retry_settings']['max_attempts'];
        
        while ($attempts < $max_attempts) {
            try {
                $attempts++;
                
                // Personalize email for recipient
                $personalized_data = $this->personalize_email($email_data, $recipient);
                
                // Prepare WordPress mail arguments
                $mail_args = array(
                    'to' => $recipient['email'],
                    'subject' => $personalized_data['subject'],
                    'message' => $personalized_data['body'],
                    'headers' => $this->build_email_headers($recipient, $options),
                    'attachments' => $this->filter_attachments_for_recipient($attachments, $recipient)
                );

                // Send email
                $sent = wp_mail(
                    $mail_args['to'],
                    $mail_args['subject'],
                    $mail_args['message'],
                    $mail_args['headers'],
                    $mail_args['attachments']
                );

                if ($sent) {
                    return array(
                        'success' => true,
                        'recipient' => $recipient['email'],
                        'attempts' => $attempts,
                        'sent_at' => current_time('mysql')
                    );
                } else {
                    throw new Exception('wp_mail returned false');
                }

            } catch (Exception $e) {
                if ($attempts >= $max_attempts) {
                    return array(
                        'success' => false,
                        'recipient' => $recipient['email'],
                        'attempts' => $attempts,
                        'error' => $e->getMessage(),
                        'failed_at' => current_time('mysql')
                    );
                }
                
                // Wait before retry (with exponential backoff)
                if ($this->config['retry_settings']['exponential_backoff']) {
                    $delay = $this->config['retry_settings']['retry_delay'] * pow(2, $attempts - 1);
                } else {
                    $delay = $this->config['retry_settings']['retry_delay'];
                }
                
                sleep($delay);
            }
        }
    }

    /**
     * Prepare email data from report.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $report_data     Report data.
     * @param    array    $options         Email options.
     * @return   array                     Prepared email data.
     */
    private function prepare_email_data($report_data, $options) {
        $template_type = $options['template'] ?? 'security_report';
        $template_config = $this->templates[$template_type] ?? $this->templates['security_report'];
        
        // Prepare template variables
        $template_vars = array(
            'site_name' => get_bloginfo('name'),
            'site_url' => home_url(),
            'report_date' => current_time('F j, Y'),
            'report_time' => current_time('g:i A'),
            'report_data' => $report_data,
            'summary' => $report_data['data']['summary'] ?? array(),
            'security_score' => $report_data['data']['security_score'] ?? array(),
            'vulnerability_count' => count($report_data['data']['vulnerabilities'] ?? array()),
            'critical_count' => $this->count_vulnerabilities_by_severity($report_data, 'critical'),
            'high_count' => $this->count_vulnerabilities_by_severity($report_data, 'high'),
            'report_period' => $options['report_period'] ?? 'Current',
            'compliance_framework' => $options['compliance_framework'] ?? 'General'
        );

        // Generate subject
        $subject = $this->process_template_string($template_config['subject'], $template_vars);
        
        // Generate body
        $body = $this->render_email_template($template_config['template'], $template_vars);

        return array(
            'subject' => $subject,
            'body' => $body,
            'template_vars' => $template_vars
        );
    }

    /**
     * Render email template.
     *
     * @since    1.0.0
     * @access   private
     * @param    string   $template_file   Template filename.
     * @param    array    $vars           Template variables.
     * @return   string                   Rendered template.
     */
    private function render_email_template($template_file, $vars) {
        // Check for custom template in theme
        $custom_template = get_stylesheet_directory() . '/wp-breach/email-templates/' . $template_file;
        
        if (file_exists($custom_template)) {
            $template_path = $custom_template;
        } else {
            // Use default template
            $template_path = plugin_dir_path(__FILE__) . '../templates/email/' . $template_file;
        }

        if (!file_exists($template_path)) {
            // Fallback to basic template
            return $this->render_basic_email_template($vars);
        }

        // Extract variables for template
        extract($vars);
        
        // Start output buffering
        ob_start();
        include $template_path;
        $content = ob_get_clean();

        return $content;
    }

    /**
     * Render basic email template as fallback.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $vars           Template variables.
     * @return   string                   Rendered template.
     */
    private function render_basic_email_template($vars) {
        $site_name = $vars['site_name'];
        $report_date = $vars['report_date'];
        $vulnerability_count = $vars['vulnerability_count'];
        $critical_count = $vars['critical_count'];
        $high_count = $vars['high_count'];
        $site_url = $vars['site_url'];

        $html = "
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset='UTF-8'>
            <title>Security Report</title>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .header { background: #0073aa; color: white; padding: 20px; text-align: center; }
                .content { padding: 20px; background: #f9f9f9; }
                .summary { background: white; padding: 15px; margin: 20px 0; border-left: 4px solid #0073aa; }
                .alert { background: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; margin: 10px 0; }
                .critical { background: #f8d7da; border-color: #f5c6cb; }
                .footer { text-align: center; padding: 20px; font-size: 12px; color: #666; }
                .button { display: inline-block; padding: 10px 20px; background: #0073aa; color: white; text-decoration: none; border-radius: 4px; }
            </style>
        </head>
        <body>
            <div class='container'>
                <div class='header'>
                    <h1>Security Report</h1>
                    <p>{$site_name} - {$report_date}</p>
                </div>
                
                <div class='content'>
                    <div class='summary'>
                        <h2>Security Summary</h2>
                        <p><strong>Total Vulnerabilities:</strong> {$vulnerability_count}</p>
                        <p><strong>Critical Issues:</strong> {$critical_count}</p>
                        <p><strong>High Priority Issues:</strong> {$high_count}</p>
                    </div>";

        if ($critical_count > 0) {
            $html .= "
                    <div class='alert critical'>
                        <strong>⚠️ Critical Issues Detected!</strong><br>
                        Your site has {$critical_count} critical security issue(s) that require immediate attention.
                    </div>";
        }

        $html .= "
                    <p>A comprehensive security report has been generated for your website. Please review the attached report for detailed information about detected vulnerabilities and recommended actions.</p>
                    
                    <p style='text-align: center; margin: 30px 0;'>
                        <a href='{$site_url}/wp-admin/admin.php?page=wp-breach-reports' class='button'>View Full Report</a>
                    </p>
                </div>
                
                <div class='footer'>
                    <p>This report was generated automatically by WP-Breach Security Plugin.<br>
                    If you have questions, please contact your site administrator.</p>
                    <p><a href='{$site_url}'>{$site_name}</a></p>
                </div>
            </div>
        </body>
        </html>";

        return $html;
    }

    /**
     * Prepare email attachments.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $report_data     Report data.
     * @param    array    $options         Email options.
     * @return   array                     Attachment file paths.
     */
    private function prepare_attachments($report_data, $options) {
        $attachments = array();
        $requested_formats = $options['attach_formats'] ?? array('pdf');
        
        foreach ($requested_formats as $format) {
            if (!in_array($format, $this->config['allowed_formats'])) {
                continue;
            }

            try {
                $attachment_path = $this->generate_attachment($report_data, $format, $options);
                
                if ($attachment_path && file_exists($attachment_path)) {
                    // Check file size
                    if (filesize($attachment_path) <= $this->config['max_attachment_size']) {
                        $attachments[] = $attachment_path;
                    } else {
                        error_log("WP-Breach: Attachment too large for email: {$attachment_path}");
                    }
                }
            } catch (Exception $e) {
                error_log("WP-Breach: Failed to generate {$format} attachment: " . $e->getMessage());
            }
        }

        return $attachments;
    }

    /**
     * Generate attachment file for email.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $report_data     Report data.
     * @param    string   $format          File format.
     * @param    array    $options         Generation options.
     * @return   string                    File path or false on failure.
     */
    private function generate_attachment($report_data, $format, $options) {
        switch ($format) {
            case 'pdf':
                $exporter = new WP_Breach_PDF_Exporter();
                break;
            case 'html':
                $exporter = new WP_Breach_HTML_Exporter();
                break;
            case 'csv':
                $exporter = new WP_Breach_CSV_Exporter();
                break;
            case 'json':
                $exporter = new WP_Breach_JSON_Exporter();
                break;
            default:
                return false;
        }

        $export_options = array_merge($options, array(
            'email_attachment' => true,
            'temp_file' => true
        ));

        $result = $exporter->export($report_data, $export_options);
        
        return ($result['success'] ?? false) ? $result['file_path'] : false;
    }

    /**
     * Build email headers.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $recipient       Recipient information.
     * @param    array    $options         Email options.
     * @return   array                     Email headers.
     */
    private function build_email_headers($recipient, $options) {
        $headers = array();
        
        // From header
        $headers[] = 'From: ' . $this->config['from_name'] . ' <' . $this->config['from_email'] . '>';
        
        // Reply-To header
        if (!empty($this->config['reply_to'])) {
            $headers[] = 'Reply-To: ' . $this->config['reply_to'];
        }
        
        // Content-Type header
        $headers[] = 'Content-Type: ' . $this->config['content_type'] . '; charset=' . $this->config['charset'];
        
        // Priority header for urgent reports
        if (($options['priority'] ?? 'normal') === 'high') {
            $headers[] = 'X-Priority: 1';
            $headers[] = 'X-MSMail-Priority: High';
            $headers[] = 'Importance: High';
        }

        return $headers;
    }

    /**
     * Validate delivery request.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $report_data     Report data.
     * @param    array    $recipients      Recipients.
     * @param    array    $options         Options.
     * @throws   Exception               If validation fails.
     */
    private function validate_delivery_request($report_data, $recipients, $options) {
        if (empty($report_data)) {
            throw new Exception('Report data is required');
        }

        if (empty($recipients) || !is_array($recipients)) {
            throw new Exception('Valid recipients array is required');
        }

        foreach ($recipients as $recipient) {
            if (empty($recipient['email']) || !is_email($recipient['email'])) {
                throw new Exception('Invalid email address: ' . ($recipient['email'] ?? 'empty'));
            }
        }
    }

    /**
     * Check rate limits for email delivery.
     *
     * @since    1.0.0
     * @access   private
     * @return   bool                     True if within limits.
     */
    private function check_rate_limits() {
        if (!$this->config['rate_limit']['enabled']) {
            return true;
        }

        // Get recent delivery counts
        $hourly_count = $this->get_delivery_count('hour');
        $daily_count = $this->get_delivery_count('day');

        return $hourly_count < $this->config['rate_limit']['max_per_hour'] &&
               $daily_count < $this->config['rate_limit']['max_per_day'];
    }

    /**
     * Get delivery count for time period.
     *
     * @since    1.0.0
     * @access   private
     * @param    string   $period         Time period ('hour' or 'day').
     * @return   int                      Delivery count.
     */
    private function get_delivery_count($period) {
        $transient_key = 'wp_breach_email_count_' . $period;
        return (int) get_transient($transient_key);
    }

    /**
     * Log delivery attempt.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $recipient      Recipient information.
     * @param    array    $result         Delivery result.
     * @param    array    $report_data    Report data.
     */
    private function log_delivery_attempt($recipient, $result, $report_data) {
        // Update rate limit counters
        if ($result['success']) {
            $this->increment_delivery_counter('hour');
            $this->increment_delivery_counter('day');
        }

        // Log to delivery tracking if enabled
        if ($this->config['delivery_tracking']['enabled']) {
            $log_entry = array(
                'timestamp' => current_time('mysql'),
                'recipient' => $recipient['email'],
                'success' => $result['success'],
                'report_type' => $report_data['type'] ?? 'unknown',
                'error' => $result['error'] ?? null
            );

            $this->delivery_log[] = $log_entry;
            
            // Store in database or transient
            $this->store_delivery_log($log_entry);
        }
    }

    /**
     * Increment delivery counter.
     *
     * @since    1.0.0
     * @access   private
     * @param    string   $period         Time period.
     */
    private function increment_delivery_counter($period) {
        $transient_key = 'wp_breach_email_count_' . $period;
        $expiration = $period === 'hour' ? HOUR_IN_SECONDS : DAY_IN_SECONDS;
        
        $count = (int) get_transient($transient_key);
        set_transient($transient_key, $count + 1, $expiration);
    }

    /**
     * Set HTML content type for wp_mail.
     *
     * @since    1.0.0
     * @return   string                   Content type.
     */
    public function set_html_content_type() {
        return 'text/html';
    }

    /**
     * Handle wp_mail failures.
     *
     * @since    1.0.0
     * @param    WP_Error $wp_error      WordPress error object.
     */
    public function handle_mail_failure($wp_error) {
        error_log('WP-Breach Email Delivery Failed: ' . $wp_error->get_error_message());
    }

    // Helper methods...
    private function personalize_email($email_data, $recipient) { 
        $personalized = $email_data;
        
        // Replace recipient-specific placeholders
        if (!empty($recipient['name'])) {
            $personalized['body'] = str_replace('{recipient_name}', $recipient['name'], $personalized['body']);
            $personalized['subject'] = str_replace('{recipient_name}', $recipient['name'], $personalized['subject']);
        }
        
        return $personalized;
    }
    
    private function filter_attachments_for_recipient($attachments, $recipient) { 
        // Filter attachments based on recipient preferences
        return $attachments;
    }
    
    private function count_vulnerabilities_by_severity($report_data, $severity) {
        if (!isset($report_data['data']['vulnerabilities'])) {
            return 0;
        }
        
        return count(array_filter($report_data['data']['vulnerabilities'], function($vuln) use ($severity) {
            return strtolower($vuln['severity'] ?? '') === $severity;
        }));
    }
    
    private function process_template_string($template, $vars) {
        $processed = $template;
        foreach ($vars as $key => $value) {
            if (is_scalar($value)) {
                $processed = str_replace('{' . $key . '}', $value, $processed);
            }
        }
        return $processed;
    }
    
    private function cleanup_attachments($attachments) {
        foreach ($attachments as $file_path) {
            if (file_exists($file_path) && strpos($file_path, 'temp') !== false) {
                unlink($file_path);
            }
        }
    }
    
    private function store_delivery_log($log_entry) {
        // Store in WordPress options or custom table
        $existing_log = get_option('wp_breach_email_delivery_log', array());
        $existing_log[] = $log_entry;
        
        // Keep only last 1000 entries
        if (count($existing_log) > 1000) {
            $existing_log = array_slice($existing_log, -1000);
        }
        
        update_option('wp_breach_email_delivery_log', $existing_log);
    }
}

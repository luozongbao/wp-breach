<?php

/**
 * Email Alert Channel for WP-Breach.
 *
 * This class handles email delivery of security alerts with customizable
 * templates, delivery modes, and advanced email features.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/monitoring/channels
 */

/**
 * The email alert channel class.
 *
 * Manages email alert delivery including immediate alerts, batch processing,
 * digest emails, and advanced formatting options.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/monitoring/channels
 * @author     WP Breach Team
 */
class WP_Breach_Email_Alert_Channel {

    /**
     * Email configuration.
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
     * Recipients list.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $recipients    Alert recipients.
     */
    private $recipients;

    /**
     * Batch queue for digest emails.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $batch_queue    Batched alerts.
     */
    private $batch_queue;

    /**
     * Initialize the email alert channel.
     *
     * @since    1.0.0
     */
    public function __construct() {
        $this->setup_config();
        $this->setup_templates();
        $this->setup_recipients();
        $this->batch_queue = array();
        
        // Register hooks
        $this->register_hooks();
    }

    /**
     * Setup email configuration.
     *
     * @since    1.0.0
     * @access   private
     */
    private function setup_config() {
        $this->config = array(
            'enabled' => true,
            'from_name' => get_bloginfo('name') . ' Security',
            'from_email' => get_option('admin_email'),
            'reply_to' => get_option('admin_email'),
            'content_type' => 'text/html',
            'charset' => 'UTF-8',
            'batch_enabled' => true,
            'batch_size' => 10,
            'batch_interval' => 300, // 5 minutes
            'digest_enabled' => true,
            'digest_frequency' => 'daily', // hourly, daily, weekly
            'priority_bypass' => true, // Send critical alerts immediately even in batch mode
            'html_enabled' => true,
            'attachments_enabled' => false,
            'max_email_size' => 1048576, // 1MB
            'rate_limiting' => true,
            'max_emails_per_hour' => 20,
            'retry_attempts' => 3,
            'retry_delay' => 300, // 5 minutes
            'bounce_handling' => false,
            'unsubscribe_link' => true,
            'tracking_enabled' => false,
            'compression' => false,
            'encryption' => false
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
            'immediate' => array(
                'subject' => '[SECURITY ALERT] {severity} - {title}',
                'header' => $this->get_email_header(),
                'body' => $this->get_immediate_alert_template(),
                'footer' => $this->get_email_footer()
            ),
            'batch' => array(
                'subject' => '[SECURITY BATCH] {count} security alerts',
                'header' => $this->get_email_header(),
                'body' => $this->get_batch_alert_template(),
                'footer' => $this->get_email_footer()
            ),
            'digest' => array(
                'subject' => '[SECURITY DIGEST] {period} Security Summary',
                'header' => $this->get_email_header(),
                'body' => $this->get_digest_template(),
                'footer' => $this->get_email_footer()
            ),
            'escalation' => array(
                'subject' => '[ESCALATED] {severity} - {title}',
                'header' => $this->get_email_header(),
                'body' => $this->get_escalation_template(),
                'footer' => $this->get_email_footer()
            )
        );
    }

    /**
     * Setup alert recipients.
     *
     * @since    1.0.0
     * @access   private
     */
    private function setup_recipients() {
        $this->recipients = array(
            'administrators' => array(
                'enabled' => true,
                'alert_types' => array('all'),
                'severity_levels' => array('critical', 'high', 'medium', 'low'),
                'delivery_modes' => array('immediate', 'batch', 'digest'),
                'emails' => $this->get_admin_emails()
            ),
            'security_team' => array(
                'enabled' => false,
                'alert_types' => array('malware_detected', 'brute_force_attack', 'system_compromise'),
                'severity_levels' => array('critical', 'high'),
                'delivery_modes' => array('immediate'),
                'emails' => array()
            ),
            'custom_recipients' => array(
                'enabled' => true,
                'alert_types' => array(),
                'severity_levels' => array(),
                'delivery_modes' => array('digest'),
                'emails' => get_option('wp_breach_custom_alert_emails', array())
            )
        );
    }

    /**
     * Register WordPress hooks.
     *
     * @since    1.0.0
     * @access   private
     */
    private function register_hooks() {
        // Email processing
        add_action('wp_breach_process_email_batch', array($this, 'process_batch_queue'));
        add_action('wp_breach_send_digest_email', array($this, 'send_digest_email'));
        
        // Email configuration
        add_filter('wp_mail_from', array($this, 'set_email_from'));
        add_filter('wp_mail_from_name', array($this, 'set_email_from_name'));
        add_filter('wp_mail_content_type', array($this, 'set_email_content_type'));
        
        // Schedule digest emails
        $this->schedule_digest_emails();
    }

    /**
     * Send alert via email.
     *
     * @since    1.0.0
     * @param    array    $alert          Alert data.
     * @param    string   $delivery_mode  Delivery mode (immediate, batch, digest).
     * @return   array                    Send result.
     */
    public function send_alert($alert, $delivery_mode = 'immediate') {
        try {
            if (!$this->config['enabled']) {
                return array(
                    'success' => false,
                    'error' => 'Email channel disabled'
                );
            }
            
            // Check rate limits
            if ($this->config['rate_limiting'] && !$this->check_rate_limits()) {
                return array(
                    'success' => false,
                    'error' => 'Rate limit exceeded'
                );
            }
            
            switch ($delivery_mode) {
                case 'immediate':
                    return $this->send_immediate_alert($alert);
                    
                case 'batch':
                    return $this->add_to_batch($alert);
                    
                case 'digest':
                    return $this->add_to_digest($alert);
                    
                default:
                    return array(
                        'success' => false,
                        'error' => 'Invalid delivery mode'
                    );
            }

        } catch (Exception $e) {
            error_log("WP-Breach Email Alert Error: " . $e->getMessage());
            return array(
                'success' => false,
                'error' => $e->getMessage()
            );
        }
    }

    /**
     * Send immediate alert email.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $alert    Alert data.
     * @return   array             Send result.
     */
    private function send_immediate_alert($alert) {
        // Get applicable recipients
        $recipients = $this->get_alert_recipients($alert, 'immediate');
        
        if (empty($recipients)) {
            return array(
                'success' => true,
                'message' => 'No recipients configured for this alert'
            );
        }
        
        // Prepare email content
        $template_type = $alert['escalated'] ?? false ? 'escalation' : 'immediate';
        $email_content = $this->prepare_email_content($alert, $template_type);
        
        // Send to each recipient
        $results = array();
        foreach ($recipients as $email) {
            $send_result = $this->send_email($email, $email_content);
            $results[$email] = $send_result;
        }
        
        // Check if any emails were successful
        $success_count = count(array_filter($results, function($result) {
            return $result['success'];
        }));
        
        return array(
            'success' => $success_count > 0,
            'sent_count' => $success_count,
            'total_recipients' => count($recipients),
            'results' => $results
        );
    }

    /**
     * Add alert to batch queue.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $alert    Alert data.
     * @return   array             Result.
     */
    private function add_to_batch($alert) {
        // Check if critical alerts should bypass batching
        if ($this->config['priority_bypass'] && $alert['severity'] === 'critical') {
            return $this->send_immediate_alert($alert);
        }
        
        // Add to batch queue
        $this->batch_queue[] = array(
            'alert' => $alert,
            'timestamp' => time()
        );
        
        // Save batch queue
        update_option('wp_breach_email_batch_queue', $this->batch_queue);
        
        // Schedule batch processing if not already scheduled
        if (!wp_next_scheduled('wp_breach_process_email_batch')) {
            wp_schedule_single_event(
                time() + $this->config['batch_interval'],
                'wp_breach_process_email_batch'
            );
        }
        
        return array(
            'success' => true,
            'message' => 'Alert added to batch queue',
            'batch_size' => count($this->batch_queue)
        );
    }

    /**
     * Process batch queue.
     *
     * @since    1.0.0
     */
    public function process_batch_queue() {
        // Load batch queue
        $this->batch_queue = get_option('wp_breach_email_batch_queue', array());
        
        if (empty($this->batch_queue)) {
            return;
        }
        
        // Group alerts by severity and type
        $grouped_alerts = $this->group_batch_alerts($this->batch_queue);
        
        // Send batch emails
        foreach ($grouped_alerts as $group) {
            $this->send_batch_email($group);
        }
        
        // Clear processed batch
        $this->batch_queue = array();
        update_option('wp_breach_email_batch_queue', $this->batch_queue);
    }

    /**
     * Send batch email.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $alert_group    Grouped alerts.
     */
    private function send_batch_email($alert_group) {
        $recipients = $this->get_batch_recipients($alert_group);
        
        if (empty($recipients)) {
            return;
        }
        
        // Prepare batch email content
        $email_content = $this->prepare_batch_email_content($alert_group);
        
        // Send to recipients
        foreach ($recipients as $email) {
            $this->send_email($email, $email_content);
        }
    }

    /**
     * Prepare email content.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $alert           Alert data.
     * @param    string   $template_type   Template type.
     * @return   array                     Email content.
     */
    private function prepare_email_content($alert, $template_type = 'immediate') {
        $template = $this->templates[$template_type];
        
        // Prepare variables for template replacement
        $variables = array(
            '{site_name}' => get_bloginfo('name'),
            '{site_url}' => get_site_url(),
            '{alert_title}' => $alert['title'],
            '{alert_message}' => $alert['message'],
            '{severity}' => strtoupper($alert['severity']),
            '{alert_type}' => $alert['type'],
            '{timestamp}' => $alert['created_at'],
            '{source}' => $alert['source'] ?? 'WP-Breach',
            '{dashboard_url}' => admin_url('admin.php?page=wp-breach-dashboard'),
            '{unsubscribe_url}' => $this->get_unsubscribe_url()
        );
        
        // Add alert-specific details
        if (!empty($alert['details'])) {
            $variables['{details}'] = $this->format_alert_details($alert['details']);
        }
        
        // Escalation-specific variables
        if ($template_type === 'escalation') {
            $variables['{escalation_level}'] = $alert['escalation_level'] ?? 1;
            $variables['{escalation_time}'] = date('Y-m-d H:i:s');
        }
        
        // Replace variables in template
        $subject = str_replace(array_keys($variables), array_values($variables), $template['subject']);
        $body = $template['header'] . str_replace(array_keys($variables), array_values($variables), $template['body']) . $template['footer'];
        
        return array(
            'subject' => $subject,
            'body' => $body,
            'headers' => $this->get_email_headers()
        );
    }

    /**
     * Send email using WordPress mail function.
     *
     * @since    1.0.0
     * @access   private
     * @param    string   $to       Recipient email.
     * @param    array    $content  Email content.
     * @return   array             Send result.
     */
    private function send_email($to, $content) {
        $attempts = 0;
        $max_attempts = $this->config['retry_attempts'];
        
        while ($attempts < $max_attempts) {
            $result = wp_mail(
                $to,
                $content['subject'],
                $content['body'],
                $content['headers']
            );
            
            if ($result) {
                $this->update_rate_limits();
                return array(
                    'success' => true,
                    'attempts' => $attempts + 1
                );
            }
            
            $attempts++;
            if ($attempts < $max_attempts) {
                sleep($this->config['retry_delay']);
            }
        }
        
        return array(
            'success' => false,
            'error' => 'Failed to send email after ' . $max_attempts . ' attempts',
            'attempts' => $attempts
        );
    }

    /**
     * Get alert recipients based on alert criteria.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $alert           Alert data.
     * @param    string   $delivery_mode   Delivery mode.
     * @return   array                     Recipient emails.
     */
    private function get_alert_recipients($alert, $delivery_mode) {
        $recipients = array();
        
        foreach ($this->recipients as $group_name => $group) {
            if (!$group['enabled']) {
                continue;
            }
            
            // Check delivery mode
            if (!in_array($delivery_mode, $group['delivery_modes'])) {
                continue;
            }
            
            // Check severity level
            if (!in_array($alert['severity'], $group['severity_levels']) && !in_array('all', $group['severity_levels'])) {
                continue;
            }
            
            // Check alert type
            if (!in_array($alert['type'], $group['alert_types']) && !in_array('all', $group['alert_types'])) {
                continue;
            }
            
            // Add group emails
            $recipients = array_merge($recipients, $group['emails']);
        }
        
        return array_unique($recipients);
    }

    /**
     * Get email header template.
     *
     * @since    1.0.0
     * @access   private
     * @return   string    Email header HTML.
     */
    private function get_email_header() {
        return '
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>WP-Breach Security Alert</title>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; }
                .header { background: #d73527; color: white; padding: 20px; text-align: center; }
                .content { padding: 20px; background: #f9f9f9; }
                .alert-box { background: white; border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin: 10px 0; }
                .critical { border-left: 5px solid #d73527; }
                .high { border-left: 5px solid #ff6b35; }
                .medium { border-left: 5px solid #f7931e; }
                .low { border-left: 5px solid #2e8b57; }
                .footer { background: #333; color: white; padding: 15px; text-align: center; font-size: 12px; }
                .button { display: inline-block; background: #0073aa; color: white; padding: 10px 20px; text-decoration: none; border-radius: 3px; }
                .details { background: #f0f0f0; padding: 10px; border-radius: 3px; font-family: monospace; font-size: 12px; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🛡️ WP-Breach Security Alert</h1>
                <p>Security monitoring for {site_name}</p>
            </div>
            <div class="content">';
    }

    /**
     * Get immediate alert template.
     *
     * @since    1.0.0
     * @access   private
     * @return   string    Alert template HTML.
     */
    private function get_immediate_alert_template() {
        return '
        <div class="alert-box {severity}">
            <h2>🚨 Security Alert: {alert_title}</h2>
            <p><strong>Severity:</strong> <span style="text-transform: uppercase; font-weight: bold; color: #d73527;">{severity}</span></p>
            <p><strong>Alert Type:</strong> {alert_type}</p>
            <p><strong>Time:</strong> {timestamp}</p>
            <p><strong>Source:</strong> {source}</p>
            
            <h3>Alert Details:</h3>
            <p>{alert_message}</p>
            
            {details}
            
            <div style="text-align: center; margin: 20px 0;">
                <a href="{dashboard_url}" class="button">View Security Dashboard</a>
            </div>
        </div>';
    }

    /**
     * Get batch alert template.
     *
     * @since    1.0.0
     * @access   private
     * @return   string    Batch template HTML.
     */
    private function get_batch_alert_template() {
        return '
        <h2>📊 Security Alert Summary</h2>
        <p>The following security alerts have been detected for {site_name}:</p>
        
        {alert_summary}
        
        <div style="text-align: center; margin: 20px 0;">
            <a href="{dashboard_url}" class="button">View Full Security Dashboard</a>
        </div>';
    }

    /**
     * Get digest template.
     *
     * @since    1.0.0
     * @access   private
     * @return   string    Digest template HTML.
     */
    private function get_digest_template() {
        return '
        <h2>📈 Security Digest Report</h2>
        <p>Security summary for {site_name} - {period}</p>
        
        {digest_content}
        
        <div style="text-align: center; margin: 20px 0;">
            <a href="{dashboard_url}" class="button">View Detailed Reports</a>
        </div>';
    }

    /**
     * Get escalation template.
     *
     * @since    1.0.0
     * @access   private
     * @return   string    Escalation template HTML.
     */
    private function get_escalation_template() {
        return '
        <div class="alert-box critical">
            <h2>🔥 ESCALATED SECURITY ALERT</h2>
            <p style="color: #d73527; font-weight: bold;">This alert has been escalated to level {escalation_level}</p>
            
            <h3>Original Alert:</h3>
            <p><strong>Title:</strong> {alert_title}</p>
            <p><strong>Severity:</strong> {severity}</p>
            <p><strong>Type:</strong> {alert_type}</p>
            <p><strong>Original Time:</strong> {timestamp}</p>
            <p><strong>Escalation Time:</strong> {escalation_time}</p>
            
            <h3>Alert Details:</h3>
            <p>{alert_message}</p>
            
            {details}
            
            <div style="background: #ffe6e6; border: 1px solid #ffcccc; padding: 10px; border-radius: 3px; margin: 10px 0;">
                <strong>⚠️ IMMEDIATE ACTION REQUIRED</strong><br>
                This security alert requires immediate attention due to escalation.
            </div>
            
            <div style="text-align: center; margin: 20px 0;">
                <a href="{dashboard_url}" class="button">Take Action Now</a>
            </div>
        </div>';
    }

    /**
     * Get email footer template.
     *
     * @since    1.0.0
     * @access   private
     * @return   string    Email footer HTML.
     */
    private function get_email_footer() {
        return '
            </div>
            <div class="footer">
                <p>This email was sent by WP-Breach Security Plugin for {site_name}</p>
                <p>Visit: <a href="{site_url}" style="color: #ccc;">{site_url}</a></p>
                {unsubscribe_link}
                <p style="font-size: 10px; margin-top: 10px;">
                    WP-Breach Security Plugin - Protecting WordPress sites from threats
                </p>
            </div>
        </body>
        </html>';
    }

    /**
     * Format alert details for email display.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $details    Alert details.
     * @return   string              Formatted details HTML.
     */
    private function format_alert_details($details) {
        if (empty($details)) {
            return '';
        }
        
        $html = '<div class="details"><h4>Technical Details:</h4>';
        
        foreach ($details as $key => $value) {
            $formatted_key = ucwords(str_replace('_', ' ', $key));
            
            if (is_array($value)) {
                $html .= "<strong>{$formatted_key}:</strong><br>";
                $html .= "<ul>";
                foreach ($value as $item) {
                    $html .= "<li>" . esc_html(is_array($item) ? json_encode($item) : $item) . "</li>";
                }
                $html .= "</ul>";
            } else {
                $html .= "<strong>{$formatted_key}:</strong> " . esc_html($value) . "<br>";
            }
        }
        
        $html .= '</div>';
        return $html;
    }

    /**
     * Get email headers.
     *
     * @since    1.0.0
     * @access   private
     * @return   array    Email headers.
     */
    private function get_email_headers() {
        $headers = array();
        
        if ($this->config['html_enabled']) {
            $headers[] = 'Content-Type: text/html; charset=' . $this->config['charset'];
        }
        
        if (!empty($this->config['reply_to'])) {
            $headers[] = 'Reply-To: ' . $this->config['reply_to'];
        }
        
        // Add security headers
        $headers[] = 'X-Mailer: WP-Breach Security Plugin';
        $headers[] = 'X-Priority: 1';
        $headers[] = 'Importance: high';
        
        return $headers;
    }

    /**
     * Get administrator emails.
     *
     * @since    1.0.0
     * @access   private
     * @return   array    Admin email addresses.
     */
    private function get_admin_emails() {
        $admin_emails = array();
        
        // Get all administrator users
        $admins = get_users(array('role' => 'administrator'));
        
        foreach ($admins as $admin) {
            if (!empty($admin->user_email)) {
                $admin_emails[] = $admin->user_email;
            }
        }
        
        // Fallback to site admin email
        if (empty($admin_emails)) {
            $admin_emails[] = get_option('admin_email');
        }
        
        return array_unique($admin_emails);
    }

    /**
     * Check email rate limits.
     *
     * @since    1.0.0
     * @access   private
     * @return   bool    Whether rate limit allows sending.
     */
    private function check_rate_limits() {
        $current_hour = date('Y-m-d H');
        $rate_key = "email_rate_{$current_hour}";
        $current_count = get_transient($rate_key) ?: 0;
        
        return $current_count < $this->config['max_emails_per_hour'];
    }

    /**
     * Update rate limiting counters.
     *
     * @since    1.0.0
     * @access   private
     */
    private function update_rate_limits() {
        $current_hour = date('Y-m-d H');
        $rate_key = "email_rate_{$current_hour}";
        $current_count = get_transient($rate_key) ?: 0;
        
        set_transient($rate_key, $current_count + 1, HOUR_IN_SECONDS);
    }

    /**
     * Get unsubscribe URL.
     *
     * @since    1.0.0
     * @access   private
     * @return   string    Unsubscribe URL.
     */
    private function get_unsubscribe_url() {
        if (!$this->config['unsubscribe_link']) {
            return '';
        }
        
        $url = add_query_arg(array(
            'action' => 'wp_breach_unsubscribe',
            'nonce' => wp_create_nonce('wp_breach_unsubscribe')
        ), admin_url('admin-ajax.php'));
        
        return '<p><a href="' . $url . '" style="color: #ccc; font-size: 10px;">Unsubscribe from security alerts</a></p>';
    }

    /**
     * Group batch alerts for organized email sending.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $batch_alerts    Batch alert queue.
     * @return   array                     Grouped alerts.
     */
    private function group_batch_alerts($batch_alerts) {
        $groups = array();
        
        foreach ($batch_alerts as $batch_item) {
            $alert = $batch_item['alert'];
            $group_key = $alert['severity'] . '_' . $alert['type'];
            
            if (!isset($groups[$group_key])) {
                $groups[$group_key] = array(
                    'severity' => $alert['severity'],
                    'type' => $alert['type'],
                    'alerts' => array(),
                    'count' => 0
                );
            }
            
            $groups[$group_key]['alerts'][] = $alert;
            $groups[$group_key]['count']++;
        }
        
        return $groups;
    }

    /**
     * Prepare batch email content.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $alert_group    Grouped alerts.
     * @return   array                    Email content.
     */
    private function prepare_batch_email_content($alert_group) {
        $template = $this->templates['batch'];
        
        // Create alert summary
        $summary_html = '<div class="alert-box ' . $alert_group['severity'] . '">';
        $summary_html .= '<h3>' . $alert_group['count'] . ' ' . ucwords(str_replace('_', ' ', $alert_group['type'])) . ' Alert(s)</h3>';
        $summary_html .= '<p><strong>Severity:</strong> ' . strtoupper($alert_group['severity']) . '</p>';
        
        $summary_html .= '<div style="margin: 10px 0;"><strong>Recent Alerts:</strong></div>';
        
        foreach (array_slice($alert_group['alerts'], 0, 5) as $alert) {
            $summary_html .= '<div style="margin: 5px 0; padding: 5px; background: #f5f5f5; border-radius: 3px;">';
            $summary_html .= '<strong>' . $alert['title'] . '</strong><br>';
            $summary_html .= '<small>' . $alert['created_at'] . '</small>';
            $summary_html .= '</div>';
        }
        
        if ($alert_group['count'] > 5) {
            $remaining = $alert_group['count'] - 5;
            $summary_html .= '<p><small>... and ' . $remaining . ' more alert(s)</small></p>';
        }
        
        $summary_html .= '</div>';
        
        // Prepare variables
        $variables = array(
            '{site_name}' => get_bloginfo('name'),
            '{site_url}' => get_site_url(),
            '{count}' => $alert_group['count'],
            '{alert_summary}' => $summary_html,
            '{dashboard_url}' => admin_url('admin.php?page=wp-breach-dashboard'),
            '{unsubscribe_url}' => $this->get_unsubscribe_url()
        );
        
        // Replace variables
        $subject = str_replace(array_keys($variables), array_values($variables), $template['subject']);
        $body = $template['header'] . str_replace(array_keys($variables), array_values($variables), $template['body']) . $template['footer'];
        
        return array(
            'subject' => $subject,
            'body' => $body,
            'headers' => $this->get_email_headers()
        );
    }

    /**
     * Get batch recipients.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $alert_group    Alert group.
     * @return   array                    Recipients.
     */
    private function get_batch_recipients($alert_group) {
        // Use first alert in group to determine recipients
        $sample_alert = $alert_group['alerts'][0];
        return $this->get_alert_recipients($sample_alert, 'batch');
    }

    /**
     * Schedule digest emails.
     *
     * @since    1.0.0
     * @access   private
     */
    private function schedule_digest_emails() {
        if (!$this->config['digest_enabled']) {
            return;
        }
        
        $frequency = $this->config['digest_frequency'];
        
        if (!wp_next_scheduled('wp_breach_send_digest_email')) {
            wp_schedule_event(time(), $frequency, 'wp_breach_send_digest_email');
        }
    }

    /**
     * Send digest email.
     *
     * @since    1.0.0
     */
    public function send_digest_email() {
        if (!$this->config['digest_enabled']) {
            return;
        }
        
        // Get digest period data
        $period = $this->config['digest_frequency'];
        $digest_data = $this->get_digest_data($period);
        
        if (empty($digest_data['alerts'])) {
            return; // No alerts to digest
        }
        
        // Get digest recipients
        $recipients = $this->get_digest_recipients();
        
        if (empty($recipients)) {
            return;
        }
        
        // Prepare digest email
        $email_content = $this->prepare_digest_email_content($digest_data, $period);
        
        // Send to recipients
        foreach ($recipients as $email) {
            $this->send_email($email, $email_content);
        }
    }

    /**
     * Get digest data for specified period.
     *
     * @since    1.0.0
     * @access   private
     * @param    string   $period    Digest period.
     * @return   array              Digest data.
     */
    private function get_digest_data($period) {
        // Get alerts from specified period
        $time_ranges = array(
            'hourly' => '-1 hour',
            'daily' => '-1 day',
            'weekly' => '-1 week'
        );
        
        $start_time = date('Y-m-d H:i:s', strtotime($time_ranges[$period] ?? '-1 day'));
        
        global $wpdb;
        $table_name = $wpdb->prefix . 'breach_alerts';
        
        $alerts = $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM {$table_name} WHERE created_at >= %s ORDER BY created_at DESC",
            $start_time
        ));
        
        // Compile digest statistics
        $digest_data = array(
            'period' => $period,
            'start_time' => $start_time,
            'alerts' => $alerts,
            'total_alerts' => count($alerts),
            'by_severity' => array(),
            'by_type' => array(),
            'critical_alerts' => array()
        );
        
        foreach ($alerts as $alert) {
            // Count by severity
            $digest_data['by_severity'][$alert->severity] = ($digest_data['by_severity'][$alert->severity] ?? 0) + 1;
            
            // Count by type
            $digest_data['by_type'][$alert->type] = ($digest_data['by_type'][$alert->type] ?? 0) + 1;
            
            // Collect critical alerts
            if ($alert->severity === 'critical') {
                $digest_data['critical_alerts'][] = $alert;
            }
        }
        
        return $digest_data;
    }

    /**
     * Get digest recipients.
     *
     * @since    1.0.0
     * @access   private
     * @return   array    Digest recipients.
     */
    private function get_digest_recipients() {
        $recipients = array();
        
        foreach ($this->recipients as $group) {
            if ($group['enabled'] && in_array('digest', $group['delivery_modes'])) {
                $recipients = array_merge($recipients, $group['emails']);
            }
        }
        
        return array_unique($recipients);
    }

    /**
     * Prepare digest email content.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $digest_data    Digest data.
     * @param    string   $period         Period.
     * @return   array                    Email content.
     */
    private function prepare_digest_email_content($digest_data, $period) {
        $template = $this->templates['digest'];
        
        // Create digest content
        $digest_html = '<div style="background: white; padding: 15px; border-radius: 5px; margin: 10px 0;">';
        $digest_html .= '<h3>📊 Alert Summary</h3>';
        $digest_html .= '<p><strong>Total Alerts:</strong> ' . $digest_data['total_alerts'] . '</p>';
        
        // Severity breakdown
        if (!empty($digest_data['by_severity'])) {
            $digest_html .= '<h4>By Severity:</h4>';
            foreach ($digest_data['by_severity'] as $severity => $count) {
                $digest_html .= '<p>• ' . ucfirst($severity) . ': ' . $count . '</p>';
            }
        }
        
        // Type breakdown
        if (!empty($digest_data['by_type'])) {
            $digest_html .= '<h4>By Type:</h4>';
            foreach ($digest_data['by_type'] as $type => $count) {
                $digest_html .= '<p>• ' . ucwords(str_replace('_', ' ', $type)) . ': ' . $count . '</p>';
            }
        }
        
        // Critical alerts
        if (!empty($digest_data['critical_alerts'])) {
            $digest_html .= '<div style="background: #ffe6e6; padding: 10px; border-radius: 3px; margin: 10px 0;">';
            $digest_html .= '<h4 style="color: #d73527;">🚨 Critical Alerts</h4>';
            foreach ($digest_data['critical_alerts'] as $alert) {
                $digest_html .= '<p><strong>' . $alert->title . '</strong><br>';
                $digest_html .= '<small>' . $alert->created_at . '</small></p>';
            }
            $digest_html .= '</div>';
        }
        
        $digest_html .= '</div>';
        
        // Prepare variables
        $variables = array(
            '{site_name}' => get_bloginfo('name'),
            '{site_url}' => get_site_url(),
            '{period}' => ucfirst($period),
            '{digest_content}' => $digest_html,
            '{dashboard_url}' => admin_url('admin.php?page=wp-breach-dashboard'),
            '{unsubscribe_url}' => $this->get_unsubscribe_url()
        );
        
        // Replace variables
        $subject = str_replace(array_keys($variables), array_values($variables), $template['subject']);
        $body = $template['header'] . str_replace(array_keys($variables), array_values($variables), $template['body']) . $template['footer'];
        
        return array(
            'subject' => $subject,
            'body' => $body,
            'headers' => $this->get_email_headers()
        );
    }

    // WordPress mail filter hooks
    
    public function set_email_from($from_email) {
        return $this->config['from_email'];
    }

    public function set_email_from_name($from_name) {
        return $this->config['from_name'];
    }

    public function set_email_content_type($content_type) {
        return $this->config['content_type'];
    }
}
